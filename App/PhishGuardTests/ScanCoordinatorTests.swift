import PhishCore
import SwiftData
import XCTest
@testable import PhishGuard

final class ScanCoordinatorTests: XCTestCase {
    private static let relay = RelayConfig(baseURL: URL(string: "https://relay.test")!, apiKey: "key", gmailPubSubTopic: "topic")

    /// Number of messages `FakeMailProvider` serves by default (one benign, two malicious).
    private static let fixtureCount = FakeMailProvider.defaultMessages.count

    /// Model answers for every message in `FakeMailProvider.defaultMessages` (unknown ids make the fake throw).
    private static let perMessage: [String: ModelAssessment] = [
        SampleEmails.benignNewsletter.messageID: FakeClassifier.benign,
        SampleEmails.paypalPhish.messageID: FakeClassifier.suspicious,
        SampleEmails.giftCardScam.messageID: ModelAssessment(isSuspicious: true, category: .scam, riskScore: 100, reasons: ["Gift card request"], summary: "Gift-card scam."),
    ]

    // MARK: - Persist / notify only when alertable

    @MainActor
    func testFlaggedRecordsPersistedAndNotifiedOnlyForAlertableVerdicts() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let classifier = FakeClassifier(behavior: .perMessage(Self.perMessage))
        let policy = AlertPolicy(minimumLevel: .medium)
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier, settings: ScanSettingsSnapshot(alertPolicy: policy))
        let accountID = try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertEqual(summary.scanned, Self.fixtureCount)
        XCTAssertTrue(summary.errors.isEmpty, "\(summary.errors)")
        XCTAssertFalse(summary.deadlineReached)
        XCTAssertFalse(summary.cancelled)

        var expectedFlagged = 0
        for email in FakeMailProvider.defaultMessages where policy.shouldAlert(await harness.coordinator.evaluate(email)) {
            expectedFlagged += 1
        }
        let records = try harness.flaggedRecords()
        XCTAssertEqual(records.count, expectedFlagged)
        XCTAssertEqual(summary.flagged, expectedFlagged)
        // Fusion: max(heuristic, risk/100). The two phishing fixtures (heuristics ≥ 0.6, model 100) land at 1.0;
        // the benign newsletter (heuristics 0, model 2) stays at 0.02 and is never alertable.
        XCTAssertEqual(records.count, 2, "the two messages the model rates 100 are alertable, the benign one is not")

        XCTAssertFalse(records.contains { $0.messageID == SampleEmails.benignNewsletter.messageID }, "benign newsletter must not be persisted")
        let paypal = try XCTUnwrap(records.first { $0.messageID == SampleEmails.paypalPhish.messageID })
        XCTAssertEqual(paypal.accountID, accountID)
        XCTAssertEqual(paypal.modelIdentifier, "fake.model")
        XCTAssertGreaterThanOrEqual(paypal.level, .medium)
        XCTAssertEqual(paypal.category, .phishing)
        XCTAssertEqual(paypal.senderAddress, "service@paypal.com")
        let giftCard = try XCTUnwrap(records.first { $0.messageID == SampleEmails.giftCardScam.messageID })
        XCTAssertEqual(giftCard.category, .scam)
        XCTAssertEqual(giftCard.provider, .gmail, "records carry the linked account's provider")

        // Every persisted record was notified exactly once, and the badge counts unread flagged records.
        let posted = harness.alerts.posted
        XCTAssertEqual(posted.count, records.count)
        XCTAssertEqual(Set(posted.compactMap(\.content.recordID)), Set(records.map(\.id)))
        XCTAssertEqual(posted.map(\.content.badge), Array(1...records.count).map { Optional($0) })
        for alert in posted {
            XCTAssertEqual(alert.content.title, NotificationManager.alertTitle)
            XCTAssertEqual(alert.content.threadIdentifier, NotificationManager.threadIdentifier(forAccount: accountID))
        }

        XCTAssertEqual(try harness.processedKeys().count, Self.fixtureCount, "every scanned message gets a ProcessedMessage row")
        XCTAssertEqual(harness.releases.value, 1, "model resources are released after the scan")
        let lastSummary = await harness.coordinator.lastSummary
        let lastScanDate = await harness.coordinator.lastScanDate
        XCTAssertEqual(lastSummary, summary)
        XCTAssertNotNil(lastScanDate)
    }

    @MainActor
    func testHigherMinimumLevelPersistsFewerRecords() async throws {
        // One verdict per band: the model rates the benign newsletter 60 and — as an independent detector — that
        // is a medium verdict on its own, while the two malicious fixtures are already in the high band on the
        // rules alone and stay there although the model calls them safe. `.high` keeps two, `.medium` keeps three.
        let answers: [String: ModelAssessment] = [
            SampleEmails.benignNewsletter.messageID: ModelAssessment(isSuspicious: true, category: .phishing, riskScore: 60, reasons: ["Odd tone"], summary: "Unsure."),
            SampleEmails.paypalPhish.messageID: FakeClassifier.benign,
            SampleEmails.giftCardScam.messageID: FakeClassifier.benign,
        ]

        let strict = try ScanHarness(
            providers: [.gmail: FakeMailProvider(provider: .gmail)],
            classifier: FakeClassifier(behavior: .perMessage(answers)),
            settings: ScanSettingsSnapshot(alertPolicy: AlertPolicy(minimumLevel: .high))
        )
        try strict.addAccount(provider: .gmail)
        let strictSummary = await strict.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertEqual(strictSummary.scanned, Self.fixtureCount)
        XCTAssertEqual(strictSummary.flagged, 2)
        XCTAssertEqual(
            Set(try strict.flaggedRecords().map(\.messageID)),
            [SampleEmails.paypalPhish.messageID, SampleEmails.giftCardScam.messageID],
            "a model answering \"safe\" cannot pull a certain phish out of the high band"
        )
        XCTAssertEqual(strict.alerts.posted.count, 2)
        XCTAssertEqual(try strict.processedKeys().count, Self.fixtureCount)

        let lenient = try ScanHarness(
            providers: [.gmail: FakeMailProvider(provider: .gmail)],
            classifier: FakeClassifier(behavior: .perMessage(answers)),
            settings: ScanSettingsSnapshot(alertPolicy: AlertPolicy(minimumLevel: .medium))
        )
        try lenient.addAccount(provider: .gmail)
        let lenientSummary = await lenient.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertEqual(lenientSummary.flagged, 3, "the model's own medium verdict is kept at the lower minimum level")
        XCTAssertGreaterThan(try lenient.flaggedRecords().count, try strict.flaggedRecords().count)
    }

    // MARK: - Dedupe and cursor

    @MainActor
    func testSecondScanDedupesAndPersistsCursor() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let classifier = FakeClassifier(behavior: .fixed(FakeClassifier.suspicious))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier)
        let accountID = try harness.addAccount(provider: .gmail)

        let first = await harness.coordinator.scan(trigger: .appLaunch, deadline: nil)
        XCTAssertEqual(first.scanned, Self.fixtureCount)
        XCTAssertEqual(try harness.account(accountID).syncCursor, "cursor-1")
        XCTAssertNotNil(try harness.account(accountID).lastScanAt)
        let recordsAfterFirst = try harness.flaggedRecords().count

        let second = await harness.coordinator.scan(trigger: .appLaunch, deadline: nil)
        XCTAssertEqual(second.scanned, 0)
        XCTAssertEqual(second.flagged, 0)
        XCTAssertEqual(classifier.callCount, Self.fixtureCount, "already-processed messages are never classified again")
        XCTAssertEqual(try harness.flaggedRecords().count, recordsAfterFirst)
        XCTAssertEqual(harness.alerts.posted.count, recordsAfterFirst)
        XCTAssertEqual(provider.fetchCalls.map { $0?.opaque }, [nil, "cursor-1"], "the persisted cursor is passed to the next fetch")
    }

    @MainActor
    func testOnlyRequestedEnabledAccountsAreScanned() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        let wanted = try harness.addAccount(provider: .gmail, email: "a@example.com")
        let other = try harness.addAccount(provider: .gmail, email: "b@example.com")
        let disabled = try harness.addAccount(provider: .gmail, email: "c@example.com", isEnabled: false)

        let summary = await harness.coordinator.scan(trigger: .silentPush, accountIDs: [wanted, disabled], deadline: nil)

        XCTAssertEqual(summary.scanned, Self.fixtureCount)
        XCTAssertEqual(provider.fetchCalls.count, 1)
        XCTAssertEqual(try harness.account(wanted).syncCursor, "cursor-1")
        XCTAssertNil(try harness.account(other).syncCursor)
        XCTAssertNil(try harness.account(disabled).syncCursor)
    }

    // MARK: - Provider-side dedupe

    @MainActor
    func testProcessedIDsArePassedToTheProviderAndSkippedBeforeDownload() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let classifier = FakeClassifier(behavior: .perMessage(Self.perMessage))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier)
        let accountID = try harness.addAccount(provider: .gmail)
        let paypalID = SampleEmails.paypalPhish.messageID
        // This account already classified the PayPal message. The same ids under another account or provider are
        // not this account's rows and must not be handed to the provider.
        try harness.insertProcessed(key: "gmail:\(accountID.uuidString):\(paypalID)", processedAt: .now)
        try harness.insertProcessed(key: "gmail:\(UUID().uuidString):\(SampleEmails.giftCardScam.messageID)", processedAt: .now)
        try harness.insertProcessed(key: "microsoft:\(accountID.uuidString):\(SampleEmails.benignNewsletter.messageID)", processedAt: .now)

        let first = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertEqual(provider.skippedIDs, [paypalID], "exactly this account's processed ids are skipped inside the provider")
        XCTAssertTrue(first.errors.isEmpty, "\(first.errors)")
        XCTAssertEqual(first.scanned, Self.fixtureCount - 1)
        XCTAssertEqual(classifier.callCount, Self.fixtureCount - 1, "a skipped message is never analyzed or classified")
        XCTAssertFalse(try harness.flaggedRecords().contains { $0.messageID == paypalID })
        XCTAssertEqual(try harness.account(accountID).syncCursor, "cursor-1")
        let log = await harness.coordinator.scanLog
        XCTAssertEqual(try XCTUnwrap(log.first { $0.accountID == accountID }).skipped, 1, "provider-side skips are reported in Diagnostics")

        // Everything is processed now: the next fetch drops every id before any body would be downloaded.
        let second = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertEqual(second.scanned, 0)
        XCTAssertEqual(Set(provider.skippedIDs.dropFirst()), Set(FakeMailProvider.defaultMessages.map(\.messageID)))
        XCTAssertEqual(classifier.callCount, Self.fixtureCount - 1)
        XCTAssertEqual(try harness.processedKeys().count, Self.fixtureCount + 2)
    }

    @MainActor
    func testCoordinatorStillDedupesWhenAProviderIgnoresTheHint() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(honorsProcessedHint: false))
        let classifier = FakeClassifier(behavior: .fixed(FakeClassifier.suspicious))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier)
        let accountID = try harness.addAccount(provider: .gmail)

        _ = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        let second = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertTrue(provider.skippedIDs.isEmpty, "the provider never consulted the hint")
        XCTAssertEqual(second.scanned, 0, "the coordinator's own dedupe still catches the re-delivered batch")
        XCTAssertEqual(classifier.callCount, Self.fixtureCount)
        let log = await harness.coordinator.scanLog
        XCTAssertEqual(try XCTUnwrap(log.last { $0.accountID == accountID }).skipped, Self.fixtureCount)
    }

    // MARK: - Organization domains

    @MainActor
    func testAnalyzerCreditsVerifiedMailFromTheLinkedAccountsDomains() async throws {
        let notice = SampleEmails.benignInternalHRNotice
        let provider = FakeMailProvider(provider: .microsoft, state: .init(messages: [notice]))
        let classifier = FakeClassifier(behavior: .fixed(FakeClassifier.benign))
        let harness = try ScanHarness(providers: [.microsoft: provider], classifier: classifier)
        try harness.addAccount(provider: .microsoft, email: "Sam.Rivera@mail.NorthwindTraders.example")

        // Diagnostics "test scan" and the real pipeline share the organization-aware analyzer.
        let verdict = await harness.coordinator.evaluate(notice)
        XCTAssertTrue(verdict.reasons.contains { $0.id == "mitigation.internal_sender" }, verdict.reasons.map(\.id).description)
        XCTAssertEqual(verdict.heuristicScore, 0, accuracy: 1e-9)
        _ = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertEqual(classifier.reportedSignalIDs(for: notice.messageID)?.contains("mitigation.internal_sender"), true)

        // A free-mail account never makes its domain "internal", and a paused account does not count.
        let webmail = FakeMailProvider(provider: .gmail, state: .init(messages: [notice]))
        let webmailHarness = try ScanHarness(providers: [.gmail: webmail], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        try webmailHarness.addAccount(provider: .gmail, email: "sam.rivera@gmail.com")
        try webmailHarness.addAccount(provider: .gmail, email: "sam@northwindtraders.example", isEnabled: false)
        let plain = await webmailHarness.coordinator.evaluate(notice)
        XCTAssertFalse(plain.reasons.contains { $0.id == "mitigation.internal_sender" }, plain.reasons.map(\.id).description)
        XCTAssertGreaterThan(plain.heuristicScore, 0)

        // The domains are refreshed per scan: linking the organization account is picked up right away.
        try webmailHarness.addAccount(provider: .gmail, email: "sam@northwindtraders.example")
        let linked = await webmailHarness.coordinator.evaluate(notice)
        XCTAssertTrue(linked.reasons.contains { $0.id == "mitigation.internal_sender" })
    }

    // MARK: - Diagnostics evaluation

    @MainActor
    func testEvaluateBatchSharesTheClassifierPersistsNothingAndReleasesResources() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let classifier = FakeClassifier(behavior: .perMessage(Self.perMessage))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier)
        try harness.addAccount(provider: .gmail)

        let verdicts = await harness.coordinator.evaluateBatch(FakeMailProvider.defaultMessages)

        XCTAssertEqual(verdicts.count, Self.fixtureCount)
        XCTAssertEqual(verdicts.map(\.modelIdentifier), Array(repeating: "fake.model", count: Self.fixtureCount))
        XCTAssertEqual(classifier.callCount, Self.fixtureCount)
        XCTAssertEqual(harness.releases.value, 1, "model resources are released once after the batch, as after a scan")
        XCTAssertTrue(provider.fetchCalls.isEmpty, "nothing is fetched")
        XCTAssertTrue(try harness.flaggedRecords().isEmpty, "nothing is persisted")
        XCTAssertTrue(try harness.processedKeys().isEmpty)
        XCTAssertTrue(harness.alerts.posted.isEmpty, "nothing is notified")

        // The single-message primitive leaves the release bookkeeping to its caller.
        _ = await harness.coordinator.evaluate(SampleEmails.paypalPhish)
        XCTAssertEqual(harness.releases.value, 1)
    }

    @MainActor
    func testEvaluateBatchLeavesTheReleaseToAScanInFlight() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(fetchDelay: .milliseconds(500)))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        try harness.addAccount(provider: .gmail)

        let scan = Task { await harness.coordinator.scan(trigger: .manual, deadline: nil) }
        // The fake records the fetch call before it sleeps, so a recorded call means the scan is in flight.
        var attempts = 0
        while provider.fetchCalls.isEmpty, attempts < 200 {
            try await Task.sleep(for: .milliseconds(5))
            attempts += 1
        }
        XCTAssertEqual(provider.fetchCalls.count, 1, "the scan should be in flight")

        let verdicts = await harness.coordinator.evaluateBatch([SampleEmails.paypalPhish])
        XCTAssertEqual(verdicts.count, 1)
        XCTAssertEqual(harness.releases.value, 0, "a batch during a scan must not drop the weights that scan is using")

        let summary = await scan.value
        XCTAssertEqual(summary.scanned, Self.fixtureCount)
        XCTAssertEqual(harness.releases.value, 1, "the scan's own finish releases them")
    }

    // MARK: - Deadline / budget

    @MainActor
    func testPastDeadlineStopsBeforeAnyWork() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.suspicious)))
        let accountID = try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .backgroundRefresh, deadline: Date())

        XCTAssertTrue(summary.deadlineReached)
        XCTAssertFalse(summary.cancelled)
        XCTAssertEqual(summary.scanned, 0)
        XCTAssertTrue(provider.fetchCalls.isEmpty)
        XCTAssertNil(try harness.account(accountID).syncCursor)
    }

    @MainActor
    func testDeadlineDuringFetchLeavesCursorUntouched() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(fetchDelay: .milliseconds(1200)))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.suspicious)))
        let accountID = try harness.addAccount(provider: .gmail)

        // Effective deadline = 4 s − 3 s margin = 1 s; the fetch takes 1.2 s.
        let summary = await harness.coordinator.scan(trigger: .silentPush, deadline: Date().addingTimeInterval(4))

        XCTAssertTrue(summary.deadlineReached)
        XCTAssertEqual(summary.scanned, 0)
        XCTAssertEqual(provider.fetchCalls.count, 1)
        XCTAssertNil(try harness.account(accountID).syncCursor, "cursor is not advanced when messages are left")
        XCTAssertNotNil(try harness.account(accountID).lastScanAt)
    }

    func testPerScanBudgetCoversAFullProviderFetch() {
        // A budget below a provider's cap would split one fetch across scans and leave the cursor behind. The caps
        // and the budget are the same number: already-processed ids are skipped inside the providers, so a capped
        // fetch only ever carries messages the coordinator still has to classify.
        XCTAssertEqual(ScanCoordinator.defaultMaxMessagesPerScan, GmailProvider.maxMessagesPerFetch)
        XCTAssertEqual(ScanCoordinator.defaultMaxMessagesPerScan, GraphMailSync.maxMessagesPerScan)
    }

    @MainActor
    func testInFlightInferenceIsTimeBoxedToTheDeadline() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let classifier = FakeClassifier(behavior: .fixed(FakeClassifier.suspicious), assessDelay: .seconds(5))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier)
        try harness.addAccount(provider: .gmail)

        // Effective budget = 4 s − 3 s margin = 1 s; the first inference alone would take 5 s.
        let started = Date()
        let summary = await harness.coordinator.scan(trigger: .silentPush, deadline: Date().addingTimeInterval(4))

        XCTAssertLessThan(Date().timeIntervalSince(started), 3, "the scan returns at its deadline, not when the model finishes")
        XCTAssertTrue(summary.deadlineReached)
        XCTAssertFalse(summary.cancelled)
        XCTAssertTrue(summary.errors.isEmpty, "\(summary.errors)")
        XCTAssertEqual(summary.scanned, 1, "the message whose inference timed out gets a heuristics-only verdict")
        XCTAssertEqual(classifier.callCount, 1)
        XCTAssertEqual(try harness.processedKeys().count, 1)
        XCTAssertTrue(try harness.flaggedRecords().allSatisfy { $0.modelIdentifier == nil })
    }

    @MainActor
    func testMessageBudgetReportsDeadlineAndResumesNextScan() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let classifier = FakeClassifier(behavior: .fixed(FakeClassifier.suspicious))
        // Budget one short of the fixture count: the first scan leaves exactly one message pending.
        let budget = Self.fixtureCount - 1
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier, maxMessagesPerScan: budget)
        let accountID = try harness.addAccount(provider: .gmail)

        let first = await harness.coordinator.scan(trigger: .backgroundRefresh, deadline: nil)
        XCTAssertEqual(first.scanned, budget)
        XCTAssertTrue(first.deadlineReached, "hitting the message budget asks for a processing task")
        XCTAssertNil(try harness.account(accountID).syncCursor)

        let second = await harness.coordinator.scan(trigger: .backgroundProcessing, deadline: nil)
        XCTAssertEqual(second.scanned, 1, "only the remaining message is classified")
        XCTAssertFalse(second.deadlineReached)
        XCTAssertEqual(try harness.account(accountID).syncCursor, "cursor-1")
        XCTAssertEqual(classifier.callCount, Self.fixtureCount)
    }

    // MARK: - Cancellation

    @MainActor
    func testCancellationStopsScanPromptly() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(fetchDelay: .seconds(5)))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.suspicious)))
        let accountID = try harness.addAccount(provider: .gmail)
        let coordinator = harness.coordinator

        let work = Task { await coordinator.scan(trigger: .backgroundRefresh, deadline: Date().addingTimeInterval(25)) }
        try await Task.sleep(for: .milliseconds(200))
        let cancelledAt = Date()
        work.cancel()
        let summary = await work.value

        XCTAssertTrue(summary.cancelled)
        XCTAssertEqual(summary.scanned, 0)
        XCTAssertLessThan(Date().timeIntervalSince(cancelledAt), 2, "cancellation must unwind well within the BGTask grace period")
        XCTAssertNil(try harness.account(accountID).syncCursor)
        XCTAssertEqual(harness.releases.value, 1, "resources are released even when cancelled")
        let lastSummary = await harness.coordinator.lastSummary
        XCTAssertEqual(lastSummary?.cancelled, true)
    }

    // MARK: - Per-account error isolation

    @MainActor
    func testOneAccountFailingDoesNotStopTheOthers() async throws {
        let gmail = FakeMailProvider(provider: .gmail, state: .init(fetchError: ProviderError.notAuthenticated))
        let microsoft = FakeMailProvider(provider: .microsoft)
        let harness = try ScanHarness(providers: [.gmail: gmail, .microsoft: microsoft], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.suspicious)))
        let gmailID = try harness.addAccount(provider: .gmail, email: "g@example.com")
        let microsoftID = try harness.addAccount(provider: .microsoft, email: "m@example.com")

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertEqual(summary.errors.count, 1)
        XCTAssertTrue(summary.errors[0].contains(ProviderError.notAuthenticated.localizedDescription), summary.errors[0])
        XCTAssertEqual(summary.scanned, Self.fixtureCount, "the healthy account is fully scanned")
        XCTAssertNil(try harness.account(gmailID).syncCursor)
        XCTAssertEqual(try harness.account(microsoftID).syncCursor, "cursor-1")
        XCTAssertFalse(summary.deadlineReached)

        let log = await harness.coordinator.scanLog
        let gmailEntry = try XCTUnwrap(log.first { $0.accountID == gmailID })
        XCTAssertEqual(gmailEntry.errors.count, 1)
        XCTAssertEqual(gmailEntry.provider, .gmail)
        let microsoftEntry = try XCTUnwrap(log.first { $0.accountID == microsoftID })
        XCTAssertEqual(microsoftEntry.scanned, Self.fixtureCount)
    }

    @MainActor
    func testNotAuthenticatedFlagsTheAccountUntilAFetchSucceeds() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(fetchError: ProviderError.notAuthenticated))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        let accountID = try harness.addAccount(provider: .gmail)
        XCTAssertFalse(try harness.account(accountID).needsReauthentication)

        let first = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertEqual(first.errors.count, 1)
        XCTAssertTrue(try harness.account(accountID).needsReauthentication, "a revoked grant is flagged for the Accounts screen")

        provider.state.withLock { $0.fetchError = nil }
        let second = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertTrue(second.errors.isEmpty, "\(second.errors)")
        XCTAssertFalse(try harness.account(accountID).needsReauthentication, "cleared by the next successful fetch")

        // Other failures (offline, rate limit) are not authentication problems.
        let offline = FakeMailProvider(provider: .gmail, state: .init(fetchError: ProviderError.network("offline")))
        let offlineHarness = try ScanHarness(providers: [.gmail: offline], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        let offlineID = try offlineHarness.addAccount(provider: .gmail)
        _ = await offlineHarness.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertFalse(try offlineHarness.account(offlineID).needsReauthentication)
    }

    @MainActor
    func testAccountWithoutRegisteredProviderIsReportedAndSkipped() async throws {
        let harness = try ScanHarness(providers: [.gmail: FakeMailProvider(provider: .gmail)], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        try harness.addAccount(provider: .microsoft, email: "m@example.com")
        try harness.addAccount(provider: .gmail, email: "g@example.com")

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertEqual(summary.errors.count, 1)
        XCTAssertTrue(summary.errors[0].contains("No provider registered"))
        XCTAssertEqual(summary.scanned, Self.fixtureCount)
    }

    // MARK: - Classifier fallback

    @MainActor
    func testClassifierFailureFallsBackToHeuristicsAndTripsBreaker() async throws {
        let messages = FakeMailProvider.defaultMessages + [
            SampleEmails.paypalPhish.withMessageID("dup-1"),
            SampleEmails.paypalPhish.withMessageID("dup-2"),
        ]
        let provider = FakeMailProvider(provider: .gmail, state: .init(messages: messages))
        let classifier = FakeClassifier(behavior: .fail(ClassifierError.invalidOutput("garbage")))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier)
        try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertEqual(summary.scanned, messages.count)
        XCTAssertTrue(summary.errors.isEmpty, "a broken model is not a scan error")
        XCTAssertEqual(classifier.callCount, ScanCoordinator.classifierFailureThreshold, "after repeated failures the model is skipped for the rest of the scan")
        // Whatever the heuristics decide, nothing persisted may claim a model verdict.
        let records = try harness.flaggedRecords()
        XCTAssertTrue(records.allSatisfy { $0.modelIdentifier == nil })

        let verdict = await harness.coordinator.evaluate(SampleEmails.paypalPhish)
        XCTAssertNil(verdict.modelIdentifier, "heuristics-only verdicts carry no model identifier")
        XCTAssertNil(verdict.modelRiskScore)
        XCTAssertEqual(verdict.confidence, verdict.heuristicScore, "without a model the confidence is the heuristic score")

        let log = await harness.coordinator.scanLog
        let scanLine = try XCTUnwrap(log.last { $0.accountID == nil })
        XCTAssertEqual(scanLine.note?.contains("model disabled"), true)
    }

    @MainActor
    func testUnavailableClassifierIsNeverCalled() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let classifier = FakeClassifier(behavior: .unavailable("Apple Intelligence is off"))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier)
        try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertEqual(summary.scanned, Self.fixtureCount)
        XCTAssertEqual(classifier.callCount, 0)
        XCTAssertTrue(try harness.flaggedRecords().allSatisfy { $0.modelIdentifier == nil })
    }

    @MainActor
    func testGuardrailViolationDoesNotDisableModel() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(messages: [
            SampleEmails.paypalPhish, SampleEmails.paypalPhish.withMessageID("dup-1"), SampleEmails.paypalPhish.withMessageID("dup-2"),
            SampleEmails.paypalPhish.withMessageID("dup-3"),
        ]))
        let classifier = FakeClassifier(behavior: .fail(ClassifierError.guardrailViolation))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier)
        try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertEqual(summary.scanned, 4)
        XCTAssertEqual(classifier.callCount, 4, "content refusals are per message and do not trip the breaker")
    }

    // MARK: - Foreground gate (no GPU work outside the foreground)

    /// A silent push or BGTask runs with the app in the background, where iOS kills the process rather than let it
    /// submit Metal work. The scan must still happen, still persist and still notify — with the rules alone.
    @MainActor
    func testBackgroundScanWithAGPUClassifierUsesTheRulesAndStillFlags() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let classifier = FakeGPUClassifier(behavior: .fixed(FakeClassifier.suspicious))
        let harness = try ScanHarness(
            providers: [.gmail: provider],
            classifier: classifier,
            foregroundGate: AppForegroundGate(isForeground: false)
        )
        try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .silentPush, deadline: nil)

        XCTAssertEqual(summary.scanned, Self.fixtureCount)
        XCTAssertTrue(summary.errors.isEmpty, "\(summary.errors)")
        XCTAssertEqual(classifier.callCount, 0, "the model is never called while the app is not frontmost")

        // The rule engine alerts on strong evidence by itself, so background detection keeps working.
        let records = try harness.flaggedRecords()
        XCTAssertEqual(records.count, 2, "both malicious fixtures are flagged by the rules alone")
        XCTAssertTrue(records.allSatisfy { $0.modelIdentifier == nil }, "nothing may claim a model verdict")
        XCTAssertEqual(summary.flagged, records.count)
        XCTAssertEqual(harness.alerts.posted.count, records.count)

        let log = await harness.coordinator.scanLog
        let scanLine = try XCTUnwrap(log.last { $0.accountID == nil })
        let note = try XCTUnwrap(scanLine.note)
        XCTAssertTrue(note.contains("app not in the foreground"), note)
        XCTAssertFalse(note.contains("model disabled"), "an expected fallback is not a disabled model: \(note)")
    }

    /// A non-GPU classifier (Apple Intelligence, which the system allows in the background) is unaffected.
    @MainActor
    func testBackgroundScanStillUsesAClassifierThatDoesNotNeedTheGPU() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let classifier = FakeClassifier(behavior: .perMessage(Self.perMessage))
        let harness = try ScanHarness(
            providers: [.gmail: provider],
            classifier: classifier,
            foregroundGate: AppForegroundGate(isForeground: false)
        )
        try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .backgroundRefresh, deadline: nil)

        XCTAssertEqual(summary.scanned, Self.fixtureCount)
        XCTAssertEqual(classifier.callCount, Self.fixtureCount)
        XCTAssertTrue(try harness.flaggedRecords().allSatisfy { $0.modelIdentifier == "fake.model" })
    }

    /// The gate closing mid-scan (the user swipes to another app) degrades the rest of the scan to the rules
    /// without marking the classifier failed: more messages than the breaker threshold go by and the model stays
    /// enabled, so the next foreground scan uses it again.
    @MainActor
    func testGateClosingMidScanDoesNotTripTheBreaker() async throws {
        let messages = FakeMailProvider.defaultMessages + (1...5).map { SampleEmails.paypalPhish.withMessageID("dup-\($0)") }
        let provider = FakeMailProvider(provider: .gmail, state: .init(messages: messages, fetchDelay: .milliseconds(400)))
        let classifier = FakeGPUClassifier(behavior: .fixed(FakeClassifier.suspicious))
        let gate = AppForegroundGate(isForeground: true)
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier, foregroundGate: gate)
        try harness.addAccount(provider: .gmail)
        let coordinator = harness.coordinator

        let work = Task { await coordinator.scan(trigger: .manual, deadline: nil) }
        try await Task.sleep(for: .milliseconds(120)) // still inside the fetch
        gate.setForeground(false)
        let summary = await work.value

        XCTAssertEqual(summary.scanned, messages.count)
        XCTAssertTrue(summary.errors.isEmpty, "\(summary.errors)")
        XCTAssertEqual(classifier.callCount, 0)
        XCTAssertGreaterThan(messages.count, ScanCoordinator.classifierFailureThreshold, "enough messages to trip the breaker if this counted as failures")
        let log = await coordinator.scanLog
        let scanLine = try XCTUnwrap(log.last { $0.accountID == nil })
        XCTAssertEqual(scanLine.note?.contains("app not in the foreground"), true)
        XCTAssertEqual(scanLine.note?.contains("model disabled"), false)

        // Back in the foreground the model answers again: nothing was disabled permanently.
        gate.setForeground(true)
        let verdict = await coordinator.evaluate(SampleEmails.paypalPhish)
        XCTAssertEqual(verdict.modelIdentifier, "fake.gpu.model")
        XCTAssertEqual(classifier.callCount, 1)
    }

    /// The residual race the classifier itself guards: the gate was open when the coordinator checked, and the app
    /// left the foreground before/while the model ran, so `assess` throws `requiresForeground`. Expected, not a
    /// failure — every message is still attempted and the breaker never trips.
    @MainActor
    func testClassifierRefusingForForegroundIsNotCountedAsAFailure() async throws {
        let messages = FakeMailProvider.defaultMessages + (1...3).map { SampleEmails.paypalPhish.withMessageID("dup-\($0)") }
        let provider = FakeMailProvider(provider: .gmail, state: .init(messages: messages))
        let classifier = FakeGPUClassifier(behavior: .fail(ClassifierError.requiresForeground(MLXClassifier.foregroundOnlyReason)))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier)
        try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertEqual(summary.scanned, messages.count)
        XCTAssertTrue(summary.errors.isEmpty, "\(summary.errors)")
        XCTAssertEqual(classifier.callCount, messages.count, "a foreground refusal is per message and does not trip the breaker")
        XCTAssertTrue(try harness.flaggedRecords().allSatisfy { $0.modelIdentifier == nil })
        let log = await harness.coordinator.scanLog
        let scanLine = try XCTUnwrap(log.last { $0.accountID == nil })
        XCTAssertEqual(scanLine.note?.contains("app not in the foreground"), true)
        XCTAssertEqual(scanLine.note?.contains("model disabled"), false)
    }

    /// Diagnostics' test scan and test notification go through `evaluateBatch`, which is exactly what the user was
    /// doing when the field crash happened.
    @MainActor
    func testEvaluateAndEvaluateBatchRespectTheForegroundGate() async throws {
        let classifier = FakeGPUClassifier(behavior: .fixed(FakeClassifier.suspicious))
        let gate = AppForegroundGate(isForeground: false)
        let harness = try ScanHarness(providers: [:], classifier: classifier, foregroundGate: gate)

        let batch = await harness.coordinator.evaluateBatch(FakeMailProvider.defaultMessages)
        XCTAssertEqual(batch.count, Self.fixtureCount)
        XCTAssertTrue(batch.allSatisfy { $0.modelIdentifier == nil }, "no model may run while the app is not frontmost")
        XCTAssertEqual(classifier.callCount, 0)
        let single = await harness.coordinator.evaluate(SampleEmails.paypalPhish)
        XCTAssertNil(single.modelIdentifier)
        XCTAssertEqual(classifier.callCount, 0)
        // The rules still produce a real verdict for the test notification to carry.
        XCTAssertGreaterThanOrEqual(single.level, .medium)
        XCTAssertEqual(single.confidence, single.heuristicScore)

        gate.setForeground(true)
        let foreground = await harness.coordinator.evaluateBatch([SampleEmails.paypalPhish])
        XCTAssertEqual(foreground.first?.modelIdentifier, "fake.gpu.model")
        XCTAssertEqual(classifier.callCount, 1)
    }

    @MainActor
    func testMemoryWarningDegradesRunningScanToHeuristics() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(fetchDelay: .milliseconds(600)))
        let classifier = FakeClassifier(behavior: .fixed(FakeClassifier.suspicious))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier)
        try harness.addAccount(provider: .gmail)
        let coordinator = harness.coordinator

        let work = Task { await coordinator.scan(trigger: .manual, deadline: nil) }
        try await Task.sleep(for: .milliseconds(150))
        await coordinator.handleMemoryWarning()
        let summary = await work.value

        XCTAssertEqual(summary.scanned, Self.fixtureCount)
        XCTAssertEqual(classifier.callCount, 0)
        XCTAssertTrue(try harness.flaggedRecords().allSatisfy { $0.modelIdentifier == nil })
        XCTAssertGreaterThanOrEqual(harness.releases.value, 2, "released on the warning and again at the end of the scan")
    }

    // MARK: - Coalescing

    @MainActor
    func testRequestsArrivingAfterTheRunningFetchShareOneFollowUp() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(fetchDelay: .milliseconds(600)))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.suspicious)))
        try harness.addAccount(provider: .gmail)
        let coordinator = harness.coordinator

        let first = Task { await coordinator.scan(trigger: .backgroundRefresh, deadline: nil) }
        try await Task.sleep(for: .milliseconds(150)) // the running scan is inside its fetch: newer mail could be missed
        let sameTrigger = Task { await coordinator.scan(trigger: .backgroundRefresh, deadline: nil) }
        let silentPush = Task { await coordinator.scan(trigger: .silentPush, deadline: nil) }
        let secondSilentPush = Task { await coordinator.scan(trigger: .silentPush, deadline: nil) }

        let firstSummary = await first.value
        let joinedSummary = await sameTrigger.value
        let pushSummary = await silentPush.value
        let secondPushSummary = await secondSilentPush.value

        XCTAssertEqual(firstSummary.scanned, Self.fixtureCount)
        XCTAssertEqual(joinedSummary.scanned, 0, "a request that arrived after the running fetch gets a follow-up pass, whatever its trigger")
        XCTAssertEqual(pushSummary.scanned, 0, "the follow-up pass finds everything already processed")
        XCTAssertEqual(secondPushSummary.scanned, 0)
        XCTAssertEqual(provider.fetchCalls.count, 2, "one in-flight scan + exactly one follow-up shared by every joiner")
    }

    @MainActor
    func testRequestArrivingBeforeTheRunningFetchIsSatisfiedByJoining() async throws {
        // With the relay configured and no subscription yet, the running scan spends 600 ms renewing the push
        // subscription before its first fetch, so a request arriving now is covered by that fetch.
        let provider = FakeMailProvider(provider: .gmail, state: .init(subscriptionDelay: .milliseconds(600)))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.suspicious)), settings: ScanSettingsSnapshot(relayConfig: Self.relay))
        try harness.addAccount(provider: .gmail)
        let coordinator = harness.coordinator

        let first = Task { await coordinator.scan(trigger: .backgroundRefresh, deadline: nil) }
        try await Task.sleep(for: .milliseconds(150))
        let joiner = Task { await coordinator.scan(trigger: .silentPush, deadline: nil) }

        let firstSummary = await first.value
        let joinedSummary = await joiner.value

        XCTAssertEqual(firstSummary.scanned, Self.fixtureCount)
        XCTAssertEqual(joinedSummary, firstSummary, "joining satisfies the request")
        XCTAssertEqual(provider.fetchCalls.count, 1, "no follow-up: the running scan had not fetched yet")
    }

    @MainActor
    func testPushForAnotherAccountIsNotDroppedByTheRunningScan() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(fetchDelay: .milliseconds(400)))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        let x = try harness.addAccount(provider: .gmail, email: "x@example.com")
        let y = try harness.addAccount(provider: .gmail, email: "y@example.com")
        let coordinator = harness.coordinator

        let pushForX = Task { await coordinator.scan(trigger: .silentPush, accountIDs: [x], deadline: nil) }
        try await Task.sleep(for: .milliseconds(150))
        let pushForY = Task { await coordinator.scan(trigger: .silentPush, accountIDs: [y], deadline: nil) }

        let xSummary = await pushForX.value
        let ySummary = await pushForY.value

        XCTAssertEqual(xSummary.scanned, Self.fixtureCount)
        XCTAssertEqual(ySummary.scanned, Self.fixtureCount, "y's mail is classified by the follow-up pass")
        XCTAssertEqual(provider.fetchAccountIDs, [x, y], "the follow-up covers exactly the joiner's account")
        XCTAssertEqual(try harness.account(y).syncCursor, "cursor-1")
    }

    @MainActor
    func testAccountLinkedDuringAManualScanIsScannedByTheFollowUp() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(fetchDelay: .milliseconds(400)))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        let existing = try harness.addAccount(provider: .gmail, email: "old@example.com")
        let coordinator = harness.coordinator

        let manual = Task { await coordinator.scan(trigger: .manual, deadline: nil) }
        try await Task.sleep(for: .milliseconds(150))
        // AccountLinker saves the new account, then starts its first scan with the same trigger as "Scan now".
        let linked = try harness.addAccount(provider: .gmail, email: "new@example.com")
        let postLink = Task { await coordinator.scan(trigger: .manual, accountIDs: [linked], deadline: nil) }

        _ = await manual.value
        let summary = await postLink.value

        XCTAssertEqual(summary.scanned, Self.fixtureCount, "the new account's first scan is not swallowed by the running one")
        XCTAssertEqual(provider.fetchAccountIDs, [existing, linked])
        XCTAssertNotNil(try harness.account(linked).lastScanAt)
    }

    @MainActor
    func testJoinerWithADeadlineStopsWaitingWithoutShorteningTheSharedScan() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(fetchDelay: .milliseconds(2500)))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.suspicious)))
        try harness.addAccount(provider: .gmail)
        let coordinator = harness.coordinator

        let processing = Task { await coordinator.scan(trigger: .backgroundProcessing, deadline: Date().addingTimeInterval(120)) }
        try await Task.sleep(for: .milliseconds(150))
        // A silent push joins the long scan; its effective wait is 3.5 s − 3 s margin = 0.5 s.
        let startedWaiting = Date()
        let push = await coordinator.scan(trigger: .silentPush, deadline: Date().addingTimeInterval(3.5))

        XCTAssertLessThan(Date().timeIntervalSince(startedWaiting), 2, "the joiner returns at its own deadline")
        XCTAssertTrue(push.deadlineReached, "so the caller queues a processing task for the leftover work")
        XCTAssertEqual(push.scanned, 0)
        XCTAssertFalse(push.cancelled)

        let processingSummary = await processing.value
        XCTAssertEqual(processingSummary.scanned, Self.fixtureCount, "the shared scan is neither cancelled nor shortened")
        XCTAssertFalse(processingSummary.cancelled)
        XCTAssertFalse(processingSummary.deadlineReached)
        XCTAssertEqual(provider.fetchCalls.count, 1, "a joiner that gave up does not start a scan of its own")
    }

    // MARK: - Push subscription renewal

    @MainActor
    func testPushSubscriptionRenewedOnlyWhenExpiringWithin24Hours() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)), settings: ScanSettingsSnapshot(relayConfig: Self.relay))
        let expiring = try harness.addAccount(provider: .gmail, email: "soon@example.com", pushSubscriptionExpiresAt: Date().addingTimeInterval(3600))
        let healthy = try harness.addAccount(provider: .gmail, email: "later@example.com", pushSubscriptionExpiresAt: Date().addingTimeInterval(3 * 24 * 3600))
        let missing = try harness.addAccount(provider: .gmail, email: "none@example.com")

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertTrue(summary.errors.isEmpty, "\(summary.errors)")
        XCTAssertEqual(provider.subscriptionCalls.count, 2, "expiring + missing are renewed, the healthy one is left alone")
        XCTAssertEqual(provider.subscriptionCalls.compactMap { $0?.id }, ["existing-sub"], "the current state is passed to the provider")

        let renewed = try harness.account(expiring)
        XCTAssertEqual(renewed.pushSubscriptionID, "sub-\(expiring.uuidString)")
        XCTAssertEqual(renewed.relayAccountKey, "key-\(expiring.uuidString)")
        XCTAssertGreaterThan(try XCTUnwrap(renewed.pushSubscriptionExpiresAt).timeIntervalSinceNow, 6 * 24 * 3600)
        XCTAssertEqual(try harness.account(healthy).pushSubscriptionID, "existing-sub")
        XCTAssertEqual(try harness.account(missing).pushSubscriptionID, "sub-\(missing.uuidString)")
    }

    @MainActor
    func testPushSubscriptionRenewedImmediatelyAfterCursorReset() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(cursorWasReset: true))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)), settings: ScanSettingsSnapshot(relayConfig: Self.relay))
        try harness.addAccount(provider: .gmail, pushSubscriptionExpiresAt: Date().addingTimeInterval(5 * 24 * 3600))

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertEqual(provider.subscriptionCalls.count, 1)
        XCTAssertEqual(summary.scanned, Self.fixtureCount)
        let log = await harness.coordinator.scanLog
        let entry = try XCTUnwrap(log.first { $0.accountID != nil })
        XCTAssertEqual(entry.note, "cursor reset")
    }

    @MainActor
    func testRequestedRenewalForcesRefreshOnNextScan() async throws {
        let provider = FakeMailProvider(provider: .microsoft)
        let harness = try ScanHarness(providers: [.microsoft: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)), settings: ScanSettingsSnapshot(relayConfig: Self.relay))
        let accountID = try harness.addAccount(provider: .microsoft, pushSubscriptionExpiresAt: Date().addingTimeInterval(5 * 24 * 3600))

        _ = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertEqual(provider.subscriptionCalls.count, 0)

        await harness.coordinator.requestPushRenewal(for: [accountID])
        _ = await harness.coordinator.scan(trigger: .silentPush, deadline: nil)
        XCTAssertEqual(provider.subscriptionCalls.count, 1)

        _ = await harness.coordinator.scan(trigger: .silentPush, deadline: nil)
        XCTAssertEqual(provider.subscriptionCalls.count, 1, "the forced renewal is consumed")
    }

    @MainActor
    func testPushSubscriptionFailureIsReportedAndBackedOff() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(subscriptionError: ProviderError.http(status: 503, message: "watch failed")))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.suspicious)), settings: ScanSettingsSnapshot(relayConfig: Self.relay))
        let accountID = try harness.addAccount(provider: .gmail)

        let first = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertEqual(first.errors.count, 1)
        XCTAssertTrue(first.errors[0].hasPrefix("Push subscription"), first.errors[0])
        XCTAssertEqual(first.scanned, Self.fixtureCount, "a subscription failure does not block scanning")
        XCTAssertEqual(try harness.account(accountID).syncCursor, "cursor-1")

        let second = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertEqual(provider.subscriptionCalls.count, 1, "not retried within the backoff window")
        XCTAssertTrue(second.errors.isEmpty)
    }

    @MainActor
    func testNoRelayMeansNoSubscriptionCalls() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        try harness.addAccount(provider: .gmail)

        _ = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertTrue(provider.subscriptionCalls.isEmpty)
    }

    // MARK: - Pruning and log

    @MainActor
    func testOldProcessedMessagesArePruned() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(messages: []))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        try harness.addAccount(provider: .gmail)
        try harness.insertProcessed(key: "gmail:x:old", processedAt: Date().addingTimeInterval(-8 * 24 * 3600))
        try harness.insertProcessed(key: "gmail:x:recent", processedAt: Date().addingTimeInterval(-24 * 3600))

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertTrue(summary.errors.isEmpty, "\(summary.errors)")
        XCTAssertEqual(try harness.processedKeys(), ["gmail:x:recent"])
    }

    @MainActor
    func testScanLogIsARingBufferWithoutMailContent() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.suspicious)))
        let accountID = try harness.addAccount(provider: .gmail)

        _ = await harness.coordinator.scan(trigger: .appLaunch, deadline: nil)
        var log = await harness.coordinator.scanLog
        XCTAssertEqual(log.count, 2, "one line per account plus one per scan")
        let accountLine = try XCTUnwrap(log.first { $0.accountID == accountID })
        XCTAssertEqual(accountLine.trigger, .appLaunch)
        XCTAssertEqual(accountLine.scanned, Self.fixtureCount)
        XCTAssertGreaterThanOrEqual(accountLine.duration, 0)
        let scanLine = try XCTUnwrap(log.first { $0.accountID == nil })
        XCTAssertEqual(scanLine.scanned, Self.fixtureCount)
        XCTAssertEqual(scanLine.flagged, accountLine.flagged)

        for _ in 0..<30 {
            _ = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        }
        log = await harness.coordinator.scanLog
        XCTAssertEqual(log.count, ScanCoordinator.scanLogCapacity)
        XCTAssertTrue(log.allSatisfy { $0.trigger == .manual }, "oldest entries are dropped first")

        let text = log.flatMap { $0.errors + [$0.note ?? ""] }.joined(separator: " ")
        XCTAssertFalse(text.contains("PayPal"))
        XCTAssertFalse(text.contains("paypal.com"))
    }
}

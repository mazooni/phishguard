#if DEBUG
import PhishCore
import SwiftData
import XCTest
@testable import PhishGuard

/// Settings → Demo: seeding sample data next to real data, never fetching the demo account, and the
/// "simulate an incoming flagged email" button.
///
/// The property under test throughout is the separation: demo rows carry `isDemo`, real rows do not, and no
/// demo operation may read or write a real one.
final class DemoModeTests: XCTestCase {
    // MARK: - Fixtures

    /// A flagged email the user really received, plus its dedupe row — the thing demo mode must never touch.
    @MainActor
    @discardableResult
    private func insertRealRecord(
        in context: ModelContext,
        accountID: UUID,
        fixture: EmailMessage = SampleEmails.paypalPhish,
        messageID: String = "real-message-1"
    ) throws -> FlaggedEmailRecord {
        var email = fixture
        email.accountID = accountID.uuidString
        email.messageID = messageID
        let verdict = VerdictEngine().makeVerdict(
            report: HeuristicAnalyzer().analyze(email), assessment: nil, modelIdentifier: nil
        )
        let record = FlaggedEmailRecord(email: email, verdict: verdict, accountID: accountID)
        context.insert(record)
        context.insert(ProcessedMessage(key: email.dedupeKey))
        try context.save()
        return record
    }

    @MainActor
    private func makeRealAccount(in context: ModelContext, email: String = "owner@gmail.com") throws -> LinkedAccount {
        let account = LinkedAccount(provider: .gmail, email: email, displayName: "Owner", relayAccountKey: "real-key")
        context.insert(account)
        try context.save()
        return account
    }

    // MARK: - On / off

    @MainActor
    func testDemoModeOnThenOffLeavesRealRecordsAndAccountsUntouched() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        let realAccount = try makeRealAccount(in: context)
        let realRecord = try insertRealRecord(in: context, accountID: realAccount.id)
        let realRecordID = realRecord.id
        let realAccountID = realAccount.id
        let realSubject = realRecord.subject
        let realConfidence = realRecord.confidence
        let realProcessedKeys = try context.fetch(FetchDescriptor<ProcessedMessage>()).map(\.key)

        let on = DemoMode.enable(in: context)

        XCTAssertGreaterThan(on.records, 5, "the seeded week is a corpus, not a token record")
        let afterOn = try context.fetch(FetchDescriptor<FlaggedEmailRecord>())
        XCTAssertEqual(afterOn.count, on.records + 1, "the demo corpus sits next to the real record")
        XCTAssertEqual(afterOn.filter { !$0.isDemo }.map(\.id), [realRecordID])
        let accountsAfterOn = try context.fetch(FetchDescriptor<LinkedAccount>())
        XCTAssertEqual(accountsAfterOn.count, 2)
        XCTAssertEqual(accountsAfterOn.filter(\.isDemo).map(\.email), [DemoData.accountEmail])
        XCTAssertTrue(afterOn.filter(\.isDemo).allSatisfy { $0.accountID == accountsAfterOn.first(where: \.isDemo)?.id })

        let off = DemoMode.disable(in: context, notifications: nil)

        XCTAssertEqual(off.records, on.records)
        XCTAssertEqual(off.accounts, 1)
        let records = try context.fetch(FetchDescriptor<FlaggedEmailRecord>())
        XCTAssertEqual(records.count, 1, "every demo record is gone and the real one is not")
        let survivor = try XCTUnwrap(records.first)
        XCTAssertEqual(survivor.id, realRecordID)
        XCTAssertEqual(survivor.subject, realSubject)
        XCTAssertEqual(survivor.confidence, realConfidence)
        XCTAssertFalse(survivor.isDemo)

        let accounts = try context.fetch(FetchDescriptor<LinkedAccount>())
        XCTAssertEqual(accounts.map(\.id), [realAccountID], "the real account survives, the demo account does not")
        XCTAssertEqual(accounts.first?.relayAccountKey, "real-key")
        XCTAssertEqual(try context.fetch(FetchDescriptor<ProcessedMessage>()).map(\.key), realProcessedKeys,
                       "the real account's dedupe rows are untouched")
    }

    @MainActor
    func testDemoModeOffWithNoDemoDataChangesNothing() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        let account = try makeRealAccount(in: context)
        try insertRealRecord(in: context, accountID: account.id)

        let change = DemoMode.disable(in: context, notifications: nil)

        XCTAssertEqual(change, DemoMode.Change(records: 0, accounts: 0))
        XCTAssertEqual(try context.fetchCount(FetchDescriptor<FlaggedEmailRecord>()), 1)
        XCTAssertEqual(try context.fetchCount(FetchDescriptor<LinkedAccount>()), 1)
    }

    @MainActor
    func testReEnablingReseedsWithFreshTimestampsAndNeverDoubles() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        let yesterday = Date().addingTimeInterval(-24 * 3600)

        let first = DemoMode.enable(in: context, now: yesterday)
        let staleNewest = try XCTUnwrap(
            context.fetch(FetchDescriptor<FlaggedEmailRecord>(sortBy: [SortDescriptor(\.receivedAt, order: .reverse)])).first
        )
        XCTAssertLessThan(staleNewest.receivedAt, Date().addingTimeInterval(-3600), "seeded as of yesterday")

        let second = DemoMode.enable(in: context)

        XCTAssertEqual(second.records, first.records, "a second 'on' re-seeds, it does not stack")
        XCTAssertEqual(try context.fetchCount(FetchDescriptor<LinkedAccount>()), 1, "one demo account, not two")
        let newest = try XCTUnwrap(
            context.fetch(FetchDescriptor<FlaggedEmailRecord>(sortBy: [SortDescriptor(\.receivedAt, order: .reverse)])).first
        )
        XCTAssertTrue(Calendar.current.isDateInToday(newest.receivedAt), "\"Today\" is always today after re-enabling")
    }

    @MainActor
    func testSeededDemoRecordsCarryEngineVerdictsAndTheSimulatorSpread() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        DemoMode.enable(in: context)

        let records = try context.fetch(DemoMode.demoRecordDescriptor())
        XCTAssertTrue(records.allSatisfy(\.isDemo))
        XCTAssertTrue(records.allSatisfy { $0.level != .safe }, "nothing is seeded that the engine would not alert on")
        XCTAssertGreaterThan(Set(records.map(\.level)).count, 1, "a spread of risk levels, not one band")
        XCTAssertTrue(records.contains { !$0.isRead }, "some are unread")
        XCTAssertTrue(records.contains(where: \.isRead), "some are read")
        XCTAssertTrue(records.contains { $0.modelIdentifier != nil }, "today's carry the measured model answer")
        XCTAssertTrue(records.contains { $0.modelIdentifier == nil }, "older ones are the rules alone")
        XCTAssertTrue(records.contains { Calendar.current.isDateInToday($0.receivedAt) })
    }

    // MARK: - The scan never touches a demo account

    @MainActor
    func testScanNeverFetchesADemoAccountAndReportsNoErrorForIt() async throws {
        let relay = RelayConfig(baseURL: URL(string: "https://relay.test")!, apiKey: "key", gmailPubSubTopic: "topic")
        let provider = FakeMailProvider(provider: .gmail)
        let harness = try ScanHarness(
            providers: [.gmail: provider],
            classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)),
            settings: ScanSettingsSnapshot(relayConfig: relay)
        )
        let realID = try harness.addAccount(provider: .gmail, email: "owner@gmail.com")
        let demoID = try harness.addAccount(provider: .gmail, email: DemoData.accountEmail, isDemo: true)

        let summary = await harness.coordinator.scan(trigger: .manual, accountIDs: nil, deadline: nil)

        XCTAssertEqual(provider.fetchAccountIDs, [realID], "only the real mailbox is fetched")
        XCTAssertFalse(provider.fetchAccountIDs.contains(demoID))
        XCTAssertTrue(summary.errors.isEmpty, "a credential-less demo account must not produce a scan error: \(summary.errors)")
        XCTAssertEqual(summary.scanned, FakeMailProvider.defaultMessages.count)
        XCTAssertEqual(provider.subscriptionCalls.count, 1, "push-subscription work runs for the real account only")
        let demoAccount = try harness.account(demoID)
        XCTAssertNil(demoAccount.syncCursor)
        XCTAssertNil(demoAccount.lastScanAt)
        XCTAssertFalse(demoAccount.needsReauthentication, "it was never fetched, so it can never need re-authentication")
    }

    @MainActor
    func testScanWithOnlyADemoAccountDoesNothingQuietly() async throws {
        let relay = RelayConfig(baseURL: URL(string: "https://relay.test")!, apiKey: "key", gmailPubSubTopic: "topic")
        let provider = FakeMailProvider(provider: .gmail)
        let harness = try ScanHarness(
            providers: [.gmail: provider],
            classifier: FakeClassifier(behavior: .fixed(FakeClassifier.suspicious)),
            settings: ScanSettingsSnapshot(relayConfig: relay)
        )
        try harness.addAccount(provider: .gmail, email: DemoData.accountEmail, isDemo: true)

        let summary = await harness.coordinator.scan(trigger: .appLaunch, accountIDs: nil, deadline: nil)

        XCTAssertTrue(provider.fetchCalls.isEmpty)
        XCTAssertTrue(provider.subscriptionCalls.isEmpty, "no push subscription is ever created for a demo account")
        XCTAssertEqual(summary, ScanSummary())
        XCTAssertTrue(harness.alerts.posted.isEmpty)
    }

    @MainActor
    func testRecheckSkipsDemoAccountsAndKeepsTheirRecords() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        let realID = try harness.addAccount(provider: .gmail, email: "owner@gmail.com")
        DemoMode.enable(in: harness.container.mainContext)
        let demoRecordsBefore = try harness.container.mainContext.fetchCount(DemoMode.demoRecordDescriptor())

        let result = await harness.coordinator.recheckRecentEmail(accountIDs: nil, deadline: nil)

        XCTAssertEqual(result.clearedAccounts, 1, "only the real account's checked-messages list is cleared")
        XCTAssertEqual(provider.fetchAccountIDs, [realID])
        XCTAssertTrue(result.errors.isEmpty)
        XCTAssertEqual(try harness.container.mainContext.fetchCount(DemoMode.demoRecordDescriptor()), demoRecordsBefore,
                       "a re-check never removes or re-verdicts demo records")
    }

    // MARK: - The simulated arrival

    @MainActor
    func testSimulatedArrivalInsertsExactlyOneRecordWithAGenuineVerdict() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        let realAccount = try makeRealAccount(in: context)
        try insertRealRecord(in: context, accountID: realAccount.id)
        DemoMode.enable(in: context)
        let before = try context.fetch(FetchDescriptor<FlaggedEmailRecord>())
        let recorder = AlertRecorder()
        let now = Date()

        let arrival = DemoMode.simulateIncomingAlert(
            in: context, notifications: recorder.makeManager(), delay: 6, now: now
        )

        let after = try context.fetch(FetchDescriptor<FlaggedEmailRecord>())
        XCTAssertEqual(after.count, before.count + 1, "exactly one new record")
        XCTAssertFalse(before.map(\.id).contains(arrival.record.id), "a new row, never a refreshed one")
        XCTAssertTrue(arrival.record.isDemo, "it goes away with the rest of the demo data")
        XCTAssertEqual(arrival.record.receivedAt, now, "dated now — as if it had just arrived")
        XCTAssertFalse(arrival.record.isRead)

        // The verdict is the engine's own, fused with the measured answer of the real local model.
        let fixture = try XCTUnwrap(SampleEmails.named.first { $0.name == arrival.fixtureName })
        let measured = try XCTUnwrap(MeasuredModelAssessments.assessment(forMessageID: fixture.email.messageID))
        let demoAccount = DemoMode.demoAccount(in: context)
        var expectedEmail = DemoData.prepare(fixture.email, accountID: demoAccount.id, receivedAt: now)
        expectedEmail.messageID = arrival.record.messageID
        let expected = DemoData.verdict(for: expectedEmail, account: demoAccount, modelAnswered: true)
        XCTAssertEqual(arrival.record.confidence, expected.confidence, accuracy: 0.0001)
        XCTAssertEqual(arrival.record.level, expected.level)
        XCTAssertEqual(arrival.record.category, expected.category)
        XCTAssertEqual(arrival.record.modelIdentifier, DemoData.localModelIdentifier)
        XCTAssertEqual(arrival.record.reasons.map(\.id), expected.reasons.map(\.id))
        XCTAssertFalse(arrival.record.reasons.isEmpty, "the reasons are the engine's, not a placeholder")
        XCTAssertEqual(arrival.record.modelIdentifier == nil, false)
        XCTAssertEqual(expected.modelRiskScore, measured.riskScore, "the measured model answer really was fused in")
        XCTAssertNotEqual(arrival.record.level, .safe, "an alert-worthy verdict, or there would be nothing to show")

        // The real record and the real account are untouched by a press.
        XCTAssertEqual(after.filter { !$0.isDemo }.count, 1)
        XCTAssertEqual(try context.fetch(FetchDescriptor<LinkedAccount>()).filter { !$0.isDemo }.map(\.id), [realAccount.id])
    }

    @MainActor
    func testSimulatedArrivalNotificationCarriesTheRecordIDAndTheDelay() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        DemoMode.enable(in: context)
        let recorder = AlertRecorder()

        let arrival = DemoMode.simulateIncomingAlert(in: context, notifications: recorder.makeManager(), delay: 6)

        let posted = recorder.posted
        XCTAssertEqual(posted.count, 1)
        let alert = try XCTUnwrap(posted.first)
        XCTAssertEqual(alert.identifier, NotificationManager.requestIdentifier(recordID: arrival.record.id))
        XCTAssertEqual(alert.delay, 6, "scheduled, so the phone can be locked first")
        // The deep link: Diagnostics' test notification passes recordID nil and cannot navigate; this one must.
        XCTAssertEqual(alert.content.recordID, arrival.record.id)
        XCTAssertEqual(alert.content.accountID, arrival.record.accountID)
        XCTAssertEqual(
            alert.content.makeNotificationContent().userInfo[NotificationManager.recordIDUserInfoKey] as? String,
            arrival.record.id.uuidString,
            "the payload AppDelegate reads into pendingRecordID"
        )

        // Built by the shipping alert path, so it reads exactly like a real detection.
        XCTAssertEqual(alert.content, NotificationManager.alertContent(for: arrival.record, unreadCount: alert.content.badge))
        XCTAssertEqual(alert.content.title, NotificationManager.alertTitle)
        XCTAssertTrue(alert.content.body.hasPrefix(arrival.record.subject.prefix(20)))
        XCTAssertEqual(alert.content.threadIdentifier, NotificationManager.threadIdentifier(forAccount: arrival.record.accountID))
        XCTAssertEqual(alert.content.badge, try context.fetchCount(FetchDescriptor<FlaggedEmailRecord>(predicate: #Predicate { $0.isRead == false })))
    }

    @MainActor
    func testImmediateDelayPostsWithoutATrigger() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let recorder = AlertRecorder()

        DemoMode.simulateIncomingAlert(
            in: container.mainContext, notifications: recorder.makeManager(), delay: DemoAlertDelay.immediate.seconds
        )

        XCTAssertEqual(recorder.posted.count, 1)
        XCTAssertNil(recorder.posted.first?.delay)
        XCTAssertEqual(DemoAlertDelay.default.seconds, 6)
        XCTAssertEqual(DemoAlertDelay.fifteenSeconds.seconds, 15)
    }

    @MainActor
    func testRepeatedPressesNeverRepeatAFixtureUntilThePoolIsExhausted() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        let recorder = AlertRecorder()
        let manager = recorder.makeManager()

        var names: [String] = []
        var messageIDs: [String] = []
        for press in 0..<DemoArrivalPool.entries.count {
            let arrival = DemoMode.simulateIncomingAlert(in: context, notifications: manager, delay: nil, arrivalNumber: press)
            names.append(arrival.fixtureName)
            messageIDs.append(arrival.record.messageID)
        }

        XCTAssertEqual(Set(names).count, names.count, "every press before exhaustion is a different email")
        XCTAssertEqual(names, DemoArrivalPool.entries.map(\.name), "and they come in the pool's order")
        XCTAssertEqual(Set(messageIDs).count, messageIDs.count)
        XCTAssertEqual(try context.fetchCount(FetchDescriptor<FlaggedEmailRecord>()), names.count)

        // One past the end: the pool cycles, and the extra arrival is still a new row rather than a refresh.
        let wrapped = DemoMode.simulateIncomingAlert(
            in: context, notifications: manager, delay: nil, arrivalNumber: DemoArrivalPool.entries.count
        )
        XCTAssertEqual(wrapped.fixtureName, DemoArrivalPool.entries[0].name)
        XCTAssertFalse(messageIDs.contains(wrapped.record.messageID))
        XCTAssertEqual(try context.fetchCount(FetchDescriptor<FlaggedEmailRecord>()), names.count + 1)
    }

    /// The live-demo case: the corpus is already seeded, so after the one unseeded fixture every entry is
    /// "already present" — and presses must still show different emails rather than repeating that one.
    @MainActor
    func testRepeatedPressesOnASeededDemoStillCycleThroughDifferentEmails() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        DemoMode.enable(in: context)
        let manager = AlertRecorder().makeManager()

        var names: [String] = []
        var ids: [String] = []
        for press in 0..<5 {
            let arrival = DemoMode.simulateIncomingAlert(in: context, notifications: manager, delay: nil, arrivalNumber: press)
            names.append(arrival.fixtureName)
            ids.append(arrival.record.messageID)
        }

        XCTAssertEqual(names.first, DemoData.liveArrivalFixtureName, "the one the seeded week holds back comes first")
        XCTAssertEqual(Set(names).count, names.count, "then the cycle keeps going instead of repeating it")
        XCTAssertEqual(Set(ids).count, ids.count, "and each press is its own row")
        XCTAssertEqual(Array(names.dropFirst()), Array(DemoArrivalPool.entries[1..<5]).map(\.name))
    }

    func testArrivalPoolDrawsUnseededFixturesFirstAndOnlyMaliciousOnes() {
        let names = DemoArrivalPool.entries.map(\.name)
        XCTAssertFalse(names.isEmpty)
        XCTAssertEqual(Set(names).count, names.count)
        let malicious = Set(SampleEmails.named.filter(\.malicious).map(\.name))
        XCTAssertTrue(names.allSatisfy { malicious.contains($0) }, "a demo alert is never a benign fixture")
        XCTAssertFalse(names.contains("techSupportScam"), "excluded for the same reason DemoData excludes it")
        let seeded = Set(DemoData.seededFixtureNames)
        XCTAssertFalse(seeded.contains(names[0]), "the first press shows an email the seeded list does not already have")
        XCTAssertEqual(names.first, DemoData.liveArrivalFixtureName)

        // The pure draw: an entry already in the store is skipped, the pool cycles once everything is present.
        let all = Set(DemoArrivalPool.entries.map(\.email.messageID))
        XCTAssertEqual(DemoArrivalPool.next(presentMessageIDs: []).name, names[0])
        XCTAssertEqual(DemoArrivalPool.next(presentMessageIDs: [DemoArrivalPool.entries[0].email.messageID]).name, names[1])
        XCTAssertEqual(DemoArrivalPool.next(presentMessageIDs: all, arrivalNumber: 0).name, names[0])
        XCTAssertEqual(DemoArrivalPool.next(presentMessageIDs: all, arrivalNumber: 1).name, names[1])
        XCTAssertEqual(DemoArrivalPool.next(presentMessageIDs: all, arrivalNumber: names.count).name, names[0], "wraps")
        // A numbered repeat of an entry still counts as that entry being present.
        let withRepeat: Set<String> = [DemoArrivalPool.entries[0].email.messageID + "-sim2"]
        XCTAssertEqual(DemoArrivalPool.next(presentMessageIDs: withRepeat).name, names[1])
        XCTAssertEqual(DemoArrivalPool.uniqueMessageID(base: "abc", taken: []), "abc")
        XCTAssertEqual(DemoArrivalPool.uniqueMessageID(base: "abc", taken: ["abc"]), "abc-sim2")
        XCTAssertEqual(DemoArrivalPool.uniqueMessageID(base: "abc", taken: ["abc", "abc-sim2"]), "abc-sim3")
    }

    @MainActor
    func testSimulatedArrivalCreatesTheDemoAccountWhenThereIsNone() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        let realAccount = try makeRealAccount(in: context)

        let arrival = DemoMode.simulateIncomingAlert(in: context, notifications: AlertRecorder().makeManager(), delay: nil)

        let accounts = try context.fetch(FetchDescriptor<LinkedAccount>())
        XCTAssertEqual(accounts.count, 2)
        let demo = try XCTUnwrap(accounts.first(where: \.isDemo))
        XCTAssertEqual(arrival.record.accountID, demo.id)
        XCTAssertNotEqual(arrival.record.accountID, realAccount.id, "a demo alert never attaches to a real mailbox")
        XCTAssertEqual(DemoMode.disable(in: context, notifications: nil), DemoMode.Change(records: 1, accounts: 1))
    }

    // MARK: - Settings

    @MainActor
    func testDemoSettingsDefaultOffAndPersist() throws {
        let suite = "PhishGuardTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        let store = SettingsStore(defaults: defaults)
        XCTAssertFalse(store.isDemoModeEnabled, "demo mode is off until it is asked for")
        XCTAssertEqual(store.demoAlertDelaySeconds, DemoAlertDelay.default.rawValue)

        XCTAssertEqual(store.demoSimulatedArrivalCount, 0)

        store.isDemoModeEnabled = true
        store.demoAlertDelaySeconds = 15
        store.demoSimulatedArrivalCount = 4
        let reloaded = SettingsStore(defaults: defaults)
        XCTAssertTrue(reloaded.isDemoModeEnabled)
        XCTAssertEqual(reloaded.demoAlertDelaySeconds, 15)
        XCTAssertEqual(reloaded.demoSimulatedArrivalCount, 4)
    }
}
#endif

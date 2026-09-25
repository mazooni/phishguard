import Foundation
import PhishCore
import SwiftData
import XCTest
@testable import PhishGuard

/// "Re-check recent email" — the way out of the trap the field report hit, where a message that had once been
/// marked processed was never looked at again — and the DEBUG evaluation trace that would have explained the
/// miss in minutes.
final class RecheckAndTraceTests: XCTestCase {
    private static func assessment(_ score: Int, reason: String) -> ModelAssessment {
        ModelAssessment(
            isSuspicious: score >= 50, category: score >= 50 ? .phishing : .safe, riskScore: score,
            reasons: [reason], summary: "\(reason) (\(score))."
        )
    }

    /// A message with a body nothing may ever copy, so "no mail content leaked" can be asserted literally.
    private static let bodyMarker = "BODY-MARKER-4f2a-DO-NOT-RECORD"
    private static let longSubject = "Your Bank Account is Compromised and this subject line is deliberately far longer than eighty characters"

    private static func markedEmail(messageID: String = "marked-1") -> EmailMessage {
        EmailMessage(
            provider: .gmail,
            accountID: "account",
            messageID: messageID,
            receivedAt: Date(timeIntervalSince1970: 1_758_412_345),
            from: EmailAddress(name: "Jordan", address: "sender@example.com"),
            to: [EmailAddress(name: nil, address: "watched@example.com")],
            subject: longSubject,
            textBody: "Please visit http://bo-fa.example/loginsecurity to restore your account. \(bodyMarker)",
            headers: [EmailHeader(name: "From", value: "Jordan <sender@example.com>")]
        )
    }

    // MARK: - Re-check

    @MainActor
    func testRecheckClearsProcessedStateAndTheCursorThenClassifiesAgain() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let classifier = FakeClassifier(behavior: .fixed(FakeClassifier.suspicious))
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: classifier)
        let accountID = try harness.addAccount(provider: .gmail)
        let fixtureCount = FakeMailProvider.defaultMessages.count

        _ = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertEqual(try harness.processedKeys().count, fixtureCount)
        XCTAssertEqual(try harness.account(accountID).syncCursor, "cursor-1")
        let flaggedAfterFirst = try harness.flaggedRecords().count
        XCTAssertGreaterThan(flaggedAfterFirst, 0)

        // Without a re-check the same mail is never examined again — the situation the owner hit.
        let repeatScan = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertEqual(repeatScan.scanned, 0)
        XCTAssertEqual(classifier.callCount, fixtureCount)

        let recheck = await harness.coordinator.recheckRecentEmail()

        XCTAssertEqual(recheck.clearedMessages, fixtureCount, "every dedupe row of the account is dropped")
        XCTAssertEqual(recheck.clearedAccounts, 1)
        XCTAssertEqual(recheck.scanned, fixtureCount, "so every message is fetched and classified afresh")
        XCTAssertEqual(recheck.flagged, flaggedAfterFirst)
        XCTAssertTrue(recheck.errors.isEmpty, "\(recheck.errors)")
        XCTAssertFalse(recheck.cancelled)
        XCTAssertEqual(classifier.callCount, fixtureCount * 2, "the model is asked again")
        XCTAssertEqual(provider.fetchCalls.map { $0?.opaque }, [nil, "cursor-1", nil],
                       "the cursor is cleared first, so the provider re-fetches the whole lookback window")
        XCTAssertEqual(try harness.account(accountID).syncCursor, "cursor-1", "and is restored by the re-scan")
        XCTAssertEqual(try harness.processedKeys().count, fixtureCount)
    }

    @MainActor
    func testRecheckUpdatesTheExistingFlaggedRecordInsteadOfDuplicatingIt() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(messages: [Self.markedEmail()]))
        let harness = try ScanHarness(
            providers: [.gmail: provider],
            classifier: FakeClassifier(behavior: .fixed(Self.assessment(60, reason: "Bank pretext")))
        )
        try harness.addAccount(provider: .gmail)

        _ = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        let first = try XCTUnwrap(try harness.flaggedRecords().first)
        let recordID = first.id
        let firstFlaggedAt = first.flaggedAt
        let firstConfidence = first.confidence
        // The user has already seen this alert.
        let editing = ModelContext(harness.container)
        let stored = try XCTUnwrap(try editing.fetch(FetchDescriptor<FlaggedEmailRecord>()).first)
        stored.isRead = true
        try editing.save()

        let recheck = await harness.coordinator.recheckRecentEmail()

        let records = try harness.flaggedRecords()
        XCTAssertEqual(records.count, 1, "re-flagging the same message must not add a second row to Home")
        XCTAssertEqual(recheck.flagged, 1, "it still counts as flagged for the report")
        let updated = try XCTUnwrap(records.first)
        XCTAssertEqual(updated.id, recordID, "the row keeps its id, so delivered notifications and deep links still resolve")
        XCTAssertTrue(updated.isRead, "and its read state: the user has already seen this email")
        XCTAssertGreaterThanOrEqual(updated.flaggedAt, firstFlaggedAt, "but the verdict is refreshed")
        XCTAssertEqual(updated.confidence, firstConfidence, accuracy: 1e-9)
        XCTAssertEqual(harness.alerts.posted.count, 2, "a re-check may notify again; the identifier is the same, so it replaces")
        XCTAssertEqual(Set(harness.alerts.posted.compactMap(\.content.recordID)), [recordID])
    }

    /// A second account watching the same mailbox keeps its own row: the identity of a record is
    /// (account, provider, message id), not the message id alone.
    @MainActor
    func testRecordsOfDifferentAccountsAreNotMergedByMessageID() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(messages: [Self.markedEmail()]))
        let harness = try ScanHarness(
            providers: [.gmail: provider],
            classifier: FakeClassifier(behavior: .fixed(Self.assessment(60, reason: "Bank pretext")))
        )
        let a = try harness.addAccount(provider: .gmail, email: "a@example.com")
        let b = try harness.addAccount(provider: .gmail, email: "b@example.com")

        _ = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        let records = try harness.flaggedRecords()
        XCTAssertEqual(Set(records.map(\.accountID)), [a, b])
        XCTAssertEqual(records.count, 2)
    }

    @MainActor
    func testRecheckOnlyTouchesTheRequestedAccounts() async throws {
        let provider = FakeMailProvider(provider: .gmail)
        let harness = try ScanHarness(providers: [.gmail: provider], classifier: FakeClassifier(behavior: .fixed(FakeClassifier.benign)))
        let kept = try harness.addAccount(provider: .gmail, email: "kept@example.com")
        let cleared = try harness.addAccount(provider: .gmail, email: "cleared@example.com")

        _ = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        let before = try harness.processedKeys().count

        let recheck = await harness.coordinator.recheckRecentEmail(accountIDs: [cleared])

        XCTAssertEqual(recheck.clearedAccounts, 1)
        XCTAssertEqual(recheck.clearedMessages, before / 2)
        XCTAssertNotNil(try harness.account(kept).syncCursor, "the other account's cursor is untouched")
        XCTAssertTrue(try harness.processedKeys().contains { $0.hasPrefix("gmail:\(kept.uuidString):") })
    }

    @MainActor
    func testRecheckResultTextReportsCountsAndProblems() {
        let clean = ScanCoordinator.RecheckSummary(clearedMessages: 12, clearedAccounts: 1, scanned: 12, flagged: 2)
        let text = RecheckRecentEmailButton.resultText(for: clean)
        XCTAssertTrue(text.contains("Re-checked 12 emails, flagged 2."), text)
        XCTAssertTrue(text.contains("Cleared 12 earlier checks across 1 account."), text)

        let singular = ScanCoordinator.RecheckSummary(clearedMessages: 1, clearedAccounts: 1, scanned: 1, flagged: 0)
        XCTAssertTrue(RecheckRecentEmailButton.resultText(for: singular).contains("Re-checked 1 email, flagged 0."))
        XCTAssertTrue(RecheckRecentEmailButton.resultText(for: singular).contains("1 earlier check"))

        let pending = ScanCoordinator.RecheckSummary(scanned: 100, flagged: 3, deadlineReached: true)
        XCTAssertTrue(RecheckRecentEmailButton.resultText(for: pending).contains("still pending"))

        let broken = ScanCoordinator.RecheckSummary(scanned: 0, flagged: 0, errors: ["Gmail: offline"])
        XCTAssertTrue(RecheckRecentEmailButton.resultText(for: broken).contains("1 error: Gmail: offline"))
    }

    // MARK: - Evaluation traces (DEBUG only)

    #if DEBUG
    @MainActor
    func testEvaluationTracesCaptureBothModelsAndNeverTheBody() async throws {
        let email = Self.markedEmail()
        let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(40, reason: "Unclear")))
        let local = FakeClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(91, reason: "Lookalike bank link")))
        let gate = AppForegroundGate(isForeground: true)
        let harness = try ScanHarness(
            providers: [.gmail: FakeMailProvider(provider: .gmail, state: .init(messages: [email]))],
            classifier: EnsembleClassifier(primary: local, corroborators: [apple], foregroundGate: gate),
            foregroundGate: gate
        )
        try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)
        XCTAssertEqual(summary.scanned, 1)

        let traces = await harness.coordinator.evaluationTraces
        let trace = try XCTUnwrap(traces.last)
        XCTAssertEqual(traces.count, 1)
        XCTAssertEqual(trace.trigger, .manual)
        XCTAssertEqual(trace.sender, "sender@example.com")
        XCTAssertEqual(trace.subject, String(Self.longSubject.prefix(80)))
        XCTAssertEqual(trace.subject.count, EvaluationTrace.maxSubjectLength)
        XCTAssertGreaterThan(trace.ruleScore, 0)
        XCTAssertFalse(trace.signals.isEmpty, "the rule score is shown with the signals behind it")
        XCTAssertEqual(trace.confidence, 0.91, accuracy: 1e-9, "the fused confidence is max(rules, best model)")
        XCTAssertEqual(trace.level, .high)
        XCTAssertTrue(trace.alerted, "and whether it actually alerted")
        XCTAssertGreaterThanOrEqual(trace.elapsedMilliseconds, 0)

        XCTAssertEqual(trace.modelRuns.count, 2, "both models are recorded, not just the one that decided")
        XCTAssertEqual(trace.modelRuns.map(\.identifier), ["mlx:test/model", "apple.foundation"], "primary first")
        XCTAssertEqual(trace.modelRuns.compactMap(\.riskScore), [91, 40])
        XCTAssertEqual(trace.modelRuns.compactMap(\.category), [.phishing, .safe])
        XCTAssertEqual(trace.modelRuns.map(\.role), [.primary, .corroborator])
        XCTAssertEqual(trace.modelRuns[1].corroboration, .notHigher, "the second opinion had nothing to add")
        XCTAssertTrue(trace.modelRuns.allSatisfy { $0.errorDescription == nil })

        // Nothing derived from the body may appear anywhere in the trace, including the signal list.
        var recorded = [trace.sender, trace.subject]
        recorded += trace.signals.map(\.id)
        recorded += trace.modelRuns.map(\.identifier)
        recorded += trace.modelRuns.compactMap(\.errorDescription)
        recorded.append(EvaluationTraceRow.rulesText(trace))
        recorded += trace.modelRuns.map(EvaluationTraceRow.modelText)
        for text in recorded {
            XCTAssertFalse(text.contains(Self.bodyMarker), "body text leaked into the trace: \(text)")
            XCTAssertFalse(text.contains("bo-fa.example"), "link evidence is not part of the trace: \(text)")
            XCTAssertFalse(text.contains("restore your account"), "body wording leaked: \(text)")
        }
        XCTAssertTrue(EvaluationTraceRow.rulesText(trace).hasPrefix("rules "), EvaluationTraceRow.rulesText(trace))
        XCTAssertTrue(EvaluationTraceRow.modelText(trace.modelRuns[0]).contains("91 phishing"))
        XCTAssertTrue(EvaluationTraceRow.modelText(trace.modelRuns[1]).contains("did not raise"))
    }

    @MainActor
    func testTracesRecordWhyAModelDidNotAnswer() async throws {
        let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(55, reason: "Bank pretext")))
        let local = FakeGPUClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(99, reason: "Never asked")))
        let gate = AppForegroundGate(isForeground: false)
        let harness = try ScanHarness(
            providers: [:],
            classifier: EnsembleClassifier(primary: local, corroborators: [apple], foregroundGate: gate),
            foregroundGate: gate
        )

        _ = await harness.coordinator.evaluateBatch([Self.markedEmail()])

        let batchTraces = await harness.coordinator.evaluationTraces
        let trace = try XCTUnwrap(batchTraces.last)
        XCTAssertEqual(trace.modelRuns.count, 2)
        XCTAssertEqual(trace.modelRuns[0].errorDescription, MLXClassifier.foregroundOnlyReason)
        XCTAssertTrue(trace.modelRuns[0].wasSkippedForForeground)
        XCTAssertFalse(trace.modelRuns[0].didFail, "not being frontmost is not a model failure")
        XCTAssertTrue(EvaluationTraceRow.modelText(trace.modelRuns[0]).contains("only runs while PhishGuard is open"))
        XCTAssertNil(trace.modelRuns[1].errorDescription)
        XCTAssertEqual(trace.modelRuns[1].role, .corroborator, "the gated-off primary is not replaced by the other model")
    }

    @MainActor
    func testTracesAreARingBufferAndCanBeCleared() async throws {
        let harness = try ScanHarness(
            providers: [:],
            classifier: FakeClassifier(identifier: "apple.foundation", behavior: .fixed(FakeClassifier.benign))
        )
        let overflow = ScanCoordinator.evaluationTraceCapacity + 5
        _ = await harness.coordinator.evaluateBatch((1...overflow).map { SampleEmails.paypalPhish.withMessageID("dup-\($0)") })

        var traces = await harness.coordinator.evaluationTraces
        XCTAssertEqual(traces.count, ScanCoordinator.evaluationTraceCapacity)
        XCTAssertEqual(traces.first?.subject, String(SampleEmails.paypalPhish.subject.prefix(EvaluationTrace.maxSubjectLength)))
        XCTAssertEqual(traces.map(\.modelRuns.count), Array(repeating: 1, count: traces.count),
                       "a single classifier still records exactly one model run")

        await harness.coordinator.clearEvaluationTraces()
        traces = await harness.coordinator.evaluationTraces
        XCTAssertTrue(traces.isEmpty)
    }
    #endif
}

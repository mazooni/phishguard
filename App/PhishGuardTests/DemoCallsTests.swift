#if DEBUG
import Foundation
import PhishCore
import SwiftData
import XCTest
@testable import PhishGuard

/// The offline call demo (docs/CALLS.md §7.4): bundled scenarios, "Simulate a scam call", the seeded week, and the
/// separation rule — demo call rows carry `isDemo`, real ones do not, and turning demo mode off only removes the former.
final class DemoCallsTests: XCTestCase {
    /// A call the relay really reported — the thing demo mode must never touch.
    @MainActor
    @discardableResult
    private func insertRealCall(in context: ModelContext) throws -> FlaggedCallRecord {
        let summary = try JSONDecoder().decode(CallSummary.self, from: CallFixtures.data(CallFixtures.summaryJSON()))
        let record = try XCTUnwrap(FlaggedCallRecord(summary: summary))
        context.insert(record)
        try context.save()
        return record
    }

    // MARK: - Scenarios

    func testScenariosAreTheRelaysFiveScamCallsInTheRuleEngineShape() {
        let scenarios = DemoCalls.scenarios
        XCTAssertEqual(scenarios.count, 5)
        XCTAssertEqual(Set(scenarios.map(\.id)).count, 5)
        XCTAssertEqual(Set(scenarios.map(\.callerNumber)).count, 5)
        XCTAssertEqual(scenarios.map(\.id), [.grandparent, .irs, .techSupport, .bankFraud, .prize], "the relay's DEMO_SCENARIO_IDS order, minus the neighbour")
        for scenario in scenarios {
            XCTAssertTrue(PhoneNumberFormat.isE164(scenario.callerNumber))
            XCTAssertGreaterThan(scenario.durationSeconds, 0)
            XCTAssertGreaterThanOrEqual(scenario.verdict.level, .medium, "alert-worthy at the relay's default floor")
            XCTAssertEqual(scenario.verdict.level, RiskLevel(confidence: scenario.verdict.confidence), "level matches the PhishCore thresholds")
            XCTAssertFalse(scenario.verdict.reasons.isEmpty)
            XCTAssertLessThanOrEqual(scenario.verdict.reasons.count, 8)
            XCTAssertTrue(scenario.verdict.reasons.allSatisfy { $0.id.hasPrefix("call.") }, "the relay's rule ids (docs/CALLS.md §6.1)")
            XCTAssertTrue(scenario.verdict.reasons.allSatisfy { $0.source == .heuristic && $0.detail.count <= 300 && !$0.title.isEmpty })
            XCTAssertTrue(scenario.verdict.reasons.contains { $0.severity == .high }, "a high signal, as the relay's rules test requires of every demo dialogue")
            let severities = scenario.verdict.reasons.map(\.severity)
            XCTAssertEqual(severities, severities.sorted(by: >), "ordered by severity desc")
            XCTAssertFalse(scenario.verdict.summary.isEmpty)
            XCTAssertLessThanOrEqual(scenario.verdict.summary.count, 500)
            XCTAssertFalse(scenario.verdict.recommendedAction.isEmpty)
            XCTAssertLessThanOrEqual(scenario.verdict.recommendedAction.count, 200)
            XCTAssertNil(scenario.verdict.modelIdentifier, "rules only: no model ran")
            XCTAssertNil(scenario.verdict.modelRiskScore)
            XCTAssertEqual(scenario.verdict.heuristicScore, scenario.verdict.confidence, accuracy: 0.0001)
            XCTAssertEqual(scenario.verdict.updatedAt, 0, "the export pins the detector's clock")
            XCTAssertGreaterThanOrEqual(scenario.verdict.sequence, 1)
            XCTAssertEqual(DemoCalls.scenario(scenario.id), scenario)
        }
        XCTAssertNil(DemoCalls.scenario(.benign), "not offered by Simulate a scam call")
        XCTAssertTrue(PhoneNumberFormat.isE164(DemoCalls.guardNumber))
    }

    /// The verdicts are `Relay/scripts/export-demo-verdicts.ts`'s output (rules + fusion over each scripted call,
    /// no model). These pin the recorded ids, levels and confidences so a re-export after a rule change shows up
    /// here, not only in the relay's tests.
    func testVerdictsAreTheRuleEnginesRecordedOutput() {
        let action = "Hang up and call the organisation back on a number you trust."

        XCTAssertEqual(DemoCalls.grandparent.verdict.level, .high)
        XCTAssertEqual(DemoCalls.grandparent.verdict.category, .scam)
        XCTAssertEqual(DemoCalls.grandparent.verdict.confidence, 0.984053125, accuracy: 1e-9)
        XCTAssertEqual(DemoCalls.grandparent.verdict.sequence, 5)
        XCTAssertEqual(DemoCalls.grandparent.verdict.reasons.map(\.id),
                       ["call.gift_cards", "call.government_threat", "call.family_emergency", "call.secrecy", "call.urgency"])
        XCTAssertEqual(DemoCalls.grandparent.verdict.reasons.map(\.severity), [.high, .high, .high, .high, .medium])
        XCTAssertEqual(DemoCalls.grandparent.verdict.summary, "This call looks like a scam: Asks for gift cards; Threatens arrest or government action.")
        XCTAssertEqual(DemoCalls.grandparent.verdict.recommendedAction, action)
        XCTAssertEqual(DemoCalls.grandparent.durationSeconds, 21)

        XCTAssertEqual(DemoCalls.irs.verdict.level, .high)
        XCTAssertEqual(DemoCalls.irs.verdict.category, .scam)
        XCTAssertEqual(DemoCalls.irs.verdict.confidence, 0.999441859375, accuracy: 1e-9)
        XCTAssertEqual(DemoCalls.irs.verdict.sequence, 4)
        XCTAssertEqual(DemoCalls.irs.verdict.reasons.map(\.id),
                       ["call.safe_account", "call.gift_cards", "call.government_threat", "call.otp_or_credentials",
                        "call.wire_or_crypto", "call.secrecy", "call.payment_pressure", "call.urgency"])
        XCTAssertEqual(DemoCalls.irs.verdict.reasons.map(\.severity), [.high, .high, .high, .high, .high, .high, .medium, .medium])
        XCTAssertEqual(DemoCalls.irs.verdict.reasons.count, 8, "the relay's MAX_VERDICT_REASONS")
        XCTAssertEqual(DemoCalls.irs.verdict.summary, "This call looks like a scam: Says to move money to a \"safe account\"; Asks for gift cards.")
        XCTAssertEqual(DemoCalls.irs.verdict.recommendedAction, action)
        XCTAssertEqual(DemoCalls.irs.durationSeconds, 21)

        XCTAssertEqual(DemoCalls.techSupport.verdict.level, .high)
        XCTAssertEqual(DemoCalls.techSupport.verdict.category, .scam)
        XCTAssertEqual(DemoCalls.techSupport.verdict.confidence, 0.9908875, accuracy: 1e-9)
        XCTAssertEqual(DemoCalls.techSupport.verdict.sequence, 4)
        XCTAssertEqual(DemoCalls.techSupport.verdict.reasons.map(\.id),
                       ["call.gift_cards", "call.remote_access", "call.secrecy", "call.tech_support", "call.payment_pressure", "call.impersonation"])
        XCTAssertEqual(DemoCalls.techSupport.verdict.reasons.map(\.severity), [.high, .high, .high, .high, .medium, .medium])
        XCTAssertEqual(DemoCalls.techSupport.verdict.summary, "This call looks like a scam: Asks for gift cards; Asks for remote access to a device.")
        XCTAssertEqual(DemoCalls.techSupport.verdict.recommendedAction, action)
        XCTAssertEqual(DemoCalls.techSupport.durationSeconds, 22)

        XCTAssertEqual(DemoCalls.bankFraud.verdict.level, .high)
        XCTAssertEqual(DemoCalls.bankFraud.verdict.category, .scam)
        XCTAssertEqual(DemoCalls.bankFraud.verdict.confidence, 0.99778515625, accuracy: 1e-9)
        XCTAssertEqual(DemoCalls.bankFraud.verdict.sequence, 6)
        XCTAssertEqual(DemoCalls.bankFraud.verdict.reasons.map(\.id),
                       ["call.user_sharing_sensitive", "call.safe_account", "call.otp_or_credentials", "call.secrecy",
                        "call.callback_refusal", "call.urgency", "call.impersonation"])
        XCTAssertEqual(DemoCalls.bankFraud.verdict.reasons.map(\.severity), [.high, .high, .high, .high, .high, .medium, .medium])
        XCTAssertEqual(DemoCalls.bankFraud.verdict.reasons[0].detail,
                       "You said: something that sounds like a card number, a code or a password was read out.",
                       "the rules never quote what the protected person read out")
        XCTAssertEqual(DemoCalls.bankFraud.verdict.recommendedAction, action)
        XCTAssertEqual(DemoCalls.bankFraud.durationSeconds, 21)

        XCTAssertEqual(DemoCalls.prize.verdict.level, .high)
        XCTAssertEqual(DemoCalls.prize.verdict.category, .scam)
        XCTAssertEqual(DemoCalls.prize.verdict.confidence, 0.981775, accuracy: 1e-9)
        XCTAssertEqual(DemoCalls.prize.verdict.sequence, 3)
        XCTAssertEqual(DemoCalls.prize.verdict.reasons.map(\.id),
                       ["call.gift_cards", "call.wire_or_crypto", "call.secrecy", "call.prize_or_lottery", "call.urgency"])
        XCTAssertEqual(DemoCalls.prize.verdict.reasons.map(\.severity), [.high, .high, .high, .high, .medium])
        XCTAssertEqual(DemoCalls.prize.verdict.recommendedAction, action)
        XCTAssertEqual(DemoCalls.prize.durationSeconds, 17)

        for scenario in DemoCalls.scenarios {
            XCTAssertTrue(scenario.verdict.reasons.allSatisfy { $0.detail.hasPrefix("Caller said: “") || $0.detail.hasPrefix("You said: ") },
                          "the rules' quoted-evidence form, never a hand-written paraphrase")
            XCTAssertFalse(scenario.verdict.reasons.contains { $0.detail.contains(scenario.callerNumber) }, "no phone number in a reason")
        }
    }

    /// The neighbour's call, recorded like the others: the rules leave it `safe` (one `call.urgency` hit on "drop the
    /// prescription by this afternoon" stays under the `low` threshold), so it is never offered as a scam to simulate and
    /// a record made from it is not alerted.
    @MainActor
    func testBenignScenarioIsTheRulesSafeVerdictAndIsNotOffered() throws {
        let benign = DemoCalls.benign
        XCTAssertEqual(benign.id, .benign)
        XCTAssertEqual(benign.callerNumber, "+14155550189")
        XCTAssertEqual(benign.durationSeconds, 18)
        XCTAssertEqual(benign.verdict.level, .safe)
        XCTAssertEqual(benign.verdict.category, .safe)
        XCTAssertEqual(benign.verdict.confidence, 0.25, accuracy: 1e-9)
        XCTAssertEqual(benign.verdict.level, RiskLevel(confidence: benign.verdict.confidence))
        XCTAssertEqual(benign.verdict.sequence, 2)
        XCTAssertEqual(benign.verdict.reasons.map(\.id), ["call.urgency"])
        XCTAssertEqual(benign.verdict.reasons.map(\.severity), [.medium])
        XCTAssertEqual(benign.verdict.summary, "No signs of a scam so far.")
        XCTAssertEqual(benign.verdict.recommendedAction, "Nothing suspicious so far.")
        XCTAssertNil(benign.verdict.modelIdentifier)
        XCTAssertFalse(DemoCalls.scenarios.contains(benign))
        XCTAssertNil(DemoCalls.scenario(.benign))

        _ = try Persistence.makeContainer(inMemory: true)
        let record = DemoCalls.makeRecord(benign, startedAt: Date(), isDemo: true)
        XCTAssertFalse(record.alerted, "below the relay's default alert floor, so the relay would not have alerted")
        XCTAssertEqual(record.level, .safe)
        XCTAssertEqual(record.category, .safe)
        XCTAssertEqual(record.reasons.map(\.id), ["call.urgency"])
        XCTAssertTrue(DemoCalls.scenarios.map { DemoCalls.makeRecord($0, startedAt: Date(), isDemo: true) }.allSatisfy(\.alerted))
    }

    @MainActor
    func testMakeRecordCarriesTheVerdictAndIsAlwaysAlerted() throws {
        _ = try Persistence.makeContainer(inMemory: true)
        let now = Date()
        let record = DemoCalls.makeRecord(DemoCalls.irs, startedAt: now, isDemo: true)

        XCTAssertTrue(record.isDemo)
        XCTAssertTrue(record.alerted)
        XCTAssertFalse(record.isRead)
        XCTAssertEqual(record.startedAt, now)
        XCTAssertEqual(record.endedAt, now.addingTimeInterval(21))
        XCTAssertEqual(record.durationSeconds, 21)
        XCTAssertEqual(record.status, .completed)
        XCTAssertEqual(record.source, .twilio)
        XCTAssertEqual(record.guardNumber, DemoCalls.guardNumber)
        XCTAssertEqual(record.callerNumber, "+12025550147")
        XCTAssertEqual(record.level, .high)
        XCTAssertEqual(record.category, .scam)
        XCTAssertEqual(record.reasons.map(\.id), DemoCalls.irs.verdict.reasons.map(\.id))
        XCTAssertEqual(record.reasons.map(\.detail), DemoCalls.irs.verdict.reasons.map(\.detail))
        XCTAssertEqual(record.summary, DemoCalls.irs.verdict.summary)
        XCTAssertEqual(record.recommendedAction, DemoCalls.irs.verdict.recommendedAction)
        XCTAssertNil(record.modelIdentifier)
        XCTAssertNotEqual(DemoCalls.makeRecord(DemoCalls.irs, startedAt: now, isDemo: true).id, record.id, "every press is its own row")
    }

    // MARK: - Simulate a scam call

    @MainActor
    func testSimulatedCallInsertsADemoRecordDatedNowAndPostsTheTimeSensitiveAlert() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        let real = try insertRealCall(in: context)
        let recorder = AlertRecorder()
        let now = Date()

        let call = DemoMode.simulateIncomingCall(DemoCalls.grandparent, in: context, notifications: recorder.makeManager(), delay: 6, now: now)

        let records = try context.fetch(FetchDescriptor<FlaggedCallRecord>())
        XCTAssertEqual(records.count, 2)
        XCTAssertTrue(call.record.isDemo, "it goes away with the rest of the demo data")
        XCTAssertEqual(call.record.startedAt, now)
        XCTAssertFalse(call.record.isRead)
        XCTAssertEqual(call.scenario, DemoCalls.grandparent)
        XCTAssertEqual(call.delay, 6)

        let posted = recorder.postedCalls
        XCTAssertEqual(posted.count, 1)
        XCTAssertEqual(posted[0].identifier, NotificationManager.callRequestIdentifier(callID: call.record.id))
        XCTAssertEqual(posted[0].delay, 6, "scheduled, so the phone can be locked first")
        XCTAssertEqual(posted[0].content, call.alert)
        XCTAssertEqual(posted[0].content, NotificationManager.callAlertContent(for: call.record))
        XCTAssertEqual(call.alert.callID, call.record.id, "the payload AppDelegate reads into pendingCallID")
        XCTAssertEqual(call.alert.title, "Likely scam call")
        let notification = call.alert.makeNotificationContent()
        XCTAssertEqual(notification.interruptionLevel, .timeSensitive)
        XCTAssertEqual(notification.categoryIdentifier, NotificationManager.callAlertCategoryIdentifier)
        XCTAssertEqual(notification.userInfo[NotificationManager.callIDUserInfoKey] as? String, call.record.id.uuidString)
        XCTAssertTrue(recorder.posted.isEmpty, "no email alert is posted")

        // The real call is untouched.
        let survivor = try XCTUnwrap(records.first { !$0.isDemo })
        XCTAssertEqual(survivor.id, real.id)
    }

    @MainActor
    func testImmediateDelayPostsWithoutATrigger() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let recorder = AlertRecorder()

        DemoMode.simulateIncomingCall(DemoCalls.techSupport, in: container.mainContext, notifications: recorder.makeManager(), delay: DemoAlertDelay.immediate.seconds)

        XCTAssertEqual(recorder.postedCalls.count, 1)
        XCTAssertNil(recorder.postedCalls.first?.delay)
        XCTAssertEqual(recorder.postedCalls.first?.content.title, "Likely scam call", "techSupport is high on the rules alone")
        XCTAssertEqual(recorder.postedCalls.first?.content.subtitle, "Call from +1 (800) 555-0162")
    }

    // MARK: - Demo mode on / off

    @MainActor
    func testDemoModeSeedsThreeCallsAndDisableRemovesOnlyDemoCalls() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        let real = try insertRealCall(in: context)
        let realID = real.id
        let realSummary = real.summary

        let on = DemoMode.enable(in: context)

        XCTAssertEqual(on.calls, 3)
        let afterOn = try context.fetch(FetchDescriptor<FlaggedCallRecord>())
        XCTAssertEqual(afterOn.count, 4, "the demo calls sit next to the real one")
        XCTAssertEqual(afterOn.filter { !$0.isDemo }.map(\.id), [realID])
        XCTAssertTrue(afterOn.filter(\.isDemo).allSatisfy(\.alerted))
        XCTAssertEqual(afterOn.filter { $0.isDemo && !$0.isRead }.count, 1, "today's call is unread, the older ones read")
        XCTAssertTrue(afterOn.contains { $0.isDemo && Calendar.current.isDateInToday($0.startedAt) })
        XCTAssertEqual(Set(afterOn.filter(\.isDemo).map { Calendar.current.startOfDay(for: $0.startedAt) }).count, 3, "spread across the week")

        DemoMode.simulateIncomingCall(DemoCalls.irs, in: context, notifications: AlertRecorder().makeManager(), delay: nil)
        XCTAssertEqual(try context.fetchCount(DemoMode.demoCallDescriptor()), 4)

        let again = DemoMode.enable(in: context)
        XCTAssertEqual(again.calls, 3, "a second 'on' re-seeds, it does not stack")

        let off = DemoMode.disable(in: context, notifications: nil)

        XCTAssertEqual(off.calls, 3)
        let records = try context.fetch(FetchDescriptor<FlaggedCallRecord>())
        XCTAssertEqual(records.map(\.id), [realID], "every demo call is gone and the real one is not")
        XCTAssertEqual(records.first?.summary, realSummary)
        XCTAssertFalse(records.first?.isDemo ?? true)
        XCTAssertEqual(DemoMode.disable(in: context, notifications: nil), DemoMode.Change(records: 0, accounts: 0, calls: 0))
        XCTAssertEqual(try context.fetch(FetchDescriptor<FlaggedCallRecord>()).map(\.id), [realID])
    }

    @MainActor
    func testDemoDataSeedsThreeRealLookingCallsAcrossTheWeek() throws {
        let container = try Persistence.makeContainer(inMemory: true)

        DemoData.seed(into: container)
        DemoData.seed(into: container)

        let calls = try container.mainContext.fetch(FetchDescriptor<FlaggedCallRecord>(sortBy: [SortDescriptor(\.startedAt, order: .reverse)]))
        XCTAssertEqual(calls.count, 3, "seeded once; a relaunch keeps what is there")
        XCTAssertTrue(calls.allSatisfy { !$0.isDemo }, "the Simulator demo marks nothing isDemo, like the seeded emails")
        XCTAssertTrue(Calendar.current.isDateInToday(try XCTUnwrap(calls.first).startedAt))
        XCTAssertFalse(try XCTUnwrap(calls.first).isRead)
        XCTAssertTrue(calls.dropFirst().allSatisfy(\.isRead))
        XCTAssertEqual(calls.map(\.callerNumber), [DemoCalls.grandparent, DemoCalls.irs, DemoCalls.techSupport].map(\.callerNumber))
        XCTAssertTrue(calls.allSatisfy { $0.startedAt <= Date() }, "never dated into the future")
        XCTAssertEqual(DemoMode.disable(in: container.mainContext, notifications: nil).calls, 0, "and demo mode's off never touches them")
        XCTAssertEqual(try container.mainContext.fetchCount(FetchDescriptor<FlaggedCallRecord>()), 3)
    }
}
#endif

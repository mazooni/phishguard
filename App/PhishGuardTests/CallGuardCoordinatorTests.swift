import Foundation
import PhishCore
import SwiftData
import UIKit
import XCTest
@testable import PhishGuard

/// `CallGuardCoordinator`: history upserts, the alert push, the live feed folding into the live card and history,
/// line registration. The relay is `RelayStubProtocol`; live events are applied directly.
final class CallGuardCoordinatorTests: XCTestCase {
    private static let baseURL = URL(string: "https://relay.test")!

    private var keychain: Keychain!
    private var defaults: UserDefaults!
    private var suite: String!

    override func setUpWithError() throws {
        try super.setUpWithError()
        suite = "PhishGuardTests.callguard.\(UUID().uuidString)"
        defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        keychain = Keychain(service: suite)
        RelayStubProtocol.reset()
    }

    override func tearDownWithError() throws {
        defaults.removePersistentDomain(forName: suite)
        try? keychain.delete(RelayClient.deviceSecretKey)
        try? keychain.delete(RelayClient.deviceIDKey)
        RelayStubProtocol.reset()
        try super.tearDownWithError()
    }

    @MainActor
    private struct Harness {
        let container: ModelContainer
        let settings: SettingsStore
        let coordinator: CallGuardCoordinator

        var context: ModelContext { container.mainContext }

        func records() throws -> [FlaggedCallRecord] {
            try context.fetch(FetchDescriptor<FlaggedCallRecord>(sortBy: [SortDescriptor(\.startedAt, order: .reverse)]))
        }
    }

    @MainActor
    private func makeHarness(configured: Bool = true) throws -> Harness {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RelayStubProtocol.self]
        let session = URLSession(configuration: configuration)
        let config = configured ? RelayConfig(baseURL: Self.baseURL, apiKey: "shared-key", gmailPubSubTopic: "t") : nil
        let relay = RelayClient(
            config: config, keychain: keychain, bundleIdentifier: "com.mazooni.PhishGuard", session: session, defaults: defaults,
            retryPolicy: RelayClient.RetryPolicy(maxAttempts: 3, initialDelay: 0, multiplier: 1)
        )
        let container = try Persistence.makeContainer(inMemory: true)
        let settings = SettingsStore(defaults: defaults)
        let coordinator = CallGuardCoordinator(client: CallGuardClient(relay: relay), container: container, settings: settings)
        return Harness(container: container, settings: settings, coordinator: coordinator)
    }

    private func summary(
        callID: String = CallFixtures.callID,
        level: RiskLevel? = .high,
        alerted: Bool = true,
        status: CallStatus = .completed,
        sequence: Int = 3,
        summaryText: String = "The caller asks for gift cards.",
        voice: CallVoiceAssessment? = nil
    ) -> CallSummary {
        let verdict = level.map { level in
            CallVerdict(
                sequence: sequence, category: .scam, confidence: 0.9, level: level,
                reasons: [CallReason(id: "call.gift_cards", title: "Asks for gift cards", detail: "…", severity: .high, source: .heuristic)],
                summary: summaryText, recommendedAction: "Hang up.", heuristicScore: 0.9, updatedAt: 1_758_600_120_000
            )
        }
        return CallSummary(
            callID: callID, source: .twilio, callerNumber: "+14155550134", calledNumber: "+16285550199",
            startedAt: 1_758_600_000_000, endedAt: status.isEnded ? 1_758_600_254_000 : nil,
            durationSeconds: status.isEnded ? 254 : nil, status: status, verdict: verdict, alerted: alerted, alertLevel: alerted ? level : nil,
            voice: voice
        )
    }

    /// An AI-voice assessment as the relay's detector reports it; `warned` adds the warning the relay sent.
    private func voice(
        _ status: VoiceStatus,
        share: Double = 0,
        confidence: Double = 0,
        warned: Bool = false,
        updatedAt: Int = 1_758_600_030_000
    ) -> CallVoiceAssessment {
        let alert = CallVoiceAlert(
            title: "AI voice detected", subtitle: "Call from +1 (415) 555-0134", body: CallFixtures.voiceAlertBody,
            sentAt: updatedAt, pushed: true, spoken: true
        )
        return CallVoiceAssessment(
            status: status, syntheticShare: share, confidence: confidence, speechMs: 6200, provider: "modulate:test-model",
            detectedAt: status == .synthetic ? updatedAt : nil, alert: warned ? alert : nil, updatedAt: updatedAt
        )
    }

    private func encode(_ summaries: [CallSummary]) throws -> String {
        struct Envelope: Encodable { var calls: [CallSummary] }
        return String(decoding: try JSONEncoder().encode(Envelope(calls: summaries)), as: UTF8.self)
    }

    // MARK: - History

    @MainActor
    func testRefreshHistoryKeepsAlertedOrQualifyingCallsAndPreservesIsRead() async throws {
        let harness = try makeHarness()
        let high = summary(callID: CallFixtures.callID, level: .high, alerted: true)
        let lowAlerted = summary(callID: CallFixtures.secondCallID, level: .low, alerted: true)
        let lowQuiet = summary(callID: UUID().uuidString.lowercased(), level: .low, alerted: false)
        let noVerdict = summary(callID: UUID().uuidString, level: nil, alerted: false)
        RelayStubProtocol.reset(responses: [.init(status: 200, body: try encode([high, lowAlerted, lowQuiet, noVerdict]))])

        await harness.coordinator.refreshHistory()

        let first = try harness.records()
        XCTAssertEqual(Set(first.map { $0.id.uuidString.lowercased() }), [CallFixtures.callID, CallFixtures.secondCallID], "medium-and-above or alerted")
        XCTAssertEqual(RelayStubProtocol.requests.first?.url?.absoluteString, "https://relay.test/v1/devices/calls?limit=50")
        XCTAssertTrue(first.allSatisfy { !$0.isRead && !$0.isDemo && $0.alerted })
        let stored = try XCTUnwrap(first.first { $0.id.uuidString.lowercased() == CallFixtures.callID })
        XCTAssertEqual(stored.level, .high)
        XCTAssertEqual(stored.callerNumber, "+14155550134")
        XCTAssertEqual(stored.guardNumber, "+16285550199")
        XCTAssertEqual(stored.durationSeconds, 254)
        XCTAssertEqual(stored.status, .completed)
        XCTAssertEqual(stored.reasons.map(\.id), ["call.gift_cards"])
        XCTAssertEqual(stored.summary, "The caller asks for gift cards.")
        XCTAssertEqual(stored.recommendedAction, "Hang up.")
        XCTAssertNotNil(harness.coordinator.lastRefreshDate)
        XCTAssertNil(harness.coordinator.lastError)

        // The user reads it; the relay then reports a newer verdict for the same call.
        stored.isRead = true
        try harness.context.save()
        let updated = summary(callID: CallFixtures.callID, level: .high, alerted: true, sequence: 5, summaryText: "Updated summary.")
        RelayStubProtocol.reset(responses: [.init(status: 200, body: try encode([updated]))])

        await harness.coordinator.refreshHistory()

        let second = try harness.records()
        XCTAssertEqual(second.count, 2, "updated in place, not duplicated")
        let refreshed = try XCTUnwrap(second.first { $0.id.uuidString.lowercased() == CallFixtures.callID })
        XCTAssertTrue(refreshed.isRead, "reading it is remembered across refreshes")
        XCTAssertEqual(refreshed.summary, "Updated summary.")
    }

    @MainActor
    func testRefreshHistoryHonoursTheCallAlertLevelSetting() async throws {
        let harness = try makeHarness()
        let medium = summary(callID: CallFixtures.callID, level: .medium, alerted: false)
        let low = summary(callID: CallFixtures.secondCallID, level: .low, alerted: false)

        harness.settings.callAlertMinimumLevel = .low
        RelayStubProtocol.reset(responses: [.init(status: 200, body: try encode([medium, low]))])
        await harness.coordinator.refreshHistory()
        XCTAssertEqual(try harness.records().count, 2)

        // Raising the level does not delete what was kept, but new lower calls are no longer added.
        harness.settings.callAlertMinimumLevel = .high
        let anotherMedium = summary(callID: UUID().uuidString, level: .medium, alerted: false)
        RelayStubProtocol.reset(responses: [.init(status: 200, body: try encode([medium, low, anotherMedium]))])
        await harness.coordinator.refreshHistory()
        XCTAssertEqual(try harness.records().count, 2)

        XCTAssertTrue(harness.coordinator.shouldKeep(summary(level: .high, alerted: false)))
        XCTAssertFalse(harness.coordinator.shouldKeep(summary(level: .medium, alerted: false)))
        XCTAssertTrue(harness.coordinator.shouldKeep(summary(level: .low, alerted: true)), "alerted always wins")
        XCTAssertFalse(harness.coordinator.shouldKeep(summary(level: .safe, alerted: false)))
        XCTAssertFalse(harness.coordinator.shouldKeep(summary(level: nil, alerted: false)))
    }

    @MainActor
    func testRefreshHistoryFailureIsReportedAndSkipsUnknownIDs() async throws {
        let harness = try makeHarness()
        RelayStubProtocol.reset(responses: [.init(status: 500, body: "down"), .init(status: 500, body: "down"), .init(status: 500, body: "down")])

        await harness.coordinator.refreshHistory()

        XCTAssertEqual(harness.coordinator.lastError, "Relay HTTP 500: down")
        XCTAssertNil(harness.coordinator.lastRefreshDate)
        XCTAssertFalse(harness.coordinator.isRefreshing)

        XCTAssertNil(harness.coordinator.upsert(summary(callID: "CA1234-not-a-uuid")), "a call the app cannot key on is skipped")
        XCTAssertEqual(try harness.records().count, 0)

        let unconfigured = try makeHarness(configured: false)
        await unconfigured.coordinator.refreshHistory()
        XCTAssertEqual(unconfigured.coordinator.status, .relayNotConfigured)
    }

    // MARK: - Alert push

    @MainActor
    func testHandleAlertPushFetchesTheCallAndPersistsIt() async throws {
        let harness = try makeHarness()
        let detail = #"{"callID": "\#(CallFixtures.callID)", "source": "twilio", "callerNumber": "+14155550134", "calledNumber": "+16285550199", "startedAt": 1758600000000, "status": "in_progress", "verdict": \#(CallFixtures.verdictJSON), "alerted": true, "alertLevel": "high", "transcript": [\#(CallFixtures.segmentJSON)]}"#
        RelayStubProtocol.reset(responses: [.init(status: 200, body: detail)])

        let result = await harness.coordinator.handleAlertPush(CallFixtures.pushUserInfo())

        XCTAssertEqual(result, .newData)
        XCTAssertEqual(RelayStubProtocol.requests.map { $0.url?.absoluteString }, ["https://relay.test/v1/devices/calls/\(CallFixtures.callID)"])
        let records = try harness.records()
        XCTAssertEqual(records.count, 1)
        let record = try XCTUnwrap(records.first)
        XCTAssertEqual(record.id, UUID(uuidString: CallFixtures.callID))
        XCTAssertTrue(record.alerted)
        XCTAssertFalse(record.isRead)
        XCTAssertEqual(record.level, .high)
        XCTAssertEqual(record.category, .scam)
        XCTAssertEqual(record.status, .inProgress, "still on the phone")
        XCTAssertNil(record.durationSeconds)
        XCTAssertEqual(record.reasons.map(\.id), ["call.gift_cards", "call.family_emergency", "model.secrecy"])
        XCTAssertEqual(record.modelIdentifier, "openai:gpt-4.1-mini")
        // The transcript the relay sent along is not in the store in any form.
        XCTAssertFalse(String(decoding: record.reasonsJSON, as: UTF8.self).contains("go buy four gift cards"))
    }

    /// The push is proof of an alert; the relay flags the session `alerted` a moment after sending it, so a fetch
    /// that wins that race must not store the call as never alerted.
    @MainActor
    func testHandleAlertPushMarksTheCallAlertedEvenWhenTheRelayHasNotRecordedItYet() async throws {
        let harness = try makeHarness()
        let detail = #"{"callID": "\#(CallFixtures.callID)", "source": "twilio", "callerNumber": "+14155550134", "calledNumber": "+16285550199", "startedAt": 1758600000000, "status": "in_progress", "verdict": \#(CallFixtures.verdictJSON), "alerted": false}"#
        RelayStubProtocol.reset(responses: [.init(status: 200, body: detail)])

        let result = await harness.coordinator.handleAlertPush(CallFixtures.pushUserInfo())

        XCTAssertEqual(result, .newData)
        let record = try XCTUnwrap(try harness.records().first)
        XCTAssertTrue(record.alerted, "a push is an alert whatever the fetched summary says")
        XCTAssertEqual(record.level, .high)
    }

    @MainActor
    func testHandleAlertPushIgnoresPayloadsThatAreNotCallAlerts() async throws {
        let harness = try makeHarness()

        let mail = await harness.coordinator.handleAlertPush(["aps": ["content-available": 1], "provider": "gmail"])
        let noID = await harness.coordinator.handleAlertPush(["kind": "call-alert"])

        XCTAssertEqual(mail, .noData)
        XCTAssertEqual(noID, .noData)
        XCTAssertTrue(RelayStubProtocol.requests.isEmpty)
        XCTAssertEqual(try harness.records().count, 0)

        let unconfigured = try makeHarness(configured: false)
        let result = await unconfigured.coordinator.handleAlertPush(CallFixtures.pushUserInfo())
        XCTAssertEqual(result, .noData)
    }

    @MainActor
    func testHandleAlertPushKeepsAPlaceholderWhenTheRelayCannotBeReached() async throws {
        let harness = try makeHarness()
        RelayStubProtocol.reset(responses: [.init(status: 503), .init(status: 503), .init(status: 503)])

        let result = await harness.coordinator.handleAlertPush(CallFixtures.pushUserInfo(level: "medium"))

        XCTAssertEqual(result, .newData, "the tap still has a record to land on")
        let record = try XCTUnwrap(try harness.records().first)
        XCTAssertEqual(record.id, UUID(uuidString: CallFixtures.callID))
        XCTAssertEqual(record.level, .medium)
        XCTAssertEqual(record.callerNumber, "+14155550134")
        XCTAssertEqual(record.startedAt, Date(timeIntervalSince1970: 1_758_600_000))
        XCTAssertEqual(record.summary, "Asks for gift cards · Says not to tell anyone", "the banner's text stands in for the summary")
        XCTAssertTrue(record.alerted)
        XCTAssertTrue(record.reasons.isEmpty)

        // A later refresh fills the placeholder in and keeps its identity.
        record.isRead = true
        try harness.context.save()
        RelayStubProtocol.reset(responses: [.init(status: 200, body: try encode([summary(level: .high, alerted: true)]))])
        await harness.coordinator.refreshHistory()
        let records = try harness.records()
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records.first?.level, .high)
        XCTAssertEqual(records.first?.reasons.count, 1)
        XCTAssertEqual(records.first?.isRead, true)

        // A second push for a call that already exists changes nothing when the relay is down.
        RelayStubProtocol.reset(responses: [.init(status: 503), .init(status: 503), .init(status: 503)])
        let again = await harness.coordinator.handleAlertPush(CallFixtures.pushUserInfo(level: "medium"))
        XCTAssertEqual(again, .failed)
        XCTAssertEqual(try harness.records().first?.level, .high, "the placeholder never overwrites a real record")
    }

    @MainActor
    func testHandleAlertPushForACallTheRelayForgotStillKeepsAPlaceholder() async throws {
        let harness = try makeHarness()
        RelayStubProtocol.reset(responses: [.init(status: 404, body: #"{"error":"not_found"}"#)])

        let result = await harness.coordinator.handleAlertPush(CallFixtures.pushUserInfo())

        XCTAssertEqual(result, .newData)
        XCTAssertEqual(RelayStubProtocol.requests.count, 1, "a 404 on this route never re-registers the device")
        XCTAssertEqual(try harness.records().count, 1)
    }

    // MARK: - Live feed

    @MainActor
    func testLiveEventsFoldIntoTheLiveCardAndThenIntoHistory() throws {
        let harness = try makeHarness()
        let coordinator = harness.coordinator
        let callID = CallFixtures.callID

        coordinator.apply(.hello(activeCalls: [], serverTime: 1))
        XCTAssertEqual(coordinator.connection, .connected)
        XCTAssertNil(coordinator.activeCall)

        coordinator.apply(.callStarted(summary(callID: callID, level: nil, alerted: false, status: .ringing)))
        let started = try XCTUnwrap(coordinator.activeCall)
        XCTAssertEqual(started.callID, callID)
        XCTAssertEqual(started.status, .ringing)
        XCTAssertEqual(started.callerNumber, "+14155550134")
        XCTAssertNil(started.verdict)
        XCTAssertFalse(started.alerted)
        XCTAssertEqual(started.level, .safe)

        coordinator.apply(.callStatus(callID: callID, status: .inProgress))
        XCTAssertEqual(coordinator.activeCall?.status, .inProgress)

        coordinator.apply(.transcriptSegment(callID: callID, segment: TranscriptSegment(id: "s1", speaker: .caller, text: "Grandma it's", atMs: 1000, isFinal: false)))
        coordinator.apply(.transcriptSegment(callID: callID, segment: TranscriptSegment(id: "s2", speaker: .user, text: "Hello?", atMs: 1500, isFinal: true)))
        coordinator.apply(.transcriptSegment(callID: callID, segment: TranscriptSegment(id: "s1", speaker: .caller, text: "Grandma it's me", atMs: 1000, isFinal: true)))
        XCTAssertEqual(coordinator.activeCall?.segments.map(\.id), ["s1", "s2"], "a final replaces its partial in place")
        XCTAssertEqual(coordinator.activeCall?.segments.first?.text, "Grandma it's me")
        XCTAssertEqual(coordinator.activeCall?.segments.first?.isFinal, true)

        let verdict3 = try XCTUnwrap(summary(callID: callID, level: .medium, sequence: 3).verdict)
        let verdict2 = try XCTUnwrap(summary(callID: callID, level: .high, sequence: 2).verdict)
        let verdict4 = try XCTUnwrap(summary(callID: callID, level: .high, sequence: 4).verdict)
        coordinator.apply(.verdictUpdated(callID: callID, verdict: verdict3))
        coordinator.apply(.verdictUpdated(callID: callID, verdict: verdict2))
        XCTAssertEqual(coordinator.activeCall?.verdict?.sequence, 3, "a stale verdict is ignored")
        XCTAssertEqual(coordinator.activeCall?.level, .medium)
        coordinator.apply(.verdictUpdated(callID: callID, verdict: verdict4))
        XCTAssertEqual(coordinator.activeCall?.verdict?.sequence, 4)
        XCTAssertEqual(coordinator.activeCall?.level, .high)

        let alert = CallAlert(sequence: 4, level: .high, title: "Likely scam call", subtitle: "Call from +1 (415) 555-0134", body: "Asks for gift cards", sentAt: 1, pushed: false, spoken: true)
        coordinator.apply(.callAlert(callID: callID, alert: alert))
        XCTAssertEqual(coordinator.activeCall?.alerts, [alert])
        XCTAssertEqual(coordinator.activeCall?.alerted, true)

        // Events about another call never touch the live card.
        coordinator.apply(.callStatus(callID: CallFixtures.secondCallID, status: .busy))
        coordinator.apply(.transcriptSegment(callID: CallFixtures.secondCallID, segment: TranscriptSegment(id: "x", speaker: .caller, text: "other", atMs: 0, isFinal: true)))
        coordinator.apply(.verdictUpdated(callID: CallFixtures.secondCallID, verdict: verdict2))
        coordinator.apply(.callAlert(callID: CallFixtures.secondCallID, alert: alert))
        XCTAssertEqual(coordinator.activeCall?.status, .inProgress)
        XCTAssertEqual(coordinator.activeCall?.segments.count, 2)
        XCTAssertEqual(coordinator.activeCall?.verdict?.sequence, 4)
        XCTAssertEqual(coordinator.activeCall?.alerts.count, 1)
        XCTAssertEqual(try harness.records().count, 0, "nothing is persisted while the call is on")

        coordinator.apply(.callEnded(summary(callID: callID, level: .high, alerted: true, status: .completed, sequence: 5)))
        XCTAssertNil(coordinator.activeCall, "folded away")
        let records = try harness.records()
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records.first?.id, UUID(uuidString: callID))
        XCTAssertEqual(records.first?.durationSeconds, 254)
        XCTAssertEqual(records.first?.status, .completed)
        XCTAssertTrue(records.first?.alerted ?? false)

        // An ended call below the level and never alerted leaves nothing behind.
        coordinator.apply(.callStarted(summary(callID: CallFixtures.secondCallID, level: nil, alerted: false, status: .inProgress)))
        coordinator.apply(.callEnded(summary(callID: CallFixtures.secondCallID, level: .low, alerted: false)))
        XCTAssertNil(coordinator.activeCall)
        XCTAssertEqual(try harness.records().count, 1)
        coordinator.apply(.pong)
    }

    @MainActor
    func testHelloRestoresTheCallInProgressAndStopLiveDropsIt() throws {
        let harness = try makeHarness()
        let coordinator = harness.coordinator
        let ended = summary(callID: CallFixtures.secondCallID, level: .high, alerted: true, status: .completed)
        var live = summary(callID: CallFixtures.callID, level: .medium, alerted: false, status: .inProgress)
        live.startedAt = ended.startedAt + 60_000

        coordinator.apply(.hello(activeCalls: [ended, live], serverTime: 1))

        XCTAssertEqual(coordinator.activeCall?.callID, CallFixtures.callID, "the newest call still in progress")
        XCTAssertEqual(coordinator.activeCall?.verdict?.level, .medium)
        XCTAssertEqual(coordinator.activeCall?.segments, [], "catch-up segments arrive as ordinary events")

        // A reconnect's hello for the same call keeps the transcript gathered so far.
        coordinator.apply(.transcriptSegment(callID: CallFixtures.callID, segment: TranscriptSegment(id: "s1", speaker: .caller, text: "hi", atMs: 0, isFinal: true)))
        var advanced = live
        advanced.verdict?.sequence = 9
        advanced.verdict?.level = .high
        coordinator.apply(.hello(activeCalls: [advanced], serverTime: 2))
        XCTAssertEqual(coordinator.activeCall?.segments.count, 1)
        XCTAssertEqual(coordinator.activeCall?.verdict?.sequence, 9)

        coordinator.apply(.hello(activeCalls: [], serverTime: 3))
        XCTAssertNil(coordinator.activeCall, "the relay says nothing is in progress")

        coordinator.apply(.callStarted(live))
        XCTAssertNotNil(coordinator.activeCall)
        coordinator.stopLive()
        XCTAssertNil(coordinator.activeCall)
        XCTAssertEqual(coordinator.connection, .disconnected)
        XCTAssertFalse(coordinator.isLive)
    }

    @MainActor
    func testLiveSegmentsAreBounded() throws {
        let harness = try makeHarness()
        let coordinator = harness.coordinator
        coordinator.apply(.callStarted(summary(callID: CallFixtures.callID, level: nil, alerted: false, status: .inProgress)))

        for index in 0..<(CallGuardCoordinator.maxLiveSegments + 25) {
            coordinator.apply(.transcriptSegment(callID: CallFixtures.callID, segment: TranscriptSegment(id: "s\(index)", speaker: .caller, text: "line \(index)", atMs: index * 1000, isFinal: true)))
        }

        XCTAssertEqual(coordinator.activeCall?.segments.count, CallGuardCoordinator.maxLiveSegments)
        XCTAssertEqual(coordinator.activeCall?.segments.first?.id, "s25", "the oldest lines are dropped first")
    }

    @MainActor
    func testStartLiveWithoutARelayDoesNothing() throws {
        let harness = try makeHarness(configured: false)
        harness.coordinator.startLive()
        XCTAssertFalse(harness.coordinator.isLive)
        XCTAssertEqual(harness.coordinator.connection, .disconnected)
    }

    // MARK: - Line

    @MainActor
    func testRegisterLineStoresTheLineAndTheSettings() async throws {
        let harness = try makeHarness()
        RelayStubProtocol.reset(responses: [.init(status: 200, body: CallFixtures.lineJSON)])
        XCTAssertFalse(harness.settings.isCallGuardEnabled)
        XCTAssertNil(harness.settings.protectedPhoneNumber)

        try await harness.coordinator.registerLine(phoneNumber: "+14155550100", minimumLevel: .safe, spokenWarning: true)

        XCTAssertEqual(harness.coordinator.line?.lineID, "line-42")
        XCTAssertTrue(harness.coordinator.hasFetchedLine)
        XCTAssertEqual(harness.coordinator.status, .protected(guardNumber: "+16285550199", phoneNumber: "+14155550100"))
        XCTAssertTrue(harness.settings.isCallGuardEnabled)
        XCTAssertEqual(harness.settings.protectedPhoneNumber, "+14155550100")
        XCTAssertEqual(harness.settings.callAlertMinimumLevel, .medium, "what the relay confirmed")
        XCTAssertTrue(harness.settings.callSpokenWarningEnabled)
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(RelayStubProtocol.requests.first?.body)) as? [String: Any])
        XCTAssertEqual(body["minimumLevel"] as? String, "low", "safe is never sent")

        RelayStubProtocol.reset(responses: [.init(status: 204)])
        try await harness.coordinator.removeLine()

        XCTAssertNil(harness.coordinator.line)
        XCTAssertEqual(harness.coordinator.status, .notSetUp)
        XCTAssertFalse(harness.settings.isCallGuardEnabled)
        XCTAssertEqual(harness.settings.protectedPhoneNumber, "+14155550100", "kept for the next set-up")
        XCTAssertEqual(RelayStubProtocol.requests.first?.method, "DELETE")
    }

    @MainActor
    func testRefreshLineReportsNoLineAndFailures() async throws {
        let harness = try makeHarness()
        RelayStubProtocol.reset(responses: [.init(status: 404, body: #"{"error":"no_line"}"#)])
        XCTAssertFalse(harness.coordinator.hasFetchedLine)

        await harness.coordinator.refreshLine()
        XCTAssertNil(harness.coordinator.line)
        XCTAssertTrue(harness.coordinator.hasFetchedLine)
        XCTAssertNil(harness.coordinator.lastError)
        XCTAssertEqual(harness.coordinator.status, .notSetUp)

        // 503 is transient, so the client retries it (three attempts in this harness) before giving up.
        let notConfigured = RelayStubProtocol.Response(status: 503, body: #"{"error":"calls_not_configured"}"#)
        RelayStubProtocol.reset(responses: [notConfigured, notConfigured, notConfigured])
        await harness.coordinator.refreshLine()
        XCTAssertEqual(harness.coordinator.lastError, "The relay does not have Call Guard turned on (CALLS_ENABLED).")

        RelayStubProtocol.reset(responses: [.init(status: 200, body: CallFixtures.lineJSON)])
        await harness.coordinator.refreshLine()
        XCTAssertEqual(harness.coordinator.line?.guardNumber, "+16285550199")
        XCTAssertNil(harness.coordinator.lastError)

        let unconfigured = try makeHarness(configured: false)
        await unconfigured.coordinator.refreshLine()
        XCTAssertTrue(unconfigured.coordinator.hasFetchedLine)
        XCTAssertNil(unconfigured.coordinator.line)
    }

    /// A first `refreshLine` that fails (relay down, `CALLS_ENABLED=false`, a device the relay does not know) is
    /// an answer: the Calls tab must show the status card with the error, not "checking…" forever.
    @MainActor
    func testRefreshLineFailureCountsAsAnsweredSoTheErrorIsVisible() async throws {
        let harness = try makeHarness()
        RelayStubProtocol.reset(responses: [.init(status: 401, body: #"{"error":"unauthorized"}"#)])
        XCTAssertFalse(harness.coordinator.hasFetchedLine)

        await harness.coordinator.refreshLine()

        XCTAssertTrue(harness.coordinator.hasFetchedLine, "an error is an answer")
        XCTAssertNil(harness.coordinator.line)
        XCTAssertEqual(harness.coordinator.status, .notSetUp)
        XCTAssertEqual(harness.coordinator.lastError, CallGuardCoordinator.message(for: RelayError.httpStatus(401, body: "unauthorized")))
        XCTAssertTrue(try XCTUnwrap(harness.coordinator.lastError).contains("does not know this phone"), "401 is explained in plain words")
        XCTAssertEqual(RelayStubProtocol.requests.map { $0.url?.path }, ["/v1/devices/call-line"], "no token to re-register with, so no retry")

        // A later success clears the error and keeps the flag.
        RelayStubProtocol.reset(responses: [.init(status: 200, body: CallFixtures.lineJSON)])
        await harness.coordinator.refreshLine()
        XCTAssertTrue(harness.coordinator.hasFetchedLine)
        XCTAssertNil(harness.coordinator.lastError)
        XCTAssertEqual(harness.coordinator.line?.lineID, "line-42")
    }

    @MainActor
    func testCallSettingsDefaultsAndPersistence() throws {
        let store = SettingsStore(defaults: defaults)
        XCTAssertFalse(store.isCallGuardEnabled)
        XCTAssertEqual(store.callAlertMinimumLevel, .medium)
        XCTAssertTrue(store.callSpokenWarningEnabled)
        XCTAssertNil(store.protectedPhoneNumber)

        store.isCallGuardEnabled = true
        store.callAlertMinimumLevel = .safe
        store.callSpokenWarningEnabled = false
        store.protectedPhoneNumber = "+14155550100"

        let reloaded = SettingsStore(defaults: defaults)
        XCTAssertTrue(reloaded.isCallGuardEnabled)
        XCTAssertEqual(reloaded.callAlertMinimumLevel, .low, "never safe")
        XCTAssertFalse(reloaded.callSpokenWarningEnabled)
        XCTAssertEqual(reloaded.protectedPhoneNumber, "+14155550100")

        reloaded.callAlertMinimumLevel = .high
        reloaded.protectedPhoneNumber = ""
        XCTAssertEqual(SettingsStore(defaults: defaults).callAlertMinimumLevel, .high)
        XCTAssertNil(SettingsStore(defaults: defaults).protectedPhoneNumber, "an empty number is no number")
    }

    // MARK: - Seams with the relay

    /// The relay's detector runs one more model pass after `ended` (docs/CALLS.md §6.3) and the live hub relays the
    /// resulting `verdict.updated` — and any `call.alert` on it — after `call.ended`, when the live card is gone.
    @MainActor
    func testAVerdictOrAlertArrivingAfterCallEndedUpdatesTheStoredRecord() throws {
        let harness = try makeHarness()
        let coordinator = harness.coordinator
        let callID = CallFixtures.callID

        coordinator.apply(.callStarted(summary(callID: callID, level: .medium, alerted: false, status: .inProgress, sequence: 2)))
        coordinator.apply(.callEnded(summary(callID: callID, level: .medium, alerted: false, status: .completed, sequence: 2, summaryText: "Provisional.")))
        XCTAssertNil(coordinator.activeCall)
        let record = try XCTUnwrap(harness.records().first)
        XCTAssertEqual(record.level, .medium)
        XCTAssertEqual(record.summary, "Provisional.")
        XCTAssertFalse(record.alerted)

        let final = try XCTUnwrap(summary(callID: callID, level: .high, sequence: 3, summaryText: "Final summary from the model.").verdict)
        coordinator.apply(.verdictUpdated(callID: callID, verdict: final))
        XCTAssertNil(coordinator.activeCall, "no live card comes back for an ended call")
        XCTAssertEqual(record.level, .high)
        XCTAssertEqual(record.category, .scam)
        XCTAssertEqual(record.summary, "Final summary from the model.")
        XCTAssertEqual(record.reasons.map(\.id), ["call.gift_cards"])
        XCTAssertFalse(record.alerted, "a verdict alone is not an alert")

        let alert = CallAlert(sequence: 3, level: .high, title: "Likely scam call", subtitle: "Call from +1 (415) 555-0134", body: "Asks for gift cards", sentAt: 1, pushed: true, spoken: false)
        coordinator.apply(.callAlert(callID: callID, alert: alert))
        XCTAssertTrue(record.alerted)
        XCTAssertEqual(try harness.records().count, 1)

        // A call the app never kept is left to the next history refresh: nothing is invented from a verdict alone.
        coordinator.apply(.verdictUpdated(callID: CallFixtures.secondCallID, verdict: final))
        coordinator.apply(.callAlert(callID: CallFixtures.secondCallID, alert: alert))
        XCTAssertEqual(try harness.records().count, 1)
        XCTAssertNil(coordinator.activeCall)
    }

    // MARK: - AI-voice assessment

    /// The assessment travels next to the verdict: it shows on the live card before any verdict exists, marks the
    /// call alerted once its warning went out, and never produces or changes a verdict.
    @MainActor
    func testVoiceUpdatesFoldIntoTheLiveCardWithoutTouchingTheVerdict() throws {
        let harness = try makeHarness()
        let coordinator = harness.coordinator
        let callID = CallFixtures.callID

        coordinator.apply(.callStarted(summary(callID: callID, level: nil, alerted: false, status: .inProgress, voice: voice(.analyzing, updatedAt: 1_000))))
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .analyzing, "the summary's assessment is on the card from the start")
        XCTAssertNil(coordinator.activeCall?.verdict)
        XCTAssertEqual(coordinator.activeCall?.alerted, false)

        coordinator.apply(.voiceUpdated(callID: callID, voice: voice(.synthetic, share: 0.9, confidence: 0.92, updatedAt: 2_000)))
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .synthetic)
        XCTAssertEqual(coordinator.activeCall?.voice?.syntheticShare, 0.9)
        XCTAssertNil(coordinator.activeCall?.verdict, "a synthetic voice is not a verdict")
        XCTAssertEqual(coordinator.activeCall?.level, .safe)
        XCTAssertEqual(coordinator.activeCall?.alerted, false, "judged synthetic, not yet warned about")

        // A stale assessment (a catch-up replay, a reordered frame) never overwrites a newer one.
        coordinator.apply(.voiceUpdated(callID: callID, voice: voice(.analyzing, updatedAt: 1_500)))
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .synthetic)

        // The relay records the warning on the assessment: that marks the call alerted.
        coordinator.apply(.voiceUpdated(callID: callID, voice: voice(.synthetic, share: 0.9, confidence: 0.92, warned: true, updatedAt: 2_100)))
        XCTAssertEqual(coordinator.activeCall?.alerted, true)
        XCTAssertNotNil(coordinator.activeCall?.voice?.alert)
        XCTAssertEqual(coordinator.activeCall?.alerts, [], "the scam alerts stay the scam alerts")
        XCTAssertNil(coordinator.activeCall?.verdict)

        // Another call's assessment never touches the live card.
        coordinator.apply(.voiceUpdated(callID: CallFixtures.secondCallID, voice: voice(.human, updatedAt: 9_000)))
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .synthetic)

        // The scam verdict arrives on its own and says what it says, whatever the voice check found.
        let safeVerdict = try XCTUnwrap(summary(callID: callID, level: .safe, sequence: 1).verdict)
        coordinator.apply(.verdictUpdated(callID: callID, verdict: safeVerdict))
        XCTAssertEqual(coordinator.activeCall?.level, .safe)
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .synthetic)
        XCTAssertEqual(try harness.records().count, 0, "nothing is persisted while the call is on")

        // The call ends flagged synthetic with a safe verdict: kept, with the verdict as the relay gave it.
        let ended = summary(callID: callID, level: .safe, alerted: true, status: .completed, sequence: 2, voice: voice(.synthetic, share: 0.88, confidence: 0.91, warned: true, updatedAt: 3_000))
        coordinator.apply(.callEnded(ended))
        XCTAssertNil(coordinator.activeCall)
        let record = try XCTUnwrap(harness.records().first)
        XCTAssertEqual(try harness.records().count, 1)
        XCTAssertEqual(record.level, .safe, "the risk level is the scam verdict's alone")
        XCTAssertEqual(record.summary, "The caller asks for gift cards.", "and so is the summary")
        XCTAssertEqual(record.voiceStatus, .synthetic)
        XCTAssertEqual(record.voiceSyntheticShare, 0.88)
        XCTAssertEqual(record.voiceConfidence, 0.91)
        XCTAssertEqual(record.voiceProvider, "modulate:test-model")
        XCTAssertTrue(record.alerted)
    }

    @MainActor
    func testHelloCarriesTheVoiceAssessmentOfTheCallInProgress() throws {
        let harness = try makeHarness()
        let coordinator = harness.coordinator
        let live = summary(callID: CallFixtures.callID, level: nil, alerted: false, status: .inProgress, voice: voice(.analyzing, updatedAt: 1_000))

        coordinator.apply(.hello(activeCalls: [live], serverTime: 1))
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .analyzing)
        XCTAssertEqual(coordinator.activeCall?.alerted, false)

        // A reconnect's hello for the same call brings the newer assessment, warning included.
        let advanced = summary(callID: CallFixtures.callID, level: nil, alerted: false, status: .inProgress, voice: voice(.synthetic, share: 0.95, confidence: 0.9, warned: true, updatedAt: 2_000))
        coordinator.apply(.hello(activeCalls: [advanced], serverTime: 2))
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .synthetic)
        XCTAssertEqual(coordinator.activeCall?.alerted, true, "an assessment that carries the warning marks the call alerted")
        XCTAssertNil(coordinator.activeCall?.verdict)

        // A card built straight from such a summary is alerted too, whatever its `alerted` flag says.
        let card = CallGuardCoordinator.LiveCallState(summary: advanced)
        XCTAssertTrue(card.alerted)
        XCTAssertEqual(card.voice, advanced.voice)
        XCTAssertNil(CallGuardCoordinator.LiveCallState(summary: summary(level: .high, alerted: true)).voice, "no detector, no assessment")
    }

    @MainActor
    func testShouldKeepKeepsASyntheticVoiceWithASafeOrAbsentVerdict() throws {
        let harness = try makeHarness()
        let coordinator = harness.coordinator
        harness.settings.callAlertMinimumLevel = .high

        XCTAssertTrue(coordinator.shouldKeep(summary(level: .safe, alerted: false, voice: voice(.synthetic, share: 0.9, confidence: 0.9))), "synthetic with a safe verdict")
        XCTAssertTrue(coordinator.shouldKeep(summary(level: nil, alerted: false, voice: voice(.synthetic, share: 0.9, confidence: 0.9))), "synthetic with no verdict at all")
        for status in [VoiceStatus.analyzing, .human, .inconclusive, .unavailable, .unknown] {
            XCTAssertFalse(coordinator.shouldKeep(summary(level: nil, alerted: false, voice: voice(status))), "\(status) alone keeps nothing")
            XCTAssertFalse(coordinator.shouldKeep(summary(level: .medium, alerted: false, voice: voice(status))), "\(status) does not lower the bar either")
        }
        XCTAssertTrue(coordinator.shouldKeep(summary(level: .high, alerted: false, voice: voice(.human))), "the scam rule is unchanged")
        XCTAssertFalse(coordinator.shouldKeep(summary(level: .safe, alerted: false)), "and so is a call nobody checked the voice of")

        // A call that ends with a synthetic voice and no verdict is stored with neutral verdict fields.
        coordinator.apply(.callEnded(summary(callID: CallFixtures.callID, level: nil, alerted: false, status: .completed, voice: voice(.synthetic, share: 0.9, confidence: 0.85))))
        // One whose caller sounded human, below the level, leaves nothing behind.
        coordinator.apply(.callEnded(summary(callID: CallFixtures.secondCallID, level: .low, alerted: false, status: .completed, voice: voice(.human, confidence: 0.97))))

        let records = try harness.records()
        XCTAssertEqual(records.map { $0.id.uuidString.lowercased() }, [CallFixtures.callID])
        let record = try XCTUnwrap(records.first)
        XCTAssertEqual(record.voiceStatus, .synthetic)
        XCTAssertEqual(record.voiceSyntheticShare, 0.9)
        XCTAssertEqual(record.level, .safe, "never a made-up scam level")
        XCTAssertEqual(record.category, .safe)
        XCTAssertEqual(record.confidence, 0)
        XCTAssertTrue(record.reasons.isEmpty)
        XCTAssertEqual(record.summary, "")
        XCTAssertNil(record.modelIdentifier)
        XCTAssertFalse(record.alerted, "judged synthetic, but the relay sent no warning")
    }

    /// The relay records the AI-voice warning on the assessment a moment after sending it, which can be after
    /// `call.ended`: the stored record takes it, like a late verdict.
    @MainActor
    func testAVoiceUpdateForACallThatIsNotActiveUpdatesTheStoredRecord() throws {
        let harness = try makeHarness()
        let coordinator = harness.coordinator
        let callID = CallFixtures.callID

        coordinator.apply(.callEnded(summary(callID: callID, level: .medium, alerted: false, status: .completed, summaryText: "Provisional.", voice: voice(.synthetic, share: 0.8, confidence: 0.82, updatedAt: 1_000))))
        let record = try XCTUnwrap(harness.records().first)
        XCTAssertEqual(record.voiceStatus, .synthetic)
        XCTAssertFalse(record.alerted)

        coordinator.apply(.voiceUpdated(callID: callID, voice: voice(.synthetic, share: 0.86, confidence: 0.9, warned: true, updatedAt: 2_000)))

        XCTAssertNil(coordinator.activeCall, "no live card comes back for an ended call")
        XCTAssertTrue(record.alerted, "the warning was sent")
        XCTAssertEqual(record.voiceSyntheticShare, 0.86)
        XCTAssertEqual(record.voiceConfidence, 0.9)
        XCTAssertEqual(record.level, .medium, "nothing the verdict decided is touched")
        XCTAssertEqual(record.category, .scam)
        XCTAssertEqual(record.summary, "Provisional.")
        XCTAssertEqual(record.reasons.map(\.id), ["call.gift_cards"])
        XCTAssertEqual(try harness.records().count, 1)

        // A call the app never kept is left to the next history refresh: nothing is invented from an assessment.
        coordinator.apply(.voiceUpdated(callID: CallFixtures.secondCallID, voice: voice(.synthetic, share: 0.9, confidence: 0.9, warned: true)))
        XCTAssertEqual(try harness.records().count, 1)
        XCTAssertNil(coordinator.activeCall)
    }

    @MainActor
    func testRefreshHistoryKeepsAndUpdatesTheVoiceAssessment() async throws {
        let harness = try makeHarness()
        let scamNoVoice = summary(callID: CallFixtures.secondCallID, level: .high, alerted: true)
        let voiceOnly = summary(callID: CallFixtures.callID, level: nil, alerted: true, voice: voice(.synthetic, share: 0.9, confidence: 0.88, warned: true))
        RelayStubProtocol.reset(responses: [.init(status: 200, body: try encode([scamNoVoice, voiceOnly]))])

        await harness.coordinator.refreshHistory()

        let first = try harness.records()
        XCTAssertEqual(first.count, 2)
        let scam = try XCTUnwrap(first.first { $0.id.uuidString.lowercased() == CallFixtures.secondCallID })
        XCTAssertNil(scam.voiceStatusRaw, "a call no detector ran on has no voice fields")
        XCTAssertNil(scam.voiceStatus)
        XCTAssertNil(scam.voiceSyntheticShare)
        XCTAssertNil(scam.voiceConfidence)
        XCTAssertNil(scam.voiceProvider)
        XCTAssertEqual(scam.level, .high)
        let flagged = try XCTUnwrap(first.first { $0.id.uuidString.lowercased() == CallFixtures.callID })
        XCTAssertEqual(flagged.voiceStatus, .synthetic)
        XCTAssertEqual(flagged.level, .safe)
        XCTAssertTrue(flagged.alerted)

        // The verdict arrives later; the row is updated in place and keeps what the voice check found.
        let withVerdict = summary(callID: CallFixtures.callID, level: .medium, alerted: true, voice: voice(.synthetic, share: 0.93, confidence: 0.9, warned: true))
        RelayStubProtocol.reset(responses: [.init(status: 200, body: try encode([scamNoVoice, withVerdict]))])
        await harness.coordinator.refreshHistory()

        XCTAssertEqual(try harness.records().count, 2)
        XCTAssertEqual(flagged.level, .medium)
        XCTAssertEqual(flagged.voiceStatus, .synthetic)
        XCTAssertEqual(flagged.voiceSyntheticShare, 0.93)
        XCTAssertNil(scam.voiceStatusRaw)
    }

    /// The AI-voice warning push for a call that has no verdict: the tap must still have a record to land on,
    /// alerted and marked synthetic, and nothing about it may read as a scam verdict.
    @MainActor
    func testHandleVoiceWarningPushStoresACallThatHasNoVerdict() async throws {
        let harness = try makeHarness()
        let coordinator = harness.coordinator
        coordinator.apply(.callStarted(summary(callID: CallFixtures.callID, level: nil, alerted: false, status: .inProgress)))
        let detail = #"{"callID": "\#(CallFixtures.callID)", "source": "twilio", "callerNumber": "+14155550134", "calledNumber": "+16285550199", "startedAt": 1758600000000, "status": "in_progress", "alerted": true, "voice": \#(CallFixtures.voiceJSON)}"#
        RelayStubProtocol.reset(responses: [.init(status: 200, body: detail)])

        let result = await coordinator.handleAlertPush(CallFixtures.voicePushUserInfo())

        XCTAssertEqual(result, .newData)
        XCTAssertEqual(RelayStubProtocol.requests.map { $0.url?.absoluteString }, ["https://relay.test/v1/devices/calls/\(CallFixtures.callID)"])
        let record = try XCTUnwrap(try harness.records().first)
        XCTAssertEqual(try harness.records().count, 1)
        XCTAssertEqual(record.id, UUID(uuidString: CallFixtures.callID))
        XCTAssertTrue(record.alerted)
        XCTAssertFalse(record.isRead)
        XCTAssertEqual(record.voiceStatus, .synthetic)
        XCTAssertEqual(try XCTUnwrap(record.voiceSyntheticShare), 0.87, accuracy: 0.0001)
        XCTAssertEqual(try XCTUnwrap(record.voiceConfidence), 0.93, accuracy: 0.0001)
        XCTAssertEqual(record.voiceProvider, "modulate:velma-2-synthetic-voice-detection-streaming")
        XCTAssertEqual(record.level, .safe, "no verdict, so no scam level")
        XCTAssertEqual(record.category, .safe)
        XCTAssertEqual(record.confidence, 0)
        XCTAssertEqual(record.summary, "")
        XCTAssertTrue(record.reasons.isEmpty)
        XCTAssertEqual(record.status, .inProgress, "still on the phone")

        // The live card of that call takes the assessment and the warning from the same fetch.
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .synthetic)
        XCTAssertEqual(coordinator.activeCall?.alerted, true)
        XCTAssertNil(coordinator.activeCall?.verdict)
    }

    /// The push is proof of what the detector found: a fetch that races it, and comes back without the
    /// assessment or the `alerted` flag, must not store the call as unwarned or unflagged.
    @MainActor
    func testHandleVoiceWarningPushMarksTheCallEvenWhenTheRelayHasNotRecordedItYet() async throws {
        let harness = try makeHarness()
        let detail = #"{"callID": "\#(CallFixtures.callID)", "source": "twilio", "callerNumber": "+14155550134", "calledNumber": "+16285550199", "startedAt": 1758600000000, "status": "in_progress", "alerted": false, "voice": {"status": "analyzing", "syntheticShare": 0.4, "confidence": 0, "speechMs": 1200, "provider": "modulate:m", "updatedAt": 1758600020000}}"#
        RelayStubProtocol.reset(responses: [.init(status: 200, body: detail)])

        let result = await harness.coordinator.handleAlertPush(CallFixtures.voicePushUserInfo())

        XCTAssertEqual(result, .newData)
        let record = try XCTUnwrap(try harness.records().first)
        XCTAssertTrue(record.alerted)
        XCTAssertEqual(record.voiceStatus, .synthetic)
        XCTAssertNil(record.voiceSyntheticShare, "figures that belonged to the earlier status are not shown next to this one")
        XCTAssertNil(record.voiceConfidence)
        XCTAssertEqual(record.level, .safe)

        // The same push for a call that has a scam verdict leaves the verdict exactly as the relay reported it.
        let second = try makeHarness()
        let withVerdict = #"{"callID": "\#(CallFixtures.callID)", "source": "twilio", "callerNumber": "+14155550134", "calledNumber": "+16285550199", "startedAt": 1758600000000, "status": "in_progress", "verdict": \#(CallFixtures.verdictJSON), "alerted": true, "alertLevel": "high"}"#
        RelayStubProtocol.reset(responses: [.init(status: 200, body: withVerdict)])
        let again = await second.coordinator.handleAlertPush(CallFixtures.voicePushUserInfo())
        XCTAssertEqual(again, .newData)
        let scam = try XCTUnwrap(try second.records().first)
        XCTAssertEqual(scam.level, .high)
        XCTAssertEqual(scam.category, .scam)
        XCTAssertEqual(scam.reasons.count, 3)
        XCTAssertEqual(scam.voiceStatus, .synthetic)
        XCTAssertTrue(scam.alerted)
    }

    @MainActor
    func testHandleVoiceWarningPushKeepsANeutralPlaceholderWhenTheRelayCannotBeReached() async throws {
        let harness = try makeHarness()
        RelayStubProtocol.reset(responses: [.init(status: 503), .init(status: 503), .init(status: 503)])

        // Whatever level the push carries, a voice warning alone is never stored as a scam.
        let result = await harness.coordinator.handleAlertPush(CallFixtures.voicePushUserInfo(level: "high"))

        XCTAssertEqual(result, .newData, "the tap still has a record to land on")
        let record = try XCTUnwrap(try harness.records().first)
        XCTAssertEqual(record.id, UUID(uuidString: CallFixtures.callID))
        XCTAssertTrue(record.alerted)
        XCTAssertEqual(record.voiceStatus, .synthetic)
        XCTAssertNil(record.voiceSyntheticShare, "the push carries no figures")
        XCTAssertNil(record.voiceConfidence)
        XCTAssertEqual(record.level, .safe, "not labelled a scam")
        XCTAssertEqual(record.category, .safe)
        XCTAssertEqual(record.confidence, 0)
        XCTAssertEqual(record.summary, "", "the voice banner's text is not a scam summary")
        XCTAssertTrue(record.reasons.isEmpty)
        XCTAssertEqual(record.callerNumber, "+14155550134")
        XCTAssertEqual(record.startedAt, Date(timeIntervalSince1970: 1_758_600_000))

        // The same push again, relay still down: nothing is duplicated.
        RelayStubProtocol.reset(responses: [.init(status: 503), .init(status: 503), .init(status: 503)])
        let again = await harness.coordinator.handleAlertPush(CallFixtures.voicePushUserInfo())
        XCTAssertEqual(again, .newData)
        XCTAssertEqual(try harness.records().count, 1)

        // A later refresh fills the placeholder in with the relay's verdict and keeps the voice status.
        record.isRead = true
        try harness.context.save()
        let reported = summary(level: .medium, alerted: true, voice: voice(.synthetic, share: 0.9, confidence: 0.9, warned: true))
        RelayStubProtocol.reset(responses: [.init(status: 200, body: try encode([reported]))])
        await harness.coordinator.refreshHistory()
        XCTAssertEqual(try harness.records().count, 1)
        XCTAssertEqual(record.level, .medium)
        XCTAssertEqual(record.voiceStatus, .synthetic)
        XCTAssertEqual(record.voiceSyntheticShare, 0.9)
        XCTAssertTrue(record.isRead)

        // A voice warning for a call the relay forgot (404) leaves a placeholder too.
        let forgotten = try makeHarness()
        RelayStubProtocol.reset(responses: [.init(status: 404, body: #"{"error":"not_found"}"#)])
        let afterForgotten = await forgotten.coordinator.handleAlertPush(CallFixtures.voicePushUserInfo())
        XCTAssertEqual(afterForgotten, .newData)
        XCTAssertEqual(try forgotten.records().first?.voiceStatus, .synthetic)
        XCTAssertEqual(try forgotten.records().first?.level, .safe)
    }

    /// Relay unreachable throughout: the AI-voice warning arrives first and leaves its neutral placeholder, then
    /// the scam alert arrives. The scam alert must not be lost on a record that says nothing about a scam.
    @MainActor
    func testScamAlertPushFillsInAVoiceOnlyPlaceholderWhenTheRelayCannotBeReached() async throws {
        let harness = try makeHarness()
        RelayStubProtocol.reset(responses: [.init(status: 503), .init(status: 503), .init(status: 503)])
        _ = await harness.coordinator.handleAlertPush(CallFixtures.voicePushUserInfo())
        let record = try XCTUnwrap(try harness.records().first)
        XCTAssertTrue(record.isVoiceOnly)
        XCTAssertTrue(record.hasNoScamVerdict)

        RelayStubProtocol.reset(responses: [.init(status: 503), .init(status: 503), .init(status: 503)])
        let result = await harness.coordinator.handleAlertPush(CallFixtures.pushUserInfo())

        XCTAssertEqual(result, .newData)
        XCTAssertEqual(try harness.records().count, 1)
        XCTAssertEqual(record.level, .high)
        XCTAssertEqual(record.category, .scam)
        XCTAssertEqual(record.confidence, 0.92, accuracy: 0.0001)
        XCTAssertEqual(record.summary, "Asks for gift cards · Says not to tell anyone")
        XCTAssertTrue(record.alerted)
        XCTAssertEqual(record.voiceStatus, .synthetic, "the voice finding stays")
        XCTAssertFalse(record.isVoiceOnly)

        // A second scam push finds a record with a verdict of its own now and leaves it alone, as before.
        RelayStubProtocol.reset(responses: [.init(status: 503), .init(status: 503), .init(status: 503)])
        let again = await harness.coordinator.handleAlertPush(CallFixtures.pushUserInfo(level: "medium"))
        XCTAssertEqual(again, .failed)
        XCTAssertEqual(record.level, .high)
    }

    /// `isVoiceOnly` is what the screens branch on: synthetic voice with a safe (or absent) scam verdict.
    @MainActor
    func testVoiceOnlyRecordsAreToldApartFromScoredOnes() throws {
        let harness = try makeHarness()
        // Scored safe by the relay, voice synthetic: voice-only, but a verdict was recorded.
        let scoredSafe = try XCTUnwrap(harness.coordinator.upsert(summary(level: .safe, alerted: false, summaryText: "No signs of a scam so far.", voice: voice(.synthetic, share: 0.9, confidence: 0.9, warned: true))))
        XCTAssertTrue(scoredSafe.isVoiceOnly)
        XCTAssertFalse(scoredSafe.hasNoScamVerdict)
        // No verdict at all.
        let unscored = try XCTUnwrap(harness.coordinator.upsert(summary(callID: CallFixtures.secondCallID, level: nil, alerted: false, voice: voice(.synthetic, share: 0.9, confidence: 0.9, warned: true))))
        XCTAssertTrue(unscored.isVoiceOnly)
        XCTAssertTrue(unscored.hasNoScamVerdict)
        // A scam call with a synthetic voice is a scam call.
        scoredSafe.apply(CallVerdict(
            sequence: 4, category: .scam, confidence: 0.8, level: .medium, reasons: [], summary: "Asks for a code.",
            recommendedAction: "Hang up.", heuristicScore: 0.8, updatedAt: 1_758_600_130_000
        ))
        XCTAssertFalse(scoredSafe.isVoiceOnly)
        XCTAssertFalse(scoredSafe.hasNoScamVerdict)
        // A human-sounding safe call is not voice-only either.
        unscored.apply(voice(.human, share: 0.02, confidence: 0.9))
        XCTAssertFalse(unscored.isVoiceOnly)
    }

    /// The live card never drops an assessment for want of a timestamp, and never takes "synthetic" back.
    @MainActor
    func testLiveCardTakesAnUnstampedAssessmentAndKeepsSynthetic() throws {
        let harness = try makeHarness()
        let coordinator = harness.coordinator
        let callID = CallFixtures.callID
        coordinator.apply(.callStarted(summary(level: nil, alerted: false, status: .inProgress, voice: voice(.analyzing, updatedAt: 1_000))))
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .analyzing)

        // `updatedAt` missing or unreadable decodes as 0: taken as it comes, not discarded as older than 1000.
        coordinator.apply(.voiceUpdated(callID: callID, voice: voice(.synthetic, share: 0.9, confidence: 0.9, updatedAt: 0)))
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .synthetic)

        // Nothing takes it back, stamped later or not at all.
        coordinator.apply(.voiceUpdated(callID: callID, voice: voice(.human, updatedAt: 5_000)))
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .synthetic)
        coordinator.apply(.voiceUpdated(callID: callID, voice: voice(.analyzing, updatedAt: 0)))
        XCTAssertEqual(coordinator.activeCall?.voice?.status, .synthetic)

        // A later synthetic one (the warning recorded) still lands.
        coordinator.apply(.voiceUpdated(callID: callID, voice: voice(.synthetic, share: 0.9, confidence: 0.9, warned: true, updatedAt: 6_000)))
        XCTAssertEqual(coordinator.activeCall?.voice?.alert?.pushed, true)
        XCTAssertEqual(coordinator.activeCall?.alerted, true)
    }

    /// A call already listed for its scam verdict gets the voice warning while the relay is unreachable: the
    /// record gains the voice status and the warning, and keeps everything the verdict decided.
    @MainActor
    func testVoiceWarningPushForAnExistingRecordNeverTouchesItsVerdict() async throws {
        let harness = try makeHarness()
        harness.coordinator.upsert(summary(level: .high, alerted: false, status: .inProgress))
        try harness.context.save()
        RelayStubProtocol.reset(responses: [.init(status: 503), .init(status: 503), .init(status: 503)])

        let result = await harness.coordinator.handleAlertPush(CallFixtures.voicePushUserInfo())

        XCTAssertEqual(result, .newData)
        let records = try harness.records()
        XCTAssertEqual(records.count, 1)
        let record = try XCTUnwrap(records.first)
        XCTAssertEqual(record.voiceStatus, .synthetic)
        XCTAssertTrue(record.alerted)
        XCTAssertEqual(record.level, .high)
        XCTAssertEqual(record.category, .scam)
        XCTAssertEqual(record.summary, "The caller asks for gift cards.")
        XCTAssertEqual(record.reasons.map(\.id), ["call.gift_cards"])

        // And the scam alert's own placeholder path is as it was: it has no voice fields.
        let scamOnly = try makeHarness()
        RelayStubProtocol.reset(responses: [.init(status: 503), .init(status: 503), .init(status: 503)])
        _ = await scamOnly.coordinator.handleAlertPush(CallFixtures.pushUserInfo(callID: CallFixtures.secondCallID, level: "medium"))
        let placeholder = try XCTUnwrap(try scamOnly.records().first)
        XCTAssertNil(placeholder.voiceStatusRaw)
        XCTAssertEqual(placeholder.level, .medium)
        XCTAssertEqual(placeholder.category, .scam)
    }

    /// Every error code the relay's §5.1 routes answer gets plain words, never a bare "Relay HTTP …".
    func testMessagesExplainEveryRelayErrorCodeTheCallRoutesAnswer() {
        let cases: [(Int, String, String)] = [
            (503, "calls_not_configured", "CALLS_ENABLED"),
            (503, "twilio_not_configured", "Twilio"),
            (502, "twilio_error", "Twilio"),
            (403, "demo_disabled", "demo"),
            (409, "no_line", "phone number"),
            (401, "invalid_api_key", "RELAY_API_KEY"),
            (401, "unauthorized", "does not know this phone"),
        ]
        for (status, code, expected) in cases {
            let message = CallGuardCoordinator.message(for: RelayError.httpStatus(status, body: code))
            XCTAssertTrue(message.contains(expected), "\(status) \(code): \(message)")
            XCTAssertFalse(message.contains("Relay HTTP"), "\(status) \(code) is explained, not echoed: \(message)")
            XCTAssertFalse(message.contains(code), "\(status) \(code): the raw code is not shown to the person: \(message)")
        }
        XCTAssertEqual(CallGuardCoordinator.message(for: RelayError.notConfigured), "The PhishGuard relay is not configured in this build.")
    }
}

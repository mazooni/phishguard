import Foundation
import Observation
import OSLog
import PhishCore
import SwiftData
import UIKit

/// The app side of Call Guard (docs/CALLS.md §8): the registered line, the call in progress as the live feed
/// reports it, the history of flagged calls in SwiftData, and the alert push that lands while a call is on.
/// Owned by `AppEnvironment`; the Calls tab and `AppDelegate` talk to it.
///
/// Nothing here ever holds a transcript beyond the live card of the call in progress: `LiveCallState.segments`
/// is in memory for that call only, and `FlaggedCallRecord` has no field for one.
@MainActor
@Observable
final class CallGuardCoordinator {
    typealias ConnectionState = CallGuardClient.ConnectionState

    /// The call in progress, as assembled from `LiveEvent`s.
    struct LiveCallState: Sendable, Equatable, Identifiable {
        /// How many transcript lines the live card keeps; the oldest are dropped first.
        static let maxLiveSegments = 200

        var callID: String
        var callerNumber: String
        var guardNumber: String
        var source: CallSource
        var startedAt: Date
        var status: CallStatus
        /// Partials are replaced in place by id; bounded to `maxLiveSegments`.
        var segments: [TranscriptSegment] = []
        var verdict: CallVerdict?
        var alerts: [CallAlert] = []
        var alerted: Bool

        var id: String { callID }

        init(summary: CallSummary) {
            callID = summary.callID
            callerNumber = summary.callerNumber
            guardNumber = summary.calledNumber
            source = summary.source
            startedAt = summary.startedDate
            status = summary.status
            verdict = summary.verdict
            alerted = summary.alerted
        }

        var level: RiskLevel { verdict?.level ?? .safe }

        /// Replaces the segment with the same id (a partial becoming final, or a newer partial) or appends.
        mutating func merge(_ segment: TranscriptSegment) {
            if let index = segments.firstIndex(where: { $0.id == segment.id }) {
                segments[index] = segment
            } else {
                segments.append(segment)
                if segments.count > Self.maxLiveSegments {
                    segments.removeFirst(segments.count - Self.maxLiveSegments)
                }
            }
        }
    }

    static var maxLiveSegments: Int { LiveCallState.maxLiveSegments }

    let client: CallGuardClient
    private let container: ModelContainer
    private let settings: SettingsStore
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "calls")

    /// The relay's registration for this device, nil until fetched or when there is none.
    private(set) var line: CallLine?
    /// True once `refreshLine` has answered at least once — with a line, with "no line" or with an error — so the
    /// Calls tab shows "checking…" only while the first answer is outstanding, never a spinner that hides `lastError`.
    private(set) var hasFetchedLine = false
    private(set) var activeCall: LiveCallState?
    private(set) var connection: ConnectionState = .disconnected
    private(set) var isRefreshing = false
    private(set) var lastRefreshDate: Date?
    /// The last failure of `refreshLine`/`refreshHistory`, user-facing, cleared by a success.
    private(set) var lastError: String?
    /// Set when the user taps a call alert notification; the Calls tab navigates to that record and clears it.
    var pendingCallID: UUID?

    @ObservationIgnored private var liveTask: Task<Void, Never>?

    init(client: CallGuardClient, container: ModelContainer, settings: SettingsStore) {
        self.client = client
        self.container = container
        self.settings = settings
    }

    var isConfigured: Bool { client.isConfigured }

    var status: CallGuardStatus {
        CallGuardStatus.make(relayConfigured: isConfigured, line: line)
    }

    // MARK: - Line

    func refreshLine() async {
        guard isConfigured else {
            line = nil
            hasFetchedLine = true
            return
        }
        do {
            line = try await client.fetchLine()
            hasFetchedLine = true
            lastError = nil
        } catch {
            // An error is an answer too: the status card (with `lastError`) replaces the loading card. The last
            // known line is kept; the relay may simply be unreachable right now.
            hasFetchedLine = true
            lastError = Self.message(for: error)
            logger.error("Fetching the call line failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Registers (or replaces) this device's line and remembers the choice in Settings.
    func registerLine(phoneNumber: String, minimumLevel: RiskLevel, spokenWarning: Bool) async throws {
        let level = max(minimumLevel, .low)
        let registered = try await client.registerLine(phoneNumber: phoneNumber, minimumLevel: level, spokenWarning: spokenWarning)
        line = registered
        hasFetchedLine = true
        settings.protectedPhoneNumber = registered.phoneNumber
        settings.callAlertMinimumLevel = registered.minimumLevel
        settings.callSpokenWarningEnabled = registered.spokenWarning
        settings.isCallGuardEnabled = true
        lastError = nil
        logger.info("Call line registered (level=\(level.rawValue, privacy: .public), spoken=\(spokenWarning))")
    }

    /// Removes the line. The protected number stays in Settings so setting up again is one tap.
    func removeLine() async throws {
        try await client.removeLine()
        line = nil
        hasFetchedLine = true
        settings.isCallGuardEnabled = false
        lastError = nil
        logger.info("Call line removed")
    }

    // MARK: - History

    /// The line, then the history (pull to refresh, the tab appearing).
    func refreshAll() async {
        await refreshLine()
        await refreshHistory()
    }

    /// Fetches the relay's recent calls and upserts a `FlaggedCallRecord` for every one worth keeping (see
    /// `shouldKeep`). Existing rows keep `isRead`.
    func refreshHistory() async {
        guard isConfigured else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            let calls = try await client.fetchCalls(limit: CallGuardClient.defaultHistoryLimit)
            var changed = 0
            for summary in calls where shouldKeep(summary) {
                if upsert(summary) != nil { changed += 1 }
            }
            save(what: "call history")
            lastRefreshDate = .now
            lastError = nil
            logger.info("Call history refreshed: \(calls.count) calls, \(changed) kept")
        } catch is CancellationError {
            // The view went away; nothing to report.
        } catch {
            lastError = Self.message(for: error)
            logger.error("Refreshing call history failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// A call is kept when its verdict reached the app's call alert level, or when the relay alerted on it (its
    /// own line level may have been lower at the time — an alert the person heard must stay findable).
    func shouldKeep(_ summary: CallSummary) -> Bool {
        if summary.alerted { return true }
        guard let level = summary.verdict?.level else { return false }
        return AlertFilter.includes(level: level, minimum: settings.callAlertMinimumLevel)
    }

    /// Inserts or updates the record for `summary` (without saving). Nil when the call id is not a UUID.
    @discardableResult
    func upsert(_ summary: CallSummary) -> FlaggedCallRecord? {
        guard let id = UUID(uuidString: summary.callID) else {
            logger.notice("Skipping a call whose id is not a UUID")
            return nil
        }
        let context = container.mainContext
        if let existing = existingRecord(id: id) {
            existing.update(from: summary)
            return existing
        }
        guard let record = FlaggedCallRecord(summary: summary) else { return nil }
        context.insert(record)
        return record
    }

    func existingRecord(id: UUID) -> FlaggedCallRecord? {
        var descriptor = FetchDescriptor<FlaggedCallRecord>(predicate: #Predicate { $0.id == id })
        descriptor.fetchLimit = 1
        return try? container.mainContext.fetch(descriptor).first
    }

    // MARK: - Alert push (§5.4)

    /// A `kind: call-alert` remote notification: iOS has already shown the banner, so this only fetches the call
    /// and persists it (so the tap has somewhere to land) — it posts nothing. When the relay cannot be reached a
    /// placeholder built from the push itself is kept and refreshed by the next `refreshHistory`.
    func handleAlertPush(_ userInfo: [AnyHashable: Any]) async -> UIBackgroundFetchResult {
        guard let payload = CallAlertPushPayload.parse(userInfo) else {
            logger.notice("Call alert push without a usable payload; ignoring")
            return .noData
        }
        return await handleAlertPush(payload)
    }

    /// The parsed form of the above (what `AppDelegate` hands over, so nothing non-Sendable crosses a task).
    func handleAlertPush(_ payload: CallAlertPushPayload) async -> UIBackgroundFetchResult {
        guard isConfigured else {
            logger.notice("Call alert push but the relay is not configured; ignoring")
            return .noData
        }
        do {
            guard let detail = try await client.fetchCall(id: payload.callID) else {
                logger.notice("Call alert push for a call the relay no longer has")
                return insertPlaceholder(for: payload) ? .newData : .noData
            }
            if let record = upsert(detail.summary) {
                // The push is itself proof of an alert. The relay records `alerted` on the session right after
                // sending it, so a fetch that races the push must not store the call as never alerted.
                record.alerted = true
            }
            save(what: "call alert")
            if activeCall?.callID == detail.summary.callID, !detail.summary.status.isEnded {
                activeCall?.verdict = detail.summary.verdict ?? activeCall?.verdict
                activeCall?.alerted = true
            }
            logger.info("Call alert push persisted (level=\(payload.level.rawValue, privacy: .public))")
            return .newData
        } catch {
            logger.error("Fetching the alerted call failed: \(error.localizedDescription, privacy: .public)")
            return insertPlaceholder(for: payload) ? .newData : .failed
        }
    }

    /// A record from the push alone, only when none exists yet. Returns whether one was written.
    private func insertPlaceholder(for payload: CallAlertPushPayload) -> Bool {
        guard let id = UUID(uuidString: payload.callID) else { return false }
        guard existingRecord(id: id) == nil else { return false }
        let record = FlaggedCallRecord(
            id: id,
            callerNumber: payload.callerNumber ?? "",
            guardNumber: line?.guardNumber ?? "",
            startedAt: payload.startedAt ?? .now,
            statusRaw: CallStatus.inProgress.rawValue,
            sourceRaw: CallSource.twilio.rawValue,
            categoryRaw: (payload.category ?? .scam).rawValue,
            confidence: payload.confidence ?? 0,
            levelRaw: payload.level.rawValue,
            reasonsJSON: FlaggedCallRecord.encodeReasons([]),
            summary: payload.alertBody ?? "",
            recommendedAction: "",
            alerted: true
        )
        container.mainContext.insert(record)
        save(what: "call alert placeholder")
        return true
    }

    // MARK: - Live feed

    /// Opens the live feed (idempotent). Driven by the Calls tab appearing and by `scenePhase == .active`.
    func startLive() {
        guard isConfigured, liveTask == nil else { return }
        connection = .connecting
        let client = self.client
        // Strong captures on purpose: the coordinator lives as long as the app, and `stopLive` cancels this task.
        liveTask = Task {
            let stream = client.liveEvents { state in
                Task { @MainActor in self.connection = state }
            }
            do {
                for try await event in stream {
                    guard !Task.isCancelled else { break }
                    self.apply(event)
                }
            } catch {
                self.logger.error("Live feed ended: \(error.localizedDescription, privacy: .public)")
            }
            // A cancelled task was replaced or stopped by `stopLive`, which already reset the state.
            guard !Task.isCancelled else { return }
            self.connection = .disconnected
            self.liveTask = nil
        }
    }

    /// Closes the live feed. The live card is dropped: the next `hello` restores any call still in progress.
    func stopLive() {
        liveTask?.cancel()
        liveTask = nil
        connection = .disconnected
        activeCall = nil
    }

    var isLive: Bool { liveTask != nil }

    /// Folds one event into `activeCall` and, for `call.ended`, into history. Internal for tests.
    func apply(_ event: LiveEvent) {
        switch event {
        case .hello(let activeCalls, _):
            connection = .connected
            let live = activeCalls.filter { !$0.status.isEnded }.max { $0.startedAt < $1.startedAt }
            if let live {
                if activeCall?.callID != live.callID {
                    activeCall = LiveCallState(summary: live)
                } else {
                    activeCall?.status = live.status
                    if let verdict = live.verdict { adopt(verdict) }
                }
            } else {
                activeCall = nil
            }
        case .callStarted(let summary):
            activeCall = LiveCallState(summary: summary)
        case .callStatus(let callID, let status):
            guard activeCall?.callID == callID else { return }
            activeCall?.status = status
        case .transcriptSegment(let callID, let segment):
            guard activeCall?.callID == callID else { return }
            activeCall?.merge(segment)
        case .verdictUpdated(let callID, let verdict):
            if activeCall?.callID == callID {
                adopt(verdict)
            } else {
                // The detector's final model pass lands up to 10 s after `call.ended` (docs/CALLS.md §6.3), when
                // the live card is already gone: the record kept at `call.ended` takes the final summary now rather
                // than at the next history refresh. A call the app never kept is left to that refresh.
                updateRecord(callID: callID, what: "final verdict") { $0.apply(verdict) }
            }
        case .callAlert(let callID, let alert):
            if activeCall?.callID == callID {
                activeCall?.alerts.append(alert)
                activeCall?.alerted = true
            } else {
                // An alert the relay sent on that final verdict, after the call ended.
                updateRecord(callID: callID, what: "late alert") { $0.alerted = true }
            }
        case .callEnded(let summary):
            if shouldKeep(summary) {
                upsert(summary)
                save(what: "ended call")
            }
            if activeCall?.callID == summary.callID {
                activeCall = nil
            }
        case .pong:
            break
        }
    }

    private func adopt(_ verdict: CallVerdict) {
        guard let current = activeCall?.verdict else {
            activeCall?.verdict = verdict
            return
        }
        // Stale verdicts (a catch-up replay, a reordered frame) never overwrite a newer one.
        guard verdict.sequence >= current.sequence else { return }
        activeCall?.verdict = verdict
    }

    /// Applies `change` to the stored record of `callID`, when there is one, and saves.
    private func updateRecord(callID: String, what: String, _ change: (FlaggedCallRecord) -> Void) {
        guard let id = UUID(uuidString: callID), let record = existingRecord(id: id) else { return }
        change(record)
        save(what: what)
    }

    // MARK: - Demo / test calls (§7)

    func startDemoCall(scenario: DemoScenario) async throws -> String {
        try await client.startDemoCall(scenario: scenario)
    }

    func startTestCall(scenario: DemoScenario) async throws -> String {
        try await client.startTestCall(scenario: scenario)
    }

    // MARK: - Helpers

    private func save(what: String) {
        let context = container.mainContext
        guard context.hasChanges else { return }
        do {
            try context.save()
        } catch {
            logger.error("Could not save \(what, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    /// What the Calls tab says when a relay call fails; the relay's error codes (§5.1) get plain words.
    nonisolated static func message(for error: any Error) -> String {
        if let relayError = error as? RelayError {
            switch relayError {
            case .notConfigured:
                return "The PhishGuard relay is not configured in this build."
            case .httpStatus(let status, let body):
                switch (status, body) {
                case (503, "calls_not_configured"?):
                    return "The relay does not have Call Guard turned on (CALLS_ENABLED)."
                case (503, "twilio_not_configured"?):
                    // `PUT /v1/devices/call-line` and `POST …/test-call` without TWILIO_* on the relay.
                    return "The relay has no phone number yet (Twilio is not set up on it), so a line cannot be registered and calls cannot be forwarded. Scripted demo calls still work."
                case (502, "twilio_error"?):
                    return "Twilio refused the call. Check the relay's Twilio credentials, and on a trial account that your number is verified there."
                case (403, "demo_disabled"?):
                    return "Scripted demo calls are turned off on the relay."
                case (409, "no_line"?):
                    return "Set up call protection first: a test call needs your phone number."
                case (401, "invalid_api_key"?):
                    // `apiKeyGuard`: the shared key this build carries is not the relay's.
                    return "The relay rejected this build's RELAY_API_KEY."
                case (401, _):
                    // `apiKeyGuard` (RELAY_API_KEY mismatch) or `deviceAuthGuard` (no row for this device, e.g. a
                    // reset relay database). RelayClient already re-registered once and was refused again; the
                    // registration itself no longer needs an APNs token (docs/CALLS.md §9).
                    return "The relay does not know this phone, or the app's RELAY_API_KEY does not match the relay's. Check Secrets.xcconfig, then reopen the app: it registers itself."
                case (400, _):
                    return "The relay rejected the request\(body.map { ": \($0)" } ?? "")."
                default:
                    return relayError.localizedDescription
                }
            case .network, .invalidResponse:
                return relayError.localizedDescription
            }
        }
        return error.localizedDescription
    }
}

/// What the Calls tab's status card shows.
enum CallGuardStatus: Equatable {
    case relayNotConfigured
    case notSetUp
    case protected(guardNumber: String, phoneNumber: String)

    static func make(relayConfigured: Bool, line: CallLine?) -> CallGuardStatus {
        guard relayConfigured else { return .relayNotConfigured }
        guard let line else { return .notSetUp }
        return .protected(guardNumber: line.guardNumber, phoneNumber: line.phoneNumber)
    }

    var isProtected: Bool {
        if case .protected = self { return true }
        return false
    }

    var title: String {
        switch self {
        case .relayNotConfigured: return DemoData.isWebDemoBuild ? "Calls are off in this web demo" : "Relay not configured"
        case .notSetUp: return "Call protection is off"
        case .protected: return "Calls protected"
        }
    }

    var detail: String {
        switch self {
        case .relayNotConfigured:
            if DemoData.isWebDemoBuild {
                // The browser-hosted demo has no phone line behind it; the seeded history below is what it shows.
                return "This browser demo has no phone line behind it, so no new calls are checked. Below are past detections from the demo data: on a real iPhone, calls to your guard number are scored while you talk."
            }
            return "Call Guard runs through the PhishGuard relay. This build has no RELAY_BASE_URL / RELAY_API_KEY, so calls cannot be checked."
        case .notSetUp:
            return "Give people a guard number to call you on. Calls to it ring your phone as usual and are checked for scams while you talk."
        case .protected(let guardNumber, _):
            return "Calls to \(PhoneNumberFormat.display(guardNumber)) ring your phone and are checked as they happen. Hand out this number instead of your own."
        }
    }

    var symbolName: String {
        switch self {
        case .relayNotConfigured: return "antenna.radiowaves.left.and.right.slash"
        case .notSetUp: return "phone.badge.checkmark"
        case .protected: return "checkmark.shield.fill"
        }
    }
}

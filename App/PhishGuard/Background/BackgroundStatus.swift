import Foundation
import Observation

/// Observable record of the last background runs, persisted in UserDefaults for the Diagnostics screen.
/// Only timestamps, short outcome strings and task identifiers are stored — never mail content.
@MainActor
@Observable
final class BackgroundStatus {
    enum Keys {
        static let lastRefreshRun = "background.lastRefreshRun"
        static let lastRefreshOutcome = "background.lastRefreshOutcome"
        static let lastProcessingRun = "background.lastProcessingRun"
        static let lastProcessingOutcome = "background.lastProcessingOutcome"
        static let lastSilentPushAt = "background.lastSilentPushAt"
        static let lastSilentPushOutcome = "background.lastSilentPushOutcome"
    }

    @ObservationIgnored private let defaults: UserDefaults

    /// Identifiers of the task requests currently pending with `BGTaskScheduler` (see `refreshPendingRequests`).
    var pendingTaskIdentifiers: [String] = []

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var lastRefreshRun: Date? {
        get { access(keyPath: \.lastRefreshRun); return defaults.object(forKey: Keys.lastRefreshRun) as? Date }
        set { withMutation(keyPath: \.lastRefreshRun) { defaults.set(newValue, forKey: Keys.lastRefreshRun) } }
    }

    var lastRefreshOutcome: String? {
        get { access(keyPath: \.lastRefreshOutcome); return defaults.string(forKey: Keys.lastRefreshOutcome) }
        set { withMutation(keyPath: \.lastRefreshOutcome) { defaults.set(newValue, forKey: Keys.lastRefreshOutcome) } }
    }

    var lastProcessingRun: Date? {
        get { access(keyPath: \.lastProcessingRun); return defaults.object(forKey: Keys.lastProcessingRun) as? Date }
        set { withMutation(keyPath: \.lastProcessingRun) { defaults.set(newValue, forKey: Keys.lastProcessingRun) } }
    }

    var lastProcessingOutcome: String? {
        get { access(keyPath: \.lastProcessingOutcome); return defaults.string(forKey: Keys.lastProcessingOutcome) }
        set { withMutation(keyPath: \.lastProcessingOutcome) { defaults.set(newValue, forKey: Keys.lastProcessingOutcome) } }
    }

    var lastSilentPushAt: Date? {
        get { access(keyPath: \.lastSilentPushAt); return defaults.object(forKey: Keys.lastSilentPushAt) as? Date }
        set { withMutation(keyPath: \.lastSilentPushAt) { defaults.set(newValue, forKey: Keys.lastSilentPushAt) } }
    }

    var lastSilentPushOutcome: String? {
        get { access(keyPath: \.lastSilentPushOutcome); return defaults.string(forKey: Keys.lastSilentPushOutcome) }
        set { withMutation(keyPath: \.lastSilentPushOutcome) { defaults.set(newValue, forKey: Keys.lastSilentPushOutcome) } }
    }

    /// Records the outcome of a run for the given trigger (other triggers are ignored).
    func record(trigger: ScanTrigger, summary: ScanSummary, at date: Date = .now) {
        switch trigger {
        case .backgroundRefresh:
            lastRefreshRun = date
            lastRefreshOutcome = summary.outcomeText
        case .backgroundProcessing:
            lastProcessingRun = date
            lastProcessingOutcome = summary.outcomeText
        case .silentPush:
            lastSilentPushAt = date
            lastSilentPushOutcome = summary.outcomeText
        case .manual, .appLaunch:
            break
        }
    }

    /// Notes that a silent push arrived (before its scan has run).
    func recordSilentPushArrival(at date: Date = .now) {
        lastSilentPushAt = date
        lastSilentPushOutcome = "received, scanning…"
    }
}

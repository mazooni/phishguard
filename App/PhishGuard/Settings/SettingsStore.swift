import Foundation
import Observation
import PhishCore

/// UserDefaults-backed user settings, observable by SwiftUI.
@MainActor
@Observable
final class SettingsStore {
    enum Keys {
        static let alertMinimumLevel = "settings.alertMinimumLevel"
        static let classifierChoice = "settings.classifierChoice"
        static let selectedMLXModelID = "settings.selectedMLXModelID"
        static let lookbackHours = "settings.lookbackHours"
        static let hasCompletedOnboarding = "settings.hasCompletedOnboarding"
        static let allowPermissiveGuardrails = "settings.allowPermissiveGuardrails"
        static let demoModeEnabled = "settings.demoModeEnabled"
        static let demoAlertDelaySeconds = "settings.demoAlertDelaySeconds"
        static let demoSimulatedArrivalCount = "settings.demoSimulatedArrivalCount"
        static let callGuardEnabled = "settings.callGuardEnabled"
        static let callAlertMinimumLevel = "settings.callAlertMinimumLevel"
        static let callSpokenWarningEnabled = "settings.callSpokenWarningEnabled"
        static let protectedPhoneNumber = "settings.protectedPhoneNumber"
    }

    static let defaultLookbackHours = 24
    static let lookbackRange = 1...168

    @ObservationIgnored private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// Minimum `RiskLevel` that triggers a notification (default `.medium`).
    var alertMinimumLevel: RiskLevel {
        get {
            access(keyPath: \.alertMinimumLevel)
            return defaults.string(forKey: Keys.alertMinimumLevel).flatMap(RiskLevel.init(rawValue:)) ?? .medium
        }
        set {
            withMutation(keyPath: \.alertMinimumLevel) {
                defaults.set(newValue.rawValue, forKey: Keys.alertMinimumLevel)
            }
        }
    }

    /// Which classifier runs after the heuristics. The downloaded local model is the stored default: onboarding
    /// fetches `ModelManager.defaultModelID` before the first account is linked, and it is the only classifier
    /// available on every supported iPhone. On a device where Apple Intelligence works, the first launch
    /// upgrades that to `.both` through `applyDefaultClassifierChoice(appleIntelligenceAvailable:)` — which
    /// cannot be decided here, because availability is only known asynchronously. Apple Intelligence stays
    /// selectable in Settings → Detection model, and heuristics-only remains the automatic fallback whenever
    /// the chosen model cannot answer.
    var classifierChoice: ClassifierChoice {
        get {
            access(keyPath: \.classifierChoice)
            return defaults.string(forKey: Keys.classifierChoice).flatMap(ClassifierChoice.init(rawValue:)) ?? .mlx
        }
        set {
            withMutation(keyPath: \.classifierChoice) {
                defaults.set(newValue.rawValue, forKey: Keys.classifierChoice)
            }
        }
    }

    /// True once a classifier has been stored — by onboarding, by Settings, or by the first-launch default
    /// below — so that default is applied exactly once and can never override the user's own pick.
    var hasStoredClassifierChoice: Bool {
        access(keyPath: \.classifierChoice)
        return defaults.object(forKey: Keys.classifierChoice) != nil
    }

    /// What a fresh install should start with, once this device's Apple Intelligence availability is known:
    /// both models where Apple Intelligence works (two independent detectors catch more than one, at the cost
    /// of a little time per email), the downloaded local model everywhere else.
    static func defaultClassifierChoice(appleIntelligenceAvailable: Bool) -> ClassifierChoice {
        appleIntelligenceAvailable ? .both : .mlx
    }

    /// Stores `defaultClassifierChoice` unless a choice is already stored. Returns the choice in force after.
    @discardableResult
    func applyDefaultClassifierChoice(appleIntelligenceAvailable: Bool) -> ClassifierChoice {
        guard !hasStoredClassifierChoice else { return classifierChoice }
        let choice = Self.defaultClassifierChoice(appleIntelligenceAvailable: appleIntelligenceAvailable)
        classifierChoice = choice
        return choice
    }

    /// The catalog entry `ClassifierChoice.mlx` classifies with, defaulting to `ModelManager.defaultModelID`
    /// (Qwen3 1.7B). Setting `nil` clears the stored pick and returns to that default, so this never reports
    /// "no model chosen" — `ClassifierRegistry.effectiveMLXModelID` is what answers "is one downloaded".
    var selectedMLXModelID: String? {
        get {
            access(keyPath: \.selectedMLXModelID)
            return defaults.string(forKey: Keys.selectedMLXModelID) ?? ModelManager.defaultModelID
        }
        set {
            withMutation(keyPath: \.selectedMLXModelID) {
                defaults.set(newValue, forKey: Keys.selectedMLXModelID)
            }
        }
    }

    /// How far back to look when an account has no valid cursor (1...168 h, default 24).
    var lookbackHours: Int {
        get {
            access(keyPath: \.lookbackHours)
            let stored = defaults.integer(forKey: Keys.lookbackHours)
            return Self.lookbackRange.contains(stored) ? stored : Self.defaultLookbackHours
        }
        set {
            withMutation(keyPath: \.lookbackHours) {
                defaults.set(min(max(newValue, Self.lookbackRange.lowerBound), Self.lookbackRange.upperBound), forKey: Keys.lookbackHours)
            }
        }
    }

    var hasCompletedOnboarding: Bool {
        get {
            access(keyPath: \.hasCompletedOnboarding)
            return defaults.bool(forKey: Keys.hasCompletedOnboarding)
        }
        set {
            withMutation(keyPath: \.hasCompletedOnboarding) {
                defaults.set(newValue, forKey: Keys.hasCompletedOnboarding)
            }
        }
    }

    /// Apple Foundation Models: when guided generation trips the default guardrails, retry once with a plain-text
    /// response from `SystemLanguageModel(guardrails: .permissiveContentTransformations)` (default true).
    /// Added by the classification owner; read by `ClassifierRegistry` when it creates `AppleFoundationClassifier`.
    var allowPermissiveGuardrails: Bool {
        get {
            access(keyPath: \.allowPermissiveGuardrails)
            guard defaults.object(forKey: Keys.allowPermissiveGuardrails) != nil else { return true }
            return defaults.bool(forKey: Keys.allowPermissiveGuardrails)
        }
        set {
            withMutation(keyPath: \.allowPermissiveGuardrails) {
                defaults.set(newValue, forKey: Keys.allowPermissiveGuardrails)
            }
        }
    }

    // MARK: - Demo (debug builds only)

    /// Settings → Demo: sample flagged emails seeded next to the user's real mail so the app can be demonstrated
    /// on a real phone. Only the `#if DEBUG` Demo section reads or writes it, and only `DemoMode` acts on it —
    /// every row it creates is marked `isDemo` and nothing else is ever touched. Defaults to off.
    var isDemoModeEnabled: Bool {
        get {
            access(keyPath: \.isDemoModeEnabled)
            return defaults.bool(forKey: Keys.demoModeEnabled)
        }
        set {
            withMutation(keyPath: \.isDemoModeEnabled) {
                defaults.set(newValue, forKey: Keys.demoModeEnabled)
            }
        }
    }

    /// Seconds between pressing "Simulate an incoming flagged email" and the alert arriving (0 = immediately).
    var demoAlertDelaySeconds: Int {
        get {
            access(keyPath: \.demoAlertDelaySeconds)
            guard defaults.object(forKey: Keys.demoAlertDelaySeconds) != nil else { return 6 }
            return defaults.integer(forKey: Keys.demoAlertDelaySeconds)
        }
        set {
            withMutation(keyPath: \.demoAlertDelaySeconds) {
                defaults.set(max(0, newValue), forKey: Keys.demoAlertDelaySeconds)
            }
        }
    }

    /// How many times "Simulate an incoming flagged email" has been pressed since demo mode was last switched.
    /// `DemoArrivalPool` cycles on it, so repeated presses show different emails once the list already holds
    /// every bundled fixture.
    var demoSimulatedArrivalCount: Int {
        get {
            access(keyPath: \.demoSimulatedArrivalCount)
            return defaults.integer(forKey: Keys.demoSimulatedArrivalCount)
        }
        set {
            withMutation(keyPath: \.demoSimulatedArrivalCount) {
                defaults.set(max(0, newValue), forKey: Keys.demoSimulatedArrivalCount)
            }
        }
    }

    // MARK: - Call Guard (docs/CALLS.md §8)

    /// True once the user registered a line with the relay (Calls › Set up call protection); cleared when they
    /// remove it. The relay's answer (`CallGuardCoordinator.line`) is what the Calls tab shows — this is the
    /// user's intent, kept so a relay that forgot the line can say "set up again" rather than "never set up".
    var isCallGuardEnabled: Bool {
        get {
            access(keyPath: \.isCallGuardEnabled)
            return defaults.bool(forKey: Keys.callGuardEnabled)
        }
        set {
            withMutation(keyPath: \.isCallGuardEnabled) {
                defaults.set(newValue, forKey: Keys.callGuardEnabled)
            }
        }
    }

    /// Minimum `RiskLevel` at which a call is alerted and kept (default `.medium`). Never `.safe`: the relay's
    /// `minimumLevel` is an `AlertLevel`, so a `.safe` is stored and read back as `.low`.
    var callAlertMinimumLevel: RiskLevel {
        get {
            access(keyPath: \.callAlertMinimumLevel)
            let stored = defaults.string(forKey: Keys.callAlertMinimumLevel).flatMap(RiskLevel.init(rawValue:)) ?? .medium
            return max(stored, .low)
        }
        set {
            withMutation(keyPath: \.callAlertMinimumLevel) {
                defaults.set(max(newValue, .low).rawValue, forKey: Keys.callAlertMinimumLevel)
            }
        }
    }

    /// Whether the relay speaks the warning into the call (only the protected person hears it). Default true.
    var callSpokenWarningEnabled: Bool {
        get {
            access(keyPath: \.callSpokenWarningEnabled)
            guard defaults.object(forKey: Keys.callSpokenWarningEnabled) != nil else { return true }
            return defaults.bool(forKey: Keys.callSpokenWarningEnabled)
        }
        set {
            withMutation(keyPath: \.callSpokenWarningEnabled) {
                defaults.set(newValue, forKey: Keys.callSpokenWarningEnabled)
            }
        }
    }

    /// The protected person's own number, E.164, as last registered. Kept after "Remove protection" so setting
    /// it up again does not start from an empty field.
    var protectedPhoneNumber: String? {
        get {
            access(keyPath: \.protectedPhoneNumber)
            return defaults.string(forKey: Keys.protectedPhoneNumber)
        }
        set {
            withMutation(keyPath: \.protectedPhoneNumber) {
                if let newValue, !newValue.isEmpty {
                    defaults.set(newValue, forKey: Keys.protectedPhoneNumber)
                } else {
                    defaults.removeObject(forKey: Keys.protectedPhoneNumber)
                }
            }
        }
    }

    // MARK: - Derived

    var alertPolicy: AlertPolicy { AlertPolicy(minimumLevel: alertMinimumLevel) }
    var lookback: TimeInterval { TimeInterval(lookbackHours) * 3600 }
}

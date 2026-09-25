import Foundation
import Observation
import PhishCore

/// Which classifier the user selected in Settings. Declaration order is the order the Detection model screen
/// lists them in, so the most accurate option comes first.
enum ClassifierChoice: String, Codable, CaseIterable, Sendable {
    /// The downloaded model *and* Apple Intelligence, both asked for every email while PhishGuard is open
    /// (`EnsembleClassifier`). The downloaded model decides; Apple Intelligence corroborates — its higher score
    /// counts only where the first model or the rules already found something, and it can never lower anything.
    case both
    case appleFoundation
    case mlx
    case heuristicsOnly

    var displayName: String {
        switch self {
        case .both: return "Both models (most accurate)"
        case .appleFoundation: return "Apple Intelligence (built in)"
        case .mlx: return "Downloaded local model (MLX)"
        case .heuristicsOnly: return "Heuristics only"
        }
    }

    /// Whether this choice needs a downloaded MLX model to be complete (onboarding's download gate and the
    /// Home "model not downloaded" banner hang off this).
    var usesDownloadedModel: Bool {
        self == .mlx || self == .both
    }
}

/// Errors thrown by app-layer classifiers. The coordinator treats every error as "model unavailable for this message"
/// and falls back to a heuristics-only verdict.
enum ClassifierError: Error, LocalizedError, Sendable {
    /// Thrown by `HeuristicsOnlyClassifier.assess`: there is no model, use `assessment: nil`.
    case noModel
    case notImplemented(String)
    case unavailable(String)
    /// The model refused the content (Foundation Models guardrails).
    case guardrailViolation
    case invalidOutput(String)
    /// The model runs on the GPU and PhishGuard is not frontmost, so iOS would refuse the Metal work (see
    /// `ForegroundGate`). Expected on every background scan with a local model selected — the coordinator falls
    /// back to the rules for that message and does *not* count it as a classifier failure.
    case requiresForeground(String)

    var errorDescription: String? {
        switch self {
        case .noModel: return "No model is configured; heuristics only."
        case .notImplemented(let what): return "Not implemented: \(what)"
        case .unavailable(let reason): return "Classifier unavailable: \(reason)"
        case .guardrailViolation: return "The model declined to analyze this message."
        case .invalidOutput(let detail): return "The model returned an unusable answer: \(detail)"
        case .requiresForeground(let reason): return reason
        }
    }
}

/// Picks the active `EmailClassifier` from the user's settings and owns the long-lived MLX classifier actors
/// (one per model id) so a loaded model can be reused across a batch and released on demand.
@MainActor
@Observable
final class ClassifierRegistry {
    private let settings: SettingsStore
    private let modelManager: ModelManager
    /// Handed to every `MLXClassifier`: no GPU work unless PhishGuard is frontmost.
    private let foregroundGate: any ForegroundGate
    @ObservationIgnored private var mlxClassifiers: [String: MLXClassifier] = [:]

    init(settings: SettingsStore, modelManager: ModelManager, foregroundGate: any ForegroundGate = AppForegroundGate.shared) {
        self.settings = settings
        self.modelManager = modelManager
        self.foregroundGate = foregroundGate
    }

    var choice: ClassifierChoice {
        get { settings.classifierChoice }
        set { settings.classifierChoice = newValue }
    }

    var selectedMLXModelID: String? {
        get { settings.selectedMLXModelID }
        set { settings.selectedMLXModelID = newValue }
    }

    /// The one source of truth for which downloaded model `.mlx` classifies with: the user's selection when that
    /// model is on disk, otherwise this device's recommended entry when that one is on disk, otherwise `nil` —
    /// nothing usable is downloaded. The Model screen shows exactly this as the selected/ready model, so its
    /// checkmark can never name a model the scans do not use.
    var effectiveMLXModelID: String? {
        if let selected = selectedMLXModelID, ModelManager.entry(for: selected) != nil, isDownloaded(selected) {
            return selected
        }
        let recommended = ModelManager.recommendedModelID()
        return isDownloaded(recommended) ? recommended : nil
    }

    /// The model `.mlx` would use once it is on disk: the user's catalog selection, else this device's
    /// recommendation. Only used to name the missing model while `effectiveMLXModelID` is nil.
    var preferredMLXModelID: String {
        if let selected = selectedMLXModelID, ModelManager.entry(for: selected) != nil { return selected }
        return ModelManager.recommendedModelID()
    }

    /// Reads the observable download state rather than the file system, so SwiftUI re-renders when a download
    /// finishes and the effective selection is not a disk hit per row.
    private func isDownloaded(_ modelID: String) -> Bool {
        modelManager.downloadStates[modelID] == .downloaded
    }

    /// The classifier for the current choice. The coordinator handles unavailability/errors by falling back to
    /// heuristics-only verdicts, so this never substitutes a different classifier.
    func activeClassifier() -> any EmailClassifier {
        classifier(for: choice)
    }

    /// One instance per choice, for the Model settings screen to display availability.
    func classifier(for choice: ClassifierChoice) -> any EmailClassifier {
        switch choice {
        case .both:
            // The downloaded model is the **primary** and Apple Intelligence **corroborates** it, never the
            // other way round — `Tools/PromptLab` measured Apple's model flagging 10 of 19 benign messages at
            // 75-90 while MLX flagged none, so a maximum of the two would have inherited Apple's false
            // positives (see `EnsembleClassifier`). The roles are fixed here rather than derived from who can
            // run, so a background scan — where MLX is gated off entirely — leaves Apple corroborating rather
            // than deciding alone.
            //
            // Both members are handed over whatever their state: `EnsembleClassifier` asks each one for its
            // availability per message, so Apple Intelligence keeps answering in the background while the
            // downloaded model waits for the foreground, and a missing download silences only that member.
            return EnsembleClassifier(
                primary: mlxClassifier(for: effectiveMLXModelID ?? preferredMLXModelID),
                corroborators: [AppleFoundationClassifier(allowPermissiveGuardrails: settings.allowPermissiveGuardrails)],
                foregroundGate: foregroundGate
            )
        case .appleFoundation:
            return AppleFoundationClassifier(allowPermissiveGuardrails: settings.allowPermissiveGuardrails)
        case .mlx:
            // With nothing downloaded, the classifier for the preferred model reports exactly which model is
            // missing; `assess` then throws and the coordinator falls back to heuristics.
            return mlxClassifier(for: effectiveMLXModelID ?? preferredMLXModelID)
        case .heuristicsOnly:
            return HeuristicsOnlyClassifier()
        }
    }

    /// Availability of every choice, for the UI.
    func availabilitySummary() async -> [ClassifierChoice: ClassifierAvailability] {
        var result: [ClassifierChoice: ClassifierAvailability] = [:]
        for choice in ClassifierChoice.allCases {
            result[choice] = await classifier(for: choice).availability()
        }
        return result
    }

    /// Unloads any resident MLX model (call before the app suspends, on memory warnings, or when a background
    /// scan hands control back to the system). Apple's model is managed by the OS and needs nothing here.
    ///
    /// On the way out of the foreground the *cancellation* comes first: `AppEnvironment.didEnterBackground()`
    /// closes the foreground gate (which synchronously cancels any generation on the GPU) and only then calls
    /// this, so the unload never races a token loop that is still submitting command buffers.
    func releaseResources() async {
        for classifier in mlxClassifiers.values {
            await classifier.releaseResources()
        }
    }

    /// Whether a loaded MLX model stays resident between classifications. Residency is the default (a scan pays one
    /// weight load, not one per message) and `releaseResources()` drops the weights at the end of every scan; pass
    /// `false` to unload now and go back to unloading after every single classification.
    func setKeepMLXModelLoaded(_ keep: Bool) async {
        for classifier in mlxClassifiers.values {
            await classifier.setKeepLoaded(keep)
        }
    }

    private func mlxClassifier(for modelID: String) -> MLXClassifier {
        if let existing = mlxClassifiers[modelID] { return existing }
        let classifier = MLXClassifier(modelID: modelID, modelManager: modelManager, foregroundGate: foregroundGate)
        mlxClassifiers[modelID] = classifier
        return classifier
    }
}

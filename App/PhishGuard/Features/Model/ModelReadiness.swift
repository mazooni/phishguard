import Foundation
import PhishCore

/// The "does this iPhone have a working detection model yet?" rules, as plain functions.
///
/// A downloaded MLX model is the default classifier (`SettingsStore.classifierChoice`), so two screens have to
/// agree about it: the onboarding page that gates setup on the one-time download, and the Home banner that
/// catches users who finished onboarding before that page existed — or skipped it. Keeping the rules here makes
/// both testable without SwiftUI and stops them drifting apart.
enum ModelReadiness {
    /// Whether this build can run a downloaded MLX model at all. `MLXClassifier` reports `.unavailable` on the
    /// Simulator (Metal cannot allocate there), so gating a simulator demo on a multi-GB download would block
    /// setup on something that could never be used.
    static var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    /// Whether onboarding's "Download the detection model" page lets the user continue.
    ///
    /// `.mlx` and `.both` are the choices that need the download (`ClassifierChoice.usesDownloadedModel`);
    /// picking Apple Intelligence (or heuristics) on that page moves setup along without one.
    static func canLeaveDownloadPage(
        choice: ClassifierChoice,
        isModelDownloaded: Bool,
        isSimulator: Bool = ModelReadiness.isSimulator
    ) -> Bool {
        if isSimulator { return true }
        if !choice.usesDownloadedModel { return true }
        return isModelDownloaded
    }

    /// Whether the page offers "Use Apple Intelligence instead". Only when this device actually reports the
    /// system model as available — an unusable second option would be worse than none.
    static func offersAppleFoundation(_ availability: ClassifierAvailability?) -> Bool {
        availability?.isAvailable == true
    }

    /// Whether Home shows "Detection model not downloaded". The model the user chose is not there, so scans
    /// run without it — heuristics-only for `.mlx`, Apple Intelligence alone for `.both`. Never on the
    /// Simulator, where downloading the model would not make it usable either.
    static func showsMissingModelBanner(
        choice: ClassifierChoice,
        isModelDownloaded: Bool,
        isSimulator: Bool = ModelReadiness.isSimulator
    ) -> Bool {
        guard !isSimulator else { return false }
        return choice.usesDownloadedModel && !isModelDownloaded
    }
}

import Foundation
import PhishCore
import XCTest
@testable import PhishGuard

/// The rules behind onboarding's required model download and the Home "model missing" banner
/// (`ModelReadiness`), plus the registry defaults they depend on.
final class OnboardingModelTests: XCTestCase {

    // MARK: - Onboarding download gate

    /// The page exists to stop setup until the default classifier can actually run, so `.mlx` without the model
    /// on disk is the one combination that must not let go.
    func testDownloadPageOnlyReleasesWhenTheModelCanRun() {
        XCTAssertFalse(ModelReadiness.canLeaveDownloadPage(choice: .mlx, isModelDownloaded: false, isSimulator: false))
        XCTAssertTrue(ModelReadiness.canLeaveDownloadPage(choice: .mlx, isModelDownloaded: true, isSimulator: false))
    }

    /// Choosing Apple Intelligence on the page is the documented way past the download; heuristics-only would be
    /// too, if it were ever selected before onboarding finished.
    func testOtherClassifierChoicesNeedNoDownload() {
        for choice in [ClassifierChoice.appleFoundation, .heuristicsOnly] {
            XCTAssertTrue(ModelReadiness.canLeaveDownloadPage(choice: choice, isModelDownloaded: false, isSimulator: false), "\(choice)")
        }
    }

    /// MLX cannot run on the Simulator at all, so blocking there would strand every simulator demo on page three.
    func testSimulatorNeverBlocksSetup() {
        XCTAssertTrue(ModelReadiness.canLeaveDownloadPage(choice: .mlx, isModelDownloaded: false, isSimulator: true))
        #if targetEnvironment(simulator)
        XCTAssertTrue(ModelReadiness.isSimulator)
        XCTAssertTrue(ModelReadiness.canLeaveDownloadPage(choice: .mlx, isModelDownloaded: false))
        #else
        XCTAssertFalse(ModelReadiness.isSimulator)
        XCTAssertFalse(ModelReadiness.canLeaveDownloadPage(choice: .mlx, isModelDownloaded: false))
        #endif
    }

    /// An "instead" button that leads to an unavailable classifier is worse than no button.
    func testAppleIntelligenceIsOfferedOnlyWhenAvailable() {
        XCTAssertTrue(ModelReadiness.offersAppleFoundation(.available))
        XCTAssertFalse(ModelReadiness.offersAppleFoundation(.unavailable(reason: "Apple Intelligence is off.")))
        XCTAssertFalse(ModelReadiness.offersAppleFoundation(nil), "still checking: do not flash the option")
    }

    // MARK: - Home banner

    /// The banner is for people who got past the download page without a model — onboarding skipped, or an
    /// install from before the page existed — and only when the missing model is the one scans would use.
    func testHomeBannerAppearsOnlyForMLXWithoutAModel() {
        XCTAssertTrue(ModelReadiness.showsMissingModelBanner(choice: .mlx, isModelDownloaded: false, isSimulator: false))
        XCTAssertFalse(ModelReadiness.showsMissingModelBanner(choice: .mlx, isModelDownloaded: true, isSimulator: false))
        XCTAssertFalse(ModelReadiness.showsMissingModelBanner(choice: .appleFoundation, isModelDownloaded: false, isSimulator: false))
        XCTAssertFalse(ModelReadiness.showsMissingModelBanner(choice: .heuristicsOnly, isModelDownloaded: false, isSimulator: false))
        XCTAssertFalse(ModelReadiness.showsMissingModelBanner(choice: .mlx, isModelDownloaded: false, isSimulator: true),
                       "downloading would not make the model usable on the Simulator")
    }

    // MARK: - Defaults the pages rely on

    /// A fresh install must land on `.mlx` + the default model, otherwise the download page would gate on a
    /// model nothing intends to use.
    @MainActor
    func testFreshInstallPrefersTheDefaultLocalModel() throws {
        let suite = "OnboardingModelTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = SettingsStore(defaults: defaults)
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "OnboardingModelTests-\(UUID().uuidString)", directoryHint: .isDirectory)
        let manager = ModelManager(modelsDirectory: directory)
        defer { try? FileManager.default.removeItem(at: directory) }
        let registry = ClassifierRegistry(settings: settings, modelManager: manager)

        XCTAssertEqual(settings.classifierChoice, .mlx)
        XCTAssertEqual(registry.choice, .mlx)
        XCTAssertEqual(registry.preferredMLXModelID, "qwen3-4b-instruct-2507-4bit")
        XCTAssertEqual(registry.preferredMLXModelID, ModelManager.defaultModelID)
        XCTAssertNil(registry.effectiveMLXModelID, "nothing is downloaded yet, so no model is ready")
        XCTAssertFalse(ModelReadiness.canLeaveDownloadPage(
            choice: registry.choice, isModelDownloaded: registry.effectiveMLXModelID != nil, isSimulator: false
        ))

        // Picking Apple Intelligence on the page is what lets setup continue without the download.
        registry.choice = .appleFoundation
        XCTAssertEqual(settings.classifierChoice, .appleFoundation)
        XCTAssertTrue(ModelReadiness.canLeaveDownloadPage(
            choice: registry.choice, isModelDownloaded: registry.effectiveMLXModelID != nil, isSimulator: false
        ))
    }

    /// The Model screen marks the default entry "Recommended" and, until it is downloaded, shows it as the model
    /// that will be used rather than as an unselected row.
    @MainActor
    func testModelRowLabelsTheChosenButMissingModel() throws {
        let entry = try XCTUnwrap(ModelManager.entry(for: ModelManager.defaultModelID))
        XCTAssertEqual(ModelRow.pendingAccessibilityLabel(for: entry), "\(entry.displayName) chosen, not downloaded")
        XCTAssertEqual(ModelManager.recommendedModelID(), entry.id)
    }
}

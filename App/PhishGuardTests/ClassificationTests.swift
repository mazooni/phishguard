import Foundation
import PhishCore
import XCTest
@testable import PhishGuard
#if canImport(FoundationModels)
import FoundationModels
#endif

/// Prompt fitting, classifier availability on the simulator, registry plumbing and the Foundation Models mapping.
final class ClassificationTests: XCTestCase {
    // MARK: - Prompt fitting

    func testEstimatedTokensFollowsCharactersPerToken() {
        XCTAssertEqual(PromptFitting.estimatedTokens(for: ""), 0)
        XCTAssertEqual(PromptFitting.estimatedTokens(for: String(repeating: "a", count: 350)), 100)
        XCTAssertEqual(PromptFitting.estimatedTokens(for: "ab"), 1, "rounds up")
        XCTAssertEqual(PromptFitting.estimatedTokens(for: "日本語のメール"), 7, "CJK: one token per character")
        XCTAssertEqual(PromptFitting.estimatedTokens(for: "안녕하세요"), 5)
        XCTAssertEqual(PromptFitting.estimatedTokens(for: "Hi 你好"), 1 + 2)
    }

    func testFittedBodyCharactersLeavesHeadroom() {
        let input = makeInput(bodyLength: 6_000)
        let contextSize = 4_096
        let fitted = PromptFitting.fittedBodyCharacters(for: input, contextSize: contextSize)
        XCTAssertLessThanOrEqual(fitted, PromptFitting.defaultBodyCharacters)
        XCTAssertGreaterThanOrEqual(fitted, PromptFitting.minimumBodyCharacters)
        XCTAssertLessThanOrEqual(
            PromptFitting.estimatedPromptTokens(for: input, maxBodyCharacters: fitted),
            contextSize - PromptFitting.defaultHeadroomTokens
        )
        // Everything but the body (instructions + prompt scaffolding) is a fixed cost; a window with room for only
        // ~300 body tokens above it must shrink the body below the default while still honouring the headroom.
        let overhead = PromptFitting.estimatedPromptTokens(for: input, maxBodyCharacters: 0)
        let tight = overhead + PromptFitting.defaultHeadroomTokens + 300
        let small = PromptFitting.fittedBodyCharacters(for: input, contextSize: tight)
        XCTAssertLessThan(small, PromptFitting.defaultBodyCharacters)
        XCTAssertGreaterThan(small, PromptFitting.minimumBodyCharacters)
        XCTAssertLessThanOrEqual(
            PromptFitting.estimatedPromptTokens(for: input, maxBodyCharacters: small),
            tight - PromptFitting.defaultHeadroomTokens
        )
        // With no room for any body at all the documented floor wins: the body is never cut below the minimum,
        // even though the prompt then overshoots the budget (the classifier halves once more and then gives up).
        let floor = PromptFitting.fittedBodyCharacters(for: input, contextSize: overhead + PromptFitting.defaultHeadroomTokens)
        XCTAssertEqual(floor, PromptFitting.minimumBodyCharacters)
    }

    func testFittedBodyCharactersUsesDefaultWhenItFitsAndNeverGoesBelowMinimum() {
        let short = makeInput(bodyLength: 100)
        XCTAssertEqual(PromptFitting.fittedBodyCharacters(for: short, contextSize: 4_096), PromptFitting.defaultBodyCharacters)
        XCTAssertEqual(PromptFitting.fittedBodyCharacters(for: short, contextSize: 100), PromptFitting.minimumBodyCharacters)
        let long = makeInput(bodyLength: 20_000)
        XCTAssertEqual(PromptFitting.fittedBodyCharacters(for: long, contextSize: 50), PromptFitting.minimumBodyCharacters)
        XCTAssertGreaterThanOrEqual(
            PromptFitting.fittedBodyCharacters(for: long, contextSize: 8_192),
            PromptFitting.fittedBodyCharacters(for: long, contextSize: 4_096),
            "a bigger window never yields a smaller body"
        )
    }

    // MARK: - MLX on the simulator

    @MainActor
    func testMLXClassifierIsUnavailableOnSimulatorAndKeepsIdentifiers() async throws {
        #if targetEnvironment(simulator)
        let manager = ModelManager(modelsDirectory: temporaryDirectory())
        defer { try? FileManager.default.removeItem(at: manager.modelsDirectory) }
        // The gate is injected open so this asserts the *simulator* reason rather than the foreground one.
        let classifier = MLXClassifier(modelID: ModelManager.defaultModelID, modelManager: manager, foregroundGate: AppForegroundGate(isForeground: true))
        XCTAssertEqual(classifier.identifier, "mlx:mlx-community/Qwen3-4B-Instruct-2507-4bit")
        let entry = try XCTUnwrap(ModelManager.entry(for: ModelManager.defaultModelID))
        XCTAssertEqual(classifier.displayName, "Local model (\(entry.displayName))")

        let availability = await classifier.availability()
        guard case .unavailable(let reason) = availability else { return XCTFail("expected unavailable, got \(availability)") }
        XCTAssertTrue(reason.localizedCaseInsensitiveContains("simulator"), reason)

        do {
            _ = try await classifier.assess(makeInput(bodyLength: 50))
            XCTFail("expected an error")
        } catch let error as ClassifierError {
            guard case .unavailable = error else { return XCTFail("unexpected \(error)") }
        }
        await classifier.setKeepLoaded(true)
        await classifier.releaseResources()

        let unknown = MLXClassifier(modelID: "bogus", modelManager: manager, foregroundGate: AppForegroundGate(isForeground: true))
        XCTAssertEqual(unknown.identifier, "mlx:bogus")
        XCTAssertNil(unknown.entry)
        #else
        throw XCTSkip("simulator-only test")
        #endif
    }

    /// The field crash (2026-09): MLX submits Metal command buffers for every generated token and iOS terminates
    /// the process — with an uncaught C++ exception, so nothing can catch it — when the app is not frontmost. The
    /// classifier must therefore refuse before it loads a single weight. Runs on every platform: the foreground
    /// check comes before the simulator branch.
    @MainActor
    func testMLXClassifierRefusesToRunWhileTheAppIsNotForeground() async throws {
        let manager = ModelManager(modelsDirectory: temporaryDirectory())
        defer { try? FileManager.default.removeItem(at: manager.modelsDirectory) }
        let classifier = MLXClassifier(
            modelID: ModelManager.defaultModelID,
            modelManager: manager,
            foregroundGate: AppForegroundGate(isForeground: false)
        )

        let availability = await classifier.availability()
        guard case .unavailable(let reason) = availability else { return XCTFail("expected unavailable, got \(availability)") }
        XCTAssertEqual(reason, MLXClassifier.foregroundOnlyReason)
        XCTAssertTrue(reason.contains("only runs while PhishGuard is open"), reason)
        XCTAssertTrue(reason.contains("background checks use the built-in rules"), reason)
        XCTAssertFalse(reason.localizedCaseInsensitiveContains("metal"), "the user-facing reason stays non-technical")
        XCTAssertFalse(reason.localizedCaseInsensitiveContains("gpu"), "the user-facing reason stays non-technical")

        do {
            _ = try await classifier.assess(makeInput(bodyLength: 50))
            XCTFail("expected a refusal")
        } catch let error as ClassifierError {
            guard case .requiresForeground(let message) = error else { return XCTFail("unexpected \(error)") }
            XCTAssertEqual(message, MLXClassifier.foregroundOnlyReason)
            XCTAssertEqual(error.errorDescription, MLXClassifier.foregroundOnlyReason)
        }

        // Opening the gate hands the question back to the usual availability checks (here: the simulator, or a
        // model that was never downloaded on a device) — never to `.available` by accident.
        let open = MLXClassifier(
            modelID: ModelManager.defaultModelID,
            modelManager: manager,
            foregroundGate: AppForegroundGate(isForeground: true)
        )
        guard case .unavailable(let openReason) = await open.availability() else {
            return XCTFail("nothing is downloaded, so the model cannot be available")
        }
        XCTAssertNotEqual(openReason, MLXClassifier.foregroundOnlyReason)
    }

    /// #12/#14/#15: nothing in the app enables residency, so the weights must stay loaded by default — otherwise
    /// every message of a scan re-reads 1-2.6 GB of safetensors. `ScanCoordinator` releases them at scan end.
    @MainActor
    func testModelStaysResidentBetweenClassificationsByDefault() async throws {
        let manager = ModelManager(modelsDirectory: temporaryDirectory())
        defer { try? FileManager.default.removeItem(at: manager.modelsDirectory) }
        let classifier = MLXClassifier(modelID: ModelManager.recommendedModelID(), modelManager: manager)

        var resident = await classifier.keepsModelLoaded
        XCTAssertTrue(resident, "a scan must pay one weight load, not one per message")

        // The explicit API still works in both directions, and `false` also unloads.
        await classifier.setKeepLoaded(false)
        resident = await classifier.keepsModelLoaded
        XCTAssertFalse(resident)
        await classifier.setKeepLoaded(true)
        resident = await classifier.keepsModelLoaded
        XCTAssertTrue(resident)

        // Releasing resources drops the weights without turning residency off, so the next scan loads once again.
        await classifier.releaseResources()
        resident = await classifier.keepsModelLoaded
        XCTAssertTrue(resident)
    }

    /// #1: mlx-swift-lm returns partial text instead of throwing when a scan is cancelled mid-generation, and
    /// `ModelOutputParser` would repair it into a real verdict, so a cut-off answer must never reach the parser.
    func testCutOffAnswersAreRejectedBeforeTheParserCanRepairThem() {
        // The shapes the parser's own tests pin as "repaired": a number cut in half and an unterminated string.
        let halfScore = "{\"isSuspicious\": true, \"category\": \"phishing\", \"riskScore\": 9"
        let halfString = "{\"isSuspicious\": true, \"category\": \"sc"
        XCTAssertFalse(MLXClassifier.hasClosedJSONObject(halfScore))
        XCTAssertFalse(MLXClassifier.hasClosedJSONObject(halfString))
        XCTAssertFalse(MLXClassifier.hasClosedJSONObject("{\"reasons\": [\"fake login page\""))

        XCTAssertTrue(MLXClassifier.hasClosedJSONObject("{\"isSuspicious\": false, \"riskScore\": 5}"))
        XCTAssertTrue(MLXClassifier.hasClosedJSONObject("```json\n{\"a\": [1, 2], \"b\": {\"c\": 3}}\n```"))
        XCTAssertTrue(MLXClassifier.hasClosedJSONObject("Sure! {\"summary\": \"uses a {curly} brace\"} done"))
        XCTAssertTrue(MLXClassifier.hasClosedJSONObject("{\"summary\": \"escaped quote \\\" and brace }\"}"))
        XCTAssertTrue(MLXClassifier.hasClosedJSONObject("{} and a truncated second {\"x\": 1"), "the first object closed")
        // No object at all is left to the parser, which reports noJSONObjectFound.
        XCTAssertTrue(MLXClassifier.hasClosedJSONObject("I could not analyse this email."))
        XCTAssertTrue(MLXClassifier.hasClosedJSONObject(""))
    }

    func testStrippingThinkingBlocks() {
        XCTAssertEqual(MLXClassifier.strippingThinkingBlocks("<think>\nhmm\n</think>\n{\"a\":1}"), "{\"a\":1}")
        XCTAssertEqual(MLXClassifier.strippingThinkingBlocks("{\"a\":1}"), "{\"a\":1}")
        XCTAssertEqual(MLXClassifier.strippingThinkingBlocks("<THINK>x</THINK><think>y</think> {}"), "{}")
        XCTAssertEqual(MLXClassifier.strippingThinkingBlocks("prefix <think>never closed"), "prefix")
        let parsed = try? ModelOutputParser.parseAssessment(from: MLXClassifier.strippingThinkingBlocks(
            "<think>{\"isSuspicious\": false}</think>\n```json\n{\"isSuspicious\": true, \"category\": \"scam\", \"riskScore\": 88, \"reasons\": [\"gift cards\"], \"summary\": \"Scam.\"}\n```"
        ))
        XCTAssertEqual(parsed?.category, .scam)
        XCTAssertEqual(parsed?.riskScore, 88)
    }

    // MARK: - Registry

    @MainActor
    func testRegistrySummaryReleaseAndInstanceReuse() async throws {
        let suite = "ClassificationTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = SettingsStore(defaults: defaults)
        let manager = ModelManager(modelsDirectory: temporaryDirectory())
        defer { try? FileManager.default.removeItem(at: manager.modelsDirectory) }
        let registry = ClassifierRegistry(settings: settings, modelManager: manager)

        XCTAssertTrue(settings.allowPermissiveGuardrails, "defaults to true")
        settings.allowPermissiveGuardrails = false
        XCTAssertFalse(SettingsStore(defaults: defaults).allowPermissiveGuardrails)
        XCTAssertEqual((registry.classifier(for: .appleFoundation) as? AppleFoundationClassifier)?.allowPermissiveGuardrails, false)

        let summary = await registry.availabilitySummary()
        XCTAssertEqual(Set(summary.keys), Set(ClassifierChoice.allCases))
        XCTAssertEqual(summary[.heuristicsOnly], .available)
        #if targetEnvironment(simulator)
        XCTAssertFalse(summary[.mlx]?.isAvailable ?? true, "MLX must be unavailable on the simulator")
        #endif

        registry.choice = .mlx
        registry.selectedMLXModelID = nil
        XCTAssertNil(registry.effectiveMLXModelID, "nothing is downloaded in this temporary cache")
        XCTAssertEqual(registry.preferredMLXModelID, ModelManager.recommendedModelID())
        registry.selectedMLXModelID = "not-in-catalog"
        XCTAssertEqual(registry.preferredMLXModelID, ModelManager.recommendedModelID(), "unknown selections fall back")
        registry.selectedMLXModelID = "llama-3.2-3b-instruct-4bit"
        XCTAssertEqual(registry.preferredMLXModelID, "llama-3.2-3b-instruct-4bit")

        let first = try XCTUnwrap(registry.activeClassifier() as? MLXClassifier)
        let second = try XCTUnwrap(registry.classifier(for: .mlx) as? MLXClassifier)
        XCTAssertTrue(first === second, "one long-lived actor per model id")
        XCTAssertEqual(first.identifier, "mlx:mlx-community/Llama-3.2-3B-Instruct-4bit")

        await registry.setKeepMLXModelLoaded(true)
        await registry.releaseResources()

        registry.choice = .heuristicsOnly
        XCTAssertEqual(registry.activeClassifier().identifier, HeuristicsOnlyClassifier.classifierIdentifier)
        registry.choice = .appleFoundation
        XCTAssertEqual(registry.activeClassifier().identifier, AppleFoundationClassifier.classifierIdentifier)
    }

    /// #13/#22: one source of truth for the model `.mlx` runs — the selection when it is downloaded, else the
    /// device recommendation when it is downloaded, else nothing. The Model screen renders exactly this value.
    @MainActor
    func testEffectiveMLXModelIDOnlyNamesDownloadedModels() throws {
        let suite = "ClassificationTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = SettingsStore(defaults: defaults)
        let manager = ModelManager(modelsDirectory: temporaryDirectory())
        defer { try? FileManager.default.removeItem(at: manager.modelsDirectory) }
        let registry = ClassifierRegistry(settings: settings, modelManager: manager)
        let recommended = ModelManager.recommendedModelID()
        let other = try XCTUnwrap(ModelManager.catalog.first { $0.id != recommended }?.id)

        // Nothing on disk: no model is ready, whatever is selected.
        XCTAssertNil(registry.effectiveMLXModelID)
        registry.selectedMLXModelID = other
        XCTAssertNil(registry.effectiveMLXModelID)

        // A downloaded selection wins.
        try makeFakeSnapshot(manager: manager, id: other)
        manager.refreshStates()
        XCTAssertEqual(registry.effectiveMLXModelID, other)

        // With no selection the recommended model is used only when it is downloaded too.
        registry.selectedMLXModelID = nil
        XCTAssertNil(registry.effectiveMLXModelID, "a downloaded non-recommended model is not silently adopted")
        XCTAssertEqual(registry.preferredMLXModelID, recommended)
        try makeFakeSnapshot(manager: manager, id: recommended)
        manager.refreshStates()
        XCTAssertEqual(registry.effectiveMLXModelID, recommended)

        // A selection that is not a catalog id is ignored, exactly like no selection.
        registry.selectedMLXModelID = "not-in-catalog"
        XCTAssertEqual(registry.effectiveMLXModelID, recommended)

        // The classifier follows the effective id; with nothing downloaded it still names the awaited model.
        registry.selectedMLXModelID = other
        let otherRepo = try XCTUnwrap(ModelManager.entry(for: other)).hfRepo
        XCTAssertEqual(registry.classifier(for: .mlx).identifier, "mlx:\(otherRepo)")
        let emptyManager = ModelManager(modelsDirectory: temporaryDirectory())
        defer { try? FileManager.default.removeItem(at: emptyManager.modelsDirectory) }
        let empty = ClassifierRegistry(settings: settings, modelManager: emptyManager)
        XCTAssertNil(empty.effectiveMLXModelID)
        XCTAssertEqual(empty.classifier(for: .mlx).identifier, "mlx:\(otherRepo)",
                       "the unavailability message must name the model the user is waiting for")
    }

    // MARK: - Apple Foundation Models

    /// #41: halving the body only helps when the rendered prompt actually changes; otherwise the retry is the same
    /// request and is guaranteed to overflow again.
    func testContextOverflowRetryIsSkippedWhenThePromptCannotShrink() {
        let minimum = PromptFitting.minimumBodyCharacters
        // Already at the floor: `max(minimum, minimum / 2) == minimum`, so the prompt would be byte-identical.
        XCTAssertNil(AppleFoundationClassifier.retryBodyCharacters(after: minimum, bodyLength: 10_000))
        // Body shorter than the halved limit: `prefix(limit)` renders the same text either way.
        XCTAssertNil(AppleFoundationClassifier.retryBodyCharacters(after: 2_500, bodyLength: 900))
        XCTAssertNil(AppleFoundationClassifier.retryBodyCharacters(after: 2_500, bodyLength: 1_250))
        // A genuinely shorter body is still retried.
        XCTAssertEqual(AppleFoundationClassifier.retryBodyCharacters(after: 2_500, bodyLength: 10_000), 1_250)
        XCTAssertEqual(AppleFoundationClassifier.retryBodyCharacters(after: 2_500, bodyLength: 1_251), 1_250)
        XCTAssertEqual(AppleFoundationClassifier.retryBodyCharacters(after: 500, bodyLength: 10_000), 250)
        XCTAssertEqual(AppleFoundationClassifier.retryBodyCharacters(after: 300, bodyLength: 10_000), minimum,
                       "clamped to the documented floor, and still shorter than the 300 already rendered")
        XCTAssertNil(AppleFoundationClassifier.retryBodyCharacters(after: 300, bodyLength: minimum),
                     "the whole body already fits under the floor, so the prompt cannot change")

        // The floor is reachable from the fitter, which is what makes the identical retry possible.
        let input = makeInput(bodyLength: 20_000)
        XCTAssertEqual(PromptFitting.fittedBodyCharacters(for: input, contextSize: 50), minimum)
        XCTAssertEqual(
            PromptBuilder.userPrompt(for: input, maxBodyCharacters: minimum),
            PromptBuilder.userPrompt(for: input, maxBodyCharacters: max(minimum, minimum / 2)),
            "the retry the guard now skips would have sent this exact prompt again"
        )
    }

    func testRefusalDetection() {
        XCTAssertTrue(AppleFoundationClassifier.looksLikeRefusal("Sorry, I can't help with that."))
        XCTAssertTrue(AppleFoundationClassifier.looksLikeRefusal("I’m unable to help with this request"))
        XCTAssertTrue(AppleFoundationClassifier.looksLikeRefusal("I cannot assist with analysing this content."))
        XCTAssertFalse(AppleFoundationClassifier.looksLikeRefusal("{\"isSuspicious\": true, \"summary\": \"Sorry, I can't help is a lure\"}"))
        XCTAssertFalse(AppleFoundationClassifier.looksLikeRefusal("Looks legitimate."))
    }

    #if canImport(FoundationModels)
    func testPhishingAssessmentMapsToModelAssessment() {
        let assessment = PhishingAssessment(
            reasons: ["  Lookalike domain paypa1.com  ", "", String(repeating: "x", count: 400), "3", "4", "5", "6", "7"],
            isSuspicious: false,
            category: .scam,
            riskScore: 140,
            summary: "  Asks for gift cards.  "
        ).modelAssessment
        XCTAssertTrue(assessment.isSuspicious, "scam implies suspicious even if the flag disagrees")
        XCTAssertEqual(assessment.category, .scam)
        XCTAssertEqual(assessment.riskScore, 100)
        XCTAssertEqual(assessment.reasons.count, 6)
        XCTAssertEqual(assessment.reasons.first, "Lookalike domain paypa1.com")
        XCTAssertEqual(assessment.reasons[1].count, 160)
        XCTAssertEqual(assessment.summary, "Asks for gift cards.")

        let benign = PhishingAssessment(reasons: [], isSuspicious: false, category: .safe, riskScore: -5, summary: "Newsletter.").modelAssessment
        XCTAssertFalse(benign.isSuspicious)
        XCTAssertEqual(benign.category, .safe)
        XCTAssertEqual(benign.riskScore, 0)
        XCTAssertEqual(benign.reasons, [])

        let phishing = PhishingAssessment(reasons: ["fake login"], isSuspicious: true, category: .phishing, riskScore: 92, summary: "Phish.").modelAssessment
        XCTAssertEqual(phishing, ModelAssessment(isSuspicious: true, category: .phishing, riskScore: 92, reasons: ["fake login"], summary: "Phish."))
        let spam = PhishingAssessment(reasons: [], isSuspicious: true, category: .spam, riskScore: 30, summary: "Ads.").modelAssessment
        XCTAssertTrue(spam.isSuspicious, "the model's own flag is kept for spam")
    }

    func testUnavailableReasonsAreDescribed() {
        XCTAssertEqual(AppleFoundationClassifier.availability(of: .available), .available)
        for reason in [SystemLanguageModel.Availability.UnavailableReason.deviceNotEligible, .appleIntelligenceNotEnabled, .modelNotReady] {
            let availability = AppleFoundationClassifier.availability(of: .unavailable(reason))
            guard case .unavailable(let text) = availability else { return XCTFail("expected unavailable for \(reason)") }
            XCTAssertFalse(text.isEmpty)
            XCTAssertFalse(text.contains("UnavailableReason"), "human-readable, not a type dump: \(text)")
        }
        XCTAssertTrue(AppleFoundationClassifier.describe(.deviceNotEligible).contains("does not support"))
        XCTAssertTrue(AppleFoundationClassifier.describe(.appleIntelligenceNotEnabled).contains("turned off"))
        XCTAssertTrue(AppleFoundationClassifier.describe(.modelNotReady).contains("downloading"))
    }

    func testAppleClassifierAvailabilityIsConsistentWithSystemModel() async {
        let classifier = AppleFoundationClassifier()
        XCTAssertEqual(classifier.identifier, "apple.foundation")
        let expected = AppleFoundationClassifier.availability(of: SystemLanguageModel.default.availability)
        let actual = await classifier.availability()
        XCTAssertEqual(actual, expected)
    }
    #endif

    // MARK: - Helpers

    private func makeInput(bodyLength: Int) -> ClassificationInput {
        let sentence = "Please verify your account now to avoid suspension. "
        var body = ""
        while body.count < bodyLength { body += sentence }
        body = String(body.prefix(bodyLength))
        let report = HeuristicReport(bodyText: body)
        return ClassificationInput(email: SampleEmails.paypalPhish, report: report)
    }

    /// Minimal snapshot that satisfies `ModelManager.looksComplete` (config, both tokenizer files, weights).
    @MainActor
    private func makeFakeSnapshot(manager: ModelManager, id: String) throws {
        let repoDirectory = manager.modelDirectory(for: id)
        let commit = "0123456789abcdef0123456789abcdef01234567"
        let snapshot = repoDirectory.appending(path: "snapshots/\(commit)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: snapshot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: repoDirectory.appending(path: "refs"), withIntermediateDirectories: true)
        try "\(commit)\n".write(to: repoDirectory.appending(path: "refs/main"), atomically: true, encoding: .utf8)
        for name in ModelManager.requiredSnapshotFiles {
            try Data("{}".utf8).write(to: snapshot.appending(path: name))
        }
        try Data(repeating: 0, count: 1024).write(to: snapshot.appending(path: "model.safetensors"))
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appending(path: "ClassificationTests-\(UUID().uuidString)", directoryHint: .isDirectory)
    }
}

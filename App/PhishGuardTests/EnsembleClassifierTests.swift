import Foundation
import PhishCore
import XCTest
@testable import PhishGuard

/// "Both models": the corroboration rule, how the coordinator drives it, and what the foreground gate does to it.
///
/// The contract is **not** the one `VerdictEngine` applies between the rules and a model. Those two detectors
/// read different evidence, so a maximum is right there. Two models read the *same* rendered prompt, and
/// `Tools/PromptLab` measured what that costs: Apple's model scored 10 of 19 benign messages at 75–90 while MLX
/// scored none, and a maximum of the two would have turned 7 of 20 benign messages into real alerts. So one
/// member is the **primary** and the rest **corroborate**: a corroborator's higher score counts only where the
/// primary answered at `EnsembleClassifier.primarySupportScore` or the rules scored at
/// `EnsembleClassifier.heuristicSupportScore`, and it can never lower anything.
final class EnsembleClassifierTests: XCTestCase {
    private static func assessment(_ score: Int, category: ThreatCategory = .phishing, reason: String) -> ModelAssessment {
        ModelAssessment(
            isSuspicious: score >= 50, category: category, riskScore: score,
            reasons: [reason], summary: "\(reason) (\(score))."
        )
    }

    /// A message the rules already dislike: `report.score` is far above `heuristicSupportScore`, so a
    /// corroborator always has independent support here.
    private func input(_ email: EmailMessage = SampleEmails.paypalPhish) -> ClassificationInput {
        ClassificationInput(email: email, report: HeuristicAnalyzer().analyze(email))
    }

    /// A message the rules found nothing in: the only case where a corroborator is on its own.
    private func quietInput() -> ClassificationInput {
        let report = HeuristicAnalyzer().analyze(SampleEmails.benignNewsletter)
        XCTAssertLessThan(report.score, EnsembleClassifier.heuristicSupportScore, "fixture must give the corroborator no cover")
        return ClassificationInput(email: SampleEmails.benignNewsletter, report: report)
    }

    private func ensemble(
        primary: any EmailClassifier,
        corroborators: [any EmailClassifier],
        foreground: Bool = true
    ) -> EnsembleClassifier {
        EnsembleClassifier(primary: primary, corroborators: corroborators, foregroundGate: AppForegroundGate(isForeground: foreground))
    }

    // MARK: - Corroboration: adopted

    @MainActor
    func testCorroboratorsHigherScoreIsAdoptedWhenThePrimaryAlreadyFoundSomething() async throws {
        // Primary at 45 — above `primarySupportScore`, so its own answer is the support.
        let mlx = FakeClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(45, reason: "Odd sender")))
        let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(88, reason: "Lookalike login page")))
        let quiet = quietInput()   // no heuristic support: the primary's own score has to carry it

        let result = await ensemble(primary: mlx, corroborators: [apple]).assessAll(quiet)

        XCTAssertEqual(result.assessment?.riskScore, 88)
        XCTAssertEqual(result.assessment?.reasons, ["Lookalike login page"], "the adopted model's reasons are kept")
        XCTAssertEqual(result.runs.map(\.identifier), ["mlx:test/model", "apple.foundation"], "runs are primary first")
        XCTAssertEqual(result.runs.map(\.role), [.primary, .corroborator])
        XCTAssertNil(result.runs[0].corroboration, "the primary is never corroborating itself")
        XCTAssertEqual(result.runs[1].corroboration, .adopted)
        XCTAssertFalse(result.hasSuppressedCorroborator)
        XCTAssertEqual(result.modelIdentifier, "ensemble(mlx:test/model,apple.foundation)→apple.foundation")
        XCTAssertEqual(mlx.callCount, 1)
        XCTAssertEqual(apple.callCount, 1)
    }

    @MainActor
    func testCorroboratorsHigherScoreIsAdoptedWhenTheRulesAlreadyFoundSomething() async throws {
        // Primary far below `primarySupportScore`; the rule engine supplies the support instead.
        let mlx = FakeClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(5, category: .safe, reason: "Looks routine")))
        let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(90, reason: "Credential lure")))
        let loud = input()   // paypalPhish: the rules score it well over 0.3
        XCTAssertGreaterThanOrEqual(loud.report.score, EnsembleClassifier.heuristicSupportScore)

        let result = await ensemble(primary: mlx, corroborators: [apple]).assessAll(loud)

        XCTAssertEqual(result.assessment?.riskScore, 90)
        XCTAssertEqual(result.runs[1].corroboration, .adopted)
    }

    // MARK: - Corroboration: suppressed

    /// The measurement that motivated the whole rule: Apple's model calling a quiet, benign message 90 while
    /// nothing else found anything. Its score is thrown away, and the caller falls back to the rules.
    @MainActor
    func testCorroboratorCannotRaiseAVerdictAloneAndTheResultStaysRulesOnly() async throws {
        let mlx = FakeClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(8, category: .safe, reason: "Routine newsletter")))
        let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(90, reason: "Sounds like a bank lure")))
        let quiet = quietInput()

        let result = await ensemble(primary: mlx, corroborators: [apple]).assessAll(quiet)

        XCTAssertEqual(result.assessment?.riskScore, 8, "the primary's assessment stands")
        XCTAssertEqual(result.runs[1].corroboration, .suppressed)
        XCTAssertEqual(result.runs[1].riskScore, 90, "what it said is still recorded for the debug panel")
        XCTAssertTrue(result.hasSuppressedCorroborator)
        XCTAssertEqual(result.modelIdentifier, "ensemble(mlx:test/model,apple.foundation)→mlx:test/model⊘apple.foundation")

        // And the verdict the app would show is the quiet one.
        let verdict = VerdictEngine().makeVerdict(
            report: quiet.report, assessment: result.assessment, modelIdentifier: result.modelIdentifier
        )
        XCTAssertFalse(AlertPolicy().shouldAlert(verdict))
    }

    /// The same, with no primary answer at all: nothing is adopted, so the caller gets no assessment and the
    /// rules alone decide — exactly what a single unavailable model produces.
    @MainActor
    func testWithNoPrimaryAnswerAnUncorroboratedSecondOpinionProducesNoAssessment() async throws {
        let mlx = FakeClassifier(identifier: "mlx:test/model", behavior: .unavailable("Qwen3 4B has not been downloaded."))
        let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(95, reason: "Sounds urgent")))
        let subject = ensemble(primary: mlx, corroborators: [apple])

        let result = await subject.assessAll(quietInput())

        XCTAssertNil(result.assessment, "nothing may alert on the second opinion alone")
        XCTAssertNil(result.modelIdentifier)
        XCTAssertEqual(result.runs[1].corroboration, .suppressed)
        XCTAssertFalse(result.hasFailure, "a suppressed second opinion is not a model failure")
        XCTAssertTrue(result.failureReason.contains("nothing corroborated it"), result.failureReason)

        do {
            _ = try await subject.assess(quietInput())
            XCTFail("expected an error so the caller falls back to heuristics")
        } catch let error as ClassifierError {
            guard case .unavailable = error else { return XCTFail("unexpected \(error)") }
        }
    }

    /// The threshold itself, swept: 39 is not support, 40 is; 0.29 of heuristic score is not, 0.30 is.
    @MainActor
    func testSupportThresholdsAreExactlyPrimary40AndRules030() async throws {
        for (primaryScore, adopted) in [(39, false), (40, true)] {
            let mlx = FakeClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(primaryScore, category: .safe, reason: "Unsure")))
            let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(85, reason: "Loud")))
            let result = await ensemble(primary: mlx, corroborators: [apple]).assessAll(quietInput())
            XCTAssertEqual(result.runs[1].corroboration, adopted ? .adopted : .suppressed, "primary \(primaryScore)")
            XCTAssertEqual(result.assessment?.riskScore, adopted ? 85 : primaryScore, "primary \(primaryScore)")
        }

        // The rule half, exercised through `combine` so the score can be set exactly.
        let primaryRun = ModelRun(identifier: "p", outcome: .answered(Self.assessment(10, category: .safe, reason: "Quiet")), duration: 0, role: .primary)
        let loudRun = ModelRun(identifier: "c", outcome: .answered(Self.assessment(85, reason: "Loud")), duration: 0, role: .corroborator)
        for (ruleScore, adopted) in [(0.29, false), (0.30, true), (0.31, true)] {
            let combined = EnsembleClassifier.combine([primaryRun, loudRun], heuristicScore: ruleScore)
            XCTAssertEqual(combined.assessment?.riskScore, adopted ? 85 : 10, "rules \(ruleScore)")
        }
        XCTAssertFalse(EnsembleClassifier.hasIndependentSupport(primaryRiskScore: nil, heuristicScore: 0.29))
        XCTAssertTrue(EnsembleClassifier.hasIndependentSupport(primaryRiskScore: nil, heuristicScore: 0.3))
        XCTAssertTrue(EnsembleClassifier.hasIndependentSupport(primaryRiskScore: 40, heuristicScore: 0))
    }

    // MARK: - A corroborator may never lower anything

    @MainActor
    func testACorroboratorNeverLowersThePrimary() async throws {
        for support in [quietInput(), input()] {
            let mlx = FakeClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(93, reason: "Fake login link")))
            let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(1, category: .safe, reason: "Looks fine")))
            let result = await ensemble(primary: mlx, corroborators: [apple]).assessAll(support)

            XCTAssertEqual(result.assessment?.riskScore, 93, "a quieter second opinion is not a veto")
            XCTAssertEqual(result.assessment?.reasons, ["Fake login link"])
            XCTAssertEqual(result.runs[1].corroboration, .notHigher)
            XCTAssertFalse(result.hasSuppressedCorroborator, "nothing was thrown away: it never tried to raise")
            XCTAssertEqual(result.modelIdentifier, "ensemble(mlx:test/model,apple.foundation)→mlx:test/model")
        }
    }

    @MainActor
    func testAnEqualScoreFromACorroboratorKeepsThePrimarysAnswer() async {
        let mlx = FakeClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(70, reason: "Primary")))
        let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(70, reason: "Corroborator")))
        let result = await ensemble(primary: mlx, corroborators: [apple]).assessAll(input())
        XCTAssertEqual(result.assessment?.reasons, ["Primary"], "ties belong to the primary, so the result is deterministic")
        XCTAssertEqual(result.runs[1].corroboration, .notHigher)
    }

    // MARK: - One model failing never discards the other

    @MainActor
    func testTheCorroboratorFailingKeepsThePrimarysAnswer() async throws {
        for failure in [ClassifierError.invalidOutput("garbage"), .guardrailViolation, .unavailable("Apple Intelligence is off")] {
            let mlx = FakeClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(76, reason: "Credential lure")))
            let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fail(failure))
            let result = await ensemble(primary: mlx, corroborators: [apple]).assessAll(input())

            XCTAssertEqual(result.assessment?.riskScore, 76, "\(failure)")
            XCTAssertEqual(result.modelIdentifier, "mlx:test/model", "one answer is recorded as that model, not as an ensemble")
            XCTAssertEqual(result.runs.count, 2)
            XCTAssertNil(result.runs[0].errorDescription)
            XCTAssertNotNil(result.runs[1].errorDescription, "the failure is still recorded for the trace")
        }
    }

    @MainActor
    func testAnUnavailableModelIsNeverAskedAndIsNotAFailure() async throws {
        let mlx = FakeClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(55, reason: "Odd sender")))
        let off = FakeClassifier(identifier: "apple.foundation", behavior: .unavailable("Apple Intelligence is turned off."))
        let result = await ensemble(primary: mlx, corroborators: [off]).assessAll(input())

        XCTAssertEqual(off.callCount, 0, "an unavailable model is not asked")
        XCTAssertEqual(result.assessment?.riskScore, 55)
        XCTAssertFalse(result.hasFailure, "unavailable is expected, not a failure: it must not trip the breaker")
        XCTAssertEqual(result.runs[1].errorDescription, "Apple Intelligence is turned off.")
    }

    @MainActor
    func testEveryMemberFailingLeavesNoAssessmentAndThrowsFromAssess() async throws {
        let subject = ensemble(
            primary: FakeClassifier(identifier: "mlx:test/model", behavior: .unavailable("not downloaded")),
            corroborators: [FakeClassifier(identifier: "apple.foundation", behavior: .fail(ClassifierError.invalidOutput("garbage")))]
        )
        let result = await subject.assessAll(input())
        XCTAssertNil(result.assessment)
        XCTAssertNil(result.modelIdentifier)
        XCTAssertTrue(result.hasFailure)
        XCTAssertTrue(result.failureReason.contains("not downloaded"), result.failureReason)

        do {
            _ = try await subject.assess(input())
            XCTFail("expected an error so the caller falls back to heuristics")
        } catch let error as ClassifierError {
            guard case .unavailable = error else { return XCTFail("unexpected \(error)") }
        }
    }

    // MARK: - Foreground gate

    /// The background contract in one test: the GPU-backed primary is not even asked, the corroborator still
    /// runs, and it stays a corroborator — it is never promoted to primary just because it is the only one left.
    @MainActor
    func testAGatedOffPrimaryIsNeverReplacedByTheCorroborator() async throws {
        let local = FakeGPUClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(99, reason: "Never asked")))
        let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(88, reason: "Bank pretext")))
        let gate = AppForegroundGate(isForeground: false)
        let subject = EnsembleClassifier(primary: local, corroborators: [apple], foregroundGate: gate)

        // Quiet message: the corroborator is alone, so nothing may be adopted.
        let quiet = await subject.assessAll(quietInput())
        XCTAssertEqual(local.callCount, 0, "no GPU work while PhishGuard is not frontmost")
        XCTAssertEqual(apple.callCount, 1, "Apple's model is a system service and still runs")
        XCTAssertNil(quiet.assessment, "background scans are exactly where the second opinion would run alone")
        XCTAssertEqual(quiet.runs.map(\.role), [.primary, .corroborator], "the roles do not shift with the gate")
        XCTAssertTrue(quiet.runs[0].wasSkippedForForeground)
        XCTAssertEqual(quiet.runs[1].corroboration, .suppressed)
        XCTAssertTrue(quiet.foregroundSkipped)
        XCTAssertFalse(quiet.hasFailure, "the skip is expected, not a model failure")
        XCTAssertEqual(quiet.runs[0].errorDescription, MLXClassifier.foregroundOnlyReason)

        // Same gate, but the rules found something: now the second opinion has cover and is adopted.
        let loud = await subject.assessAll(input())
        XCTAssertEqual(local.callCount, 0)
        XCTAssertEqual(loud.assessment?.riskScore, 88)
        XCTAssertEqual(loud.runs[1].corroboration, .adopted)
        XCTAssertEqual(loud.modelIdentifier, "apple.foundation")

        // Availability answers the same question the same way, and says why.
        guard case .available = await subject.availability() else {
            return XCTFail("one member is available, so the ensemble is")
        }

        // Back in the foreground the primary runs again and decides.
        gate.setForeground(true)
        let open = await subject.assessAll(quietInput())
        XCTAssertEqual(local.callCount, 1)
        XCTAssertEqual(open.assessment?.riskScore, 99)
        XCTAssertEqual(open.modelIdentifier, "ensemble(mlx:test/model,apple.foundation)→mlx:test/model")
        XCTAssertFalse(open.foregroundSkipped)
    }

    @MainActor
    func testAvailabilityIsTheUnionOfTheMembersAndExplainsItself() async throws {
        let available = ensemble(
            primary: FakeClassifier(identifier: "model.off", behavior: .unavailable("Apple Intelligence is off.")),
            corroborators: [FakeClassifier(identifier: "model.on", behavior: .fixed(FakeClassifier.benign))]
        )
        let unionAvailability = await available.availability()
        XCTAssertEqual(unionAvailability, .available)

        let none = ensemble(
            primary: FakeClassifier(identifier: "model.missing", behavior: .unavailable("Qwen3 4B has not been downloaded.")),
            corroborators: [FakeClassifier(identifier: "model.off", behavior: .unavailable("Apple Intelligence is off."))]
        )
        guard case .unavailable(let reason) = await none.availability() else { return XCTFail("nothing can run") }
        XCTAssertTrue(reason.contains("Apple Intelligence is off."), reason)
        XCTAssertTrue(reason.contains("has not been downloaded."), reason)
    }

    // MARK: - Identifier

    func testEnsembleIdentifierRoundTripsAndNamesTheWinnerAndTheSuppressed() throws {
        let members = ["mlx:mlx-community/Qwen3-4B-Instruct-2507-4bit", "apple.foundation"]
        let listed = EnsembleIdentifier.make(members: members, winner: nil)
        XCTAssertEqual(listed, "ensemble(mlx:mlx-community/Qwen3-4B-Instruct-2507-4bit,apple.foundation)")
        let decided = EnsembleIdentifier.make(members: members, winner: members[0])
        XCTAssertEqual(decided, listed + "→" + members[0])
        let suppressed = EnsembleIdentifier.make(members: members, winner: members[0], suppressed: [members[1]])
        XCTAssertEqual(suppressed, decided + "⊘" + members[1])

        let parsedList = try XCTUnwrap(EnsembleIdentifier.parse(listed))
        XCTAssertEqual(parsedList.members, members)
        XCTAssertNil(parsedList.winner)
        XCTAssertTrue(parsedList.suppressed.isEmpty)
        let parsedDecided = try XCTUnwrap(EnsembleIdentifier.parse(decided))
        XCTAssertEqual(parsedDecided.members, members)
        XCTAssertEqual(parsedDecided.winner, members[0])
        XCTAssertTrue(parsedDecided.suppressed.isEmpty)
        let parsedSuppressed = try XCTUnwrap(EnsembleIdentifier.parse(suppressed))
        XCTAssertEqual(parsedSuppressed.members, members)
        XCTAssertEqual(parsedSuppressed.winner, members[0])
        XCTAssertEqual(parsedSuppressed.suppressed, [members[1]])

        XCTAssertNil(EnsembleIdentifier.parse("apple.foundation"))
        XCTAssertNil(EnsembleIdentifier.parse("mlx:mlx-community/Qwen3-4B-Instruct-2507-4bit"))
        XCTAssertNil(EnsembleIdentifier.parse(HeuristicsOnlyClassifier.classifierIdentifier))
    }

    func testEnsembleIdentifiersRenderForTheDetailScreenAndTheDebugPanel() throws {
        let entry = try XCTUnwrap(ModelManager.entry(for: ModelManager.defaultModelID))
        let mlx = "mlx:\(entry.hfRepo)"
        let members = [mlx, "apple.foundation"]
        let decided = EnsembleIdentifier.make(members: members, winner: mlx)

        XCTAssertEqual(ClassifierDisplay.name(forIdentifier: decided), "Both models (from: \(entry.displayName))")
        XCTAssertEqual(
            ClassifierDisplay.name(forIdentifier: EnsembleIdentifier.make(members: members, winner: nil)),
            "Both models (\(entry.displayName) + Apple Intelligence)"
        )
        XCTAssertEqual(ClassifierDisplay.shortName(forIdentifier: "apple.foundation"), "Apple Intelligence")
        XCTAssertEqual(ClassifierDisplay.shortName(forIdentifier: mlx), entry.displayName)
        XCTAssertEqual(ClassifierDisplay.shortName(forIdentifier: HeuristicsOnlyClassifier.classifierIdentifier), "Heuristics")

        let footnote = ClassifierDisplay.footnote(forIdentifier: decided)
        XCTAssertTrue(footnote.contains("\(entry.displayName) and Apple Intelligence"), footnote)
        XCTAssertTrue(footnote.contains("the risk score came from \(entry.displayName)"), footnote)

        // A suppressed second opinion says so, in both places the user can see it.
        let suppressed = EnsembleIdentifier.make(members: members, winner: mlx, suppressed: ["apple.foundation"])
        XCTAssertEqual(
            ClassifierDisplay.name(forIdentifier: suppressed),
            "Both models (from: \(entry.displayName); Apple Intelligence not corroborated)"
        )
        XCTAssertTrue(ClassifierDisplay.footnote(forIdentifier: suppressed).contains("that score was not used"))
    }

    // MARK: - Registry and settings

    @MainActor
    func testBothChoiceMakesTheLocalModelPrimaryAndAppleTheCorroborator() async throws {
        let suite = "EnsembleClassifierTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = SettingsStore(defaults: defaults)
        let directory = FileManager.default.temporaryDirectory
            .appending(path: "EnsembleClassifierTests-\(UUID().uuidString)", directoryHint: .isDirectory)
        let manager = ModelManager(modelsDirectory: directory)
        defer { try? FileManager.default.removeItem(at: directory) }
        let registry = ClassifierRegistry(settings: settings, modelManager: manager)

        registry.choice = .both
        let classifier = try XCTUnwrap(registry.activeClassifier() as? EnsembleClassifier)
        let mlxIdentifier = "mlx:\(try XCTUnwrap(ModelManager.entry(for: registry.preferredMLXModelID)).hfRepo)"
        XCTAssertEqual(classifier.primary.identifier, mlxIdentifier, "the measured-better model decides")
        XCTAssertEqual(classifier.corroborators.map(\.identifier), [AppleFoundationClassifier.classifierIdentifier])
        XCTAssertEqual(classifier.members.map(\.identifier), [mlxIdentifier, AppleFoundationClassifier.classifierIdentifier])
        XCTAssertTrue(classifier.primary is any GPUBackedClassifier, "the local model stays the GPU-backed member")
        // Through the existential the coordinator actually sees: an ensemble must not look GPU-backed as a
        // whole, or `ScanCoordinator` would skip it entirely in the background.
        let asClassifier: any EmailClassifier = classifier
        XCTAssertFalse(asClassifier is any GPUBackedClassifier, "the ensemble itself must stay runnable in the background")
        XCTAssertTrue(asClassifier is any MultiModelClassifier, "so the coordinator asks every member")

        // The MLX member is the registry's long-lived actor, so a scan still pays one weight load.
        let again = try XCTUnwrap(registry.activeClassifier() as? EnsembleClassifier)
        XCTAssertTrue((classifier.primary as AnyObject) === (again.primary as AnyObject))

        XCTAssertTrue(ClassifierChoice.allCases.contains(.both))
        XCTAssertEqual(ClassifierChoice(rawValue: "both"), .both)
        XCTAssertTrue(ClassifierChoice.both.usesDownloadedModel)
        XCTAssertTrue(ClassifierChoice.mlx.usesDownloadedModel)
        XCTAssertFalse(ClassifierChoice.appleFoundation.usesDownloadedModel)
        let summary = await registry.availabilitySummary()
        XCTAssertEqual(Set(summary.keys), Set(ClassifierChoice.allCases))

        // Apple Intelligence chosen on its own is the user saying "make it the primary", and it is one.
        registry.choice = .appleFoundation
        let alone = registry.activeClassifier()
        XCTAssertFalse(alone is EnsembleClassifier)
        XCTAssertEqual(alone.identifier, AppleFoundationClassifier.classifierIdentifier)
    }

    @MainActor
    func testBothIsTheFreshInstallDefaultWhereAppleIntelligenceWorks() throws {
        XCTAssertEqual(SettingsStore.defaultClassifierChoice(appleIntelligenceAvailable: true), .both)
        XCTAssertEqual(SettingsStore.defaultClassifierChoice(appleIntelligenceAvailable: false), .mlx)

        let suite = "EnsembleClassifierTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let fresh = SettingsStore(defaults: defaults)
        XCTAssertFalse(fresh.hasStoredClassifierChoice)
        XCTAssertEqual(fresh.classifierChoice, .mlx, "the stored default is unchanged for devices without Apple Intelligence")
        XCTAssertEqual(fresh.applyDefaultClassifierChoice(appleIntelligenceAvailable: true), .both)
        XCTAssertTrue(fresh.hasStoredClassifierChoice)
        XCTAssertEqual(SettingsStore(defaults: defaults).classifierChoice, .both, "and it is persisted")

        // A user (or onboarding) that already chose is never overridden.
        fresh.classifierChoice = .heuristicsOnly
        XCTAssertEqual(fresh.applyDefaultClassifierChoice(appleIntelligenceAvailable: true), .heuristicsOnly)
    }

    // MARK: - Through the coordinator

    @MainActor
    func testScanWithBothModelsRecordsWhoDecidedAndWhoCorroborated() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(messages: [SampleEmails.paypalPhish]))
        let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(30, category: .safe, reason: "Probably fine")))
        let local = FakeClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(95, reason: "Fake login link")))
        let gate = AppForegroundGate(isForeground: true)
        let harness = try ScanHarness(
            providers: [.gmail: provider],
            classifier: EnsembleClassifier(primary: local, corroborators: [apple], foregroundGate: gate),
            foregroundGate: gate
        )
        try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertEqual(summary.scanned, 1)
        XCTAssertTrue(summary.errors.isEmpty, "\(summary.errors)")
        XCTAssertEqual(apple.callCount, 1)
        XCTAssertEqual(local.callCount, 1, "both models are asked about the same message")
        let record = try XCTUnwrap(try harness.flaggedRecords().first)
        XCTAssertEqual(record.modelIdentifier, "ensemble(mlx:test/model,apple.foundation)→mlx:test/model")
        XCTAssertGreaterThanOrEqual(record.confidence, 0.95, "the primary's score drives the verdict")
        XCTAssertEqual(record.level, .high)
    }

    /// End to end, on a real benign fixture: a background scan where the second opinion screams and nothing else
    /// agrees must produce no flagged row and no alert. This is the field failure the corroboration rule exists
    /// to prevent — Apple's model wrongly scoring benign mail 75–90 while MLX is gated off.
    @MainActor
    func testBackgroundScanDoesNotAlertOnABenignMessageTheSecondOpinionDislikes() async throws {
        let benign = [
            SampleEmails.benignNewsletter, SampleEmails.benignAmexStatement,
            SampleEmails.benignGoogleSecurityAlert, SampleEmails.benignOTPCode,
        ]
        let provider = FakeMailProvider(provider: .gmail, state: .init(messages: benign))
        let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(90, reason: "Sounds like a bank lure")))
        let local = FakeGPUClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(99, reason: "Never asked")))
        let gate = AppForegroundGate(isForeground: false)
        let harness = try ScanHarness(
            providers: [.gmail: provider],
            classifier: EnsembleClassifier(primary: local, corroborators: [apple], foregroundGate: gate),
            foregroundGate: gate
        )
        try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .silentPush, deadline: nil)

        XCTAssertEqual(summary.scanned, benign.count)
        XCTAssertEqual(local.callCount, 0, "iOS kills the app for GPU work in the background; it is never attempted")
        XCTAssertEqual(apple.callCount, benign.count, "the second opinion is still consulted")
        XCTAssertEqual(summary.flagged, 0, "and none of it alerted: nothing corroborated the second opinion")
        XCTAssertTrue(try harness.flaggedRecords().isEmpty)
        let log = await harness.coordinator.scanLog
        let scanLine = try XCTUnwrap(log.last { $0.accountID == nil })
        XCTAssertEqual(scanLine.note?.contains("app not in the foreground"), true)
        XCTAssertNotEqual(scanLine.note?.contains("model disabled"), true, "an expected skip is not a disabled model")
    }

    /// The other half: the corroborator is not silenced, only fenced. With the rules already elevated it decides
    /// the verdict on a background scan exactly as before.
    @MainActor
    func testBackgroundScanStillUsesTheCorroboratorWhenTheRulesFoundSomething() async throws {
        let provider = FakeMailProvider(provider: .gmail, state: .init(messages: [SampleEmails.paypalPhish]))
        let apple = FakeClassifier(identifier: "apple.foundation", behavior: .fixed(Self.assessment(81, reason: "Bank pretext")))
        let local = FakeGPUClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(99, reason: "Never asked")))
        let gate = AppForegroundGate(isForeground: false)
        let harness = try ScanHarness(
            providers: [.gmail: provider],
            classifier: EnsembleClassifier(primary: local, corroborators: [apple], foregroundGate: gate),
            foregroundGate: gate
        )
        try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .silentPush, deadline: nil)

        XCTAssertEqual(summary.scanned, 1)
        XCTAssertTrue(summary.errors.isEmpty, "\(summary.errors)")
        XCTAssertEqual(local.callCount, 0)
        XCTAssertEqual(apple.callCount, 1, "Apple Intelligence keeps checking while PhishGuard is closed")
        let record = try XCTUnwrap(try harness.flaggedRecords().first)
        XCTAssertEqual(record.modelIdentifier, "apple.foundation", "nothing may claim a verdict the local model did not give")

        // Opening the app brings the primary back without any extra bookkeeping.
        gate.setForeground(true)
        let verdict = await harness.coordinator.evaluate(SampleEmails.paypalPhish)
        XCTAssertEqual(verdict.modelIdentifier, "ensemble(mlx:test/model,apple.foundation)→mlx:test/model")
        XCTAssertEqual(local.callCount, 1)
    }

    @MainActor
    func testScanKeepsGoingWhenOneModelKeepsFailing() async throws {
        let messages = (1...5).map { SampleEmails.paypalPhish.withMessageID("dup-\($0)") }
        let provider = FakeMailProvider(provider: .gmail, state: .init(messages: messages))
        let broken = FakeClassifier(identifier: "apple.foundation", behavior: .fail(ClassifierError.invalidOutput("garbage")))
        let working = FakeClassifier(identifier: "mlx:test/model", behavior: .fixed(Self.assessment(93, reason: "Fake login link")))
        let gate = AppForegroundGate(isForeground: true)
        let harness = try ScanHarness(
            providers: [.gmail: provider],
            classifier: EnsembleClassifier(primary: working, corroborators: [broken], foregroundGate: gate),
            foregroundGate: gate
        )
        try harness.addAccount(provider: .gmail)

        let summary = await harness.coordinator.scan(trigger: .manual, deadline: nil)

        XCTAssertEqual(summary.scanned, messages.count)
        XCTAssertTrue(summary.errors.isEmpty, "a broken model is not a scan error")
        XCTAssertGreaterThan(messages.count, ScanCoordinator.classifierFailureThreshold)
        XCTAssertEqual(working.callCount, messages.count, "the healthy model is asked about every message")
        XCTAssertEqual(broken.callCount, messages.count, "and the broken one keeps being given a chance")
        XCTAssertTrue(try harness.flaggedRecords().allSatisfy { $0.modelIdentifier == "mlx:test/model" })
        let log = await harness.coordinator.scanLog
        let scanLine = try XCTUnwrap(log.last { $0.accountID == nil })
        XCTAssertNotEqual(scanLine.note?.contains("model disabled"), true, "one model answering keeps the run healthy: \(scanLine.note ?? "-")")
    }
}

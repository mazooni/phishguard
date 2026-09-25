import XCTest
@testable import PhishCore

final class VerdictEngineTests: XCTestCase {
    private let engine = VerdictEngine()

    private func report(score: Double, signals: [Signal] = []) -> HeuristicReport {
        HeuristicReport(signals: signals, score: score, bodyText: "body")
    }

    private func assessment(risk: Int, suspicious: Bool = true, category: ThreatCategory = .phishing) -> ModelAssessment {
        ModelAssessment(isSuspicious: suspicious, category: category, riskScore: risk, reasons: ["r1"], summary: "model summary")
    }

    private let highSignal = Signal(id: "link.lookalike_domain", title: "Lookalike link", detail: "paypal.com.evil.test", severity: .high, weight: 0.9)
    private let lowSignal = Signal(id: "content.generic_greeting", title: "Generic greeting", detail: "Dear Customer", severity: .low, weight: 0.2)

    func testHeuristicsOnlyUsesHeuristicScoreDirectly() {
        let verdict = engine.makeVerdict(report: report(score: 0.8), assessment: nil, modelIdentifier: nil)
        XCTAssertEqual(verdict.confidence, 0.8, accuracy: 1e-9)
        XCTAssertEqual(verdict.level, .high)
        XCTAssertNil(verdict.modelIdentifier)
        XCTAssertNil(verdict.modelRiskScore)
    }

    func testFusionTakesTheStrongerOfTheTwoDetectors() {
        let verdict = engine.makeVerdict(report: report(score: 0.4), assessment: assessment(risk: 40, suspicious: false), modelIdentifier: "apple.foundation")
        XCTAssertEqual(verdict.confidence, 0.4, accuracy: 1e-9)
        XCTAssertEqual(verdict.level, .low)
        XCTAssertEqual(verdict.modelIdentifier, "apple.foundation")
        XCTAssertEqual(verdict.modelRiskScore, 40)

        // Whichever detector is more certain sets the confidence; the quiet one is out-voted, not averaged in.
        XCTAssertEqual(engine.makeVerdict(report: report(score: 0.8), assessment: assessment(risk: 10), modelIdentifier: "m").confidence, 0.8, accuracy: 1e-9)
        XCTAssertEqual(engine.makeVerdict(report: report(score: 0.1), assessment: assessment(risk: 80), modelIdentifier: "m").confidence, 0.8, accuracy: 1e-9)
    }

    // MARK: - Two independent detectors

    /// The matrix the redesign exists for: either detector may raise the alert on its own, neither may veto the
    /// other, and the authenticated-brand cap is the one exception.
    func testEitherDetectorCanRaiseTheAlertAloneAndNeitherCanVetoTheOther() {
        let policy = AlertPolicy()

        // 1. Rules found nothing, the model is confident: the model alerts on its own. This is the case the old
        //    average silently discarded (0.5*0 + 0.5*0.9 = 0.45 → .low).
        let modelOnly = engine.makeVerdict(report: report(score: 0.0), assessment: assessment(risk: 90), modelIdentifier: "m")
        XCTAssertEqual(modelOnly.confidence, 0.9, accuracy: 1e-9)
        XCTAssertGreaterThanOrEqual(modelOnly.level, .medium)
        XCTAssertTrue(policy.shouldAlert(modelOnly))

        // 2. Rules are certain, the model says safe: the rules alert on their own, undiminished.
        let safe = assessment(risk: 0, suspicious: false, category: .safe)
        let rulesOnly = engine.makeVerdict(report: report(score: 0.85, signals: [highSignal]), assessment: safe, modelIdentifier: "m")
        XCTAssertEqual(rulesOnly.confidence, 0.85, accuracy: 1e-9, "a model saying safe subtracts nothing")
        XCTAssertEqual(rulesOnly.level, .high)
        XCTAssertTrue(policy.shouldAlert(rulesOnly))

        // 3. An authenticated brand notice the model is certain about: capped, and it does not alert.
        let brand = Signal(id: "mitigation.brand_authenticated", title: "Authenticated brand", detail: "…", severity: .info, weight: 0)
        let wording = Signal(id: "content.credential_request", title: "Credential request", detail: "…", severity: .high, weight: 0.4)
        let capped = engine.makeVerdict(report: report(score: 0.0, signals: [brand, wording]), assessment: assessment(risk: 100), modelIdentifier: "m")
        XCTAssertEqual(capped.confidence, VerdictEngine.authenticatedBrandConfidenceCap, accuracy: 1e-9)
        XCTAssertEqual(capped.level, .low)
        XCTAssertFalse(policy.shouldAlert(capped))

        // 4. Both quiet: nothing happens.
        let quiet = engine.makeVerdict(report: report(score: 0.1), assessment: assessment(risk: 10, suspicious: false, category: .safe), modelIdentifier: "m")
        XCTAssertEqual(quiet.confidence, 0.1, accuracy: 1e-9)
        XCTAssertEqual(quiet.level, .safe)
        XCTAssertFalse(policy.shouldAlert(quiet))

        // The model can never lower a heuristics-only verdict: over the whole grid, adding a model only ever raises it.
        for heuristic in stride(from: 0.0, through: 1.0, by: 0.05) {
            let alone = engine.makeVerdict(report: report(score: heuristic), assessment: nil, modelIdentifier: nil)
            for risk in stride(from: 0, through: 100, by: 5) {
                for suspicious in [true, false] {
                    let fused = engine.makeVerdict(
                        report: report(score: heuristic),
                        assessment: assessment(risk: risk, suspicious: suspicious, category: suspicious ? .phishing : .safe),
                        modelIdentifier: "m"
                    )
                    XCTAssertGreaterThanOrEqual(fused.confidence, alone.confidence - 1e-9, "h=\(heuristic) risk=\(risk)")
                    XCTAssertEqual(fused.confidence, max(heuristic, Double(risk) / 100), accuracy: 1e-9, "h=\(heuristic) risk=\(risk)")
                }
            }
        }
    }

    /// An unavailable or erroring model reaches the engine as `assessment: nil`, and then nothing about the verdict
    /// may differ from the pre-model behaviour — including the fields that name the model.
    func testAnAbsentModelIsExactlyTheHeuristicsOnlyPath() {
        for score in stride(from: 0.0, through: 1.0, by: 0.05) {
            let verdict = engine.makeVerdict(report: report(score: score, signals: [highSignal, lowSignal]), assessment: nil, modelIdentifier: "m")
            XCTAssertEqual(verdict.confidence, score, accuracy: 1e-9)
            XCTAssertEqual(verdict.level, RiskLevel(confidence: score))
            XCTAssertNil(verdict.modelIdentifier, "no assessment ⇒ no model is credited")
            XCTAssertNil(verdict.modelRiskScore)
            XCTAssertTrue(verdict.reasons.allSatisfy { $0.source == .heuristic })
        }
    }

    func testBumpAppliesOnlyWithSuspiciousModelAndHighSignal() {
        let withHigh = engine.makeVerdict(report: report(score: 0.6, signals: [highSignal]), assessment: assessment(risk: 60), modelIdentifier: "m")
        XCTAssertEqual(withHigh.confidence, 0.7, accuracy: 1e-9)
        XCTAssertEqual(withHigh.level, .medium)

        let withoutHigh = engine.makeVerdict(report: report(score: 0.6, signals: [lowSignal]), assessment: assessment(risk: 60), modelIdentifier: "m")
        XCTAssertEqual(withoutHigh.confidence, 0.6, accuracy: 1e-9)

        let notSuspicious = engine.makeVerdict(report: report(score: 0.6, signals: [highSignal]), assessment: assessment(risk: 60, suspicious: false), modelIdentifier: "m")
        XCTAssertEqual(notSuspicious.confidence, 0.6, accuracy: 1e-9)
    }

    func testConfidenceIsClampedToOne() {
        let verdict = engine.makeVerdict(report: report(score: 1.0, signals: [highSignal]), assessment: assessment(risk: 100), modelIdentifier: "m")
        XCTAssertEqual(verdict.confidence, 1.0, accuracy: 1e-9)
        XCTAssertEqual(verdict.level, .high)
    }

    func testLevelThresholds() {
        XCTAssertEqual(engine.makeVerdict(report: report(score: 0.75), assessment: nil, modelIdentifier: nil).level, .high)
        XCTAssertEqual(engine.makeVerdict(report: report(score: 0.749), assessment: nil, modelIdentifier: nil).level, .medium)
        XCTAssertEqual(engine.makeVerdict(report: report(score: 0.5), assessment: nil, modelIdentifier: nil).level, .medium)
        XCTAssertEqual(engine.makeVerdict(report: report(score: 0.499), assessment: nil, modelIdentifier: nil).level, .low)
        XCTAssertEqual(engine.makeVerdict(report: report(score: 0.3), assessment: nil, modelIdentifier: nil).level, .low)
        XCTAssertEqual(engine.makeVerdict(report: report(score: 0.299), assessment: nil, modelIdentifier: nil).level, .safe)
        XCTAssertEqual(engine.makeVerdict(report: report(score: 0), assessment: nil, modelIdentifier: nil).level, .safe)
    }

    func testCategoryPrefersModelWhenConfidentAndNotSafe() {
        let scam = engine.makeVerdict(report: report(score: 0.5), assessment: assessment(risk: 80, category: .scam), modelIdentifier: "m")
        XCTAssertEqual(scam.category, .scam)

        // Model says phishing but fused confidence < 0.5 → derived from signals (none) → safe.
        let weak = engine.makeVerdict(report: report(score: 0.1), assessment: assessment(risk: 20, category: .phishing), modelIdentifier: "m")
        XCTAssertEqual(weak.confidence, 0.2, accuracy: 1e-9)
        XCTAssertEqual(weak.category, .safe)

        // A model score in the low band now lands in the low band rather than being halved into "safe"; a flagged
        // level (even `.low`) never carries category `.safe`.
        let lowBand = engine.makeVerdict(report: report(score: 0.1), assessment: assessment(risk: 35, category: .phishing), modelIdentifier: "m")
        XCTAssertEqual(lowBand.level, .low)
        XCTAssertEqual(lowBand.category, .phishing)

        // Model says safe → derived from signals.
        let modelSafe = engine.makeVerdict(report: report(score: 0.9, signals: [highSignal]), assessment: assessment(risk: 90, suspicious: false, category: .safe), modelIdentifier: "m")
        XCTAssertEqual(modelSafe.category, .phishing)
    }

    func testCategoryDerivedFromSignals() {
        let payment = Signal(id: "content.gift_card_request", title: "Gift card request", detail: "…", severity: .high, weight: 0.8)
        let scam = engine.makeVerdict(report: report(score: 0.8, signals: [payment]), assessment: nil, modelIdentifier: nil)
        XCTAssertEqual(scam.category, .scam)

        let phish = engine.makeVerdict(report: report(score: 0.8, signals: [highSignal, payment]), assessment: nil, modelIdentifier: nil)
        XCTAssertEqual(phish.category, .phishing, "credential/link signals win over payment signals")

        // Unattributed risk at a flagged level is never labelled "Safe"; without risk it is.
        let none = engine.makeVerdict(report: report(score: 0.8), assessment: nil, modelIdentifier: nil)
        XCTAssertEqual(none.category, .phishing, "a flagged verdict must not carry category .safe")
        let quiet = engine.makeVerdict(report: report(score: 0.1), assessment: nil, modelIdentifier: nil)
        XCTAssertEqual(quiet.category, .safe)
    }

    func testReasonsAreOrderedBySeverityDescendingAndIncludeModelReasons() {
        let verdict = engine.makeVerdict(report: report(score: 0.6, signals: [lowSignal, highSignal]), assessment: assessment(risk: 80), modelIdentifier: "m")
        XCTAssertEqual(verdict.reasons.map(\.severity), [.high, .high, .low])
        XCTAssertEqual(verdict.reasons.first?.id, "link.lookalike_domain")
        XCTAssertEqual(verdict.reasons[1].source, .model)
        XCTAssertEqual(verdict.summary, "model summary")
    }

    func testGeneratedSummaryWhenNoModel() {
        let verdict = engine.makeVerdict(report: report(score: 0.0), assessment: nil, modelIdentifier: nil)
        XCTAssertFalse(verdict.summary.isEmpty)
        XCTAssertFalse(verdict.isFlagged)
    }
}

// MARK: - Generated summary wording

/// The summary a rules-only verdict shows on the detail screen is a sentence, not a chip label. "This email
/// looks scam" is what came out when the two were the same string.
final class GeneratedSummaryWordingTests: XCTestCase {
    func testEveryCategoryReadsAsASentence() {
        let signals = [Signal(id: "content.payment_request", title: "Asks for a payment or fee", detail: "d", severity: .medium, weight: 0.35)]
        let expected: [ThreatCategory: String] = [
            .phishing: "This email looks like phishing: Asks for a payment or fee.",
            .scam: "This email looks like a scam: Asks for a payment or fee.",
            .spam: "This email looks like spam: Asks for a payment or fee.",
        ]
        for (category, sentence) in expected {
            XCTAssertEqual(VerdictEngine.generatedSummary(level: .medium, category: category, signals: signals), sentence)
        }
    }

    func testSummaryWithNoSignalsStillReadsAsASentence() {
        XCTAssertEqual(VerdictEngine.generatedSummary(level: .low, category: .scam, signals: []),
                       "This email looks like a scam (low risk).")
        XCTAssertEqual(VerdictEngine.generatedSummary(level: .safe, category: .safe, signals: []),
                       "No signs of phishing or scam were found.")
    }

    /// The real path this shows up on: an email checked while the app was closed, so no model summary exists.
    func testARulesOnlyVerdictOverAFixtureReadsAsASentence() {
        let report = HeuristicAnalyzer().analyze(SampleEmails.subscriptionDunningNotice)
        let verdict = VerdictEngine().makeVerdict(report: report, assessment: nil, modelIdentifier: nil)
        XCTAssertTrue(verdict.summary.hasPrefix("This email looks like a scam: "), verdict.summary)
    }
}

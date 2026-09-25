import XCTest
@testable import PhishCore

/// Regression tests for the rules-review findings on `VerdictEngine`: category of heuristics-only verdicts (#38) and
/// the model "safe" veto (#66).
final class VerdictEngineReviewTests: XCTestCase {
    private let engine = VerdictEngine()
    private let analyzer = HeuristicAnalyzer()

    private func report(score: Double, signals: [Signal] = []) -> HeuristicReport {
        HeuristicReport(signals: signals, score: score, bodyText: "body")
    }

    private func assessment(risk: Int, suspicious: Bool = true, category: ThreatCategory = .phishing) -> ModelAssessment {
        ModelAssessment(isSuspicious: suspicious, category: category, riskScore: risk, reasons: ["r1"], summary: "model summary")
    }

    private func heuristicsOnly(_ email: EmailMessage) -> Verdict {
        engine.makeVerdict(report: analyzer.analyze(email), assessment: nil, modelIdentifier: nil)
    }

    private let highSignal = Signal(id: "link.lookalike_domain", title: "Lookalike link", detail: "paypal.com.evil.test", severity: .high, weight: 0.9)
    private let lowSignal = Signal(id: "content.generic_greeting", title: "Generic greeting", detail: "Dear Customer", severity: .low, weight: 0.2)

    // MARK: - #66 Model "safe" cannot veto the heuristics

    /// #66 used to be answered by `modelVetoAllowance`, which merely limited how far a model "safe" could pull a
    /// strong heuristic verdict down. Since the two detectors became independent the answer is absolute: a model
    /// that says safe subtracts nothing at all, at any heuristic score, with or without a high-severity signal.
    func testModelSafeNeverLowersAHeuristicVerdict() {
        let safe = assessment(risk: 0, suspicious: false, category: .safe)

        let strong = engine.makeVerdict(report: report(score: 0.95, signals: [highSignal]), assessment: safe, modelIdentifier: "m")
        XCTAssertEqual(strong.confidence, 0.95, accuracy: 1e-9)
        XCTAssertEqual(strong.level, .high)
        XCTAssertTrue(AlertPolicy().shouldAlert(strong))
        XCTAssertEqual(strong.modelRiskScore, 0)
        XCTAssertEqual(strong.category, .phishing, "the model said safe, so the category comes from the signals")

        // The same holds without a high-severity signal: the old average halved this to 0.475 (`.low`).
        let weakSignals = engine.makeVerdict(report: report(score: 0.95, signals: [lowSignal]), assessment: safe, modelIdentifier: "m")
        XCTAssertEqual(weakSignals.confidence, 0.95, accuracy: 1e-9)
        XCTAssertEqual(weakSignals.level, .high)

        // A borderline heuristic report can no longer be talked out of the alert band either.
        let borderline = engine.makeVerdict(report: report(score: 0.6, signals: [highSignal]), assessment: safe, modelIdentifier: "m")
        XCTAssertEqual(borderline.confidence, 0.6, accuracy: 1e-9)
        XCTAssertEqual(borderline.level, .medium)
        XCTAssertTrue(AlertPolicy().shouldAlert(borderline))

        // Agreement adds the bonus on top of the stronger detector, and nothing else.
        let agreeing = engine.makeVerdict(report: report(score: 0.6, signals: [highSignal]), assessment: assessment(risk: 60), modelIdentifier: "m")
        XCTAssertEqual(agreeing.confidence, 0.7, accuracy: 1e-9, "max(0.6, 0.6) + agreement bonus 0.1")

        // And the mirror image of #66: heuristics that found nothing no longer halve a confident model.
        let benign = engine.makeVerdict(report: report(score: 0), assessment: assessment(risk: 100), modelIdentifier: "m")
        XCTAssertEqual(benign.confidence, 1.0, accuracy: 1e-9)
        XCTAssertTrue(AlertPolicy().shouldAlert(benign))
    }

    func testEveryMaliciousFixtureStillAlertsUnderAModelSafeVerdict() {
        let safe = assessment(risk: 0, suspicious: false, category: .safe)
        for email in SampleEmails.malicious {
            let verdict = engine.makeVerdict(report: analyzer.analyze(email), assessment: safe, modelIdentifier: "m")
            XCTAssertTrue(AlertPolicy().shouldAlert(verdict), "\(email.subject): \(verdict.confidence) (heuristic \(verdict.heuristicScore))")
        }
        for email in SampleEmails.benign where SampleEmails.benignScoreTolerances[email.messageID] == nil {
            let verdict = engine.makeVerdict(report: analyzer.analyze(email), assessment: safe, modelIdentifier: "m")
            XCTAssertEqual(verdict.level, .safe, email.subject)
        }
    }

    // MARK: - #38 Category of heuristics-only verdicts

    func testFlaggedHeuristicVerdictsNeverCarryCategorySafe() {
        // Link-free spoofs: display-name brand claim + failed authentication + threats, no credential/link/money keyword.
        let spoof = TestEmailFactory.email(
            from: EmailAddress(name: "Chase Bank", address: "chase.alerts.2291@gmail.com"),
            textBody: "Unusual sign-in detected on your account. Call us immediately or the account will be suspended within 24 hours.",
            authenticationResults: "mx; spf=fail smtp.mailfrom=chase.alerts.2291@gmail.com; dkim=fail header.d=gmail.com; dmarc=fail header.from=gmail.com"
        )
        let spoofVerdict = heuristicsOnly(spoof)
        XCTAssertTrue(spoofVerdict.isFlagged)
        XCTAssertEqual(spoofVerdict.category, .phishing)

        // QR-code MFA lure with no links.
        let qr = TestEmailFactory.email(
            from: EmailAddress(name: "Microsoft 365 Security", address: "security@m365-mfa-portal.example"),
            textBody: "Scan the QR code below with your phone camera to re-enrol your authenticator. Access expires in 24 hours."
        )
        let qrVerdict = heuristicsOnly(qr)
        XCTAssertTrue(qrVerdict.isFlagged)
        XCTAssertEqual(qrVerdict.category, .phishing)

        // Signals without any category keyword at a flagged level default to phishing, not safe.
        let urgency = Signal(id: "content.urgency", title: "Urgency", detail: "…", severity: .medium, weight: 0.5)
        let threat = Signal(id: "content.threat", title: "Threat", detail: "…", severity: .medium, weight: 0.5)
        let generic = engine.makeVerdict(report: report(score: 0.55, signals: [urgency, threat]), assessment: nil, modelIdentifier: nil)
        XCTAssertEqual(generic.level, .medium)
        XCTAssertEqual(generic.category, .phishing)

        // Impersonation / secrecy cues classify as scam; money keywords still do.
        let bec = Signal(id: "content.executive_impersonation", title: "CEO fraud", detail: "…", severity: .medium, weight: 0.6)
        XCTAssertEqual(engine.makeVerdict(report: report(score: 0.6, signals: [bec]), assessment: nil, modelIdentifier: nil).category, .scam)
        XCTAssertEqual(heuristicsOnly(SampleEmails.giftCardScam).category, .scam)
        XCTAssertEqual(heuristicsOnly(SampleEmails.techSupportScam).category, .scam)
        XCTAssertEqual(heuristicsOnly(SampleEmails.paypalPhish).category, .phishing)

        // The same holds when a model is present but says safe or is unsure.
        let modelSafe = engine.makeVerdict(report: report(score: 0.8, signals: [urgency, threat]), assessment: assessment(risk: 60, suspicious: false, category: .safe), modelIdentifier: "m")
        XCTAssertTrue(modelSafe.isFlagged)
        XCTAssertNotEqual(modelSafe.category, .safe)

        // Every flagged verdict over the fixture corpus carries a non-safe category; quiet verdicts stay safe.
        for email in SampleEmails.all {
            let verdict = heuristicsOnly(email)
            if verdict.isFlagged {
                XCTAssertNotEqual(verdict.category, .safe, "\(email.subject) is flagged \(verdict.level) but labelled safe")
            }
        }
        for email in SampleEmails.benign where SampleEmails.benignScoreTolerances[email.messageID] == nil {
            XCTAssertEqual(heuristicsOnly(email).category, .safe, email.subject)
        }
    }

    func testMitigationsAndWeightlessSignalsNeverDriveTheCategory() {
        let brand = Signal(id: "mitigation.brand_authenticated", title: "Authenticated brand", detail: "…", severity: .info, weight: 0)
        let dmarc = Signal(id: "mitigation.dmarc_pass", title: "DMARC passed", detail: "…", severity: .info, weight: 0)
        let list = Signal(id: "sender.sender_header_list", title: "Mailing list", detail: "…", severity: .info, weight: 0)
        let quiet = engine.makeVerdict(report: report(score: 0, signals: [brand, dmarc, list]), assessment: nil, modelIdentifier: nil)
        XCTAssertEqual(quiet.level, .safe)
        XCTAssertEqual(quiet.category, .safe)

        for keyword in VerdictEngine.phishingKeywords + VerdictEngine.scamKeywords {
            for id in ["mitigation.brand_authenticated", "mitigation.dmarc_pass", "mitigation.newsletter_headers", "mitigation.internal_sender"] {
                XCTAssertFalse(id.contains(keyword), "\(id) must not match \(keyword)")
            }
        }
        XCTAssertEqual(VerdictEngine.derivedCategory(from: [brand], level: .safe), .safe)
        XCTAssertEqual(VerdictEngine.derivedCategory(from: [brand], level: .medium), .phishing)
    }
}

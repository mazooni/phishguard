import XCTest
@testable import PhishCore

/// The checked-in record of what the real local model answered about the fixtures (see the file's provenance
/// header). These tests keep the record and the corpus from drifting apart — a fixture added, renamed or
/// re-worded without re-running `Tools/PromptLab` would otherwise silently lose its measured answer, and the
/// demo would quietly fall back to rules-only verdicts.
final class MeasuredModelAssessmentsTests: XCTestCase {
    func testEveryFixtureHasAMeasuredAnswer() {
        for entry in SampleEmails.named {
            XCTAssertNotNil(
                MeasuredModelAssessments.assessment(forFixtureNamed: entry.name),
                "\(entry.name) has no measured model answer; re-run Tools/PromptLab and regenerate the file"
            )
        }
        XCTAssertEqual(MeasuredModelAssessments.byFixtureName.count, SampleEmails.named.count)
    }

    func testKeysAreFixtureNames() {
        let names = Set(SampleEmails.named.map(\.name))
        for key in MeasuredModelAssessments.byFixtureName.keys {
            XCTAssertTrue(names.contains(key), "\(key) is not a fixture name")
        }
    }

    func testMessageIDLookupResolvesTheSameAnswer() {
        for entry in SampleEmails.named {
            XCTAssertEqual(
                MeasuredModelAssessments.assessment(forMessageID: entry.email.messageID),
                MeasuredModelAssessments.assessment(forFixtureNamed: entry.name),
                entry.name
            )
        }
        XCTAssertEqual(MeasuredModelAssessments.byMessageID.count, SampleEmails.named.count, "message ids are unique")
    }

    /// The measurement is only worth keeping if it still says what the README and ARCHITECTURE tables say it
    /// said: the 4B called every malicious fixture suspicious and no benign one.
    func testTheMeasuredRunSeparatesTheCorpus() {
        for entry in SampleEmails.named {
            guard let assessment = MeasuredModelAssessments.assessment(forFixtureNamed: entry.name) else { continue }
            if entry.malicious {
                XCTAssertGreaterThanOrEqual(assessment.riskScore, 50, entry.name)
                XCTAssertTrue(assessment.isSuspicious, entry.name)
            } else {
                XCTAssertLessThan(assessment.riskScore, 50, entry.name)
            }
        }
    }

    /// Fused with the rules, the measured answers must still alert on every malicious fixture and on no benign
    /// one — the demo seeding shows exactly these verdicts.
    func testFusedVerdictsMatchTheGroundTruth() {
        let analyzer = HeuristicAnalyzer()
        let engine = VerdictEngine()
        let policy = AlertPolicy()
        for entry in SampleEmails.named {
            let report = analyzer.analyze(entry.email)
            let verdict = engine.makeVerdict(
                report: report,
                assessment: MeasuredModelAssessments.assessment(forFixtureNamed: entry.name),
                modelIdentifier: "mlx:\(MeasuredModelAssessments.modelRepository)"
            )
            XCTAssertEqual(policy.shouldAlert(verdict), entry.malicious, "\(entry.name) at \(verdict.confidence)")
        }
    }
}

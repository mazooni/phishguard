import XCTest
@testable import PhishCore

/// Regression tests for the review findings against `ModelOutputParser` (negated category labels, riskScore 1.0).
final class ModelOutputParserReviewTests: XCTestCase {
    private func category(_ raw: String) throws -> ThreatCategory {
        try ModelOutputParser.parseAssessment(from: #"{"category": "\#(raw)", "riskScore": 10}"#).category
    }

    // MARK: - Finding 64a: negated labels

    func testNegatedCategoryLabelsAreNotThePositiveClass() throws {
        XCTAssertEqual(try category("not phishing"), .safe)
        XCTAssertEqual(try category("Not Phishing"), .safe)
        XCTAssertEqual(try category("legitimate, not a scam"), .safe)
        XCTAssertEqual(try category("safe (not phishing)"), .safe)
        XCTAssertEqual(try category("non-malicious"), .safe)
        XCTAssertEqual(try category("no phishing detected"), .safe)
        XCTAssertEqual(try category("isn't spam"), .safe)
        XCTAssertEqual(try category("is not a scam"), .safe)
        XCTAssertEqual(try category("not suspicious"), .safe)
        XCTAssertEqual(try category("never phishing"), .safe)
    }

    func testClauseBeforeTheNegationWins() throws {
        XCTAssertEqual(try category("spam, not phishing"), .spam)
        XCTAssertEqual(try category("scam but not phishing"), .scam)
        XCTAssertEqual(try category("phishing, not spam"), .phishing)
    }

    func testPositiveLabelsContainingNegationSubstringsStillMatch() throws {
        XCTAssertEqual(try category("phishing"), .phishing)
        XCTAssertEqual(try category("notification scam"), .scam, "'notification' is not a negation")
        XCTAssertEqual(try category("nonsense phishing"), .phishing, "'nonsense' is not a negation")
        XCTAssertEqual(try category("normal"), .safe)
        XCTAssertEqual(try category("credential-phishing"), .phishing)
        XCTAssertEqual(try category("Fraud"), .scam)
        XCTAssertEqual(try category("junk mail"), .spam)
    }

    func testNegatedLabelDrivesTheDerivedFields() throws {
        let a = try ModelOutputParser.parseAssessment(from: #"{"category": "not phishing", "reasons": ["Sender verified"], "summary": "Looks fine."}"#)
        XCTAssertFalse(a.isSuspicious)
        XCTAssertEqual(a.category, .safe)
        XCTAssertEqual(a.riskScore, 5)

        // The category-in-the-isSuspicious-slot fallback honours the negation too.
        let b = try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": "not phishing", "reasons": ["x"]}"#)
        XCTAssertFalse(b.isSuspicious)
        XCTAssertEqual(b.category, .safe)

        // An unknown negated label stays unknown and is derived from the other fields.
        let c = try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": true, "category": "not sure", "riskScore": 70}"#)
        XCTAssertEqual(c.category, .phishing)
    }

    // MARK: - Finding 64b: riskScore written as a probability of exactly 1

    func testRiskScoreOneIsAProbabilityOnlyWhenWrittenAsAFraction() throws {
        func risk(_ literal: String) throws -> Int {
            try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": true, "category": "phishing", "riskScore": \#(literal)}"#).riskScore
        }
        XCTAssertEqual(try risk("1.0"), 100)
        XCTAssertEqual(try risk("1.00"), 100)
        XCTAssertEqual(try risk("1e0"), 100)
        XCTAssertEqual(try risk("1"), 1, "an integer 1 is a score of 1/100")
        XCTAssertEqual(try risk("0.9"), 90)
        XCTAssertEqual(try risk("0.0"), 0)
        XCTAssertEqual(try risk("100.0"), 100)
        XCTAssertEqual(try risk("12.6"), 13)
        XCTAssertEqual(try risk(#""1.0""#), 100)
        XCTAssertEqual(try risk(#""0.35""#), 35)
        XCTAssertEqual(try risk(#""1""#), 1)
        XCTAssertEqual(try risk(#""1.0%""#), 1, "a percentage is never a probability")
        XCTAssertEqual(try risk(#""1/100""#), 1)
        XCTAssertEqual(try risk(#""85%""#), 85)
        XCTAssertEqual(try risk(#""1.0 (certain)""#), 100)
        XCTAssertEqual(try risk("true"), 80)
    }
}

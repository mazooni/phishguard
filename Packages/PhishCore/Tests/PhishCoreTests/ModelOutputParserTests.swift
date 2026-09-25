import XCTest
@testable import PhishCore

final class ModelOutputParserTests: XCTestCase {
    private let clean = #"{"isSuspicious": true, "category": "phishing", "riskScore": 88, "reasons": ["DKIM failed", "Lookalike link"], "summary": "Credential phish."}"#

    func testCleanJSON() throws {
        let a = try ModelOutputParser.parseAssessment(from: clean)
        XCTAssertEqual(a, ModelAssessment(isSuspicious: true, category: .phishing, riskScore: 88, reasons: ["DKIM failed", "Lookalike link"], summary: "Credential phish."))
    }

    func testThinkTagsFencesAndProseAreStripped() throws {
        let variants = [
            "<think>Let me reason about this...\n{ not json }\n</think>\n" + clean,
            "<THINK>unterminated thinking that never closes" + "\n</think>" + clean,
            "Sure! Here is the analysis:\n```json\n" + clean + "\n```\nHope this helps.",
            "```\n" + clean + "\n```",
            "Answer: " + clean + " Let me know if you need more.",
            "Some prose with { braces } first, then " + clean,
            "```json\n" + clean,   // fence never closed
        ]
        for text in variants {
            let a = try ModelOutputParser.parseAssessment(from: text)
            XCTAssertEqual(a.riskScore, 88, text)
            XCTAssertEqual(a.category, .phishing, text)
        }
    }

    func testUnterminatedThinkWithoutJSONThrows() {
        XCTAssertThrowsError(try ModelOutputParser.parseAssessment(from: "<think>still thinking about {objects}"))
    }

    func testTruncatedJSONIsRepaired() throws {
        let cases: [(String, Int, ThreatCategory)] = [
            (#"{"isSuspicious": true, "category": "scam", "riskScore": 91, "reasons": ["Gift cards", "Secre"#, 91, .scam),
            (#"{"isSuspicious": true, "category": "scam", "riskScore": 9"#, 9, .scam),
            (#"{"isSuspicious": true, "category": "scam", "riskScore":"#, 80, .scam),
            (#"{"isSuspicious": true, "category": "scam", "riskScore": 91, "reasons": ["a", "b"], "summary": "Truncated summ"#, 91, .scam),
            (#"{"isSuspicious": true, "category": "sc"#, 80, .phishing),
            (#"{"isSuspicious": true, "category": "scam", "riskScore": 70, "reasons": ["x",  "#, 70, .scam),
        ]
        for (text, risk, category) in cases {
            let a = try ModelOutputParser.parseAssessment(from: text)
            XCTAssertEqual(a.riskScore, risk, text)
            XCTAssertEqual(a.category, category, text)
        }
        let repaired = try ModelOutputParser.parseAssessment(from: cases[0].0)
        XCTAssertEqual(repaired.reasons, ["Gift cards", "Secre"])
        // A truncation that leaves no complete field is an error, not a fabricated assessment.
        XCTAssertThrowsError(try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": tr"#))
    }

    func testWrongTypesAreCoerced() throws {
        let a = try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": "Yes", "category": "PHISH", "riskScore": "85%", "reasons": "one\ntwo\n- three", "summary": ""}"#)
        XCTAssertTrue(a.isSuspicious)
        XCTAssertEqual(a.category, .phishing)
        XCTAssertEqual(a.riskScore, 85)
        XCTAssertEqual(a.reasons, ["one", "two", "three"])
        XCTAssertEqual(a.summary, "one. two. three.", "missing summary is built from reasons")

        let b = try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": 0, "category": "Legitimate", "riskScore": 12.6, "reasons": ["only reason"]}"#)
        XCTAssertFalse(b.isSuspicious)
        XCTAssertEqual(b.category, .safe)
        XCTAssertEqual(b.riskScore, 13)
        XCTAssertEqual(b.summary, "only reason.")

        let c = try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": 1, "category": "fraud", "riskScore": 0.9, "reasons": "a; b; c", "summary": "s"}"#)
        XCTAssertTrue(c.isSuspicious)
        XCTAssertEqual(c.category, .scam)
        XCTAssertEqual(c.riskScore, 90, "probabilities are scaled to 0…100")
        XCTAssertEqual(c.reasons, ["a", "b", "c"])

        let d = try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": "false", "category": "malicious spoofing attempt", "riskScore": "high", "reasons": [], "summary": "x"}"#)
        XCTAssertFalse(d.isSuspicious)
        XCTAssertEqual(d.category, .phishing)
        XCTAssertEqual(d.riskScore, 85)
    }

    func testCategorySynonymsAndDerivation() throws {
        func category(_ raw: String) throws -> ThreatCategory {
            try ModelOutputParser.parseAssessment(from: #"{"category": "\#(raw)", "riskScore": 70}"#).category
        }
        XCTAssertEqual(try category("Phishing"), .phishing)
        XCTAssertEqual(try category("phish"), .phishing)
        XCTAssertEqual(try category("credential-phishing"), .phishing)
        XCTAssertEqual(try category("spoof"), .phishing)
        XCTAssertEqual(try category("Fraud"), .scam)
        XCTAssertEqual(try category("SCAM/BEC"), .scam)
        XCTAssertEqual(try category("junk mail"), .spam)
        XCTAssertEqual(try category("benign"), .safe)
        XCTAssertEqual(try category("legit"), .safe)

        // Unknown category → derived from isSuspicious.
        let unknownSuspicious = try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": true, "category": "weird", "riskScore": 60}"#)
        XCTAssertEqual(unknownSuspicious.category, .phishing)
        let unknownSafe = try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": false, "category": "weird", "riskScore": 10}"#)
        XCTAssertEqual(unknownSafe.category, .safe)
        // Missing isSuspicious → derived from category / risk.
        XCTAssertTrue(try ModelOutputParser.parseAssessment(from: #"{"category": "scam"}"#).isSuspicious)
        XCTAssertFalse(try ModelOutputParser.parseAssessment(from: #"{"category": "safe", "riskScore": 10}"#).isSuspicious)
        XCTAssertTrue(try ModelOutputParser.parseAssessment(from: #"{"riskScore": 75}"#).isSuspicious)
        // Missing riskScore → derived.
        XCTAssertEqual(try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": true, "category": "phishing"}"#).riskScore, 80)
        XCTAssertEqual(try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": false, "category": "safe"}"#).riskScore, 5)
    }

    func testLooseJSONSyntax() throws {
        let python = "{'isSuspicious': True, 'category': 'scam', 'riskScore': 77, 'reasons': ['it\\'s bad', \"quoted \\\"x\\\"\"], 'summary': None}"
        let a = try ModelOutputParser.parseAssessment(from: python)
        XCTAssertTrue(a.isSuspicious)
        XCTAssertEqual(a.category, .scam)
        XCTAssertEqual(a.riskScore, 77)
        XCTAssertEqual(a.reasons, ["it's bad", "quoted \"x\""])

        let unquoted = "{isSuspicious: false, category: safe, riskScore: 5, reasons: [], summary: \"Fine\", }"
        let b = try ModelOutputParser.parseAssessment(from: unquoted)
        XCTAssertFalse(b.isSuspicious)
        XCTAssertEqual(b.category, .safe)
        XCTAssertEqual(b.reasons, [])
        XCTAssertEqual(b.summary, "Fine")

        let comments = "{ // model note\n \"isSuspicious\": true, /* block */ \"category\": \"phishing\", \"riskScore\": 66, }"
        XCTAssertEqual(try ModelOutputParser.parseAssessment(from: comments).riskScore, 66)
    }

    func testAlternativeKeyNamesAndReasonObjects() throws {
        let a = try ModelOutputParser.parseAssessment(from: #"{"is_suspicious": true, "classification": "scam", "risk_score": 70, "indicators": [{"reason": "gift cards"}, {"text": "urgency"}, 42], "explanation": "Gift card scam."}"#)
        XCTAssertTrue(a.isSuspicious)
        XCTAssertEqual(a.category, .scam)
        XCTAssertEqual(a.riskScore, 70)
        XCTAssertEqual(a.reasons, ["gift cards", "urgency", "42"])
        XCTAssertEqual(a.summary, "Gift card scam.")
    }

    func testClampingAndLimits() throws {
        let a = try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": true, "category": "phishing", "riskScore": 140, "reasons": ["a","b","c","d","e","f","g"], "summary": "s"}"#)
        XCTAssertEqual(a.riskScore, 100)
        XCTAssertEqual(a.reasons.count, 6)
        let b = try ModelOutputParser.parseAssessment(from: #"{"isSuspicious": false, "category": "safe", "riskScore": -5, "reasons": ["  ", "1. numbered", "• bullet"], "summary": "s"}"#)
        XCTAssertEqual(b.riskScore, 0)
        XCTAssertEqual(b.reasons, ["numbered", "bullet"])
    }

    func testFirstObjectWithoutKnownKeysIsSkipped() throws {
        let text = #"{"note": "ignore me"} then the real one {"isSuspicious": true, "category": "phishing", "riskScore": 90, "reasons": [], "summary": "s"}"#
        XCTAssertEqual(try ModelOutputParser.parseAssessment(from: text).riskScore, 90)
    }

    func testErrors() {
        XCTAssertThrowsError(try ModelOutputParser.parseAssessment(from: "no json here")) { error in
            XCTAssertEqual(error as? ModelOutputParserError, .noJSONObjectFound)
        }
        XCTAssertThrowsError(try ModelOutputParser.parseAssessment(from: "{}")) { error in
            guard case .invalidJSON? = error as? ModelOutputParserError else { return XCTFail("expected invalidJSON, got \(error)") }
        }
        XCTAssertThrowsError(try ModelOutputParser.parseAssessment(from: #"{"foo": 1, "bar": [1,2]}"#))
        XCTAssertThrowsError(try ModelOutputParser.parseAssessment(from: ""))
        XCTAssertThrowsError(try ModelOutputParser.parseAssessment(from: "Sorry, I can't help with that request."))
    }

    func testHostileInputIsBounded() {
        let text = String(repeating: "{", count: 100_000) + "\"isSuspicious\": true"
        let start = Date()
        _ = try? ModelOutputParser.parseAssessment(from: text)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2.0)
    }
}

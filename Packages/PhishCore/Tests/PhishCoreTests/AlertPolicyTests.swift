import XCTest
@testable import PhishCore

final class AlertPolicyTests: XCTestCase {
    private func verdict(_ level: RiskLevel) -> Verdict {
        Verdict(category: .phishing, confidence: 0.5, level: level, reasons: [], summary: "", heuristicScore: 0.5)
    }

    func testDefaultMinimumIsMedium() {
        let policy = AlertPolicy()
        XCTAssertEqual(policy.minimumLevel, .medium)
        XCTAssertFalse(policy.shouldAlert(verdict(.safe)))
        XCTAssertFalse(policy.shouldAlert(verdict(.low)))
        XCTAssertTrue(policy.shouldAlert(verdict(.medium)))
        XCTAssertTrue(policy.shouldAlert(verdict(.high)))
    }

    func testHighOnly() {
        let policy = AlertPolicy(minimumLevel: .high)
        XCTAssertFalse(policy.shouldAlert(verdict(.medium)))
        XCTAssertTrue(policy.shouldAlert(verdict(.high)))
    }

    func testNeverAlertsForSafeEvenWhenMinimumIsSafe() {
        let policy = AlertPolicy(minimumLevel: .safe)
        XCTAssertFalse(policy.shouldAlert(verdict(.safe)))
        XCTAssertTrue(policy.shouldAlert(verdict(.low)))
    }

    func testCodableRoundTrip() throws {
        let policy = AlertPolicy(minimumLevel: .low)
        let data = try JSONEncoder().encode(policy)
        XCTAssertEqual(try JSONDecoder().decode(AlertPolicy.self, from: data), policy)
    }
}

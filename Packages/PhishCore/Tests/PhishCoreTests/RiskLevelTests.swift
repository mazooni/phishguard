import XCTest
@testable import PhishCore

final class RiskLevelTests: XCTestCase {
    func testOrdering() {
        XCTAssertLessThan(RiskLevel.safe, .low)
        XCTAssertLessThan(RiskLevel.low, .medium)
        XCTAssertLessThan(RiskLevel.medium, .high)
        XCTAssertEqual(RiskLevel.allCases.sorted(), [.safe, .low, .medium, .high])
        XCTAssertEqual(RiskLevel.allCases.max(), .high)
    }

    func testSeverityOrdering() {
        XCTAssertLessThan(Severity.info, .low)
        XCTAssertLessThan(Severity.low, .medium)
        XCTAssertLessThan(Severity.medium, .high)
        XCTAssertEqual([Severity.high, .info, .medium, .low].sorted(), [.info, .low, .medium, .high])
    }

    func testConfidenceMapping() {
        XCTAssertEqual(RiskLevel(confidence: 1.0), .high)
        XCTAssertEqual(RiskLevel(confidence: 0.75), .high)
        XCTAssertEqual(RiskLevel(confidence: 0.5), .medium)
        XCTAssertEqual(RiskLevel(confidence: 0.3), .low)
        XCTAssertEqual(RiskLevel(confidence: 0.29), .safe)
        XCTAssertEqual(RiskLevel(confidence: -1), .safe)
    }

    func testRawValuesAreStable() {
        XCTAssertEqual(RiskLevel.medium.rawValue, "medium")
        XCTAssertEqual(RiskLevel(rawValue: "high"), .high)
    }
}

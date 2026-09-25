import Foundation

/// Final risk level. Ordered: safe < low < medium < high.
public enum RiskLevel: String, Codable, Sendable, Comparable, CaseIterable {
    case safe
    case low
    case medium
    case high

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool {
        let all = RiskLevel.allCases
        guard let l = all.firstIndex(of: lhs), let r = all.firstIndex(of: rhs) else { return false }
        return l < r
    }

    public var displayName: String {
        switch self {
        case .safe: return "Safe"
        case .low: return "Low risk"
        case .medium: return "Medium risk"
        case .high: return "High risk"
        }
    }

    /// Level for a fused confidence: ≥0.75 high, ≥0.5 medium, ≥0.3 low, else safe.
    public init(confidence: Double) {
        switch confidence {
        case 0.75...: self = .high
        case 0.5..<0.75: self = .medium
        case 0.3..<0.5: self = .low
        default: self = .safe
        }
    }
}

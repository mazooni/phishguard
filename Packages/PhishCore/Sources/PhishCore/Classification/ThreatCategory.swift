import Foundation

/// Category assigned by the model and/or heuristics.
public enum ThreatCategory: String, Codable, Sendable, CaseIterable {
    case phishing
    case scam
    case spam
    case safe

    public var displayName: String {
        switch self {
        case .phishing: return "Phishing"
        case .scam: return "Scam"
        case .spam: return "Spam"
        case .safe: return "Safe"
        }
    }
}

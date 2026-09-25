import Foundation

/// Structured output of an LLM classifier. Mirrors the JSON schema in `PromptBuilder.jsonOutputInstructions`
/// and the `@Generable` struct used by the Apple Foundation Models path.
public struct ModelAssessment: Codable, Sendable, Equatable {
    public var isSuspicious: Bool
    public var category: ThreatCategory
    /// 0...100
    public var riskScore: Int
    /// ≤ 6 short reasons.
    public var reasons: [String]
    /// One or two sentences.
    public var summary: String

    public init(isSuspicious: Bool, category: ThreatCategory, riskScore: Int, reasons: [String], summary: String) {
        self.isSuspicious = isSuspicious
        self.category = category
        self.riskScore = min(max(riskScore, 0), 100)
        self.reasons = Array(reasons.prefix(6))
        self.summary = summary
    }
}

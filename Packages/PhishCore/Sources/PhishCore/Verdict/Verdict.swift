import Foundation

/// The fused result for one email. This (not the email) is what gets persisted and shown.
public struct Verdict: Sendable, Codable, Equatable {
    public var category: ThreatCategory
    /// 0...1 confidence that the email is malicious.
    public var confidence: Double
    public var level: RiskLevel
    /// Ordered by severity, descending.
    public var reasons: [Reason]
    public var summary: String
    public var heuristicScore: Double
    public var modelRiskScore: Int?
    /// nil ⇒ heuristics only.
    public var modelIdentifier: String?

    public init(
        category: ThreatCategory,
        confidence: Double,
        level: RiskLevel,
        reasons: [Reason],
        summary: String,
        heuristicScore: Double,
        modelRiskScore: Int? = nil,
        modelIdentifier: String? = nil
    ) {
        self.category = category
        self.confidence = confidence
        self.level = level
        self.reasons = reasons
        self.summary = summary
        self.heuristicScore = heuristicScore
        self.modelRiskScore = modelRiskScore
        self.modelIdentifier = modelIdentifier
    }

    /// True when the level is anything other than `.safe`.
    public var isFlagged: Bool { level != .safe }
}

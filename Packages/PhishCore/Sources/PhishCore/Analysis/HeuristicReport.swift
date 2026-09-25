import Foundation

/// Output of `HeuristicAnalyzer`. Safe to keep in memory and to serialize for diagnostics
/// (it holds no raw message, only derived text/links).
public struct HeuristicReport: Sendable, Codable {
    /// Maximum number of links kept in `links`.
    public static let maxLinks = 50
    /// Number of characters kept in `bodyExcerpt`.
    public static let excerptLength = 600

    public var signals: [Signal]
    /// 0...1 aggregate heuristic score.
    public var score: Double
    /// Deduplicated links, ≤ 50.
    public var links: [EmailLink]
    public var authentication: AuthenticationResults
    /// Plain text derived from `textBody` or the stripped `htmlBody`.
    public var bodyText: String
    /// First `excerptLength` characters of `bodyText`, for prompts and evidence.
    public var bodyExcerpt: String

    public init(
        signals: [Signal] = [],
        score: Double = 0,
        links: [EmailLink] = [],
        authentication: AuthenticationResults = AuthenticationResults(),
        bodyText: String = "",
        bodyExcerpt: String? = nil
    ) {
        self.signals = signals
        self.score = min(max(score, 0), 1)
        self.links = Array(links.prefix(Self.maxLinks))
        self.authentication = authentication
        self.bodyText = bodyText
        self.bodyExcerpt = bodyExcerpt ?? String(bodyText.prefix(Self.excerptLength))
    }

    /// Highest severity among `signals`, nil when there are none.
    public var maxSeverity: Severity? { signals.map(\.severity).max() }
}

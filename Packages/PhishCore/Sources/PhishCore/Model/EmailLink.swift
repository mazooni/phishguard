import Foundation

/// A hyperlink found in the body. `anchorText` is the visible text (nil for bare URLs in plain text).
public struct EmailLink: Hashable, Sendable, Codable {
    public var href: String
    public var anchorText: String?

    public init(href: String, anchorText: String? = nil) {
        self.href = href
        self.anchorText = anchorText
    }

    /// Lowercased host of `href`, nil when it cannot be determined.
    public var host: String? { DomainAnalysis.host(of: href) }
}

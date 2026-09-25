import Foundation

public enum ReasonSource: String, Codable, Sendable {
    case heuristic
    case model
}

/// A user-facing reason attached to a `Verdict`. Persisted (as JSON) in `FlaggedEmailRecord.reasonsJSON`,
/// so `detail` must stay short (≤ 300 chars) and must not contain raw message content beyond snippets.
public struct Reason: Identifiable, Hashable, Sendable, Codable {
    public var id: String
    public var title: String
    public var detail: String
    public var severity: Severity
    public var source: ReasonSource

    public init(id: String, title: String, detail: String, severity: Severity, source: ReasonSource) {
        self.id = id
        self.title = title
        self.detail = String(detail.prefix(300))
        self.severity = severity
        self.source = source
    }

    public init(signal: Signal) {
        self.init(id: signal.id, title: signal.title, detail: signal.detail, severity: signal.severity, source: .heuristic)
    }
}

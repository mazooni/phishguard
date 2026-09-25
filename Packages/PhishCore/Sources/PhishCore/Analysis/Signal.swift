import Foundation

/// Severity of a heuristic signal. Ordered: info < low < medium < high.
public enum Severity: String, Codable, Sendable, Comparable {
    case info
    case low
    case medium
    case high

    private var rank: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }
}

/// One heuristic finding. `id` is a stable key such as "auth.dkim_fail" or "link.anchor_host_mismatch".
///
/// Id conventions (used by `VerdictEngine` to derive a category when no model assessment is present; the exact
/// fragment lists are `VerdictEngine.phishingKeywords` / `scamKeywords`):
/// - credential / link / malware / sender-spoof / authentication-failure / QR-lure ids contain one of: "credential",
///   "link", "url", "login", "password", "malware", "lookalike", "display_name", "from_equals_recipient",
///   "brand_unauthenticated", "dmarc_fail", "dkim_fail", "dkim_unaligned", "spf_fail", "qr_code" → phishing
/// - money / impersonation-scam ids contain one of: "payment", "gift", "wire", "invoice", "crypto", "bank",
///   "executive_impersonation", "secrecy", "advance_fee", "support_callback", "sextortion" → scam
/// - benign mitigations use the "mitigation." prefix, severity `.info` and weight 0 (their negative contribution is
///   applied inside `HeuristicAnalyzer`); weight-0 signals never drive a category and mitigation ids must not contain
///   any of the fragments above.
///
/// Families emitted by `HeuristicAnalyzer`: `auth.*`, `sender.*`, `link.*`, `content.*`, `attachment.*`, `mitigation.*`.
public struct Signal: Identifiable, Hashable, Sendable, Codable {
    public var id: String
    /// Short, user-facing title.
    public var title: String
    /// User-facing explanation including evidence (≤ 300 chars).
    public var detail: String
    public var severity: Severity
    /// 0...1 contribution used by `VerdictEngine` / `HeuristicAnalyzer` scoring.
    public var weight: Double

    public init(id: String, title: String, detail: String, severity: Severity, weight: Double) {
        self.id = id
        self.title = title
        self.detail = String(detail.prefix(300))
        self.severity = severity
        self.weight = min(max(weight, 0), 1)
    }
}

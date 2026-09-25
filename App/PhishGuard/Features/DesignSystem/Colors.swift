import PhishCore
import SwiftUI

// MARK: - Risk level presentation

extension RiskLevel {
    /// Badge / gauge color: high red, medium orange, low yellow, safe green.
    var color: Color {
        switch self {
        case .safe: return .green
        case .low: return .yellow
        case .medium: return .orange
        case .high: return .red
        }
    }

    /// Short label used in compact badges ("High", "Medium", …).
    var shortName: String {
        switch self {
        case .safe: return "Safe"
        case .low: return "Low"
        case .medium: return "Medium"
        case .high: return "High"
        }
    }

    var symbolName: String {
        switch self {
        case .safe: return "checkmark.shield.fill"
        case .low: return "exclamationmark.shield"
        case .medium: return "exclamationmark.shield.fill"
        case .high: return "xmark.shield.fill"
        }
    }

    /// Plain-language description used by the alert-level picker.
    var alertDescription: String {
        switch self {
        case .safe:
            return "Alerts for every email, including ones that look safe. Not recommended."
        case .low:
            return "Alert about anything that looks even slightly suspicious. Expect more alerts, including some false alarms."
        case .medium:
            return "Alert when an email is probably phishing or a scam. A good balance for most people."
        case .high:
            return "Alert only when PhishGuard is very confident. Fewest alerts, but subtle scams may slip through."
        }
    }
}

// MARK: - Severity presentation

extension Severity {
    var color: Color {
        switch self {
        case .info: return .secondary
        case .low: return .yellow
        case .medium: return .orange
        case .high: return .red
        }
    }

    var symbolName: String {
        switch self {
        case .info: return "info.circle.fill"
        case .low: return "exclamationmark.circle.fill"
        case .medium: return "exclamationmark.triangle.fill"
        case .high: return "exclamationmark.octagon.fill"
        }
    }

    var displayName: String {
        switch self {
        case .info: return "Info"
        case .low: return "Low"
        case .medium: return "Medium"
        case .high: return "High"
        }
    }
}

// MARK: - Threat category presentation

extension ThreatCategory {
    var symbolName: String {
        switch self {
        case .phishing: return "fish.fill"
        case .scam: return "creditcard.trianglebadge.exclamationmark"
        case .spam: return "envelope.badge.fill"
        case .safe: return "checkmark.seal.fill"
        }
    }

    var color: Color {
        switch self {
        case .phishing: return .red
        case .scam: return .orange
        case .spam: return .gray
        case .safe: return .green
        }
    }
}

// MARK: - Mail provider presentation

extension MailProvider {
    var symbolName: String {
        switch self {
        case .gmail: return "envelope.fill"
        case .microsoft: return "envelope.open.fill"
        case .imap: return "at"
        }
    }

    var brandColor: Color {
        switch self {
        case .gmail: return Color(red: 0.86, green: 0.20, blue: 0.18)
        case .microsoft: return Color(red: 0.00, green: 0.47, blue: 0.83)
        case .imap: return Color(red: 0.36, green: 0.42, blue: 0.51)
        }
    }

    /// One-letter monogram shown in provider avatars.
    var monogram: String {
        switch self {
        case .gmail: return "G"
        case .microsoft: return "M"
        case .imap: return "@"
        }
    }
}

// MARK: - Reason source presentation

extension ReasonSource {
    var tagName: String {
        switch self {
        case .heuristic: return "Heuristic"
        case .model: return "AI"
        }
    }

    var symbolName: String {
        switch self {
        case .heuristic: return "function"
        case .model: return "sparkles"
        }
    }
}

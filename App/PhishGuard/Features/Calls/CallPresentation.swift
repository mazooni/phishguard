import Foundation
import PhishCore
import SwiftUI

// MARK: - Model names

/// User-facing name for a call verdict's `modelIdentifier` (`"openai:<model id>"` from the relay, nil for rules only).
enum CallModelDisplay {
    static func name(forIdentifier identifier: String?) -> String {
        guard let identifier, !identifier.isEmpty else { return "Call rules only" }
        if identifier.hasPrefix("openai:") {
            let model = String(identifier.dropFirst("openai:".count))
            return model.isEmpty ? "OpenAI" : "OpenAI \(model)"
        }
        return identifier
    }

    /// Footnote for the detail screen.
    static func footnote(forIdentifier identifier: String?) -> String {
        guard let identifier, !identifier.isEmpty else {
            return "Scored by the relay with PhishGuard's call rules only (no language model answered)."
        }
        return "Transcribed and scored by the relay with \(name(forIdentifier: identifier)) plus PhishGuard's call rules."
    }
}

// MARK: - Durations

enum CallDurationFormat {
    /// "0:42", "4:14", "1:02:03".
    static func string(seconds: Int) -> String {
        let total = max(0, seconds)
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        let secs = total % 60
        if hours > 0 {
            return String(format: "%d:%02d:%02d", hours, minutes, secs)
        }
        return String(format: "%d:%02d", minutes, secs)
    }

    /// Elapsed time of a call in progress, from its start to `now`.
    static func elapsed(since start: Date, now: Date) -> String {
        string(seconds: Int(now.timeIntervalSince(start).rounded(.down)))
    }
}

// MARK: - Level descriptions for the call alert picker

extension RiskLevel {
    /// Plain-language description used by the call alert level picker.
    var callAlertDescription: String {
        switch self {
        case .safe:
            return "Warn about every call. Not recommended."
        case .low:
            return "Warn about anything that sounds even slightly off. More warnings, including some false alarms."
        case .medium:
            return "Warn when the call is probably a scam. A good balance for most people."
        case .high:
            return "Warn only when PhishGuard is very sure. Fewest warnings, but subtle scams may slip through."
        }
    }
}

// MARK: - Speakers and statuses

extension Speaker {
    var color: Color {
        switch self {
        case .caller: return .red
        case .user: return .blue
        }
    }
}

extension CallGuardClient.ConnectionState {
    var label: String {
        switch self {
        case .disconnected: return "Not connected"
        case .connecting: return "Connecting…"
        case .connected: return "Live"
        }
    }

    var color: Color {
        switch self {
        case .disconnected: return .secondary
        case .connecting: return .orange
        case .connected: return .green
        }
    }
}

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

// MARK: - AI-voice assessment

extension VoiceStatus {
    /// What the app says about the caller's voice; nil for the statuses it shows nothing for (inconclusive,
    /// unavailable, and one a newer relay made up).
    var displayTitle: String? {
        switch self {
        case .analyzing: return "Checking the caller's voice…"
        case .human: return "Voice sounds human"
        case .synthetic: return CallVoiceDisplay.detectedTitle
        case .inconclusive, .unavailable, .unknown: return nil
        }
    }

    var symbolName: String {
        switch self {
        case .synthetic: return "waveform.badge.exclamationmark"
        case .human: return "person.wave.2"
        case .analyzing, .inconclusive, .unavailable, .unknown: return "waveform"
        }
    }

    /// A warning tint for a synthetic voice, quiet for everything else. Deliberately not `RiskLevel.color`: the
    /// voice check is not a risk level, and never recolours the gauge or the badge.
    var color: Color {
        switch self {
        case .synthetic: return .orange
        case .analyzing, .human, .inconclusive, .unavailable, .unknown: return .secondary
        }
    }
}

/// Wording and number formatting for the AI-voice check. None of it is scam wording: a synthetic voice is not by
/// itself a scam, and these strings only ever sit next to the verdict's own.
enum CallVoiceDisplay {
    static let detectedTitle = "AI voice detected"
    /// The caption label of a call row.
    static let rowLabel = "AI voice"
    /// The live card, while the call is on.
    static let liveDetail = "This caller's voice appears to be AI-generated."
    /// A call row with no summary of its own (a call listed only because of the caller's voice).
    static let listSummary = "The caller's voice appeared to be AI-generated."
    /// The detail screen's card.
    static let explanation = "The caller's voice appeared to be AI-generated. That alone does not prove the call was a scam — automated assistants make legitimate calls too — but be careful if the caller claimed to be someone you know."
    /// The detail screen's reasons section, for a call with no scam signs on record.
    static let listedForVoiceOnly = "This call is listed because the caller's voice appeared to be AI-generated. No signs of a scam were recorded."
    /// Under the caller on a voice-only call's detail screen, in place of the scam verdict's badge and gauge.
    static let noScamSigns = "No signs of a scam were found in what was said."
    static let noScamVerdict = "What was said on this call was not scored for scam signs."
    static let humanFact = "Sounded human"

    /// 0…1 → 0…100, clamped and rounded.
    static func percent(_ value: Double) -> Int {
        guard value.isFinite else { return 0 }
        return Int((min(max(value, 0), 1) * 100).rounded())
    }

    /// "About 87% of the caller's speech sounded AI-generated."; nil when there is no share to speak of (none
    /// recorded, or one that rounds to nothing).
    static func shareText(_ share: Double?) -> String? {
        guard let share else { return nil }
        let value = percent(share)
        guard value > 0 else { return nil }
        return "About \(value)% of the caller's speech sounded AI-generated."
    }

    /// "Detector confidence: 93%."; nil when none was recorded.
    static func confidenceText(_ confidence: Double?) -> String? {
        guard let confidence else { return nil }
        let value = percent(confidence)
        guard value > 0 else { return nil }
        return "Detector confidence: \(value)%."
    }

    /// The share and the confidence on one line, whichever of them there are; nil when there is neither.
    static func measurement(share: Double?, confidence: Double?) -> String? {
        let parts = [shareText(share), confidenceText(confidence)].compactMap { $0 }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }

    /// The live card's sentence under "AI voice detected", with the share when it means something.
    static func liveMessage(share: Double) -> String {
        guard let text = shareText(share) else { return liveDetail }
        return liveDetail + " " + text
    }

    /// User-facing name for an assessment's `provider` (`"<vendor>:<model>"`); nil when there is none.
    static func providerName(forIdentifier identifier: String?) -> String? {
        guard let identifier, !identifier.isEmpty else { return nil }
        if identifier.hasPrefix("modulate:") { return "Modulate" }
        return identifier
    }

    /// Footnote for the detail screen; nil unless the check reached a judgement (human or synthetic).
    static func footnote(status: VoiceStatus?, provider: String?) -> String? {
        guard status == .human || status == .synthetic else { return nil }
        if let provider, provider.hasPrefix("demo:") {
            return "The AI-voice result on this call is part of the relay's scripted demo."
        }
        guard let name = providerName(forIdentifier: provider) else {
            return "The caller's voice was checked for AI-generated speech."
        }
        return "The caller's voice was checked for AI-generated speech by \(name)."
    }

    /// What a call row shows under the caller. A call listed only because of the caller's voice (synthetic, scam
    /// level safe) says so — its verdict's own summary would read "No signs of a scam so far." right under a
    /// warning. Every other call shows the verdict's summary, or the scam fallback without one: a call with a
    /// scam level keeps its scam wording whatever the voice check said.
    static func rowSummary(summary: String, level: RiskLevel, voiceStatus: VoiceStatus?) -> String {
        if voiceStatus == .synthetic, level == .safe { return listSummary }
        if !summary.isEmpty { return summary }
        return CallAlertText.fallbackBody
    }

    /// One line for the shared diagnostics text; nil when no detector ran on the call.
    static func diagnostics(statusRaw: String?, share: Double?, confidence: Double?, provider: String?) -> String? {
        guard let statusRaw else { return nil }
        var details: [String] = []
        if let share { details.append("synthetic share \(percent(share))%") }
        if let confidence { details.append("confidence \(percent(confidence))%") }
        if let provider, !provider.isEmpty { details.append(provider) }
        return "AI voice check: \(statusRaw)" + (details.isEmpty ? "" : " (\(details.joined(separator: ", ")))")
    }
}

/// Shown where the risk badge would be on a call listed only because of the caller's voice.
struct CallVoiceBadge: View {
    var compact = false

    var body: some View {
        Label(CallVoiceDisplay.rowLabel, systemImage: VoiceStatus.synthetic.symbolName)
            .labelStyle(.titleAndIcon)
            .font(compact ? .caption2.weight(.bold) : .caption.weight(.bold))
            .padding(.horizontal, compact ? 6 : 8)
            .padding(.vertical, compact ? 2 : 4)
            .background(VoiceStatus.synthetic.color.opacity(0.16), in: Capsule())
            .foregroundStyle(VoiceStatus.synthetic.color)
            .accessibilityLabel(CallVoiceDisplay.detectedTitle)
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

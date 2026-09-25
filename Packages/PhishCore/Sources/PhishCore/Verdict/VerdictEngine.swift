import Foundation

/// Fuses the heuristic report with an optional model assessment (see ARCHITECTURE.md "Confidence fusion").
///
/// **The rules and the model are two independent detectors.** Either may raise the alert on its own and neither
/// may veto the other, so the fusion is a maximum rather than an average:
///
///     confidence = clamp(max(heuristicScore, modelScore) + agreementBonus)        // modelScore = riskScore/100
///
/// The old `0.5*heuristicScore + 0.5*modelScore` average made each detector a veto on the other: with heuristics
/// at 0 the model had to return a flawless 100 just to touch the 0.5 medium threshold, so a correct model verdict
/// of 90 was thrown away, and symmetrically a model that said "safe" halved a heuristic score that rested on hard
/// structural evidence. A maximum has neither failure: a detector that is certain is believed, a detector that is
/// quiet is simply out-voted rather than counted as a vote for "safe". (A noisy-OR, `h + m - h*m`, behaves the
/// same way at the extremes; the maximum was chosen because it is exactly readable off the two scores, which
/// matters when a verdict has to be explained in the UI.)
///
/// This is safe because neither detector is trusted to *lower* a verdict — only to raise one — and because the
/// one shape a small on-device model reliably gets wrong is fenced off by `authenticatedBrandConfidenceCap`
/// below. Everything else the model can now flag on its own is a message the rules had no opinion about.
///
/// In order:
/// - `assessment == nil` (model unavailable, erroring, out of budget, or declined) ⇒ `confidence = heuristicScore`,
///   exactly the old heuristics-only behaviour.
/// - agreement bonus: +`agreementBonus` (0.1) when both detectors are independently elevated — the model says
///   suspicious *and* scores at least `agreementModelScore` (0.5), and the heuristics hold at least one
///   high-severity *structural* signal (`sender.*`, `link.*`, `auth.*`, `attachment.*`). Two detectors that agree
///   about the message itself are worth more than the louder one alone; a phrase found in the body may not
///   amplify the model, because that is the model re-reading its own evidence.
/// - corroborated evidence floor: heuristics of `corroboratedEvidenceScore` or more, resting on at least two
///   weighted signals of which one is a high-severity structural signal, stay at `corroboratedEvidenceFloor`
///   (medium) whatever the model says. The maximum already implies this; it is kept as an explicit invariant so
///   that any future re-tuning of the combination cannot quietly lose it.
/// - authenticated-brand cap: with `mitigation.brand_authenticated` and no medium-or-higher signal outside
///   `content.*`, the confidence is capped at `authenticatedBrandConfidenceCap` (never alerted by default).
///   Applied last, after every term that can raise the confidence, so nothing can lift it — including a model
///   returning riskScore 100.
/// - level: ≥0.75 high, ≥0.5 medium, ≥0.3 low, else safe
/// - category: model's category if present and not `.safe` when confidence ≥ 0.5; otherwise derived from the weighted
///   signal ids (credential/link/sender-spoof/auth-failure/QR lure → phishing, payment/gift card/wire/crypto/impersonation
///   scam → scam); a verdict whose level is not `.safe` never carries category `.safe` (falls back to `.phishing`).
///
/// Cost of the independence, stated plainly: a model that wrongly returns a high riskScore on a message the rules
/// found nothing in now alerts on its own. That is the point — it is how the field cases the rules missed get
/// caught — and the authenticated-brand cap is the only thing holding it back, which is why that cap is pinned by
/// its own tests (`LowEffortScamTests`).
public struct VerdictEngine: Sendable {
    /// Added when the rules and the model independently agree that the *message* — not only its wording — is wrong.
    /// Deliberately small: the maximum has already taken the stronger of the two detectors, so this only moves a
    /// pair of agreeing mid-band detectors up one band.
    ///
    /// (There is no longer a `modelVetoAllowance`. It existed to stop a model "safe" from pulling a strong
    /// heuristic verdict down below `.medium`; under a maximum the model cannot pull anything down at all, so the
    /// constant was a no-op and was removed rather than left as reassuring dead code.)
    public static let agreementBonus = 0.1

    /// Model risk (0...1) from which the model counts as "elevated" for `agreementBonus`. A model that ticks
    /// `isSuspicious` while scoring 20 has not agreed with anything.
    public static let agreementModelScore = 0.5

    /// Ceiling on the fused confidence for a message a well-known brand demonstrably sent itself: the heuristics found
    /// `mitigation.brand_authenticated` (aligned DKIM pass for one of the brand's own domains — never webmail) and
    /// nothing of medium severity or worse outside `content.*`. Only the wording is unusual, and wording is what a
    /// small on-device model over-reads: a genuine "new sign-in" or password-reset notice from the brand's real domain
    /// is exactly the shape it likes to call phishing. 0.45 keeps such a verdict below the default alert threshold
    /// (`.medium` = 0.5) while still showing as low risk in the UI, however certain the model claims to be. Structural
    /// evidence — a spoofed sender, a foreign link, a failed signature, an attachment — lifts the cap immediately.
    ///
    /// Since the fusion became a maximum this cap is the *only* brake on a nervous model, so it is applied last and
    /// unconditionally, with `min`: no term that could raise the confidence past it runs afterwards.
    public static let authenticatedBrandConfidenceCap = 0.45

    /// Heuristic score from which corroborated evidence outranks the model (see `corroboratedEvidenceFloor`).
    public static let corroboratedEvidenceScore = 0.6

    /// Floor under the fused confidence when the heuristics reach `corroboratedEvidenceScore` on at least two weighted
    /// signals, one of them a high-severity structural signal: several independent rules agreeing on a sender, its
    /// links and its request keep the mail in the alert band whatever the model answers. `max(h, m) >= h` already
    /// guarantees this, so the floor is an explicit invariant rather than a correction — kept so the property
    /// survives any later re-tuning of the combination, and pinned by its own test.
    public static let corroboratedEvidenceFloor = 0.5

    /// Signal families that describe the *message*, not its wording: who sent it, where it points, whether it
    /// authenticated, what it carries. Only these may amplify a suspicious model answer.
    public static let structuralSignalFamilies = ["sender.", "link.", "auth.", "attachment."]

    /// True for a signal whose id belongs to a structural family.
    public static func isStructural(_ signalID: String) -> Bool {
        structuralSignalFamilies.contains { signalID.hasPrefix($0) }
    }

    public init() {}

    public func makeVerdict(report: HeuristicReport, assessment: ModelAssessment?, modelIdentifier: String?) -> Verdict {
        let heuristicScore = clamp(report.score)
        let hasStructuralHighSignal = report.signals.contains { $0.severity == .high && Self.isStructural($0.id) }
        let weightedSignalCount = report.signals.filter { $0.weight > 0 && !$0.id.hasPrefix("mitigation.") }.count
        let isCorroborated = heuristicScore >= Self.corroboratedEvidenceScore && hasStructuralHighSignal && weightedSignalCount >= 2
        // A brand the mail really came from, with nothing structurally wrong: only its wording is being judged.
        // This can never be true at the same time as `isCorroborated`, which needs a high-severity structural
        // signal, so the floor below and the cap after it can never fight over the same message.
        let brandAuthenticated = report.signals.contains { $0.id == "mitigation.brand_authenticated" }
            && !report.signals.contains { $0.severity >= .medium && !$0.id.hasPrefix("content.") }
        var confidence: Double
        if let assessment {
            // Two independent detectors: the more certain one sets the confidence, neither can pull the other down.
            let modelScore = clamp(Double(assessment.riskScore) / 100.0)
            confidence = max(heuristicScore, modelScore)
            if assessment.isSuspicious, modelScore >= Self.agreementModelScore, hasStructuralHighSignal {
                confidence = clamp(confidence + Self.agreementBonus)
            }
            if isCorroborated {
                confidence = max(confidence, Self.corroboratedEvidenceFloor)
            }
        } else {
            confidence = heuristicScore
        }
        // Last, and with `min`: nothing after this may raise an authenticated brand notice back over the cap.
        if brandAuthenticated {
            confidence = min(confidence, Self.authenticatedBrandConfidenceCap)
        }

        let level = RiskLevel(confidence: confidence)

        let category: ThreatCategory
        if let assessment, assessment.category != .safe, confidence >= 0.5 {
            category = assessment.category
        } else {
            category = Self.derivedCategory(from: report.signals, level: level)
        }

        var reasons: [Reason] = report.signals.map(Reason.init(signal:))
        if let assessment {
            let modelSeverity: Severity = Self.severity(forRiskScore: assessment.riskScore)
            for (index, text) in assessment.reasons.enumerated() where !text.trimmingCharacters(in: .whitespaces).isEmpty {
                reasons.append(Reason(
                    id: "model.reason.\(index)",
                    title: "Model finding",
                    detail: text,
                    severity: modelSeverity,
                    source: .model
                ))
            }
        }
        // Stable sort by severity descending (keeps heuristic ordering within the same severity).
        reasons = reasons.enumerated()
            .sorted { lhs, rhs in
                if lhs.element.severity != rhs.element.severity { return lhs.element.severity > rhs.element.severity }
                return lhs.offset < rhs.offset
            }
            .map(\.element)

        let summary: String
        if let assessment, !assessment.summary.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            summary = assessment.summary
        } else {
            summary = Self.generatedSummary(level: level, category: category, signals: report.signals)
        }

        return Verdict(
            category: category,
            confidence: confidence,
            level: level,
            reasons: reasons,
            summary: summary,
            heuristicScore: heuristicScore,
            modelRiskScore: assessment?.riskScore,
            modelIdentifier: assessment == nil ? nil : modelIdentifier
        )
    }

    // MARK: - Helpers

    /// Signal-id fragments that derive a category. Tokens are whole id fragments ("dmarc_fail", not "dmarc") so that
    /// mitigation ids (mitigation.dmarc_pass, mitigation.brand_authenticated) can never match.
    static let phishingKeywords = [
        "credential", "link", "url", "login", "password", "malware",
        "lookalike", "display_name", "from_equals_recipient", "brand_unauthenticated",
        "dmarc_fail", "dkim_fail", "dkim_unaligned", "spf_fail", "qr_code",
    ]
    static let scamKeywords = [
        "payment", "gift", "wire", "invoice", "crypto", "bank",
        "executive_impersonation", "secrecy", "advance_fee", "support_callback", "sextortion",
    ]

    /// Category from signal ids when the model gives none, says safe, or is unsure. The category always agrees with the
    /// level: a `.safe` verdict is `.safe` whatever weak signals it carries, and a flagged verdict is never labelled
    /// `.safe` — unattributed risk (spoofed sender, urgency, threats) defaults to phishing. Only weighted risk signals
    /// count; mitigations and other weight-0 signals never drive a category.
    static func derivedCategory(from signals: [Signal], level: RiskLevel) -> ThreatCategory {
        guard level != .safe else { return .safe }
        let ids = signals.filter { $0.weight > 0 && !$0.id.hasPrefix("mitigation.") }.map { $0.id.lowercased() }
        if ids.contains(where: { id in phishingKeywords.contains { id.contains($0) } }) { return .phishing }
        if ids.contains(where: { id in scamKeywords.contains { id.contains($0) } }) { return .scam }
        return .phishing
    }

    static func severity(forRiskScore score: Int) -> Severity {
        switch score {
        case 75...: return .high
        case 50..<75: return .medium
        case 30..<50: return .low
        default: return .info
        }
    }

    /// How the summary names a category in "This email looks …". `category.displayName` is a label for a chip
    /// ("Scam"), and dropping it into a sentence produced "This email looks scam", which is what every rules-only
    /// verdict used to say on the detail screen.
    static func summaryPhrase(for category: ThreatCategory) -> String {
        switch category {
        case .phishing: return "like phishing"
        case .scam: return "like a scam"
        case .spam: return "like spam"
        case .safe: return "suspicious"
        }
    }

    static func generatedSummary(level: RiskLevel, category: ThreatCategory, signals: [Signal]) -> String {
        switch level {
        case .safe:
            return "No signs of phishing or scam were found."
        default:
            let top = signals.sorted { $0.severity > $1.severity }.prefix(2).map(\.title)
            let what = summaryPhrase(for: category)
            if top.isEmpty { return "This email looks \(what) (\(level.displayName.lowercased()))." }
            return "This email looks \(what): \(top.joined(separator: "; "))."
        }
    }

    private func clamp(_ value: Double) -> Double { min(max(value, 0), 1) }
}

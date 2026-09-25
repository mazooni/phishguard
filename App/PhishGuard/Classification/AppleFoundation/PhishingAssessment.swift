#if canImport(FoundationModels)
import Foundation
import FoundationModels
import PhishCore

/// Guided-generation mirror of `ModelAssessment` for the Apple Foundation Models path.
/// Properties are generated in declaration order, so the reasons come first and the score follows the evidence.
@Generable(description: "Security assessment of one email.")
struct PhishingAssessment: Sendable {
    @Generable(description: "The single best category for the email.")
    enum Category: String, Sendable {
        /// Tries to steal credentials or install malware (fake login, malicious link or attachment).
        case phishing
        /// Tries to obtain money, gift cards or personal data through deception.
        case scam
        /// Unwanted bulk marketing, not malicious.
        case spam
        /// Legitimate mail.
        case safe
    }

    @Guide(description: "Short reasons citing concrete evidence from the email (sender, links, wording).", .maximumCount(6))
    var reasons: [String]

    @Guide(description: "True if the email is phishing, a scam, or otherwise deceptive.")
    var isSuspicious: Bool

    @Guide(description: "The category that best matches the email.")
    var category: Category

    @Guide(description: "Risk from 0 (certainly legitimate) to 100 (certainly malicious).", .range(0...100))
    var riskScore: Int

    @Guide(description: "One or two plain sentences telling the user what this email is.")
    var summary: String

    init(reasons: [String], isSuspicious: Bool, category: Category, riskScore: Int, summary: String) {
        self.reasons = reasons
        self.isSuspicious = isSuspicious
        self.category = category
        self.riskScore = riskScore
        self.summary = summary
    }

    /// Converts to PhishCore's value type. Phishing/scam categories always count as suspicious; the score is
    /// clamped to 0...100 and reasons are limited to six entries of at most 160 characters (evidence-snippet size).
    var modelAssessment: ModelAssessment {
        let category: ThreatCategory
        switch self.category {
        case .phishing: category = .phishing
        case .scam: category = .scam
        case .spam: category = .spam
        case .safe: category = .safe
        }
        let reasons = self.reasons
            .map { String($0.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160)) }
            .filter { !$0.isEmpty }
        return ModelAssessment(
            isSuspicious: isSuspicious || category == .phishing || category == .scam,
            category: category,
            riskScore: min(max(riskScore, 0), 100),
            reasons: Array(reasons.prefix(6)),
            summary: summary.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }
}
#endif

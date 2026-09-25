import Foundation

/// What the real local model answered about the bundled fixtures, recorded once and checked in.
///
/// PhishGuard's verdicts are a fusion of two detectors, and only one of them — `HeuristicAnalyzer` — can be
/// re-run anywhere. The other is `mlx-community/Qwen3-4B-Instruct-2507-4bit` running through MLX, which needs an
/// Apple-silicon GPU: it cannot run in the Simulator, in `swift test`, or in a SwiftUI preview. So the answers
/// below were measured once, on real hardware, with the app's own prompt and parser, and stored verbatim. They
/// are the model's own words, not a reconstruction: the demo seeding (`DemoData`) feeds them to
/// `VerdictEngine.makeVerdict` next to a freshly computed `HeuristicReport`, so a screen recording made in the
/// Simulator shows the same confidence, level, category, reasons and summary the product produces on a phone.
///
/// ## Provenance
///
/// - model: `mlx-community/Qwen3-4B-Instruct-2507-4bit` (`ModelManager.defaultModelID`), temperature 0
/// - prompt: `PromptBuilder.systemPrompt` + `PromptBuilder.userPrompt` + `PromptBuilder.jsonOutputInstructions`,
///   parsed by `ModelOutputParser` — the same code path `MLXClassifier` uses on the device
/// - measured: 2026-09-21 on an Apple M4 Pro (Mac16,8), 24 GB, macOS 26.6.2, 91.0 s for 30 emails (mean 3.0 s)
/// - command:
///   ```sh
///   cd Tools/PromptLab
///   xcodebuild -scheme PromptLab -destination 'platform=macOS,arch=arm64' \
///              -configuration Release -derivedDataPath .build/xcode build
///   ./.build/xcode/Build/Products/Release/prompt-lab --set fixtures \
///       --json measurements/2026-09-21-qwen3-4b-fixtures.json
///   ```
/// - raw run, including the benign fixtures and the timings: `Tools/PromptLab/measurements/2026-09-21-qwen3-4b-fixtures.json`
///
/// A second run on 2026-09-22, same model, same machine, same command with
/// `--only mailboxQuotaUpsell,subscriptionDunningNotice,benignSurveyPrizeDraw`, added the three borderline fixtures
/// the corpus gained that day (raw run: `Tools/PromptLab/measurements/2026-09-22-qwen3-4b-borderline-fixtures.json`).
/// The answers from the first run were not re-measured and not touched.
///
/// Re-measure with the same command after any change to `PromptBuilder`, `SampleEmails` or the default model,
/// and regenerate this file from the JSON. Nothing here is hand-written or hand-corrected — where the model
/// produced an odd phrase, the odd phrase is what is stored.
public enum MeasuredModelAssessments {
    /// The model these answers came from.
    public static let modelRepository = "mlx-community/Qwen3-4B-Instruct-2507-4bit"

    /// When they were measured (ISO-8601 day).
    public static let measuredOn = "2026-09-21"

    /// The machine that produced them.
    public static let machine = "Apple M4 Pro (Mac16,8), 24 GB, macOS 26.6.2"

    /// One line naming the model and the date, for a UI or a document that has to say where a number came from.
    public static var provenance: String {
        "Measured with \(modelRepository) on \(measuredOn) (\(machine))."
    }

    /// The measured assessment for each fixture in `SampleEmails.named`, keyed by its fixture name.
    public static let byFixtureName: [String: ModelAssessment] = [
        "advanceFeeScam": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 95,
            reasons: [
                "Asks for bank account details and payment of processing fee",
                "Too good to be true: inheritance of $12.5M from a late client",
                "Stranger on free webmail claiming legal authority over a deceased client",
                "Reply-To differs from sender, indicating spoofing or phishing attempt",
                "Urgency and secrecy language: 'final notice', 'strictly confidential'",
                "No legitimate legal or financial entity would request personal bank details via email",
            ],
            summary: "Phishing attempt impersonating a barrister to steal bank details for a fake inheritance claim."
        ),
        "bankAccountCompromisedPretext": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 95,
            reasons: [
                "Link domain 'bo-fa.com' is a misspelling of 'Bank of America'",
                "Requests immediate action to restore account",
                "Uses threatening language 'compromised' and urgency 'immediately'",
                "Links to a short, unfamiliar domain that mimics a legitimate bank",
                "No legitimate bank or service would request account restoration via a stranger",
            ],
            summary: "The email uses a misspelled domain (bo-fa.com) to impersonate Bank of America and urgently requests account restoration, a classic phishing tactic."
        ),
        "benignAmazonOrder": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 0,
            reasons: [
                "From and display name match Amazon.com",
                "Links resolve to legitimate Amazon domains",
                "DKIM/SPF/DMARC pass and align with amazon.com",
                "No credential or payment request",
                "No urgency or threats present",
                "Standard order confirmation email",
            ],
            summary: "This is a legitimate Amazon order confirmation email with valid authentication and no malicious intent."
        ),
        "benignAmexStatement": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 0,
            reasons: [
                "From and display name match American Express",
                "Links point to legitimate amex.com domains",
                "SPF/DKIM/DMARC all pass and align with amex.com",
                "No credential or payment request",
                "No urgency or threats present",
                "No attachment or malicious link",
            ],
            summary: "This is a legitimate American Express statement notification with valid authentication and no malicious intent."
        ),
        "benignBankStatement": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 5,
            reasons: [
                "From address matches official Chase domain",
                "DKIM/SPF/DMARC all pass and aligned with chase.com",
                "Link directs to secure.chase.com, legitimate domain",
                "No credential request or urgency",
                "Body contains standard account notification text",
                "No suspicious link text or domain shortening",
            ],
            summary: "This is a legitimate Chase notification about an available statement. All authentication and links are verified and consistent with official Chase practices."
        ),
        "benignCalendarInvite": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 0,
            reasons: [
                "From and display name match Google Calendar, legitimate service",
                "Links point to official Google domains with no deviation",
                "No credential or payment request, no urgency",
                "SPF/DKIM/DMARC all pass and aligned with google.com",
                "No attachment or link that shortens or misspells a brand",
                "Event is a normal calendar invite with no suspicious action",
            ],
            summary: "This is a legitimate Google Calendar event invitation with verified authentication and no malicious intent."
        ),
        "benignDocsShareNotification": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 5,
            reasons: [
                "From and display name match Google Docs service",
                "Reply-To domain is a fabricated example domain, not Google",
                "Link points to Google Docs, domain matches expected behavior",
                "No credential or payment request",
                "No urgency or threats present",
                "SPF/DKIM/DMARC all pass and aligned with Google Docs",
            ],
            summary: "The email is a legitimate Google Docs sharing notification with no malicious intent. All authentication and domain indicators are valid and consistent with Google's services."
        ),
        "benignGitHubNotification": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 0,
            reasons: [
                "From and display name match GitHub's known pattern",
                "Reply-To domain is a GitHub subdomain with a long random string",
                "Links point to legitimate GitHub URLs and are brand-aligned",
                "No credential or payment request",
                "No urgency or threats present",
                "SPF/DKIM/DMARC all pass and align with github.com",
            ],
            summary: "This is a legitimate GitHub notification about a pull request review. All authentication and links are verified and from an authorized domain."
        ),
        "benignGoogleSecurityAlert": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 5,
            reasons: [
                "From domain matches Google's official domain",
                "Links point to legitimate Google subdomains",
                "DKIM/SPF/DMARC all pass and align with sender",
                "No credential or payment request",
                "Standard security alert for account sign-in",
                "No urgency or malicious intent",
            ],
            summary: "This is a legitimate Google security alert for a new device sign-in. All links and domains are authentic and aligned with Google's official services."
        ),
        "benignInternalHRNotice": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 5,
            reasons: [
                "From domain matches known organization with valid SPF/DKIM/DMARC alignment",
                "Link points to a subdomain of the legitimate domain and stays within the same domain",
                "No credential or payment request, no urgency beyond standard deadline",
                "Email content is consistent with internal company communication about a survey",
                "No attachment or malicious link behavior",
                "Sender is a known internal team (People Team) with plausible role and context",
            ],
            summary: "This is a legitimate internal reminder about a survey with no malicious intent or data collection."
        ),
        "benignMailingListPost": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 5,
            reasons: [
                "From field uses gmail.com, but sender is a mailing list with different domain",
                "Reply-To and To match the list domain, consistent with group communication",
                "Link destination is within the list's own domain, no redirection or spoofing",
                "No credential, payment, or account action requested",
                "DMARC fails due to mismatch between From and list domain, but this is expected for list re-sending",
                "No urgency, threats, or personal data exposure",
            ],
            summary: "A legitimate group email about a carpool event with no malicious intent or data requests. DMARC failure is due to list re-sending, not forgery."
        ),
        "benignNewsletter": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 5,
            reasons: [
                "From and display name match, domain is legitimate and brand-aligned",
                "Links point to the correct domain with no shortening or misspelling",
                "No credential, payment, or account restoration request",
                "No urgency, threats, or malicious attachment",
                "SPF/DKIM/DMARC all pass and aligned with domain",
                "Content is promotional and consistent with a known brand",
            ],
            summary: "This is a legitimate promotional email from Trailhead Outfitters about trail recommendations and a discount. No malicious intent or data collection."
        ),
        "benignOTPCode": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 5,
            reasons: [
                "Verified SPF/DKIM/DMARC alignment with mail.lumennotes.example",
                "Link and attachment absent",
                "No request for personal data or payment",
                "Email content matches legitimate service behavior for account verification",
                "Sender domain is a valid, non-malicious example domain",
                "No urgency, threats, or social engineering pressure",
            ],
            summary: "The email is a legitimate verification notice from a known service with proper authentication. No malicious intent or data collection is present."
        ),
        "benignOrganizationPayrollNotice": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 5,
            reasons: [
                "From domain matches known organization with valid SPF/DKIM/DMARC alignment",
                "Link points to a subdomain of the same domain, consistent with internal portal",
                "No credential or payment request, no urgency or threats",
                "Email content matches expected internal payroll communication",
                "No attachment or malicious link behavior",
                "Sender is known and legitimate within the organization",
            ],
            summary: "This is a legitimate payslip notification from Northwind Payroll with valid authentication and no malicious intent."
        ),
        "benignPersonalEmail": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 0,
            reasons: [
                "Link points to a legitimate, well-known food site with no malicious intent",
                "No credential, payment, or account restoration requested",
                "Sender is a known personal contact with a plausible context (hiking, shared recipe)",
                "No urgency, threats, or security prompts",
                "Domain matches expected and is not a lookalike or shortened",
                "No attachment or redirect to suspicious domain",
            ],
            summary: "A personal, non-sensitive email about a hiking meetup and recipe sharing. No malicious intent or indicators."
        ),
        "benignRegionalBankAlert": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 0,
            reasons: [
                "From and display name match HSBC UK",
                "Link points to official HSBC domain with correct path",
                "No credential or payment request",
                "DKIM/SPF/DMARC pass and aligned with domain",
                "No urgency, threats, or suspicious links",
                "Body confirms standard transaction alert format",
            ],
            summary: "This is a legitimate transaction alert from HSBC UK with valid authentication and no malicious intent."
        ),
        "benignRetailGiftCardPromo": ModelAssessment(
            isSuspicious: false,
            category: .spam,
            riskScore: 10,
            reasons: [
                "Domain 'marigoldhome.example' is a valid, branded domain with no known malicious history",
                "Links point to a legitimate-looking domain with matching SPF/DKIM/DMARC alignment",
                "No credential or payment request, no urgency beyond 'deadline' which is common in promotions",
                "No attachment or malware link",
                "Sender and display name match, with clear unsubscribe option",
                "No impersonation of a financial or account service",
            ],
            summary: "Promotional email for gift cards with no sensitive data requests. Low risk, typical marketing content."
        ),
        "benignShopifyOrder": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 0,
            reasons: [
                "From and display name match legitimate brand",
                "Reply-To is valid and consistent with domain",
                "Links point to cedarandsage.example, which aligns with From domain",
                "No credential requests or urgency",
                "SPF/DKIM/DMARC all pass and aligned",
                "No suspicious attachment or payment request",
            ],
            summary: "Email confirms a legitimate order update from Cedar & Sage Candle Co. with valid authentication and no malicious intent."
        ),
        "benignStrangerPersonalNote": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 5,
            reasons: [
                "Link domain 'photos.example.net' is a generic placeholder, not a known service",
                "No credential, payment, or account-sensitive request",
                "Sender is a personal contact with known email domain (Gmail)",
                "No urgency, threats, or malware indicators",
                "No attachment or redirect to suspicious domain",
                "Domain does not imitate a real organization",
            ],
            summary: "Personal photo sharing email from a known contact. No malicious intent or data request."
        ),
        "benignZoomInvite": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 5,
            reasons: [
                "From and display name match Zoom's official identity",
                "Reply-To matches From and is consistent with Zoom's known address",
                "SPF/DKIM/DMARC all pass and align with zoom.us domain",
                "Links point to zoom.us subdomains and are legitimate Zoom meeting URLs",
                "No credential request, no urgency, no malware attachment",
                "Meeting invitation for a known internal team (Northwind) is plausible and contextually appropriate",
            ],
            summary: "This is a legitimate Zoom meeting invitation with valid authentication and no malicious intent."
        ),
        "cryptoGiveawayScam": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 95,
            reasons: [
                "Sender domain imitates Tesla with a short, unfamiliar extension tesla-crypto-event.xyz",
                "Link destination and display name impersonate Tesla without authorization",
                "Cryptocurrency giveaway with high-value prize and urgent action",
                "Use of fake BTC address and double-back mechanism to steal funds",
                "Pressure to act quickly with 'limited time' and 'first come first served'",
                "Shortened link bit.ly/3TeslaBTC hides malicious destination",
            ],
            summary: "This is a phishing attempt impersonating Tesla to steal cryptocurrency through a fake giveaway scheme with a forged BTC address and urgent action."
        ),
        "fakeInvoiceHTMLAttachment": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 90,
            reasons: [
                "From domain shortens and misspells 'northwindtraders' as 'billing-docs-portal.com'",
                "HTML attachment likely opens fake sign-in page",
                "Asks for payment confirmation and threatens late fees",
                "Untrusted sender with no SPF/DKIM/DMARC verification",
                "No legitimate business would send such a request via a stranger",
            ],
            summary: "Phishing attempt disguised as a payment reminder from a fake billing portal with malicious HTML attachment and forged sender domain."
        ),
        "giftCardScam": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 85,
            reasons: [
                "Asks for gift cards and photos of codes, which is a classic phishing tactic to steal credentials or data through social engineering",
                "Uses executive impersonation with 'Quick favor' and urgency to pressure action",
                "Requests photos of gift card codes, which is a direct data request that compromises privacy and security",
                "Reply-To differs from sender, indicating a spoofed or compromised account",
                "Urgency and secrecy language ('right now', 'keep this between us') create pressure to act without verification",
                "No legitimate business would request physical gift cards and photos of codes via email",
            ],
            summary: "This is a phishing attempt disguised as an executive request, asking for sensitive data through physical gift card codes."
        ),
        "microsoft365PasswordPhish": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 95,
            reasons: [
                "Link imitates Microsoft with a fake domain login-microsoftonline.secure-verify.top",
                "Display name and sender domain mimic Microsoft 365 but use a non-aligned, short-lived domain",
                "Asks for password confirmation via a login link that redirects to a malicious site",
                "Link uses a high-risk domain ending and is not the official Microsoft domain",
                "Threatens account lockout to create urgency and pressure to act",
                "No SPF/DKIM/DMARC validation or alignment with Microsoft's domain",
            ],
            summary: "The email uses a fake login URL and impersonates Microsoft 365 to steal credentials under urgency and threat of account lockout."
        ),
        "packageDeliveryFeeScam": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 95,
            reasons: [
                "Link imitates a well-known brand with a misspelled domain (usps-redelivery.click) instead of USPS",
            ],
            summary: "The email impersonates USPS with a fake domain and pressures the user to pay a redelivery fee via a malicious link, indicating phishing activity."
        ),
        "paypalPhish": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 95,
            reasons: [
                "DMARC failed for paypal.com",
                "Link uses fake domain paypal.com.account-verify-login.com",
                "Reply-To imitates PayPal with support@paypal-resolution-center.com",
                "Asks for account verification and credentials",
                "Threatens permanent suspension for inaction",
                "Bounce address does not match sender",
            ],
            summary: "The email uses a fake domain and forged authentication to mimic PayPal, demanding account verification under threat of suspension."
        ),
        "sextortionScam": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 95,
            reasons: [
                "From address matches user's own, but no valid SPF/DKIM/DMARC alignment",
                "DMARC failed, indicating forgery of example.com domain",
                "threatens to leak video of user's webcam to contacts and family",
                "uses extortion via cryptocurrency payment demand",
                "high urgency and blackmail language to pressure action",
                "links to no known legitimate service, only a cryptocurrency wallet address",
            ],
            summary: "This is a phishing attempt using blackmail and cryptocurrency extortion to steal funds. The email falsely claims unauthorized access to the user's device and threatens to expose private content."
        ),
        "techSupportScam": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 90,
            reasons: [
                "Brand name from personal mailbox claiming Norton but sent from Gmail",
                "Asks for phone call to cancel subscription and get refund — typical phishing tactic",
                "Urgency to act within 24 hours to cancel charge",
                "Unfamiliar sender with 'Billing Desk' role not part of official Norton support",
                "No links or attachments, but request to call implies phishing intent",
                "Norton official domain not used; spoofed via Gmail with fake billing department",
            ],
            summary: "This is a phishing attempt impersonating Norton LifeLock billing to诱导 users to call a fake support number and potentially reveal personal information or payment details."
        ),
        "webmailPayPalPretext": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 95,
            reasons: [
                "PayPal pretext from personal mailbox with unrelated domain",
                "Asks to verify or restore information, requesting credentials",
                "Link leads to paypal.com but from unknown sender with spoofed address",
                "Sender uses throwaway pattern (qq.com) and impersonates a financial service",
            ],
            summary: "The email falsely claims to be from PayPal and requests account verification through a suspicious sender domain. It uses urgency and a spoofed address to trick users into revealing credentials."
        ),
        "webmailPayrollMeetingLure": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 90,
            reasons: [
                "Link domain 'zoom.schedule.com' is a spoofed Zoom domain, not owned by Zoom",
                "Sender uses pay-related pretext 'regarding your payroll' from outside organization",
                "Sender address contains 'qq.com' indicating spoofing or throwaway pattern",
                "Untrusted sender with no known affiliation requests action on personal account",
                "Urgency and personal data context (payroll, student employee) trigger phishing red flags",
                "Link redirects to non-official Zoom domain with no brand alignment",
            ],
            summary: "The email uses a spoofed Zoom link and payroll pretext from an untrusted sender to impersonate a legitimate request, indicating phishing activity."
        ),
        "benignSurveyPrizeDraw": ModelAssessment(
            isSuspicious: false,
            category: .safe,
            riskScore: 5,
            reasons: [
                "From domain matches display name and is authenticated with SPF/DKIM/DMARC",
                "Links point to legitimate subdomains of the claimed organization",
                "No credential or payment request, no urgency beyond standard survey prompt",
                "No attachment or malicious payload",
                "Domain is not a lookalike or misspelled version of a known brand",
                "No stranger requesting account restoration or sensitive data",
            ],
            summary: "A legitimate survey request from Northpoint Outfitters with authenticated links and no malicious intent."
        ),
        "mailboxQuotaUpsell": ModelAssessment(
            isSuspicious: true,
            category: .scam,
            riskScore: 85,
            reasons: [
                "From domain is unrelated to mailbox service and not a known provider",
                "Links use URL shortener to hide destination",
                "Threatens suspension and urgency to act within 48 hours",
                "Asks for payment details from card on file without user consent",
                "Generic greeting and no personalization",
            ],
            summary: "The email falsely claims to be from a mailbox service and pressures users into paying for a subscription upgrade, using urgent threats and payment requests without verification."
        ),
        "subscriptionDunningNotice": ModelAssessment(
            isSuspicious: true,
            category: .phishing,
            riskScore: 85,
            reasons: [
                "From domain does not match known billing or account service domains",
                "Links point to a short, unfamiliar domain that mimics a legitimate service",
                "Urgency and threat of account closure pressure action",
                "No credential or personal data requested, but payment is demanded via a third-party link",
            ],
            summary: "The email uses a forged domain that resembles a legitimate billing service and pressures the user to pay immediately via a malicious link, indicating phishing activity."
        ),    ]

    /// The same answers keyed by the fixture's provider message id, which is what a classifier sees at runtime.
    public static let byMessageID: [String: ModelAssessment] = {
        var result: [String: ModelAssessment] = [:]
        for entry in SampleEmails.named {
            if let assessment = byFixtureName[entry.name] {
                result[entry.email.messageID] = assessment
            }
        }
        return result
    }()

    /// The measured answer for a fixture, by its name in `SampleEmails.named`.
    public static func assessment(forFixtureNamed name: String) -> ModelAssessment? {
        byFixtureName[name]
    }

    /// The measured answer for a message, by the provider message id of the fixture it came from.
    public static func assessment(forMessageID messageID: String) -> ModelAssessment? {
        byMessageID[messageID]
    }

    /// How long the model took to answer about each fixture, in seconds, in that same run. Replayed by the
    /// screen-recording demo so a scan there takes as long as it really takes — an instant answer from a 4B
    /// model would be the one obviously untrue thing on screen.
    public static let measuredSecondsByFixtureName: [String: TimeInterval] = [
        "advanceFeeScam": 3.56,
        "bankAccountCompromisedPretext": 2.95,
        "benignAmazonOrder": 2.60,
        "benignAmexStatement": 2.44,
        "benignBankStatement": 2.69,
        "benignCalendarInvite": 3.18,
        "benignDocsShareNotification": 2.99,
        "benignGitHubNotification": 2.86,
        "benignGoogleSecurityAlert": 2.79,
        "benignInternalHRNotice": 3.06,
        "benignMailingListPost": 3.40,
        "benignNewsletter": 3.08,
        "benignOTPCode": 2.59,
        "benignOrganizationPayrollNotice": 2.70,
        "benignPersonalEmail": 2.75,
        "benignRegionalBankAlert": 2.69,
        "benignRetailGiftCardPromo": 3.23,
        "benignShopifyOrder": 2.95,
        "benignStrangerPersonalNote": 2.60,
        "benignZoomInvite": 3.00,
        "cryptoGiveawayScam": 3.60,
        "fakeInvoiceHTMLAttachment": 2.92,
        "giftCardScam": 3.60,
        "microsoft365PasswordPhish": 3.96,
        "packageDeliveryFeeScam": 2.70,
        "paypalPhish": 3.15,
        "sextortionScam": 3.32,
        "techSupportScam": 3.43,
        "webmailPayPalPretext": 2.89,
        "webmailPayrollMeetingLure": 3.35,
        "benignSurveyPrizeDraw": 3.06,
        "mailboxQuotaUpsell": 3.09,
        "subscriptionDunningNotice": 2.88,
    ]

    /// The same durations keyed by the fixture's provider message id.
    public static let measuredSecondsByMessageID: [String: TimeInterval] = {
        var result: [String: TimeInterval] = [:]
        for entry in SampleEmails.named {
            if let seconds = measuredSecondsByFixtureName[entry.name] {
                result[entry.email.messageID] = seconds
            }
        }
        return result
    }()

    /// How long the measured run took for this message, by the provider message id of its fixture.
    public static func measuredSeconds(forMessageID messageID: String) -> TimeInterval? {
        measuredSecondsByMessageID[messageID]
    }
}

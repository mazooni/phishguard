import Foundation

/// Rule-based analysis: authentication headers, sender/reply-to mismatches, lookalike links, urgency language,
/// attachments, etc. Produces `Signal`s and an aggregate 0...1 score.
///
/// Scoring: saturating noisy-OR over risk signals (`score = 1 − Π(1 − wᵢ)`), minus benign mitigations
/// (`mitigation.*` signals, reported with weight 0), clamped to 0...1. Each rule emits at most one signal (with a few
/// examples in `detail`) so that many similar links cannot saturate the score on their own.
///
/// Safety and speed: every text pass is linear (see `HTMLTextExtractor`); all phrase lexicons are compiled into one
/// Aho-Corasick `PhraseAutomaton` and matched in a single pass; the three remaining regexes (phone numbers, wallet
/// addresses, one-time-code tokens) have no nested quantifiers and run over a capped prefix; inputs are capped
/// (`maxScannedCharacters`, `HeuristicReport.maxLinks`, `LinkExtractor.maxAnchorsScanned`, `HTMLTextExtractor.maxHTMLLength`).
public struct HeuristicAnalyzer: Sendable {
    /// Characters of body text scanned by the content rules.
    public static let maxScannedCharacters = 100_000

    /// Registrable domains of the user's own organization(s) — typically the domains of the linked accounts. Mail whose
    /// From domain is one of these *and* whose origin the receiving server proved (DMARC pass or aligned DKIM, no
    /// failure) earns `mitigation.internal_sender` credit, so routine HR/IT notices are not paged. Free-mail domains
    /// (gmail.com, outlook.com, …) are ignored because anyone can send from them; an unauthenticated or failing
    /// same-domain From (classic CEO fraud) gets no credit.
    public var organizationDomains: Set<String> {
        didSet { organizationDomains = Self.normalizedOrganizationDomains(organizationDomains) }
    }

    public init(organizationDomains: Set<String> = []) {
        self.organizationDomains = Self.normalizedOrganizationDomains(organizationDomains)
    }

    /// Lowercased registrable domains, without empties and without free-mail domains.
    private static func normalizedOrganizationDomains(_ domains: Set<String>) -> Set<String> {
        Set(domains
            .map { DomainAnalysis.registrableDomain(of: $0.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)) }
            .filter { !$0.isEmpty && !DomainAnalysis.isFreeMailDomain($0) })
    }

    public func analyze(_ email: EmailMessage) -> HeuristicReport {
        let bodyText = HTMLTextExtractor.plainText(for: email)
        let links = LinkExtractor.extractLinks(from: email)
        let authentication = AuthenticationResults.extract(from: email.headers)
        let context = Context(email: email, bodyText: bodyText, links: links, authentication: authentication, organizationDomains: organizationDomains)

        var signals: [Signal] = []
        var mitigations: [(signal: Signal, credit: Double)] = []

        signals += Self.authenticationSignals(context, mitigations: &mitigations)
        signals += Self.senderSignals(context)
        signals += Self.linkSignals(context)
        signals += Self.contentSignals(context)
        signals += Self.attachmentSignals(context)
        mitigations += Self.generalMitigations(context)

        // Noisy-OR over risk weights, minus mitigations.
        let survival = signals.filter { $0.weight > 0 }.reduce(1.0) { $0 * (1 - $1.weight) }
        var score = 1 - survival
        let credit = mitigations.reduce(0.0) { $0 + $1.credit }
        score = min(max(score - credit, 0), 1)

        // Present the strongest findings first, mitigations last.
        signals.sort { lhs, rhs in
            if lhs.severity != rhs.severity { return lhs.severity > rhs.severity }
            return lhs.weight > rhs.weight
        }
        signals += mitigations.map(\.signal)

        return HeuristicReport(
            signals: signals,
            score: score,
            links: links,
            authentication: authentication,
            bodyText: bodyText
        )
    }

    // MARK: - Context

    struct Context {
        let email: EmailMessage
        let bodyText: String
        let links: [EmailLink]
        let authentication: AuthenticationResults

        /// Subject + body (capped) — what the content rules scan.
        let scanText: String
        let subject: String
        let fromAddress: EmailAddress?
        let fromDomain: String
        let fromRegistrable: String
        let fromIsFreeMail: Bool
        /// Registrable domain of From when it belongs to a protected brand.
        let fromBrandKey: String?
        let displayName: String
        /// Brands the mail *claims* (display name, subject, opening of the body).
        let mentionedBrands: [String]
        let recipientRegistrables: Set<String>
        let hasListHeaders: Bool
        let hiddenSpans: [String]
        /// Phrase matches per `Lexicon` set over `scanText` (one automaton pass).
        let scanMatches: [[String]]
        /// DKIM passed for a domain aligned with From.
        let dkimAlignedPass: Bool
        /// SPF, DKIM or DMARC reported a failure (SPF soft-fail counts).
        let authenticationFailed: Bool
        /// From is one of `HeuristicAnalyzer.organizationDomains` and the receiving server proved the message originated
        /// there (DMARC pass or aligned DKIM, no failure). Never true for free-mail domains.
        let isVerifiedInternalSender: Bool
        /// Aligned DKIM pass + DMARC pass from a non-free-mail domain.
        let isAuthenticatedSender: Bool
        /// `isAuthenticatedSender` with List headers: how legitimate retail/loyalty bulk mail arrives. Only tones down
        /// promo-prone lexical rules; explicit request phrases still fire at full weight.
        let isAuthenticatedBulkSender: Bool
        /// A well-known brand really sent this notice: aligned DKIM pass **and** DMARC pass from one of the brand's own
        /// domains (never webmail), no attachment, no authentication failure, and every link on the brand's domains.
        /// Nobody but the brand can produce this shape, so its security/sign-in wording is routine rather than a lure.
        let isAuthenticatedBrandNotice: Bool
        /// Mail from a domain the receiving side has reason to trust for organizational business: the user's own
        /// organization, or any authenticated non-webmail domain that does not imitate a brand.
        let isOrganizationalSender: Bool
        /// The mail asks the reader to do something: it carries a link or an attachment, or its text asks for a reply
        /// or an attachment. Used to separate "names a brand" from "names a brand and wants an action".
        let hasActionRequest: Bool
        /// The opening of the body greets the recipient by name — weak evidence of an existing relationship, which a
        /// stranger blasting a template does not have.
        let addressesRecipientByName: Bool

        init(email: EmailMessage, bodyText: String, links: [EmailLink], authentication: AuthenticationResults, organizationDomains: Set<String> = []) {
            self.email = email
            self.bodyText = bodyText
            self.links = links
            self.authentication = authentication
            let cappedBody = String(bodyText.prefix(HeuristicAnalyzer.maxScannedCharacters))
            self.subject = email.subject
            self.scanText = email.subject + "\n" + cappedBody
            self.fromAddress = email.from
            let domain = email.from?.domain ?? ""
            let registrable = domain.isEmpty ? "" : DomainAnalysis.registrableDomain(of: domain)
            let freeMail = !domain.isEmpty && DomainAnalysis.isFreeMailDomain(domain)
            self.fromDomain = domain
            self.fromRegistrable = registrable
            self.fromIsFreeMail = freeMail
            // `brandKey(forRegistrableDomain:)`, not a raw scan of the catalog's `domains` lists: it is the same
            // accessor `isLegitimateDomain` uses, so a brand's regional domain (`natwest.co.uk`, `dhl.fr`) counts
            // as the brand here too. Otherwise the two disagreed — the sender was "not impersonating" but also
            // "not a brand", so an aligned DKIM pass from it earned no `mitigation.brand_authenticated`.
            self.fromBrandKey = domain.isEmpty ? nil : DomainAnalysis.brandKey(forRegistrableDomain: registrable)
            self.displayName = email.from?.name ?? ""
            let mentionText = [email.from?.name ?? "", email.subject, String(cappedBody.prefix(400))].joined(separator: "\n")
            self.mentionedBrands = HeuristicAnalyzer.brandsMentioned(in: mentionText)
            self.recipientRegistrables = Set(email.to.map { DomainAnalysis.registrableDomain(of: $0.domain) }.filter { !$0.isEmpty })
            let hasListHeaders = email.header("List-Unsubscribe") != nil || email.header("List-Id") != nil || email.header("List-ID") != nil
            self.hasListHeaders = hasListHeaders
            if let html = email.htmlBody, !html.isEmpty {
                self.hiddenSpans = HTMLTextExtractor.hiddenText(inHTML: html)
            } else {
                self.hiddenSpans = []
            }
            self.scanMatches = Lexicon.automaton.scan(self.scanText, limitPerSet: 4)

            let dkimAlignedPass = authentication.dkim == .pass && !registrable.isEmpty
                && authentication.dkimDomain.map { DomainAnalysis.registrableDomain(of: $0) == registrable } == true
            let failed = [authentication.spf, authentication.dkim, authentication.dmarc].contains { $0 == .fail } || authentication.spf == .softfail
            self.dkimAlignedPass = dkimAlignedPass
            self.authenticationFailed = failed
            let provenOrigin = !failed && (authentication.dmarc == .pass || dkimAlignedPass)
            self.isVerifiedInternalSender = !registrable.isEmpty && !freeMail && provenOrigin && organizationDomains.contains(registrable)
            let authenticatedSender = dkimAlignedPass && authentication.dmarc == .pass && !freeMail
            self.isAuthenticatedSender = authenticatedSender
            self.isAuthenticatedBulkSender = hasListHeaders && authenticatedSender

            let fromBrandKey = self.fromBrandKey
            let linksStayWithTheBrand = links.allSatisfy { link in
                guard let host = link.host else { return true }
                if DomainAnalysis.registrableDomain(of: host) == registrable { return true }
                guard let key = fromBrandKey else { return false }
                return DomainAnalysis.isLegitimateDomain(host, for: key)
            }
            self.isAuthenticatedBrandNotice = authenticatedSender && fromBrandKey != nil
                && email.attachments.isEmpty && linksStayWithTheBrand
            self.isOrganizationalSender = self.isVerifiedInternalSender
                || (authenticatedSender && DomainAnalysis.lookalikeMatch(for: domain) == nil)
            self.hasActionRequest = !links.isEmpty || !email.attachments.isEmpty
                || !self.scanMatches[Lexicon.actionRequest.rawValue].isEmpty
                || !self.scanMatches[Lexicon.attachmentRequest.rawValue].isEmpty
            self.addressesRecipientByName = HeuristicAnalyzer.greetsRecipientByName(
                recipients: email.to, opening: String(cappedBody.prefix(240))
            )
        }

        func isAlignedWithSender(_ host: String) -> Bool {
            guard !fromRegistrable.isEmpty else { return false }
            return DomainAnalysis.registrableDomain(of: host) == fromRegistrable
        }
    }

    // MARK: - Signal helpers

    private static func signal(_ id: String, _ title: String, _ detail: String, _ severity: Severity, _ weight: Double) -> Signal {
        Signal(id: id, title: title, detail: detail, severity: severity, weight: weight)
    }

    private static func mitigation(_ id: String, _ title: String, _ detail: String, credit: Double) -> (signal: Signal, credit: Double) {
        (Signal(id: id, title: title, detail: detail, severity: .info, weight: 0), credit)
    }

    private static func quoted(_ items: [String], limit: Int = 3) -> String {
        items.prefix(limit).map { "“\(String($0.prefix(60)))”" }.joined(separator: ", ")
    }

    private static func brandName(_ key: String) -> String {
        DomainAnalysis.brands.first { $0.key == key }?.names.first?.capitalized ?? key
    }

    // MARK: - Brand mentions

    /// Brands whose catalog name is an ordinary word ("apple", "zoom", "visa", "meta", "steam", …): a bare mention in a
    /// display name or body is not a brand claim ("Apple Valley Dental", "a Zoom call", "need a visa", "on Steam").
    /// These keys only count when one of the qualified phrases below appears — the convention the catalog already uses
    /// for "chase bank" / "discover card" / "ledger live". Lookalike-host detection is unaffected (it keys off the brand
    /// key, not its names). Kept here rather than in `DomainAnalysis` so the catalog stays a plain data table.
    static let qualifiedBrandMentions: [String: [String]] = [
        "apple": ["apple id", "apple account", "apple support", "apple pay", "apple inc", "apple store", "icloud", "app store"],
        "zoom": ["zoom account", "zoom video communications", "zoom support", "zoom billing"],
        "visa": ["visa card", "visa account", "visa secure", "verified by visa", "visa inc"],
        "facebook": ["facebook", "meta platforms", "meta business", "meta support", "meta verified", "meta account"],
        "steam": ["steam account", "steam wallet", "steam gift", "steam support", "steam guard", "steam community"],
        "slack": ["slack account", "slack workspace", "slack technologies", "slack support"],
        "uber": ["uber eats", "uber account", "uber receipt", "uber ride", "uber one", "uber support"],
        "stripe": ["stripe account", "stripe payments", "stripe support", "stripe inc"],
        "discord": ["discord account", "discord nitro", "discord support"],
    ]

    // MARK: - Relationship cues

    /// True when the opening of the body names one of the recipients ("Hi Sam,", "Dear Ms Rivera"). Tokens come from
    /// the display name and from the local part split on separators and digits; only alphabetic tokens of ≥ 3
    /// characters count, so "info@" or "sam2024" cannot match by accident. A stranger working from an address list
    /// usually cannot do this, which is why it only ever *suppresses* a signal.
    static func greetsRecipientByName(recipients: [EmailAddress], opening: String) -> Bool {
        guard !opening.isEmpty else { return false }
        let lower = opening.lowercased()
        for recipient in recipients.prefix(3) {
            var tokens: [Substring] = []
            if let name = recipient.name, !name.isEmpty {
                tokens += name.lowercased().split(whereSeparator: { !$0.isLetter })
            }
            if let local = recipient.address.split(separator: "@").first {
                tokens += local.lowercased().split(whereSeparator: { !$0.isLetter })
            }
            for token in tokens where token.count >= 3 && token.allSatisfy(\.isLetter) {
                if DomainAnalysis.containsWord(String(token), in: lower) { return true }
            }
        }
        return false
    }

    /// `DomainAnalysis.brandsMentioned` with dictionary-word brands gated on a qualified phrase.
    static func brandsMentioned(in text: String) -> [String] {
        let keys = DomainAnalysis.brandsMentioned(in: text)
        guard !keys.isEmpty else { return keys }
        let lower = String(text.prefix(2_000)).lowercased()
        return keys.filter { key in
            guard let qualified = qualifiedBrandMentions[key] else { return true }
            return qualified.contains { DomainAnalysis.containsWord($0, in: lower) }
        }
    }

    // MARK: - auth.*

    static func authenticationSignals(_ c: Context, mitigations: inout [(signal: Signal, credit: Double)]) -> [Signal] {
        var out: [Signal] = []
        let auth = c.authentication
        let fromIsBrand = c.fromBrandKey != nil
        // A mailing list re-signs and forwards a member's post, which breaks the original DKIM signature and DMARC.
        // When the receiving provider validated the list's ARC seal (arc=pass in its own Authentication-Results) and
        // the message has the list shape, that breakage is expected and is reported as one low signal
        // (auth.list_relay_dmarc_fail) instead of DKIM/DMARC failures. Brand senders keep their full weights (a spoof
        // relayed through a list must still alarm); webmail domains are catalog brands (google, microsoft, …) but a
        // gmail.com From is a personal sender, not a brand. The sealed dkim/dmarc results inside the ARC set are never
        // copied over the provider's own results.
        let listRelayViaARC = auth.arc == .pass && (!fromIsBrand || c.fromIsFreeMail) && (c.hasListHeaders || c.email.sender != nil)

        guard auth.hasAnyResult else {
            out.append(signal("auth.missing", "No authentication results", "The message carries no SPF/DKIM/DMARC results, so the sender could not be verified.", .info, 0))
            if fromIsBrand, !c.fromDomain.isEmpty {
                out.append(signal("auth.brand_unauthenticated", "Unverified brand sender",
                                  "The message claims to come from \(c.fromDomain) but carries no authentication results.", .high, 0.45))
            }
            return out
        }

        switch auth.spf {
        case .fail?:
            out.append(signal("auth.spf_fail", "SPF failed", "The sending server is not authorized for \(auth.spfDomain ?? c.fromDomain) (spf=fail).", .medium, 0.3))
        case .softfail?:
            out.append(signal("auth.spf_softfail", "SPF soft-fail", "The sending server is probably not authorized for \(auth.spfDomain ?? c.fromDomain) (spf=softfail).", .low, 0.2))
        case .permerror?, .temperror?:
            out.append(signal("auth.spf_error", "SPF could not be evaluated", "spf=\(auth.spf?.rawValue ?? "error").", .info, 0.05))
        default:
            break
        }

        switch auth.dkim {
        case .fail? where !listRelayViaARC:
            let detail = "The DKIM signature\(auth.dkimDomain.map { " for \($0)" } ?? "") did not verify (dkim=fail)."
            out.append(signal("auth.dkim_fail", "DKIM signature failed", detail, .medium, fromIsBrand ? 0.45 : 0.35))
        case .pass?:
            if let d = auth.dkimDomain, !c.fromRegistrable.isEmpty {
                let aligned = DomainAnalysis.registrableDomain(of: d) == c.fromRegistrable
                if aligned {
                    if fromIsBrand, !c.fromIsFreeMail {
                        mitigations.append(mitigation("mitigation.brand_authenticated", "Authenticated brand sender",
                                                      "DKIM passed for \(d), matching the From domain of a well-known sender.", credit: 0.25))
                    }
                } else if auth.dmarc != .pass, !listRelayViaARC {
                    // (In an ARC-validated list relay the unaligned signature is the list's own; see above.)
                    let detail = "DKIM passed for \(d), which is not the From domain \(c.fromDomain)."
                    if fromIsBrand {
                        out.append(signal("auth.dkim_unaligned", "DKIM domain does not match sender", detail, .high, 0.4))
                    } else {
                        out.append(signal("auth.dkim_unaligned", "DKIM domain does not match sender", detail, .low, 0.15))
                    }
                }
            }
        case .none?, nil:
            // DMARC can pass on aligned SPF alone (RFC 7489): only call the sender unverified when DMARC did not confirm it.
            if fromIsBrand, auth.dmarc != .pass {
                out.append(signal("auth.brand_unauthenticated", "Unverified brand sender",
                                  "The message claims to come from \(c.fromDomain) but has no valid DKIM signature.", .high, 0.45))
            }
        default:
            break
        }

        switch auth.dmarc {
        case .fail? where listRelayViaARC:
            out.append(signal("auth.list_relay_dmarc_fail", "Authentication broken by a mailing list",
                              "DMARC failed for \(auth.dmarcFromDomain ?? c.fromDomain) because a mailing list re-sent the message; the receiving server validated the list's ARC seal (arc=pass).",
                              .low, 0.15))
        case .fail?:
            let detail = "DMARC failed for \(auth.dmarcFromDomain ?? c.fromDomain): the sender is not authorized to use this domain."
            out.append(signal("auth.dmarc_fail", "DMARC failed", detail, .high, fromIsBrand ? 0.55 : 0.45))
        case .pass?:
            // A webmail domain authorizes every one of its millions of mailboxes, so "gmail.com passed DMARC" says
            // nothing about the human behind the address: the result is reported as evidence but earns no credit.
            // Aligned brand and organization domains keep the full credit (plus `mitigation.brand_authenticated`).
            let credit = c.fromIsFreeMail ? 0.0 : 0.08
            let detail = c.fromIsFreeMail
                ? "The webmail provider \(c.fromDomain) authorized this message, which says nothing about the sender."
                : "The From domain \(c.fromDomain) authorized this message."
            mitigations.append(mitigation("mitigation.dmarc_pass", "DMARC passed", detail, credit: credit))
        default:
            break
        }
        return out
    }

    // MARK: - sender.*

    private static let addressInNameRegex = try! NSRegularExpression(pattern: #"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+"#, options: [])

    static let companyWordsPhrases: [String] = [
        "support", "billing", "security", "service", "services", "team", "department", "dept", "admin", "administrator",
        "helpdesk", "help desk", "customer care", "customer service", "accounts", "account", "payroll", "finance", "invoice",
        "notification", "notifications", "alert", "alerts", "office", "desk", "bank", "inc", "llc", "ltd", "corp", "official",
        "ceo", "cfo", "president", "director", "verification", "delivery", "shipping", "refund", "lottery", "prize", "claims",
        "agent", "barrister", "attorney", "solicitor", "chambers", "treasury", "compliance", "hr", "it", "webmail", "mail team",
    ]

    /// Top-level domains that make a dotted fragment of a mailbox name read as a domain. Deliberately generic: a
    /// two-letter country code would fire on ordinary names ("mary.co@", "hans.de@"), and "dev"/"app"/"io" are common
    /// nicknames.
    static let localPartDomainTLDs: Set<String> = [
        "com", "net", "org", "edu", "gov", "info", "biz", "online", "site", "shop", "store", "xyz", "top", "live", "club", "ru", "cn",
    ]

    /// The domain or brand a mailbox name embeds ("809107334.**qq.com**@gmail.com", "**paypal**.support@gmail.com"),
    /// nil for ordinary addresses. Throwaway accounts made in bulk carry the domain they came from or the brand they
    /// impersonate inside the local part, where no provider verifies anything.
    ///
    /// The brand half only accepts distinctive catalog names as a *whole* token, so "chase.miller@" (a first name) and
    /// "wise.owl@" stay quiet, and a brand the From domain legitimately serves ("gmail" on gmail.com) never counts.
    static func localPartImpersonation(of address: EmailAddress, fromDomain: String) -> String? {
        guard let localPart = address.address.split(separator: "@").first else { return nil }
        let local = localPart.lowercased()
        guard local.count >= 4, local.count <= 128 else { return nil }

        for piece in local.split(whereSeparator: { $0 == "_" || $0 == "+" || $0 == "-" }) where piece.contains(".") {
            let labels = piece.split(separator: ".", omittingEmptySubsequences: true)
            guard labels.count >= 2, let tld = labels.last, localPartDomainTLDs.contains(String(tld)) else { continue }
            let second = labels[labels.count - 2]
            guard second.count >= 2, second.allSatisfy({ $0.isLetter || $0.isNumber }) else { continue }
            return "\(second).\(tld)"
        }

        for token in local.split(whereSeparator: { !$0.isLetter }) where token.count >= 4 {
            let word = String(token)
            guard let key = DomainAnalysis.brandKey(forBrandName: word), !DomainAnalysis.isDictionaryWordBrand(key),
                  !DomainAnalysis.isLegitimateDomain(fromDomain, for: key) else { continue }
            return word
        }
        return nil
    }

    static func senderSignals(_ c: Context) -> [Signal] {
        var out: [Signal] = []
        guard let from = c.fromAddress, !from.address.isEmpty else {
            return [signal("sender.missing_from", "No sender address", "The message has no usable From address.", .low, 0.1)]
        }

        // Display name carries a different email address.
        if !c.displayName.isEmpty {
            let ns = c.displayName as NSString
            if let match = addressInNameRegex.firstMatch(in: c.displayName, range: NSRange(location: 0, length: min(ns.length, 200))) {
                let shown = ns.substring(with: match.range).lowercased()
                let shownDomain = shown.split(separator: "@").last.map(String.init) ?? ""
                if DomainAnalysis.registrableDomain(of: shownDomain) != c.fromRegistrable {
                    out.append(signal("sender.display_name_address_mismatch", "Display name shows a different address",
                                      "The name shows \(shown) but the real sender is \(from.address).", .high, 0.5))
                }
            }
        }

        // Local part impersonates a domain or a brand ("809107334.qq.com@gmail.com", "paypal.support@gmail.com").
        if let tell = Self.localPartImpersonation(of: from, fromDomain: c.fromDomain) {
            out.append(signal("sender.localpart_contains_domain", "Sender address hides another name",
                              "The mailbox name of \(from.address) contains “\(tell)”, a throwaway/spoofing pattern: the address reads like another domain or brand.",
                              .medium, 0.3))
        }

        // Display name claims a brand that the From domain does not belong to.
        let nameBrands = Self.brandsMentioned(in: c.displayName)
        let claimedFromName = nameBrands.first(where: { !DomainAnalysis.isLegitimateDomain(c.fromDomain, for: $0) })
        if let brand = claimedFromName {
            if c.fromIsFreeMail {
                out.append(signal("sender.free_mail_brand_claim", "Brand name from a personal mailbox",
                                  "“\(c.displayName)” claims \(brandName(brand)) but was sent from the webmail address \(from.address).", .high, 0.45))
            } else {
                out.append(signal("sender.brand_display_name_mismatch", "Display name impersonates a brand",
                                  "“\(c.displayName)” claims \(brandName(brand)) but the sender domain is \(c.fromDomain).", .high, 0.45))
            }
        } else if c.fromIsFreeMail, !c.displayName.isEmpty, !Self.matches(.companyWords, in: c.displayName, limit: 1).isEmpty {
            out.append(signal("sender.free_mail_company_claim", "Company name from a personal mailbox",
                              "“\(c.displayName)” sounds like an organization but was sent from the webmail address \(from.address).", .medium, 0.3))
        }

        // The *message* speaks for a brand although the mailbox is personal webmail, and it wants the reader to act.
        // The low-effort scam that needs no lookalike domain and no urgency: "PayPal account in question — click here",
        // sent from someone's free mailbox. The display-name rule above only sees the name, which is often a nickname.
        if c.fromIsFreeMail, c.hasActionRequest,
           let brand = c.mentionedBrands.first(where: { $0 != claimedFromName && !DomainAnalysis.isLegitimateDomain(c.fromDomain, for: $0) }) {
            out.append(signal("sender.brand_pretext_from_webmail", "\(brandName(brand)) pretext from a personal mailbox",
                              "The message is about \(brandName(brand)) and asks you to act, but it was sent from the webmail address \(from.address), which \(brandName(brand)) does not use.",
                              .high, 0.5))
        }

        // From domain itself resembles a brand.
        if let match = DomainAnalysis.lookalikeMatch(for: c.fromDomain) {
            out.append(signal("sender.lookalike_domain", "Sender domain imitates \(brandName(match.brand.key))",
                              "\(c.fromDomain) looks like \(brandName(match.brand.key)) but is not one of its domains (\(match.kind.rawValue): “\(match.label)”).", .high, 0.55))
        }

        // Reply-To goes elsewhere.
        for reply in c.email.replyTo.prefix(3) {
            let replyDomain = reply.domain
            guard !replyDomain.isEmpty else { continue }
            let replyRegistrable = DomainAnalysis.registrableDomain(of: replyDomain)
            guard replyRegistrable != c.fromRegistrable else { continue }
            if c.recipientRegistrables.contains(replyRegistrable) { continue }   // replies go back to the recipient's own org
            if let match = DomainAnalysis.lookalikeMatch(for: replyDomain) {
                out.append(signal("sender.reply_to_lookalike", "Reply-To imitates \(brandName(match.brand.key))",
                                  "Replies go to \(reply.address), a domain that imitates \(brandName(match.brand.key)).", .high, 0.5))
            } else if !c.fromIsFreeMail, DomainAnalysis.isFreeMailDomain(replyDomain) {
                out.append(signal("sender.reply_to_freemail", "Replies go to a personal mailbox",
                                  "Sent from \(from.address) but replies go to \(reply.address).", .medium, 0.4))
            } else if c.fromIsFreeMail, DomainAnalysis.isFreeMailDomain(replyDomain) {
                out.append(signal("sender.reply_to_mismatch", "Reply-To differs from sender",
                                  "Sent from \(from.address) but replies go to a different webmail address, \(reply.address).", .medium, 0.3))
            } else {
                let weight = c.authentication.dmarc == .pass ? 0.2 : 0.25
                out.append(signal("sender.reply_to_mismatch", "Reply-To differs from sender",
                                  "Sent from \(from.address) but replies go to \(reply.address).", .low, weight))
            }
            break
        }

        // Sender: header from another domain (legitimate for mailing lists).
        if let senderHeader = c.email.sender, !senderHeader.domain.isEmpty,
           DomainAnalysis.registrableDomain(of: senderHeader.domain) != c.fromRegistrable {
            if c.hasListHeaders {
                out.append(signal("sender.sender_header_list", "Sent via a mailing list", "Sender header: \(senderHeader.address).", .info, 0))
            } else {
                out.append(signal("sender.sender_header_mismatch", "Sent on behalf of a different domain",
                                  "From \(from.address) but actually sent by \(senderHeader.address).", .medium, 0.25))
            }
        }

        // Return-Path from another domain.
        if let returnPath = c.email.header("Return-Path").flatMap({ EmailAddress.parse($0).first }), !returnPath.domain.isEmpty {
            let rpRegistrable = DomainAnalysis.registrableDomain(of: returnPath.domain)
            if rpRegistrable != c.fromRegistrable, c.authentication.dmarc != .pass {
                // Webmail domains are catalog "brands" (google, microsoft, …) but a gmail.com From re-sent by a mailing
                // list is not a brand spoof; treat it like any other personal sender.
                if c.fromBrandKey != nil, !c.fromIsFreeMail {
                    out.append(signal("sender.return_path_mismatch", "Bounce address does not match sender",
                                      "Return-Path is \(returnPath.address) although the mail claims to be from \(c.fromDomain).", .medium, 0.3))
                } else if !c.hasListHeaders {
                    out.append(signal("sender.return_path_mismatch", "Bounce address does not match sender",
                                      "Return-Path is \(returnPath.address), not \(c.fromDomain).", .low, 0.1))
                }
            }
        }

        // From equals the recipient (spoofed "from yourself").
        if c.email.to.contains(where: { $0.address == from.address }), c.authentication.dkim != .pass {
            out.append(signal("sender.from_equals_recipient", "Appears to be sent from your own address",
                              "The From address \(from.address) is your own address, without a valid signature.", .high, 0.45))
        }
        return out
    }

    // MARK: - link.*

    private static let credentialPathKeywords = [
        "login", "log-in", "logon", "signin", "sign-in", "verify", "verification", "secure", "account", "update", "password",
        "passwd", "auth", "confirm", "validate", "unlock", "reactivate", "wallet", "recover", "sso", "webmail", "owa",
        "office365", "o365", "sharepoint", "onedrive", "docusign", "invoice", "billing", "credential", "session", "2fa", "mfa",
    ]

    static func linkSignals(_ c: Context) -> [Signal] {
        var out: [Signal] = []
        struct Finding { var examples: [String] = []; var count = 0; mutating func add(_ s: String) { count += 1; if examples.count < 2 { examples.append(s) } } }
        var anchorMismatch = Finding(), lookalike = Finding(), brandMismatch = Finding(), ipHost = Finding(), punycode = Finding()
        var brandSubdomain = Finding(), bareAnchorMismatch = Finding()
        var brandSubdomainKeys: [String] = []
        var shortener = Finding(), badTLD = Finding(), deep = Finding(), credentialPath = Finding(), freeHosting = Finding()
        var plainHTTP = Finding(), dangerousScheme = Finding(), userinfo = Finding(), credentialHost = Finding()
        var lookalikeBrands: Set<String> = []
        var credentialOnFreeHosting = false
        var anchorShowsBrandSignIn = false
        var distinctHosts: Set<String> = []

        for link in c.links {
            let href = link.href
            let lower = href.lowercased()
            if lower.hasPrefix("javascript:") || lower.hasPrefix("data:") || lower.hasPrefix("vbscript:") {
                dangerousScheme.add(String(href.prefix(60)))
                continue
            }
            guard let host = DomainAnalysis.host(of: href) else { continue }
            let registrable = DomainAnalysis.registrableDomain(of: host)
            let aligned = c.isAlignedWithSender(host)
            let isBrandDomain = DomainAnalysis.isAnyBrandDomain(host)
            if !aligned { distinctHosts.insert(registrable) }

            // Anchor text shows a different destination. A visible URL behind the sender's own tracker or a known ESP
            // click-tracker is a redirect, not a hidden destination — unless the text shows a protected brand the sender is not.
            if let anchor = link.anchorText?.trimmingCharacters(in: .whitespacesAndNewlines), !anchor.isEmpty, !anchor.contains("@"),
               anchor.count <= 200, looksLikeURL(anchor), let anchorHost = DomainAnalysis.host(of: anchor),
               DomainAnalysis.registrableDomain(of: anchorHost) != registrable {
                let anchorIsBrand = DomainAnalysis.isAnyBrandDomain(anchorHost)
                if anchorIsBrand || !(aligned || emailServiceTrackerDomains.contains(registrable)) {
                    anchorMismatch.add("“\(String(anchor.prefix(50)))” → \(host)")
                    // "paypal.com/signin" shown over a foreign host is the phish shape whoever sends it; a brand's ordinary
                    // page ("github.com/acme/repo") behind a tracker is what newsletters do.
                    let anchorPath = pathAndQuery(of: anchor)
                    if anchorIsBrand, credentialPathKeywords.contains(where: { anchorPath.contains($0) }) { anchorShowsBrandSignIn = true }
                }
            } else if let anchor = link.anchorText?.trimmingCharacters(in: .whitespacesAndNewlines),
                      let anchorHost = bareDomainAnchorHost(anchor),
                      DomainAnalysis.registrableDomain(of: anchorHost) != registrable,
                      !aligned, !emailServiceTrackerDomains.contains(registrable) {
                // A bare domain as the visible text ("Zoom.schedule.com", "acme-invoices.com") promises a destination
                // as plainly as a full URL, but `looksLikeURL` only accepts a bare domain when it is a brand's own, so
                // the mismatch above never sees this shape.
                bareAnchorMismatch.add("“\(String(anchor.prefix(50)))” → \(host)")
            }

            if let match = DomainAnalysis.lookalikeMatch(for: host) {
                lookalike.add("\(host) (\(brandName(match.brand.key)))")
                lookalikeBrands.insert(match.brand.key)
            } else if !aligned, let match = DomainAnalysis.brandSubdomainMatch(for: host) {
                brandSubdomain.add("\(host) (\(brandName(match.brandKey)) → \(match.registrableDomain))")
                if !brandSubdomainKeys.contains(match.brandKey) { brandSubdomainKeys.append(match.brandKey) }
            } else if !aligned, !isBrandDomain, !c.mentionedBrands.isEmpty, !DomainAnalysis.isURLShortener(host), !DomainAnalysis.isIPLiteral(host) {
                if !c.mentionedBrands.contains(where: { DomainAnalysis.isLegitimateDomain(host, for: $0) }) {
                    brandMismatch.add(host)
                }
            }

            if DomainAnalysis.isIPLiteral(host) { ipHost.add(host) }
            if DomainAnalysis.isPunycode(host) { punycode.add(host) }
            if DomainAnalysis.isURLShortener(host) { shortener.add(host) }
            if DomainAnalysis.hasSuspiciousTLD(host) { badTLD.add(host) }
            if !aligned, !isBrandDomain, DomainAnalysis.subdomainDepth(of: host) >= 3 { deep.add(host) }

            let pathAndQuery = pathAndQuery(of: href)
            let hasCredentialKeyword = credentialPathKeywords.contains { pathAndQuery.contains($0) }
            if hasCredentialKeyword, !aligned, !isBrandDomain {
                credentialPath.add(host + String(pathAndQuery.prefix(40)))
            } else if !aligned, !isBrandDomain, hostHasCredentialToken(host) {
                credentialHost.add(host)
            }
            if !aligned, DomainAnalysis.isFreeHosting(host) {
                freeHosting.add(host)
                if hasCredentialKeyword { credentialOnFreeHosting = true }
            }
            if lower.hasPrefix("http://"), !aligned, !DomainAnalysis.isIPLiteral(host), pathAndQuery.count > 1 { plainHTTP.add(host) }
            if hasUserInfo(href) { userinfo.add(String(href.prefix(80))) }
        }

        if anchorMismatch.count > 0 {
            // A visible URL from a fully authenticated sender is most likely routed through an unlisted click-tracker;
            // a brand sign-in URL over a foreign host is the classic phish shape whoever sends it.
            let tracked = !anchorShowsBrandSignIn && c.isAuthenticatedSender
            out.append(signal("link.anchor_host_mismatch", "Link text hides its real destination",
                              "The visible link text points elsewhere than the actual link: \(anchorMismatch.examples.joined(separator: "; ")).",
                              tracked ? .medium : .high, tracked ? 0.3 : 0.55))
        }
        if lookalike.count > 0 {
            let mentioned = lookalikeBrands.first { c.mentionedBrands.contains($0) }
            let suffix = mentioned.map { " The mail also refers to \(brandName($0))." } ?? ""
            out.append(signal("link.lookalike_domain", "Link imitates a well-known brand",
                              "Links go to \(lookalike.examples.joined(separator: ", ")), which imitate a brand without being its real domain.\(suffix)", .high, 0.55))
        }
        if brandSubdomain.count > 0, let brand = brandSubdomainKeys.first {
            out.append(signal("link.brand_subdomain_mismatch", "Link only looks like \(brandName(brand))",
                              "\(brandName(brand)) is the first part of the link's host, but the domain that owns it belongs to someone else: \(brandSubdomain.examples.joined(separator: ", ")).",
                              .high, 0.5))
        }
        if bareAnchorMismatch.count > 0 {
            out.append(signal("link.anchor_is_bare_domain_mismatch", "Link text names a different site",
                              "The visible text is a domain, but the link goes to another one: \(bareAnchorMismatch.examples.joined(separator: "; ")).",
                              .medium, 0.35))
        }
        if brandMismatch.count > 0, let brand = c.mentionedBrands.first {
            out.append(signal("link.brand_domain_mismatch", "Links do not go to \(brandName(brand))",
                              "The mail refers to \(brandName(brand)) but links go to \(brandMismatch.examples.joined(separator: ", ")).", .medium, 0.25))
        }
        if userinfo.count > 0 {
            out.append(signal("link.userinfo_url", "Link hides its host behind an @ sign",
                              "URL uses the user@host trick: \(userinfo.examples.joined(separator: ", ")).", .high, 0.5))
        }
        if ipHost.count > 0 {
            out.append(signal("link.ip_literal_host", "Link goes to a raw IP address", "Links use an IP address instead of a domain: \(ipHost.examples.joined(separator: ", ")).", .high, 0.5))
        }
        if punycode.count > 0 {
            out.append(signal("link.punycode_host", "Link uses an internationalized (punycode) domain", "Hosts: \(punycode.examples.joined(separator: ", ")).", .medium, 0.35))
        }
        if dangerousScheme.count > 0 {
            out.append(signal("link.dangerous_scheme", "Link runs script or embeds a page", "javascript:/data: links: \(dangerousScheme.examples.joined(separator: ", ")).", .medium, 0.4))
        }
        if shortener.count > 0 {
            out.append(signal("link.url_shortener", "Shortened link hides its destination", "URL shortener: \(shortener.examples.joined(separator: ", ")).", .low, 0.2))
        }
        if badTLD.count > 0 {
            out.append(signal("link.suspicious_tld", "Link uses a high-risk domain ending", "Hosts: \(badTLD.examples.joined(separator: ", ")).", .medium, 0.3))
        }
        if credentialPath.count > 0 {
            out.append(signal("link.credential_path", "Link looks like a sign-in or verification page",
                              "Unrelated site with a login/verify-style path: \(credentialPath.examples.joined(separator: ", ")).", .medium, 0.3))
        }
        if credentialHost.count > 0 {
            out.append(signal("link.credential_host", "Link domain is named like a sign-in page",
                              "Unrelated site whose name suggests login/verification: \(credentialHost.examples.joined(separator: ", ")).", .medium, 0.25))
        }
        if freeHosting.count > 0 {
            let weight = credentialOnFreeHosting ? 0.35 : 0.2
            out.append(signal("link.free_hosting", "Link goes to a free hosting page", "Anyone can publish on: \(freeHosting.examples.joined(separator: ", ")).", credentialOnFreeHosting ? .medium : .low, weight))
        }
        if deep.count > 0 {
            out.append(signal("link.deep_subdomain", "Link has an unusually long domain chain", "Hosts: \(deep.examples.joined(separator: ", ")).", .low, 0.15))
        }
        if distinctHosts.count > 10 {
            out.append(signal("link.many_hosts", "Links go to many different sites", "\(distinctHosts.count) different domains are linked.", .low, 0.1))
        }
        if plainHTTP.count > 0 {
            out.append(signal("link.plain_http", "Unencrypted (http) link", "Links without TLS: \(plainHTTP.examples.joined(separator: ", ")).", .low, 0.1))
        }
        return out
    }

    private static let credentialHostTokens: Set<String> = [
        "login", "logon", "signin", "verify", "verification", "secure", "account", "update", "password", "auth", "confirm",
        "validate", "unlock", "reactivate", "wallet", "recover", "recovery", "sso", "webmail", "authenticate", "authentication",
    ]

    /// True when a hyphen/dot-separated token of the host (below the public suffix) is a credential keyword.
    private static func hostHasCredentialToken(_ host: String) -> Bool {
        let suffixCount = DomainAnalysis.publicSuffix(of: host).split(separator: ".").count
        let labels = host.split(separator: ".").dropLast(suffixCount)
        for label in labels {
            for token in label.split(separator: "-") where credentialHostTokens.contains(String(token)) { return true }
        }
        return false
    }

    /// Registrable domains of e-mail service providers' click-trackers, which legitimately wrap every link of a
    /// newsletter ("https://example.com/post" → x.us21.list-manage.com/track/click). Local to the analyzer (the host
    /// catalogs in `DomainAnalysis` are owned by the parsing rules); candidates for moving there later.
    private static let emailServiceTrackerDomains: Set<String> = [
        "list-manage.com", "mailchimpapp.net", "mcsv.net", "rsgsv.net", "mandrillapp.com", "sendgrid.net", "substack.com",
        "hubspotlinks.com", "convertkit-mail.com", "convertkit-mail2.com", "klclick.com", "klclick1.com", "klclick2.com",
        "klclick3.com", "cmail19.com", "cmail20.com", "cmail29.com", "createsend.com", "mailerlite.com", "beehiiv.com",
        "mailgun.org", "sparkpostmail.com", "exacttarget.com", "customeriomail.com", "iterable.com", "mailjet.com", "awstrack.me",
    ]

    /// Top-level domains a *visible* anchor text may end in for it to read as an address rather than as the name of a
    /// piece of software ("Node.js", "socket.io", "ASP.NET"). Deliberately a common-TLD list: the anchor is what the
    /// reader is meant to believe, and nobody is fooled by a TLD they have never seen. A rare TLD in the anchor is
    /// still caught by the other link rules once the href disagrees with it.
    static let anchorDomainTLDs: Set<String> = [
        "com", "net", "org", "edu", "gov", "mil", "info", "biz", "co", "us", "uk", "ca", "de", "fr", "nl", "es", "it",
        "se", "no", "dk", "fi", "pl", "pt", "ch", "at", "be", "ie", "au", "nz", "jp", "cn", "in", "br", "mx", "ru",
        "za", "tv", "me", "xyz", "top", "site", "online", "shop", "store", "live", "club", "link",
    ]

    /// Host of an anchor text that is nothing but a bare domain ("Zoom.schedule.com", "www.acme-invoice.net"), nil for
    /// prose, addresses, full URLs with a path (covered by `looksLikeURL`) and anything unparsable. Requires at least
    /// two labels and a TLD from `anchorDomainTLDs`, so a sentence with a dot or a library name cannot qualify.
    static func bareDomainAnchorHost(_ text: String) -> String? {
        var candidate = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !candidate.isEmpty, candidate.count <= 100, !candidate.contains(" "), !candidate.contains("@"),
              !candidate.contains("/"), !candidate.contains(":"), !candidate.contains("?") else { return nil }
        while candidate.hasSuffix(".") || candidate.hasSuffix(",") { candidate.removeLast() }
        let labels = candidate.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, let tld = labels.last, anchorDomainTLDs.contains(String(tld)),
              labels.allSatisfy({ !$0.isEmpty && $0.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" } }) else { return nil }
        guard let host = DomainAnalysis.host(of: candidate), host == candidate else { return nil }
        return host
    }

    private static func looksLikeURL(_ text: String) -> Bool {
        let lower = text.lowercased()
        if lower.hasPrefix("http://") || lower.hasPrefix("https://") || lower.hasPrefix("www.") { return true }
        // "paypal.com/signin" style: no spaces, a dot followed by letters, and either a path or a protected-brand host.
        // Bare product names ("Node.js", "ASP.NET", "socket.io") are not addresses.
        guard !lower.contains(" "), let dot = lower.firstIndex(of: "."), lower.count >= 5 else { return false }
        let afterDot = lower[lower.index(after: dot)...]
        let tld = afterDot.prefix { $0.isLetter }
        guard tld.count >= 2, let host = DomainAnalysis.host(of: lower) else { return false }
        return lower.contains("/") || DomainAnalysis.isAnyBrandDomain(host)
    }

    private static func pathAndQuery(of href: String) -> String {
        let trimmed = href.trimmingCharacters(in: .whitespacesAndNewlines)
        if let components = URLComponents(string: trimmed) {
            return (components.percentEncodedPath + "?" + (components.percentEncodedQuery ?? "")).lowercased()
        }
        guard let schemeEnd = trimmed.range(of: "://") else { return trimmed.lowercased() }
        let rest = trimmed[schemeEnd.upperBound...]
        guard let slash = rest.firstIndex(of: "/") else { return "" }
        return String(rest[slash...]).lowercased()
    }

    private static func hasUserInfo(_ href: String) -> Bool {
        guard let schemeEnd = href.range(of: "://") else { return false }
        let authority = href[schemeEnd.upperBound...].prefix { $0 != "/" && $0 != "?" && $0 != "#" }
        return authority.contains("@")
    }

    // MARK: - content.*

    static let urgencyPhrases: [String] = [
        "immediately", "urgent", "urgently", "within 24 hours", "within 48 hours", "within 72 hours", "within 12 hours",
        "24 hours", "48 hours", "72 hours", "12 hours",
        "right now", "right away", "as soon as possible", "asap", "act now", "expires today", "expire today", "today only",
        "final notice", "final warning", "last warning", "last chance", "time-sensitive", "time sensitive", "before it's too late",
        "limited time", "deadline", "will expire", "expires in", "expiring", "will be closed", "will be suspended", "will be terminated",
        "will be deleted", "will be locked", "end of the day", "end of day", "by tonight", "respond immediately", "without delay",
        "prompt attention", "do not ignore", "do not delay", "hurry", "only a few hours",
    ]

    static let threatPhrases: [String] = [
        "suspended", "suspension", "terminated", "termination", "permanently", "locked", "has been limited", "limited access",
        "will be closed", "legal action", "lawsuit", "arrest", "warrant", "police", "prosecut",
        // Qualified forms only: bare "unauthorized" is legal-footer boilerplate ("any unauthorized use … is prohibited").
        "unauthorized access", "unauthorised access", "unauthorized login", "unauthorised login", "unauthorized sign-in",
        "unauthorised sign-in", "unauthorized transaction", "unauthorised transaction", "unauthorized activity",
        "unauthorised activity", "unauthorized attempt", "unauthorised attempt", "unauthorized purchase", "unauthorised purchase",
        "unauthorized charge", "unauthorised charge", "unauthorized use of your", "unauthorised use of your",
        "unusual activity", "suspicious activity", "suspicious sign-in", "unusual sign-in", "compromised", "hacked", "breach",
        "failure to", "we will be forced", "penalty", "blocked", "disabled", "deactivated", "restricted", "on hold",
    ]

    static let credentialPhrases: [String] = [
        "verify your account", "verify your identity", "verify your information", "verify your email", "verify your details",
        "verify your password", "confirm your account", "confirm your identity", "confirm your password", "confirm your details",
        "confirm your information", "confirm your email", "update your password", "update your account", "update your payment",
        "update your details", "update your information", "update your billing", "your password will expire", "password expires",
        "password has expired", "password expiry", "password expiration", "keep my password", "keep your password",
        "keep the same password", "keep current password", "keep my current password", "keep same password", "re-enter your", "reenter your", "validate your account",
        "validate your", "reactivate your account", "reactivate your", "unlock your account", "restore access", "restore your account",
        "restore your information", "restore your details", "restore your access",
        "security code", "one-time code", "one time code", "verification code", "2fa code", "authentication code",
        "social security number", "ssn", "date of birth", "mother's maiden name", "login credentials", "log in credentials",
        "username and password", "user name and password", "enter your password", "sign in to continue", "login to continue",
        "log in to continue", "confirm your account now", "account verification", "identity verification", "verify now",
        "review your account", "review the activity", "secure your account", "your account has been limited", "reset your password",
        "password reset",
    ]

    static let paymentPhrases: [String] = [
        "payment details", "payment information", "billing information", "billing details", "credit card number", "card number",
        "card details", "pay a fee", "processing fee", "redelivery fee", "delivery fee", "customs fee", "shipping fee",
        "service fee", "release fee", "small fee", "clearance fee", "handling fee", "unpaid fee", "outstanding balance",
        "outstanding payment", "overdue invoice", "overdue payment", "past due", "make a payment", "make the payment", "pay now",
        "pay the", "pay $", "pay usd", "pay €", "pay £", "payment required", "payment is required", "payment failed",
        "payment declined", "payment could not be processed", "update your payment method", "reschedule delivery",
        "reschedule your delivery", "redeliver", "re-deliver", "payment link", "settle the", "remit", "remittance",
        "pending payment", "confirm payment", "payment confirmation required",
    ]

    static let giftCardPhrases: [String] = [
        "gift card", "gift cards", "giftcard", "giftcards", "itunes card", "itunes cards", "google play card", "google play cards",
        "steam card", "steam cards", "amazon card", "prepaid card", "prepaid cards", "scratch off", "scratch the back",
        "card codes", "redemption code", "redemption codes", "claim code", "e-gift", "egift", "vanilla card", "razer gold",
        "send me the codes", "photos of the codes", "picture of the cards",
    ]

    static let wirePhrases: [String] = [
        "wire transfer", "bank transfer", "transfer the funds", "transfer of funds", "funds transfer", "wire the", "wire payment",
        "account number and routing", "routing number", "iban", "swift code", "bic code", "bank details", "banking details",
        "bank account details", "bank account number", "update your bank", "new bank account", "change of bank", "changed our bank",
        "updated banking", "account details for payment", "beneficiary account", "telegraphic transfer", "ach transfer",
        "western union", "moneygram",
    ]

    static let cryptoPhrases: [String] = [
        "bitcoin", "btc", "ethereum", "usdt", "tether", "crypto wallet", "wallet address", "cryptocurrency", "send crypto",
        "bitcoin address", "monero", "xmr", "litecoin", "dogecoin", "bc1q", "crypto giveaway", "airdrop", "seed phrase",
        "recovery phrase", "private key", "crypto",
    ]

    private static let walletRegex = try! NSRegularExpression(pattern: #"(?<![A-Za-z0-9])(?:bc1[a-z0-9]{25,62}|0x[a-fA-F0-9]{40})(?![A-Za-z0-9])"#, options: [])

    static let genericGreetingPhrases: [String] = [
        "dear customer", "dear user", "dear member", "dear client", "dear account holder", "dear valued customer",
        "dear valued member", "dear sir/madam", "dear sir or madam", "dear sir", "dear madam", "dear beneficiary", "dear friend",
        "dear winner", "dear email user", "dear mailbox user", "dear account user", "dear subscriber", "dear cardholder",
        "dear customer,", "hello dear", "attention:", "attn:", "dear taxpayer", "dear applicant", "dear recipient", "dear owner",
        "greetings of the day", "dear colleague",
    ]

    static let secrecyPhrases: [String] = [
        "keep this between us", "keep this confidential", "keep it confidential", "do not tell", "don't tell", "don't share this",
        "do not share this", "strictly confidential", "highly confidential", "discreet", "discretion",
        "between you and me", "top secret", "keep this private", "tell no one", "keep it to yourself", "not to inform",
        "do not discuss", "keep this quiet", "it's a surprise", "it is a surprise",
    ]

    static let executiveCuePhrases: [String] = [
        "in a meeting", "in meetings", "back-to-back meetings", "back to back meetings", "can't take calls", "cannot take calls",
        "can't talk", "can not talk", "unable to take calls", "reply here",
        "are you available", "are you at your desk", "quick favor", "quick task", "need you to handle", "need your help",
        "need a favor", "urgent request", "sent from my iphone", "sent from my mobile", "get back to me", "text me",
        "your personal cell", "your cell number", "do this for me", "handle something for me", "let me know how soon",
        "can't call", "not reachable by phone", "before the end of the day", "i'm in a conference",
    ]

    static let executiveTitlePhrases: [String] = [
        "chief executive officer", "ceo", "cfo", "coo", "cto", "chief financial officer", "managing director", "president",
        "vice president", "executive director", "director", "head of", "chairman", "founder", "owner", "general manager",
        "executive office", "office of the ceo",
    ]

    static let lurePhrases: [String] = [
        "you have won", "you've won", "you have been selected", "you've been selected", "you are the winner", "winner",
        "lottery", "lotto", "jackpot", "prize", "claim your", "claim the", "inheritance", "next of kin", "beneficiary",
        "million", "usd", "unclaimed", "compensation", "giveaway", "double your", "guaranteed return", "guaranteed profit",
        "risk-free", "risk free", "100% free", "congratulations", "award", "grant", "fund release", "release of funds",
        "consignment", "diplomat", "atm card", "reward", "bonus", "cash prize", "sweepstakes", "investment opportunity",
        "trust fund", "late client", "deceased", "abandoned fund", "dormant account", "send back", "return to you",
        "receive twice", "receive 2x", "first come first served",
    ]

    static let sextortionPhrases: [String] = [
        "recorded you", "webcam", "web cam", "adult website", "adult websites", "adult sites", "porn", "pornographic",
        "masturbat", "intimate", "compromising video", "compromising material", "i have a video", "i have video", "video of you",
        "your contacts", "all your contacts", "your device was hacked", "i hacked", "i have hacked", "installed malware",
        "installed a trojan", "trojan", "spyware", "expose you", "embarrassing", "your secret", "pleasuring yourself",
        "explicit video", "screen recording", "your camera", "keylogger", "rat software", "remote access",
        "browsing history", "i know what you", "send the video", "your family and friends",
    ]

    private static let phoneRegex = try! NSRegularExpression(pattern: #"(?<![0-9])(?:\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?![0-9])"#, options: [])

    static let renewalPhrases: [String] = [
        "auto-renew", "auto renew", "auto-renewed", "auto renewed", "automatically renewed", "has been renewed", "been renewed",
        "renewal", "renewed", "subscription", "charged", "will be charged", "been charged", "has been debited", "debited",
        "invoice", "order id", "order number", "purchase", "annual plan", "license key", "your plan", "membership",
        "successfully paid", "payment received", "amount paid", "transaction id",
    ]

    static let callbackPhrases: [String] = [
        "call us", "call our", "call now", "call the number", "call this number", "call customer", "contact our support",
        "contact us at", "contact customer care", "customer care", "helpline", "help line", "toll free", "toll-free",
        "to cancel", "cancel the subscription", "cancel your subscription", "to stop the charge", "for refund", "for a refund",
        "get a refund", "refund", "dispute", "support number", "support team at", "reach us at", "speak to an agent",
        "talk to our", "24/7", "24x7", "helpdesk number",
    ]

    static let invoiceSubjectPhrases: [String] = [
        "invoice", "receipt", "payment", "order", "statement", "shipment", "delivery", "purchase", "quotation", "quote",
        "remittance", "refund", "bill", "po ", "purchase order", "transaction", "wire",
    ]

    static let attachmentRequestPhrases: [String] = [
        "open the attached", "open the attachment", "see attached", "see the attached", "see attachment", "attached invoice",
        "attached file", "attached document", "find attached", "find the attached", "please find attached", "attached is",
        "attached herewith", "review the attached", "download the attached", "view the attached", "check the attached",
        "attachment for", "in the attachment", "the attachment contains", "kindly find attached", "attached copy",
        "attached statement", "attached receipt", "attached payment", "as attached", "attached for your review",
        "enclosed", "open attachment", "attached below",
    ]

    /// Payroll / wages pretexts. Phrases are possessive or role-bound ("your payroll", "student employee") so that
    /// ordinary business prose about salaries or an HR newsletter does not match.
    static let payrollPhrases: [String] = [
        "your payroll", "payroll department", "payroll information", "payroll details", "payroll update", "payroll portal",
        "payroll system", "payroll account", "payroll form", "payroll change", "payroll setup", "regarding your payroll",
        "direct deposit", "your paycheck", "paycheck details", "pay stub", "paystub", "pay slip", "payslip", "your salary",
        "salary payment", "salary details", "salary increase", "wage payment", "your wages", "timesheet", "time sheet",
        "student employee", "student employment", "student worker", "work-study", "work study", "new hire paperwork",
        "onboarding paperwork", "hr onboarding", "employment verification", "banking details for payroll",
        "update your bank details", "reimbursement form",
    ]

    /// Imperatives that ask the reader to do something with a link, a document or a meeting. Short and explicit: these
    /// gate the "stranger with a link" multiplier, so prose that merely mentions a link must not match.
    static let actionRequestPhrases: [String] = [
        "click on this link", "click on the link", "click this link", "click the link", "click here", "click below",
        "click on the button", "kindly click", "please click", "open the link", "follow the link", "use the link below",
        "use this link", "here is the link", "here's the link", "link below to", "below to restore", "tap the link",
        "schedule a meeting", "schedule a call", "set up a meeting", "book a meeting", "arrange a meeting", "confirm the meeting",
        "sign in here", "log in here", "fill out the", "fill in the", "complete the form", "complete the attached",
        "download the", "view the document", "review the document", "get back to me", "reply to this email", "reply with your",
        "let me know your availability", "let me know if you can",
    ]

    static let qrPhrases: [String] = [
        "scan the qr code", "scan this qr code", "scan the code below", "scan qr code", "qr code to", "using your phone camera",
        "scan with your phone", "scan the barcode",
    ]

    /// Credential phrases that also describe legitimate one-time-code delivery (2FA, sign-in codes).
    static let codeDeliveryPhrases: Set<String> = ["security code", "one-time code", "one time code", "verification code", "2fa code", "authentication code"]
    /// Secrecy / urgency phrases that are boilerplate in code-delivery mail ("do not share this code", "expires in 10 minutes").
    static let codeDeliverySecrecyPhrases: Set<String> = ["do not share this", "don't share this"]
    static let codeDeliveryUrgencyPhrases: Set<String> = ["expires in", "will expire", "expiring"]
    /// A 4–8 digit code (or "123 456" / "123-456") within 40 non-digit characters of "code"/"passcode"/"otp"/"pin".
    /// Bounded, no nested quantifiers.
    private static let otpCodeRegex = try! NSRegularExpression(
        pattern: #"(?i)(?:\b(?:code|passcode|otp|pin)\b[^0-9]{0,40}(?<![0-9])(?:[0-9]{4,8}|[0-9]{3}[ -][0-9]{3})(?![0-9]))|(?:(?<![0-9])(?:[0-9]{4,8}|[0-9]{3}[ -][0-9]{3})(?![0-9])[^0-9]{0,40}\b(?:code|passcode|otp|pin)\b)"#,
        options: [])

    /// Legitimate OTP/2FA delivery: the only credential cues are code-delivery phrases, a code token is present, every
    /// link stays on the sender's domain, there is no attachment, and the sender authenticated (DMARC pass or aligned
    /// DKIM) without any failure. A code mail that also says "enter your password", links elsewhere, carries a file or
    /// failed authentication keeps the full credential signal.
    static func isCodeDelivery(_ c: Context, credentials: [String], text: String) -> Bool {
        guard !credentials.isEmpty, credentials.allSatisfy({ codeDeliveryPhrases.contains($0.lowercased()) }) else { return false }
        guard c.email.attachments.isEmpty, !c.authenticationFailed, c.authentication.dmarc == .pass || c.dkimAlignedPass else { return false }
        guard c.links.allSatisfy({ $0.host.map(c.isAlignedWithSender) ?? false }) else { return false }
        return otpCodeRegex.firstMatchText(in: text) != nil
    }

    /// Gift-card phrases that express a request for cards/codes rather than a promotion.
    static let giftCardRequestPhrases: Set<String> = [
        "scratch off", "scratch the back", "card codes", "redemption code", "redemption codes", "claim code",
        "send me the codes", "photos of the codes", "picture of the cards",
    ]
    /// Lure words that are routine in loyalty/marketing copy from authenticated bulk senders.
    static let promotionalLureWords: Set<String> = [
        "bonus", "reward", "award", "claim your", "claim the", "congratulations", "giveaway", "sweepstakes", "first come first served",
    ]

    /// Characters covered by the three single-pattern regexes (phone numbers, wallet addresses, code tokens); lexicon
    /// matching covers the full `scanText` through the automaton.
    static let maxRegexScanCharacters = 30_000

    /// A body shorter than this counts as "a couple of sentences" for `content.action_request_from_stranger`.
    public static let strangerRequestBodyCharacters = 600

    static func contentSignals(_ c: Context) -> [Signal] {
        var out: [Signal] = []
        let text = String(c.scanText.prefix(maxRegexScanCharacters))

        // One-time-code delivery shares wording with credential phish; recognise the authenticated, link-less shape once
        // and tone down the three rules it would otherwise trip (credential request, "do not share", "expires in").
        let allCredentials = c.matches(.credential, limit: 4)
        let codeDelivery = Self.isCodeDelivery(c, credentials: allCredentials, text: text)

        var urgency = c.matches(.urgency, limit: 3)
        if codeDelivery { urgency.removeAll { codeDeliveryUrgencyPhrases.contains($0.lowercased()) } }
        if !urgency.isEmpty {
            out.append(signal("content.urgency", "Pressure to act quickly", "Urgency language: \(quoted(urgency)).", .medium, 0.25))
        }
        let threats = c.matches(.threat, limit: 3)
        if !threats.isEmpty {
            out.append(signal("content.threat", "Threatens consequences", "Threatening language: \(quoted(threats)).", .medium, 0.3))
        }
        let credentials = codeDelivery ? [] : Array(allCredentials.prefix(3))
        if !credentials.isEmpty {
            // Sign-in, security and password wording is the daily business of the brands people actually have accounts
            // with. When the brand's own domain signed the mail (aligned DKIM + DMARC), nothing is attached and every
            // link stays on its domains, the wording is routine: report it, but not as high-severity evidence.
            if c.isAuthenticatedBrandNotice {
                out.append(signal("content.credential_request", "Mentions your account or sign-in",
                                  "Account/sign-in wording (\(quoted(credentials))) in a message \(brandName(c.fromBrandKey ?? "")) itself signed, with links only to its own site.",
                                  .medium, 0.25))
            } else {
                out.append(signal("content.credential_request", "Asks you to verify or sign in",
                                  "Requests credentials or account confirmation: \(quoted(credentials)).", .high, 0.4))
            }
        }
        let payments = c.matches(.payment, limit: 3)
        if !payments.isEmpty {
            out.append(signal("content.payment_request", "Asks for a payment or fee", "Payment language: \(quoted(payments)).", .medium, 0.35))
        }
        // Payroll / direct-deposit / student-employment pretexts. Payroll is where an employee expects money to move,
        // which is why the "quick question about your payroll" mail from an unknown mailbox works; the real payroll
        // notice comes from the organization's own authenticated domain, which is exactly what is excluded here.
        let payroll = c.matches(.payroll, limit: 3)
        if !payroll.isEmpty, !c.isOrganizationalSender, c.hasActionRequest {
            out.append(signal("content.payroll_payment_lure", "Payroll or salary pretext from an outside sender",
                              "Payroll/payment-of-wages language from a sender outside your organization: \(quoted(payroll)).",
                              .high, 0.45))
        }
        let giftCards = c.matches(.giftCard, limit: 4)
        if !giftCards.isEmpty {
            let requestSemantics = giftCards.contains { giftCardRequestPhrases.contains($0.lowercased()) }
            if c.isAuthenticatedBulkSender, !requestSemantics {
                out.append(signal("content.gift_card_request", "Mentions gift cards",
                                  "Gift-card language from an authenticated mailing-list sender: \(quoted(giftCards)).", .low, 0.15))
            } else {
                out.append(signal("content.gift_card_request", "Asks for gift cards", "Gift-card language: \(quoted(giftCards)).", .high, 0.5))
            }
        }
        let wires = c.matches(.wire, limit: 3)
        if !wires.isEmpty {
            out.append(signal("content.wire_transfer_request", "Asks for a bank transfer or bank details",
                              "Wire/bank language: \(quoted(wires)).", .high, 0.45))
        }
        let cryptoWords = c.matches(.crypto, limit: 3)
        let walletAddresses = walletRegex.firstMatchText(in: text)
        if walletAddresses != nil || cryptoWords.count >= 2 || (cryptoWords.count == 1 && !["crypto", "airdrop", "tether"].contains(cryptoWords[0].lowercased())) {
            var examples = cryptoWords
            if let wallet = walletAddresses { examples.append(wallet) }
            out.append(signal("content.crypto_payment_request", "Involves cryptocurrency payment", "Crypto language: \(quoted(examples)).", .high, 0.45))
        }
        let greetings = Self.matches(.genericGreeting, in: String(c.bodyText.prefix(300)), limit: 1)
        if !greetings.isEmpty {
            out.append(signal("content.generic_greeting", "Generic greeting", "Does not address you by name: \(quoted(greetings)).", .low, 0.15))
        }
        var secrecy = c.matches(.secrecy, limit: 3)
        if codeDelivery { secrecy.removeAll { codeDeliverySecrecyPhrases.contains($0.lowercased()) } }
        if !secrecy.isEmpty {
            out.append(signal("content.secrecy_request", "Asks for secrecy", "Secrecy language: \(quoted(secrecy)).", .medium, 0.35))
        }

        let execCues = c.matches(.executiveCue, limit: 4)
        let execTitles = c.matches(.executiveTitle, limit: 2)
        // One cue plus a signature title is only evidence when the sender is not a verified organization: "are you
        // available … Director of Partnerships" from an authenticated partner domain is ordinary correspondence.
        let replyToElsewhere = c.email.replyTo.contains { reply in
            guard !reply.domain.isEmpty else { return false }
            let registrable = DomainAnalysis.registrableDomain(of: reply.domain)
            return registrable != c.fromRegistrable && !c.recipientRegistrables.contains(registrable)
        }
        let senderUnverified = c.fromIsFreeMail || replyToElsewhere || c.authenticationFailed || !c.authentication.hasAnyResult
        if execCues.count >= 2 || (execCues.count == 1 && !execTitles.isEmpty && senderUnverified) {
            let corporateRecipient = !c.recipientRegistrables.isEmpty && !c.recipientRegistrables.contains { DomainAnalysis.isFreeMailDomain($0) }
            let weight = (c.fromIsFreeMail && corporateRecipient) ? 0.4 : 0.35
            out.append(signal("content.executive_impersonation", "Looks like an executive impersonation",
                              "Typical CEO-fraud cues: \(quoted(execCues + execTitles, limit: 4)).", .medium, weight))
        }

        var lures = c.matches(.lure, limit: 4)
        if c.isAuthenticatedBulkSender { lures.removeAll { promotionalLureWords.contains($0.lowercased()) } }
        if lures.count >= 2 {
            out.append(signal("content.advance_fee_payment_lure", "Too good to be true", "Prize/inheritance/giveaway language: \(quoted(lures, limit: 4)).", .high, 0.4))
        } else if lures.count == 1, !["award", "bonus", "reward", "grant", "usd", "million", "winner", "congratulations"].contains(lures[0].lowercased()) {
            out.append(signal("content.advance_fee_payment_lure", "Prize or windfall language", "Found \(quoted(lures)).", .low, 0.2))
        }

        let sextortion = c.matches(.sextortion, limit: 4)
        if sextortion.count >= 2 || (sextortion.count == 1 && (walletAddresses != nil || cryptoWords.count >= 1)) {
            out.append(signal("content.sextortion_crypto_threat", "Extortion attempt", "Blackmail language: \(quoted(sextortion, limit: 4)).", .high, 0.6))
        }

        // Tech-support / fake-renewal callback scam: phone number + renewal/charge wording + "call/cancel/refund".
        if let phone = phoneRegex.firstMatchText(in: text) {
            let renewals = c.matches(.renewal, limit: 3)
            let callbacks = c.matches(.callback, limit: 3)
            if !renewals.isEmpty, !callbacks.isEmpty, c.links.count <= 3 {
                out.append(signal("content.support_callback_payment_scam", "Asks you to call about a charge",
                                  "A phone number (\(phone)) with \(quoted(renewals, limit: 2)) and \(quoted(callbacks, limit: 2)) — typical of fake-renewal support scams.", .high, 0.45))
            }
        }

        // Subject says invoice/order, body asks to sign in.
        if !Self.matches(.invoiceSubject, in: c.subject, limit: 1).isEmpty, !credentials.isEmpty {
            out.append(signal("content.subject_body_mismatch_login", "Subject and request do not match",
                              "The subject is about a document or payment but the mail asks you to sign in or verify.", .medium, 0.3))
        }

        // Excessive caps / exclamation in the subject.
        let letters = c.subject.filter(\.isLetter)
        let upper = letters.filter(\.isUppercase)
        let exclamations = c.subject.filter { $0 == "!" }.count
        if (letters.count >= 10 && Double(upper.count) / Double(letters.count) >= 0.6) || exclamations >= 2 {
            out.append(signal("content.excessive_caps_or_exclamation", "Shouting subject line", "Subject: “\(String(c.subject.prefix(80)))”.", .low, 0.15))
        }

        // QR code lure (link-less credential phish).
        let qr = c.matches(.qr, limit: 2)
        if !qr.isEmpty {
            out.append(signal("content.qr_code_lure", "Asks you to scan a QR code", "QR-code instructions: \(quoted(qr)).", .medium, 0.3))
        }

        // Two plain sentences, one link and an instruction, from a webmail stranger. On its own this is what half of
        // personal mail looks like, so it carries little weight; it is the multiplier that tips a brand, payroll or
        // payment pretext over the alert threshold. Suppressed for mail that greets the recipient by name (a
        // correspondent), for mailing-list traffic and for the user's own organization.
        let actionRequests = c.matches(.actionRequest, limit: 2)
        if !actionRequests.isEmpty, c.fromIsFreeMail, !c.hasListHeaders, !c.isVerifiedInternalSender,
           !c.addressesRecipientByName, c.bodyText.count < strangerRequestBodyCharacters, (1...2).contains(c.links.count) {
            out.append(signal("content.action_request_from_stranger", "Short request with a link from an unknown sender",
                              "A \(c.bodyText.count)-character message from the webmail address \(c.fromAddress?.address ?? "?") tells you to act (\(quoted(actionRequests, limit: 2))) and carries \(c.links.count) link(s).",
                              .medium, 0.25))
        }

        // Hidden text in HTML.
        if !c.hiddenSpans.isEmpty {
            let total = c.hiddenSpans.reduce(0) { $0 + $1.count }
            let sample = String(c.hiddenSpans[0].prefix(80))
            if total >= 200 || c.hiddenSpans.count >= 3 {
                out.append(signal("content.hidden_text", "Hidden text in the message", "\(c.hiddenSpans.count) hidden block(s), \(total) characters, e.g. “\(sample)”.", .medium, 0.3))
            } else {
                out.append(signal("content.hidden_text", "Hidden text in the message", "Hidden block: “\(sample)”.", .low, 0.12))
            }
        }

        // Image-only / HTML-only single-link bodies.
        if let html = c.email.htmlBody, !html.isEmpty {
            let textIsEmpty = (c.email.textBody?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
            let visibleLength = c.bodyText.count
            let hasImage = visibleLength < 60 && html.range(of: "<img", options: .caseInsensitive) != nil
            if hasImage, visibleLength < 60, c.links.count == 1 {
                out.append(signal("content.image_only_link_body", "Image-only message with a single link",
                                  "The message is an image with one link (\(c.links[0].host ?? "unknown host")) and almost no text.", .medium, 0.35))
            } else if textIsEmpty, c.links.count == 1, visibleLength < 400, let anchor = c.links[0].anchorText, !anchor.isEmpty {
                out.append(signal("content.html_only_single_link", "Short HTML-only message with one call to action",
                                  "No text version; the only link is “\(String(anchor.prefix(40)))” → \(c.links[0].host ?? "unknown host").", .low, 0.2))
            }
        }
        return out
    }

    // MARK: - attachment.*

    private static let executableExtensions: Set<String> = [
        "exe", "js", "jse", "vbs", "vbe", "wsf", "wsh", "scr", "bat", "cmd", "ps1", "psm1", "jar", "lnk", "iso", "img", "msi",
        "msp", "hta", "com", "pif", "cpl", "reg", "vhd", "vhdx", "dll", "apk", "sh", "url", "chm", "xll",
    ]
    private static let executableMimeTypes: Set<String> = [
        "application/x-msdownload", "application/x-msdos-program", "application/x-executable", "application/x-dosexec",
        "application/x-ms-shortcut", "application/x-iso9660-image", "application/java-archive", "application/x-sh",
        "text/javascript", "application/javascript", "application/x-javascript", "application/x-bat", "application/vnd.microsoft.portable-executable",
        "application/x-ms-installer", "application/hta", "application/x-shellscript",
    ]
    private static let htmlExtensions: Set<String> = ["html", "htm", "shtml", "xhtml", "mht", "mhtml", "svg"]
    private static let archiveExtensions: Set<String> = ["zip", "rar", "7z", "gz", "tgz", "tar", "z", "arj", "cab", "ace", "bz2", "xz"]
    private static let macroExtensions: Set<String> = ["docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "potm", "sldm"]
    private static let documentExtensions: Set<String> = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "csv", "rtf", "mp3", "mp4", "odt"]
    private static let financialFilenameWords = [
        "invoice", "inv", "payment", "remittance", "statement", "receipt", "purchase order", "purchaseorder", "po_", "po-", "bill",
        "wire", "transfer", "swift", "payslip", "salary", "bonus", "tax", "refund", "order", "quotation", "quote", "contract", "agreement",
    ]
    static let archivePasswordPhrases: [String] = [
        "password for the attachment", "password for the archive", "password for the zip", "the password is", "archive password",
        "zip password", "protected with the password", "password protected", "password-protected",
    ]

    static func attachmentSignals(_ c: Context) -> [Signal] {
        var out: [Signal] = []
        guard !c.email.attachments.isEmpty else { return out }
        var executables: [String] = [], htmlFiles: [String] = [], archives: [String] = [], macros: [String] = []
        var doubleExtensions: [String] = [], financial: [String] = []

        for attachment in c.email.attachments.prefix(50) {
            let name = attachment.filename.trimmingCharacters(in: .whitespacesAndNewlines)
            let lowerName = name.lowercased()
            let ext = attachment.fileExtension
            let mime = attachment.mimeType?.lowercased().split(separator: ";").first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
            let parts = lowerName.split(separator: ".").map { $0.trimmingCharacters(in: .whitespaces) }

            if executableExtensions.contains(ext) || executableMimeTypes.contains(mime) {
                executables.append(name)
            } else if htmlExtensions.contains(ext) || mime == "text/html" || mime == "application/xhtml+xml" {
                htmlFiles.append(name)
            } else if macroExtensions.contains(ext) || mime == "application/vnd.ms-excel.sheet.macroenabled.12" || mime == "application/vnd.ms-word.document.macroenabled.12" {
                macros.append(name)
            } else if archiveExtensions.contains(ext) || mime == "application/zip" || mime == "application/x-rar-compressed" || mime == "application/x-7z-compressed" {
                archives.append(name)
            }

            // Double extension: "invoice.pdf.exe", "photo.jpg.js", "report.pdf                 .exe".
            if parts.count >= 3 || (parts.count == 2 && lowerName.contains("  ")) {
                let penultimate = parts.count >= 2 ? parts[parts.count - 2] : ""
                let isDangerousLast = executableExtensions.contains(ext) || htmlExtensions.contains(ext) || archiveExtensions.contains(ext) || macroExtensions.contains(ext)
                if isDangerousLast && (documentExtensions.contains(penultimate) || lowerName.contains("  ")) {
                    doubleExtensions.append(name)
                }
            }

            if financialFilenameWords.contains(where: { lowerName.contains($0) }) {
                financial.append(name)
            }
        }

        if !executables.isEmpty {
            out.append(signal("attachment.malware_extension", "Executable or script attachment",
                              "Attachment(s) that can run code: \(executables.prefix(3).joined(separator: ", ")).", .high, 0.55))
        }
        if !htmlFiles.isEmpty {
            out.append(signal("attachment.html_credential_lure", "HTML attachment",
                              "HTML attachments usually open a fake sign-in page: \(htmlFiles.prefix(3).joined(separator: ", ")).", .high, 0.5))
        }
        if !doubleExtensions.isEmpty {
            out.append(signal("attachment.double_extension_malware", "Attachment disguises its file type",
                              "Double extension: \(doubleExtensions.prefix(3).joined(separator: ", ")).", .high, 0.5))
        }
        if !macros.isEmpty {
            out.append(signal("attachment.macro_document_malware_risk", "Macro-enabled Office attachment",
                              "Macro documents are a common malware carrier: \(macros.prefix(3).joined(separator: ", ")).", .medium, 0.4))
        }
        if !archives.isEmpty {
            let passwordHint = !c.matches(.archivePassword, limit: 1).isEmpty
            out.append(signal("attachment.archive_malware_risk", passwordHint ? "Password-protected archive attachment" : "Archive attachment",
                              (passwordHint ? "A password is supplied for the archive, which defeats malware scanning: " : "Compressed attachment(s): ")
                              + archives.prefix(3).joined(separator: ", ") + ".", passwordHint ? .high : .medium, passwordHint ? 0.5 : 0.3))
        }
        if !financial.isEmpty {
            let requests = c.matches(.attachmentRequest, limit: 2)
            let payments = c.matches(.payment, limit: 1)
            if !requests.isEmpty || !payments.isEmpty {
                // Authenticated brand senders (Amazon, Chase, …) do send invoices; webmail domains count as brands in the
                // catalog but any gmail.com sender passes DKIM/DMARC, so they get no such exemption.
                let authenticated = c.authentication.dkim == .pass && c.authentication.dmarc == .pass && c.fromBrandKey != nil && !c.fromIsFreeMail
                if !authenticated {
                    out.append(signal("attachment.invoice_lure", "Unexpected financial document",
                                      "Asks you to open \(financial.prefix(2).joined(separator: ", ")) (\(quoted(requests + payments, limit: 2))).", .medium, 0.35))
                }
            }
        }
        return out
    }

    // MARK: - mitigation.*

    static func generalMitigations(_ c: Context) -> [(signal: Signal, credit: Double)] {
        var out: [(signal: Signal, credit: Double)] = []
        if c.hasListHeaders, c.authentication.dkim == .pass {
            out.append(mitigation("mitigation.newsletter_headers", "Standard mailing-list headers",
                                  "Carries List-Unsubscribe headers and a valid DKIM signature, as legitimate newsletters do.", credit: 0.1))
        }
        if c.isVerifiedInternalSender {
            out.append(mitigation("mitigation.internal_sender", "Sent from your own organization",
                                  "The From domain \(c.fromDomain) is your organization's and the receiving server verified that the message originated there.", credit: 0.3))
        }
        return out
    }
}

// MARK: - Lexicon

/// Every phrase list the analyzer consults, compiled into one `PhraseAutomaton` (single linear pass per text).
enum Lexicon: Int, CaseIterable, Sendable {
    case urgency, threat, credential, payment, giftCard, wire, crypto, genericGreeting, secrecy, executiveCue, executiveTitle,
         lure, sextortion, renewal, callback, invoiceSubject, attachmentRequest, qr, archivePassword, companyWords,
         payroll, actionRequest

    var phrases: [String] {
        switch self {
        case .urgency: return HeuristicAnalyzer.urgencyPhrases
        case .threat: return HeuristicAnalyzer.threatPhrases
        case .credential: return HeuristicAnalyzer.credentialPhrases
        case .payment: return HeuristicAnalyzer.paymentPhrases
        case .giftCard: return HeuristicAnalyzer.giftCardPhrases
        case .wire: return HeuristicAnalyzer.wirePhrases
        case .crypto: return HeuristicAnalyzer.cryptoPhrases
        case .genericGreeting: return HeuristicAnalyzer.genericGreetingPhrases
        case .secrecy: return HeuristicAnalyzer.secrecyPhrases
        case .executiveCue: return HeuristicAnalyzer.executiveCuePhrases
        case .executiveTitle: return HeuristicAnalyzer.executiveTitlePhrases
        case .lure: return HeuristicAnalyzer.lurePhrases
        case .sextortion: return HeuristicAnalyzer.sextortionPhrases
        case .renewal: return HeuristicAnalyzer.renewalPhrases
        case .callback: return HeuristicAnalyzer.callbackPhrases
        case .invoiceSubject: return HeuristicAnalyzer.invoiceSubjectPhrases
        case .attachmentRequest: return HeuristicAnalyzer.attachmentRequestPhrases
        case .qr: return HeuristicAnalyzer.qrPhrases
        case .archivePassword: return HeuristicAnalyzer.archivePasswordPhrases
        case .companyWords: return HeuristicAnalyzer.companyWordsPhrases
        case .payroll: return HeuristicAnalyzer.payrollPhrases
        case .actionRequest: return HeuristicAnalyzer.actionRequestPhrases
        }
    }

    static let automaton = PhraseAutomaton(sets: Lexicon.allCases.map(\.phrases))
}

extension HeuristicAnalyzer {
    /// Phrases of `set` found in an arbitrary (small) text.
    static func matches(_ set: Lexicon, in text: String, limit: Int) -> [String] {
        Array(Lexicon.automaton.scan(text, limitPerSet: limit)[set.rawValue].prefix(limit))
    }
}

extension HeuristicAnalyzer.Context {
    /// Phrases of `set` found in the subject + body scan text (computed once per analysis).
    func matches(_ set: Lexicon, limit: Int) -> [String] {
        Array(scanMatches[set.rawValue].prefix(limit))
    }
}

extension NSRegularExpression {
    func firstMatchText(in text: String) -> String? {
        let ns = text as NSString
        guard let match = firstMatch(in: text, options: [], range: NSRange(location: 0, length: ns.length)) else { return nil }
        return ns.substring(with: match.range)
    }
}

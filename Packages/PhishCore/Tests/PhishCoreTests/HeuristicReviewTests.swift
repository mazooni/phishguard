import XCTest
@testable import PhishCore

/// Regression tests for the rules-review findings on `HeuristicAnalyzer`: one-time-code delivery (#10), own-organization
/// mail and legal-footer boilerplate (#11), retail promotions (#35), click-trackers and product-name anchors (#36),
/// SPF-aligned DMARC pass for brands (#37), invoice lures from webmail (#61), dictionary-word brands (#62) and the
/// benign fixture shapes (#65).
final class HeuristicReviewTests: XCTestCase {
    private let analyzer = HeuristicAnalyzer()
    private let engine = VerdictEngine()

    private let me = EmailAddress(name: "Sam Rivera", address: "sam.rivera@northwindtraders.example")
    private let hr = EmailAddress(name: "Northwind People Team", address: "people@northwindtraders.example")

    private func html(_ links: [(href: String, text: String)]) -> String {
        "<html><body><p>Hello Sam,</p>" + links.map { "<p><a href=\"\($0.href)\">\($0.text)</a></p>" }.joined() + "</body></html>"
    }

    /// Aligned DKIM + SPF + DMARC pass for `domain`.
    private func cleanAuth(for domain: String) -> String {
        "mx.google.com; dkim=pass header.d=\(domain) header.s=s1 header.b=abc; spf=pass smtp.mailfrom=bounce@\(domain); dmarc=pass header.from=\(domain)"
    }

    private func heuristicsOnly(_ email: EmailMessage) -> Verdict {
        engine.makeVerdict(report: analyzer.analyze(email), assessment: nil, modelIdentifier: nil)
    }

    // MARK: - #10 One-time-code delivery

    private let otpBody = "Your verification code is 482913. This code expires in 10 minutes. Do not share this code with anyone."

    func testAuthenticatedOTPDeliveryIsNotACredentialRequest() {
        let notion = TestEmailFactory.email(
            from: EmailAddress(name: "Notion", address: "notify@mail.notion.so"),
            subject: "Your Notion sign-in code",
            textBody: otpBody,
            authenticationResults: cleanAuth(for: "mail.notion.so")
        )
        let report = analyzer.analyze(notion)
        XCTAssertFalse(report.has("content.credential_request"), report.ids.joined(separator: ", "))
        XCTAssertFalse(report.has("content.secrecy_request"), "'do not share this code' is code-delivery boilerplate")
        XCTAssertFalse(report.has("content.urgency"), "'expires in 10 minutes' is code-delivery boilerplate")
        XCTAssertLessThan(report.score, 0.3)
        XCTAssertEqual(heuristicsOnly(notion).level, .safe)
        XCTAssertFalse(AlertPolicy().shouldAlert(heuristicsOnly(notion)))

        // Aligned DKIM without a DMARC result is enough; a split code and a link on the sender's own domain are fine.
        let creditUnion = TestEmailFactory.email(
            from: EmailAddress(name: "First Cascade CU", address: "alerts@firstcascadecu.example"),
            textBody: "Your one-time code is 220 981. It will expire in 5 minutes. Don't share this code. Manage alerts at https://www.firstcascadecu.example/alerts",
            authenticationResults: "mx; dkim=pass header.d=firstcascadecu.example; spf=pass smtp.mailfrom=alerts@firstcascadecu.example"
        )
        XCTAssertFalse(analyzer.analyze(creditUnion).has("content.credential_request"))
        XCTAssertLessThan(analyzer.analyze(creditUnion).score, 0.3)
    }

    func testOTPWordingKeepsTheCredentialSignalWhenTheShapeIsWrong() {
        // A link off the sender's domain: the code is bait for a sign-in page elsewhere.
        let link = TestEmailFactory.email(
            textBody: nil,
            htmlBody: "<p>\(otpBody)</p><p><a href=\"https://verify-login.example-secure.net/otp\">Enter the code</a></p>",
            authenticationResults: TestEmailFactory.cleanAuth
        )
        XCTAssertTrue(analyzer.analyze(link).has("content.credential_request"))
        // Authentication failure.
        let failed = analyzer.analyze(TestEmailFactory.email(textBody: otpBody, authenticationResults: "mx; spf=fail smtp.mailfrom=x@acme-example.com; dkim=none; dmarc=fail header.from=acme-example.com"))
        XCTAssertTrue(failed.has("content.credential_request"))
        XCTAssertTrue(failed.has("content.secrecy_request"))
        // No authentication results at all.
        XCTAssertTrue(analyzer.analyze(TestEmailFactory.email(textBody: otpBody)).has("content.credential_request"))
        // A second, non-code credential cue.
        let password = TestEmailFactory.email(textBody: otpBody + " Then enter your password to continue.", authenticationResults: TestEmailFactory.cleanAuth)
        XCTAssertTrue(analyzer.analyze(password).has("content.credential_request"))
        // Code wording without an actual code.
        let noCode = TestEmailFactory.email(textBody: "We could not deliver your verification code by SMS. Request a new one from the app.", authenticationResults: TestEmailFactory.cleanAuth)
        XCTAssertTrue(analyzer.analyze(noCode).has("content.credential_request"))
        // An attachment.
        let attachment = TestEmailFactory.email(textBody: otpBody, authenticationResults: TestEmailFactory.cleanAuth, attachments: [EmailAttachment(filename: "code.html", mimeType: "text/html")])
        XCTAssertTrue(analyzer.analyze(attachment).has("content.credential_request"))
    }

    // MARK: - #37 Brand sender authenticated by SPF-aligned DMARC

    func testBrandSenderWithSPFAlignedDMARCPassIsNotUnverified() {
        let email = TestEmailFactory.email(
            from: EmailAddress(name: "Apple", address: "noreply@apple.com"),
            authenticationResults: "mx.google.com; dkim=none (message not signed) header.i=none; spf=pass smtp.mailfrom=bounce@apple.com; dmarc=pass header.from=apple.com"
        )
        let report = analyzer.analyze(email)
        XCTAssertFalse(report.has("auth.brand_unauthenticated"))
        XCTAssertTrue(report.has("mitigation.dmarc_pass"))
        XCTAssertEqual(report.score, 0, accuracy: 1e-9)
        XCTAssertFalse(report.signals.contains { $0.severity == .high })

        // No DKIM clause at all behaves the same; dmarc=none keeps the signal.
        let missingClause = TestEmailFactory.email(from: EmailAddress(name: "Apple", address: "noreply@apple.com"), authenticationResults: "mx.google.com; spf=pass smtp.mailfrom=bounce@apple.com; dmarc=pass header.from=apple.com")
        XCTAssertFalse(analyzer.analyze(missingClause).has("auth.brand_unauthenticated"))
        let dmarcNone = TestEmailFactory.email(from: EmailAddress(name: "Apple", address: "noreply@apple.com"), authenticationResults: "mx.google.com; dkim=none; spf=pass smtp.mailfrom=bounce@apple.com; dmarc=none header.from=apple.com")
        XCTAssertTrue(analyzer.analyze(dmarcNone).has("auth.brand_unauthenticated"))
    }

    // MARK: - #11 Own organization, legal footers, signature titles

    private let hrBody = """
    Hi Sam, we need your help completing the 2026 engagement survey before the deadline on Friday. \
    Please do not reply to this email. Jordan Lee, Director of People Operations. \
    CONFIDENTIALITY NOTICE: This message may contain confidential information. Any unauthorized use, disclosure or \
    distribution is prohibited.
    """

    func testLegalFooterAndSignatureTitleAreNotThreatSecrecyOrImpersonation() {
        let email = TestEmailFactory.email(from: hr, to: [me], textBody: hrBody, authenticationResults: cleanAuth(for: "northwindtraders.example"))
        let report = analyzer.analyze(email)
        XCTAssertFalse(report.has("content.secrecy_request"), "a CONFIDENTIALITY NOTICE is boilerplate")
        XCTAssertFalse(report.has("content.threat"), "'any unauthorized use' is boilerplate")
        XCTAssertFalse(report.has("content.executive_impersonation"), "one cue plus a signature title from a verified corporate sender")
        XCTAssertTrue(report.has("content.urgency"))
        XCTAssertLessThan(report.score, 0.3)
        XCTAssertFalse(AlertPolicy().shouldAlert(heuristicsOnly(email)))

        // Qualified threat wording and real secrecy requests still fire.
        XCTAssertTrue(analyzer.analyze(TestEmailFactory.email(textBody: "We detected an unauthorized sign-in to your account.")).has("content.threat"))
        XCTAssertTrue(analyzer.analyze(TestEmailFactory.email(textBody: "There was an unauthorised transaction on your card.")).has("content.threat"))
        XCTAssertTrue(analyzer.analyze(TestEmailFactory.email(textBody: "This is strictly confidential, keep this between us.")).has("content.secrecy_request"))
    }

    func testOrganizationDomainsCreditVerifiedInternalMailOnly() {
        let orgAware = HeuristicAnalyzer(organizationDomains: [" NorthwindTraders.example ", "mail.northwindtraders.example", "gmail.com", ""])
        XCTAssertEqual(orgAware.organizationDomains, ["northwindtraders.example"], "normalized to registrable domains; free-mail dropped")
        XCTAssertEqual(HeuristicAnalyzer().organizationDomains, [])
        var reconfigured = HeuristicAnalyzer()
        reconfigured.organizationDomains = ["Mail.NorthwindTraders.example", "outlook.com"]
        XCTAssertEqual(reconfigured.organizationDomains, ["northwindtraders.example"], "assignment normalizes too")

        let verified = TestEmailFactory.email(from: hr, to: [me], textBody: hrBody, authenticationResults: cleanAuth(for: "northwindtraders.example"))
        let report = orgAware.analyze(verified)
        XCTAssertTrue(report.has("mitigation.internal_sender"))
        XCTAssertEqual(report.signal("mitigation.internal_sender")?.weight, 0)
        XCTAssertEqual(report.score, 0, accuracy: 1e-9)
        XCTAssertFalse(analyzer.analyze(verified).has("mitigation.internal_sender"), "no credit without configured domains")

        // Aligned DKIM without a DMARC result is proof of origin too (Google Workspace signs internal mail).
        let dkimOnly = TestEmailFactory.email(from: hr, to: [me], textBody: hrBody, authenticationResults: "mx; dkim=pass header.d=northwindtraders.example; spf=pass smtp.mailfrom=people@northwindtraders.example")
        XCTAssertTrue(orgAware.analyze(dkimOnly).has("mitigation.internal_sender"))

        // A same-domain From that is unauthenticated, failing, or only SPF-authorized for another domain is the CEO-fraud shape.
        let noAuth = TestEmailFactory.email(from: hr, to: [me], textBody: hrBody)
        XCTAssertFalse(orgAware.analyze(noAuth).has("mitigation.internal_sender"))
        let dmarcFail = TestEmailFactory.email(from: hr, to: [me], textBody: hrBody, authenticationResults: "mx; spf=pass smtp.mailfrom=x@attacker.example; dkim=none; dmarc=fail header.from=northwindtraders.example")
        XCTAssertFalse(orgAware.analyze(dmarcFail).has("mitigation.internal_sender"))
        let dmarcNone = TestEmailFactory.email(from: hr, to: [me], textBody: hrBody, authenticationResults: "mx; spf=pass smtp.mailfrom=x@attacker.example; dkim=none; dmarc=none header.from=northwindtraders.example")
        XCTAssertFalse(orgAware.analyze(dmarcNone).has("mitigation.internal_sender"), "SPF pass for the attacker's own domain proves nothing")
        let softfail = TestEmailFactory.email(from: hr, to: [me], textBody: hrBody, authenticationResults: "mx; spf=softfail smtp.mailfrom=x@northwindtraders.example; dkim=pass header.d=northwindtraders.example; dmarc=pass")
        XCTAssertFalse(orgAware.analyze(softfail).has("mitigation.internal_sender"))

        // Free-mail is never "internal", even when listed.
        let webmail = HeuristicAnalyzer(organizationDomains: ["gmail.com"])
        let personal = TestEmailFactory.email(from: EmailAddress(name: "Sam", address: "sam@gmail.com"), to: [EmailAddress(name: nil, address: "sam2@gmail.com")], authenticationResults: cleanAuth(for: "gmail.com"))
        XCTAssertFalse(webmail.analyze(personal).has("mitigation.internal_sender"))

        // The shipped fixture: tolerable without configuration, clean with it.
        XCTAssertLessThan(analyzer.analyze(SampleEmails.benignInternalHRNotice).score, 0.3)
        let fixture = orgAware.analyze(SampleEmails.benignInternalHRNotice)
        XCTAssertTrue(fixture.has("mitigation.internal_sender"))
        XCTAssertEqual(fixture.score, 0, accuracy: 1e-9)
    }

    // MARK: - ARC-validated mailing-list relays

    func testARCPassForgivesAuthenticationBrokenByAMailingListButNotBrandSpoofs() {
        let member = EmailAddress(name: "Alex Kim", address: "alex.kim.dev@gmail.com")
        let listSender = EmailAddress(name: nil, address: "bend-hikers-bounces@lists.cascadetrails.example")
        let listHeaders = [
            EmailHeader(name: "List-Id", value: "Bend hikers <bend-hikers.lists.cascadetrails.example>"),
            EmailHeader(name: "List-Unsubscribe", value: "<mailto:bend-hikers-request@lists.cascadetrails.example?subject=unsubscribe>"),
        ]
        let body = "A few of us are heading to Alder Creek Falls this Sunday; meet at the trailhead at 8am."
        // The receiving provider's own stamp: the list broke the member's DKIM signature and DMARC, but the provider
        // validated the list's ARC seal over the original results.
        let brokenByList = "mx.google.com; dkim=fail header.i=@gmail.com; arc=pass (i=1 spf=pass spfdomain=gmail.com dkim=pass dkdomain=gmail.com dmarc=pass fromdomain=gmail.com); spf=pass smtp.mailfrom=bend-hikers-bounces@lists.cascadetrails.example; dmarc=fail (p=NONE) header.from=gmail.com"

        let relayed = TestEmailFactory.email(from: member, sender: listSender, textBody: body, authenticationResults: brokenByList, extraHeaders: listHeaders)
        let report = analyzer.analyze(relayed)
        XCTAssertTrue(report.has("auth.list_relay_dmarc_fail"), report.ids.joined(separator: ", "))
        XCTAssertEqual(report.signal("auth.list_relay_dmarc_fail")?.severity, .low)
        XCTAssertEqual(report.signal("auth.list_relay_dmarc_fail")?.weight, 0.15)
        XCTAssertFalse(report.has("auth.dmarc_fail"))
        XCTAssertFalse(report.has("auth.dkim_fail"))
        XCTAssertEqual(report.authentication.arc, .pass)
        XCTAssertEqual(report.authentication.dkim, .fail, "the provider's own results are kept; nothing is copied from the ARC set")
        XCTAssertEqual(report.authentication.dmarc, .fail)
        XCTAssertLessThan(report.score, 0.3)
        XCTAssertEqual(heuristicsOnly(relayed).level, .safe)

        // The list shape is part of the rule: arc=pass alone forgives nothing, a Sender header alone is enough.
        let noListShape = TestEmailFactory.email(from: member, textBody: body, authenticationResults: brokenByList)
        let plain = analyzer.analyze(noListShape)
        XCTAssertTrue(plain.has("auth.dmarc_fail"))
        XCTAssertTrue(plain.has("auth.dkim_fail"))
        XCTAssertFalse(plain.has("auth.list_relay_dmarc_fail"))
        let senderOnly = TestEmailFactory.email(from: member, sender: listSender, textBody: body, authenticationResults: brokenByList)
        XCTAssertTrue(analyzer.analyze(senderOnly).has("auth.list_relay_dmarc_fail"))

        // A sealed ARC-Authentication-Results set the provider did not vouch for (no arc=pass of its own) proves nothing.
        let unverifiedSeal = TestEmailFactory.email(
            from: member, sender: listSender, textBody: body,
            authenticationResults: "mx.google.com; dkim=fail header.i=@gmail.com; spf=pass smtp.mailfrom=bend-hikers-bounces@lists.cascadetrails.example; dmarc=fail header.from=gmail.com",
            extraHeaders: listHeaders + [EmailHeader(name: "ARC-Authentication-Results", value: "i=1; lists.cascadetrails.example; arc=pass; dkim=pass header.i=@gmail.com; dmarc=pass header.from=gmail.com")]
        )
        let sealed = analyzer.analyze(unverifiedSeal)
        XCTAssertNil(sealed.authentication.arc)
        XCTAssertTrue(sealed.has("auth.dmarc_fail"))
        XCTAssertFalse(sealed.has("auth.list_relay_dmarc_fail"))

        // Brand senders keep their full weights: a PayPal spoof relayed through a "list" is still high with arc=pass.
        let paypal = EmailAddress(name: "PayPal", address: "service@paypal.com")
        let brandBrokenByList = "mx.google.com; dkim=fail header.i=@paypal.com; arc=pass (i=1 spf=pass dkim=pass dmarc=pass); spf=pass smtp.mailfrom=bend-hikers-bounces@lists.cascadetrails.example; dmarc=fail (p=REJECT) header.from=paypal.com"
        let spoof = TestEmailFactory.email(from: paypal, sender: listSender, textBody: body, authenticationResults: brandBrokenByList, extraHeaders: listHeaders)
        let spoofReport = analyzer.analyze(spoof)
        XCTAssertFalse(spoofReport.has("auth.list_relay_dmarc_fail"))
        XCTAssertEqual(spoofReport.signal("auth.dkim_fail")?.weight, 0.45)
        XCTAssertEqual(spoofReport.signal("auth.dmarc_fail")?.severity, .high)
        XCTAssertEqual(spoofReport.signal("auth.dmarc_fail")?.weight, 0.55)
        XCTAssertEqual(heuristicsOnly(spoof).level, .high, "\(spoofReport.score) \(spoofReport.ids)")

        // The shipped fixture clears the standard benign bar without any tolerance.
        let fixture = analyzer.analyze(SampleEmails.benignMailingListPost)
        XCTAssertTrue(fixture.has("auth.list_relay_dmarc_fail"))
        XCTAssertTrue(fixture.signals.filter { $0.severity == .high }.isEmpty, fixture.ids.joined(separator: ", "))
        XCTAssertLessThan(fixture.score, 0.3, "score \(fixture.score): \(fixture.ids)")
    }

    func testSingleExecutiveCueWithTitleStillFiresFromUnverifiedSenders() {
        let body = "Are you available? I need the vendor list by noon. Margaret Chen, Director of Finance"
        let freeMail = TestEmailFactory.email(from: EmailAddress(name: "Margaret Chen", address: "m.chen.exec@gmail.com"), to: [me], textBody: body, authenticationResults: cleanAuth(for: "gmail.com"))
        XCTAssertTrue(analyzer.analyze(freeMail).has("content.executive_impersonation"))
        let replyElsewhere = TestEmailFactory.email(from: EmailAddress(name: "Margaret Chen", address: "m.chen@northwindtraders.example"), replyTo: [EmailAddress(name: nil, address: "m.chen.exec@gmail.com")], to: [me], textBody: body, authenticationResults: cleanAuth(for: "northwindtraders.example"))
        XCTAssertTrue(analyzer.analyze(replyElsewhere).has("content.executive_impersonation"))
        let unauthenticated = TestEmailFactory.email(from: EmailAddress(name: "Margaret Chen", address: "m.chen@northwindtraders.example"), to: [me], textBody: body, authenticationResults: "mx; spf=fail; dkim=none; dmarc=fail header.from=northwindtraders.example")
        XCTAssertTrue(analyzer.analyze(unauthenticated).has("content.executive_impersonation"))
        let noResults = TestEmailFactory.email(from: EmailAddress(name: "Margaret Chen", address: "m.chen@northwindtraders.example"), to: [me], textBody: body)
        XCTAssertTrue(analyzer.analyze(noResults).has("content.executive_impersonation"))
        // Two cues fire regardless of the sender.
        let twoCues = TestEmailFactory.email(from: hr, to: [me], textBody: "Are you available? I'm in a meeting, so reply here.", authenticationResults: cleanAuth(for: "northwindtraders.example"))
        XCTAssertTrue(analyzer.analyze(twoCues).has("content.executive_impersonation"))

        // A verified partner's meeting request with a title signature, a bare "Zoom" and a deadline is ordinary mail (#62 too).
        let partner = TestEmailFactory.email(
            from: EmailAddress(name: "Alex Kim", address: "alex.kim@partnerco.example"), to: [me],
            textBody: "Are you available Thursday for a Zoom call? The slides are on https://portal.partnerco-cloud.example/q4 if you want to look before the deadline. Alex Kim, Director of Partnerships",
            authenticationResults: cleanAuth(for: "partnerco.example")
        )
        let partnerReport = analyzer.analyze(partner)
        XCTAssertFalse(partnerReport.has("content.executive_impersonation"))
        XCTAssertFalse(partnerReport.has("link.brand_domain_mismatch"), "a bare 'Zoom' is not a brand claim")
        XCTAssertFalse(AlertPolicy().shouldAlert(heuristicsOnly(partner)))
    }

    // MARK: - #35 Retail promotions from authenticated bulk senders

    private let promoBody = "Buy a gift card this weekend and get a $10 bonus card on us. Claim your loyalty reward before the deadline. Limited time only!"
    private let retailer = EmailAddress(name: "Trailhead Outfitters", address: "hello@news.trailheadoutfitters.com")
    private let listHeader = EmailHeader(name: "List-Unsubscribe", value: "<https://news.trailheadoutfitters.com/u>")

    func testAuthenticatedBulkPromoMentioningGiftCardsIsNotAScam() {
        let promo = TestEmailFactory.email(from: retailer, textBody: promoBody, authenticationResults: cleanAuth(for: "news.trailheadoutfitters.com"), extraHeaders: [listHeader])
        let report = analyzer.analyze(promo)
        XCTAssertEqual(report.signal("content.gift_card_request")?.severity, .low)
        XCTAssertFalse(report.has("content.advance_fee_payment_lure"), "bonus / reward / claim your are loyalty vocabulary")
        XCTAssertTrue(report.has("content.urgency"))
        XCTAssertLessThan(report.score, 0.3)
        XCTAssertFalse(AlertPolicy().shouldAlert(heuristicsOnly(promo)))

        // Real prize language is still counted for bulk senders.
        let prize = TestEmailFactory.email(from: retailer, textBody: "You have won! Claim your prize now, you are the winner of our lottery.", authenticationResults: cleanAuth(for: "news.trailheadoutfitters.com"), extraHeaders: [listHeader])
        XCTAssertEqual(analyzer.analyze(prize).signal("content.advance_fee_payment_lure")?.severity, .high)
    }

    func testGiftCardRequestsKeepFullWeightOutsideAuthenticatedBulkMail() {
        // The same copy from a personal mailbox, or without list headers, is the BEC shape.
        let webmail = analyzer.analyze(TestEmailFactory.email(from: EmailAddress(name: "Trailhead Outfitters", address: "trailhead.promos@gmail.com"), textBody: promoBody, authenticationResults: cleanAuth(for: "gmail.com"), extraHeaders: [listHeader]))
        XCTAssertEqual(webmail.signal("content.gift_card_request")?.severity, .high)
        XCTAssertTrue(webmail.has("content.advance_fee_payment_lure"))
        let noList = analyzer.analyze(TestEmailFactory.email(from: retailer, textBody: promoBody, authenticationResults: cleanAuth(for: "news.trailheadoutfitters.com")))
        XCTAssertEqual(noList.signal("content.gift_card_request")?.severity, .high)
        let unalignedDKIM = analyzer.analyze(TestEmailFactory.email(from: retailer, textBody: promoBody, authenticationResults: "mx; dkim=pass header.d=bulk-relay.example; spf=pass; dmarc=pass header.from=news.trailheadoutfitters.com", extraHeaders: [listHeader]))
        XCTAssertEqual(unalignedDKIM.signal("content.gift_card_request")?.severity, .high)
        // Request semantics fire at full weight even from an authenticated bulk sender.
        let request = analyzer.analyze(TestEmailFactory.email(from: retailer, textBody: "Buy 5 gift cards, scratch the back and send me the codes.", authenticationResults: cleanAuth(for: "news.trailheadoutfitters.com"), extraHeaders: [listHeader]))
        XCTAssertEqual(request.signal("content.gift_card_request")?.severity, .high)
        // The shipped BEC fixture is unchanged.
        let scam = analyzer.analyze(SampleEmails.giftCardScam)
        XCTAssertEqual(scam.signal("content.gift_card_request")?.severity, .high)
        XCTAssertTrue(scam.has("content.executive_impersonation"))
        XCTAssertGreaterThanOrEqual(scam.score, 0.6)
    }

    // MARK: - #36 Anchor text: product names, click-trackers

    func testProductNamesAndTrackedVisibleURLsAreNotHiddenDestinations() {
        let names = TestEmailFactory.email(htmlBody: html([
            ("https://javascriptweekly.com/link/1", "Node.js"),
            ("https://devdigest.example/t/2", "ASP.NET"),
            ("https://devdigest.example/t/3", "socket.io"),
        ]))
        XCTAssertFalse(analyzer.analyze(names).has("link.anchor_host_mismatch"))

        // The sender's own click-tracker and a known ESP tracker are redirects, not hidden destinations.
        let ownTracker = TestEmailFactory.email(htmlBody: html([("https://click.acme-example.com/t/9", "https://arxiv.org/abs/2401.00001")]))
        XCTAssertFalse(analyzer.analyze(ownTracker).has("link.anchor_host_mismatch"))
        let esp = TestEmailFactory.email(htmlBody: html([("https://acme.us21.list-manage.com/track/click?u=1", "www.acme-example.com/blog")]))
        XCTAssertFalse(analyzer.analyze(esp).has("link.anchor_host_mismatch"))
        let substack = TestEmailFactory.email(from: EmailAddress(name: "Dev Digest", address: "devdigest@substack.com"), htmlBody: html([("https://substack.com/redirect/abc?j=eyJ1Ijoi", "https://arxiv.org/abs/2401.00001")]))
        XCTAssertFalse(analyzer.analyze(substack).has("link.anchor_host_mismatch"))

        // A visible URL through an unlisted tracker, or a brand's ordinary page through the sender's own tracker, is
        // downgraded for an authenticated sender rather than asserted as phishing.
        let list = EmailHeader(name: "List-Unsubscribe", value: "<https://acme-example.com/u>")
        let unlistedLinks = html([("https://links.unknown-esp.example/c/77", "https://arxiv.org/abs/2401.00001")])
        let bulk = TestEmailFactory.email(htmlBody: unlistedLinks, authenticationResults: TestEmailFactory.cleanAuth, extraHeaders: [list])
        let bulkReport = analyzer.analyze(bulk)
        XCTAssertEqual(bulkReport.signal("link.anchor_host_mismatch")?.severity, .medium)
        XCTAssertLessThan(bulkReport.score, 0.3)
        XCTAssertEqual(analyzer.analyze(TestEmailFactory.email(htmlBody: unlistedLinks)).signal("link.anchor_host_mismatch")?.severity, .high, "unauthenticated sender keeps the high signal")
        let githubViaOwnTracker = html([("https://click.acme-example.com/t/9", "https://github.com/acme/repo")])
        let devNewsletter = analyzer.analyze(TestEmailFactory.email(htmlBody: githubViaOwnTracker, authenticationResults: TestEmailFactory.cleanAuth, extraHeaders: [list]))
        XCTAssertEqual(devNewsletter.signal("link.anchor_host_mismatch")?.severity, .medium)
        XCTAssertLessThan(devNewsletter.score, 0.3)
        XCTAssertEqual(analyzer.analyze(TestEmailFactory.email(htmlBody: githubViaOwnTracker)).signal("link.anchor_host_mismatch")?.severity, .high)

        // A brand sign-in URL over a foreign host is the phish shape, even behind an authenticated sender's own tracker or an ESP.
        let brandOwnTracker = html([("https://click.acme-example.com/t/9", "https://www.paypal.com/signin")])
        XCTAssertEqual(analyzer.analyze(TestEmailFactory.email(htmlBody: brandOwnTracker)).signal("link.anchor_host_mismatch")?.severity, .high)
        XCTAssertEqual(analyzer.analyze(TestEmailFactory.email(htmlBody: brandOwnTracker, authenticationResults: TestEmailFactory.cleanAuth, extraHeaders: [list])).signal("link.anchor_host_mismatch")?.severity, .high)
        let brandESP = TestEmailFactory.email(htmlBody: html([("https://acme.us21.list-manage.com/track/click?u=1", "https://www.paypal.com/myaccount/security")]), authenticationResults: TestEmailFactory.cleanAuth, extraHeaders: [list])
        XCTAssertEqual(analyzer.analyze(brandESP).signal("link.anchor_host_mismatch")?.severity, .high)
        // The original shape (visible URL over an unrelated host) is unchanged.
        XCTAssertEqual(analyzer.analyze(TestEmailFactory.email(htmlBody: html([("https://evil-login.example/x", "https://www.paypal.com/signin")]))).signal("link.anchor_host_mismatch")?.severity, .high)
        XCTAssertEqual(analyzer.analyze(TestEmailFactory.email(htmlBody: html([("https://evil-host.example/x", "acme-example.com/x")]))).signal("link.anchor_host_mismatch")?.severity, .high)
    }

    // MARK: - #61 Invoice lure from webmail

    func testInvoiceLureFromWebmailIsNotExemptedAsABrand() {
        let body = "Please see attached invoice and remit payment."
        let pdf = [EmailAttachment(filename: "Invoice_4471.pdf", mimeType: "application/pdf")]
        let webmail = TestEmailFactory.email(from: EmailAddress(name: "Accounts Payable", address: "ap.dept.2291@gmail.com"), textBody: body, authenticationResults: cleanAuth(for: "gmail.com"), attachments: pdf)
        XCTAssertTrue(analyzer.analyze(webmail).has("attachment.invoice_lure"))
        let brand = TestEmailFactory.email(from: EmailAddress(name: "Microsoft", address: "billing@microsoft.com"), textBody: body, authenticationResults: cleanAuth(for: "microsoft.com"), attachments: pdf)
        XCTAssertFalse(analyzer.analyze(brand).has("attachment.invoice_lure"), "authenticated real brands send invoices")
    }

    // MARK: - #62 Dictionary-word brands

    func testDictionaryWordBrandsNeedAQualifiedMention() {
        XCTAssertEqual(HeuristicAnalyzer.brandsMentioned(in: "Apple Valley Dental"), [])
        XCTAssertEqual(HeuristicAnalyzer.brandsMentioned(in: "are you free for a zoom call? I need a visa; grab it on steam; paid with Visa; a slack week"), [])
        XCTAssertEqual(HeuristicAnalyzer.brandsMentioned(in: "Your Apple ID has been locked"), ["apple"])
        XCTAssertEqual(HeuristicAnalyzer.brandsMentioned(in: "Zoom account suspended"), ["zoom"])
        XCTAssertEqual(HeuristicAnalyzer.brandsMentioned(in: "Verified by Visa: confirm your card"), ["visa"])
        XCTAssertEqual(HeuristicAnalyzer.brandsMentioned(in: "PayPal: action required"), ["paypal"], "non-dictionary brands are unchanged")
        XCTAssertEqual(HeuristicAnalyzer.brandsMentioned(in: "Facebook security team"), ["facebook"])
        XCTAssertEqual(HeuristicAnalyzer.brandsMentioned(in: "the meta question"), [])

        let dentist = TestEmailFactory.email(from: EmailAddress(name: "Apple Valley Dental", address: "applevalleydental@gmail.com"), textBody: "Reminder: your cleaning is Tuesday at 9am.", authenticationResults: cleanAuth(for: "gmail.com"))
        let dentistReport = analyzer.analyze(dentist)
        XCTAssertFalse(dentistReport.has("sender.free_mail_brand_claim"))
        XCTAssertFalse(dentistReport.signals.contains { $0.severity == .high })
        let appleID = TestEmailFactory.email(from: EmailAddress(name: "Apple ID Support", address: "appleid.support.desk@gmail.com"))
        XCTAssertTrue(analyzer.analyze(appleID).has("sender.free_mail_brand_claim"))
        // Lookalike hosts still key off the brand key.
        XCTAssertTrue(analyzer.analyze(TestEmailFactory.email(htmlBody: html([("https://apple-id-verify.example/x", "Verify")]))).has("link.lookalike_domain"))
    }

    // MARK: - #65 Benign fixture shapes

    func testNewBenignFixturesAreQuietOnTheHeuristicsOnlyPath() {
        let quiet: [(EmailMessage, String)] = [
            (SampleEmails.benignOTPCode, "OTP"),
            (SampleEmails.benignShopifyOrder, "Shopify order"),
            (SampleEmails.benignRegionalBankAlert, "regional bank"),
            (SampleEmails.benignRetailGiftCardPromo, "gift-card promo"),
            (SampleEmails.benignDocsShareNotification, "docs share"),
            (SampleEmails.benignInternalHRNotice, "internal HR"),
        ]
        for (email, name) in quiet {
            let verdict = heuristicsOnly(email)
            XCTAssertEqual(verdict.level, .safe, "\(name): \(verdict.confidence) \(verdict.reasons.map(\.id))")
            XCTAssertEqual(verdict.category, .safe, name)
            XCTAssertFalse(AlertPolicy(minimumLevel: .low).shouldAlert(verdict), name)
        }
        // The promo actually exercises the toned-down rules (it is not a vacuous fixture).
        let promo = analyzer.analyze(SampleEmails.benignRetailGiftCardPromo)
        XCTAssertTrue(promo.has("content.gift_card_request"))
        XCTAssertTrue(promo.has("content.urgency"))
        XCTAssertTrue(analyzer.analyze(SampleEmails.benignInternalHRNotice).has("content.urgency"))

        // The mailing-list forward: the provider's arc=pass explains the broken authentication (one low signal).
        let list = analyzer.analyze(SampleEmails.benignMailingListPost)
        XCTAssertTrue(list.has("sender.sender_header_list"))
        XCTAssertFalse(list.has("sender.return_path_mismatch"), "a webmail From through a list is not a brand spoof")
        XCTAssertTrue(list.has("auth.list_relay_dmarc_fail"))
        XCTAssertLessThan(list.score, 0.3, list.ids.joined(separator: ", "))
        XCTAssertTrue(list.signals.filter { $0.severity == .high }.isEmpty, list.ids.joined(separator: ", "))
    }
}

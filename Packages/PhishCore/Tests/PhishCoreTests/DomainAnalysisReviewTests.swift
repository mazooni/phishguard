import XCTest
@testable import PhishCore

/// Regression tests for the review findings against `DomainAnalysis` (regional brand domains, multi-tenant brand
/// hosting, public-suffix brand entries, backslash authorities) and their effect on the analyzer.
final class DomainAnalysisReviewTests: XCTestCase {
    private let analyzer = HeuristicAnalyzer()

    private func html(_ links: [(String, String)], intro: String = "<p>Hello</p>") -> String {
        intro + links.map { "<p><a href=\"\($0.0)\">\($0.1)</a></p>" }.joined()
    }

    private func alignedAuth(_ domain: String) -> String {
        "mx.google.com; dkim=pass header.d=\(domain) header.s=s1 header.b=abc; spf=pass smtp.mailfrom=bounce@\(domain); dmarc=pass header.from=\(domain)"
    }

    // MARK: - Finding 8: regional / subsidiary brand domains

    func testRegionalBrandDomainsAreNotLookalikes() {
        for host in ["paypal.co.uk", "www.paypal.co.uk", "amazon.nl", "amazon.com.mx", "amazon.com.br", "amazon.se", "ebay.ca",
                     "amazon.jobs", "google-analytics.com", "www.google-analytics.com", "amazon-adsystem.com",
                     "email.microsoftrewards.com", "microsoft365.com", "dhl.fr", "fedex.ca", "netflix.co.uk", "google.de",
                     "no-reply.sharepointonline.com"] {
            XCTAssertNil(DomainAnalysis.lookalikeBrand(for: host), host)
        }
    }

    func testBrandUnderCountryCodeSuffixIsTheBrandsOwnDomain() {
        XCTAssertEqual(DomainAnalysis.brandKey(forRegistrableDomain: "paypal.co.uk"), "paypal")
        XCTAssertEqual(DomainAnalysis.brandKey(forRegistrableDomain: "amazon.nl"), "amazon")
        XCTAssertEqual(DomainAnalysis.brandKey(forRegistrableDomain: "dhl.fr"), "dhl", "not listed, inferred from the ccTLD rule")
        XCTAssertEqual(DomainAnalysis.brandKey(forRegistrableDomain: "facebookmail.com"), "facebook")
        XCTAssertTrue(DomainAnalysis.isLegitimateDomain("paypal.co.uk", for: "paypal"))
        XCTAssertTrue(DomainAnalysis.isLegitimateDomain("www.dhl.fr", for: "dhl"))
        XCTAssertTrue(DomainAnalysis.isLegitimateDomain("facebookmail.com", for: "instagram"), "shared domains keep every owner")
        XCTAssertTrue(DomainAnalysis.isAnyBrandDomain("www.amazon.com.mx"))
        XCTAssertFalse(DomainAnalysis.isLegitimateDomain("paypal.co.uk", for: "amazon"))
    }

    func testSquatsAndAbusedSuffixesStillCountAsLookalikes() {
        XCTAssertNil(DomainAnalysis.brandKey(forRegistrableDomain: "paypal.tk"), "abused ccTLD")
        XCTAssertNil(DomainAnalysis.brandKey(forRegistrableDomain: "paypal.top"), "not a country code")
        XCTAssertNil(DomainAnalysis.brandKey(forRegistrableDomain: "usps.uk"), "domestic brand has no regional domains")
        XCTAssertNil(DomainAnalysis.brandKey(forRegistrableDomain: "apple.co.uk"), "dictionary-word brand")
        XCTAssertNil(DomainAnalysis.brandKey(forRegistrableDomain: "paypal.github.io"), "free hosting suffix")
        for (host, brand) in [("paypal.tk", "paypal"), ("paypal.ml", "paypal"), ("paypal.top", "paypal"), ("paypal-login.co.uk", "paypal"),
                              ("paypal.com.secure-login.net", "paypal"), ("secure.paypal-login.top", "paypal"),
                              ("paypal-resolution-center.com", "paypal"), ("paypal1.com", "paypal"), ("usps.uk", "usps"),
                              ("paypal.github.io", "paypal"), ("amazon.xyz", "amazon"), ("login.amazon.de.verify-now.com", "amazon")] {
            XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: host), brand, host)
        }
    }

    func testAuthenticatedRegionalBrandMailIsNotImpersonation() {
        let email = TestEmailFactory.email(
            from: EmailAddress(name: "PayPal", address: "service@paypal.co.uk"),
            subject: "Receipt for your payment to Trailhead Outfitters",
            textBody: "Thanks for using PayPal. You can view the details of this transaction in your activity.",
            htmlBody: html([("https://www.paypal.co.uk/myaccount/transactions", "View transaction")],
                           intro: "<p>Thanks for using PayPal. You can view the details of this transaction in your activity.</p>"),
            authenticationResults: alignedAuth("paypal.co.uk")
        )
        let report = analyzer.analyze(email)
        XCTAssertFalse(report.has("sender.lookalike_domain"), report.ids.joined(separator: ","))
        XCTAssertFalse(report.has("link.lookalike_domain"), report.ids.joined(separator: ","))
        XCTAssertFalse(report.has("sender.brand_display_name_mismatch"), report.ids.joined(separator: ","))
        XCTAssertTrue(report.has("mitigation.brand_authenticated"), report.ids.joined(separator: ","))
        XCTAssertLessThan(report.score, 0.3)

        // A regional domain that is not in the catalog (inferred from the ccTLD rule).
        let dhl = TestEmailFactory.email(
            from: EmailAddress(name: "DHL", address: "noreply@dhl.fr"),
            subject: "Votre colis est en route",
            textBody: "Votre colis 00340434292135100186 arrive demain.",
            htmlBody: html([("https://www.dhl.fr/fr/particuliers.html", "Suivre mon colis")]),
            authenticationResults: alignedAuth("dhl.fr")
        )
        let dhlReport = analyzer.analyze(dhl)
        XCTAssertFalse(dhlReport.has("sender.lookalike_domain"), dhlReport.ids.joined(separator: ","))
        XCTAssertFalse(dhlReport.has("link.lookalike_domain"), dhlReport.ids.joined(separator: ","))
        XCTAssertFalse(dhlReport.has("sender.brand_display_name_mismatch"), dhlReport.ids.joined(separator: ","))
        XCTAssertLessThan(dhlReport.score, 0.3)

        // The squat next door still scores as impersonation.
        let squat = TestEmailFactory.email(
            from: EmailAddress(name: "PayPal", address: "service@paypal-login.co.uk"),
            subject: "Receipt for your payment",
            htmlBody: html([("https://www.paypal-login.co.uk/myaccount/transactions", "View transaction")]),
            authenticationResults: alignedAuth("paypal-login.co.uk")
        )
        let squatReport = analyzer.analyze(squat)
        XCTAssertTrue(squatReport.has("sender.lookalike_domain"))
        XCTAssertTrue(squatReport.has("sender.brand_display_name_mismatch"))
    }

    // MARK: - Finding 9: Shopify storefronts

    func testShopifyStorefrontsAreMultiTenantNotLookalikes() {
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "store.myshopify.com"), "myshopify.com")
        XCTAssertNil(DomainAnalysis.lookalikeMatch(for: "trailheadoutfitters.myshopify.com"))
        XCTAssertNil(DomainAnalysis.lookalikeMatch(for: "acme.myshopify.com"))
        XCTAssertNil(DomainAnalysis.lookalikeMatch(for: "myshopify.com"))
        XCTAssertTrue(DomainAnalysis.isMultiTenantBrandHost("acme.myshopify.com"))
        XCTAssertTrue(DomainAnalysis.isLegitimateDomain("acme.myshopify.com", for: "shopify"))
        XCTAssertFalse(DomainAnalysis.isAnyBrandDomain("acme.myshopify.com"), "the merchant, not Shopify, controls the page")
        XCTAssertTrue(DomainAnalysis.isAnyBrandDomain("myshopify.com"))
        // Attacker storefronts are still caught on their own labels.
        XCTAssertEqual(DomainAnalysis.lookalikeMatch(for: "paypal-secure.myshopify.com")?.brand.key, "paypal")
        XCTAssertEqual(DomainAnalysis.lookalikeMatch(for: "paypalsecure.myshopify.com")?.kind, .embedded)
        XCTAssertEqual(DomainAnalysis.lookalikeMatch(for: "paypa1.myshopify.com")?.kind, .homoglyph)
        XCTAssertEqual(DomainAnalysis.lookalikeMatch(for: "mypaypal-billing.com")?.kind, .embedded, "unchanged outside tenant hosting")
    }

    func testShopifyOrderStatusLinkIsNotALookalikeLink() {
        let email = TestEmailFactory.email(
            from: EmailAddress(name: "Trailhead Outfitters", address: "orders@trailheadoutfitters.com"),
            subject: "Order #1042 confirmed",
            textBody: "Thank you for your purchase! Your order #1042 is confirmed. View your order status using the link below.",
            htmlBody: html([("https://trailheadoutfitters.myshopify.com/12345678/orders/0123456789abcdef0123456789abcdef/authenticate?key=8f3a", "View your order")],
                           intro: "<p>Thank you for your purchase! Your order #1042 is confirmed.</p>"),
            authenticationResults: alignedAuth("trailheadoutfitters.com")
        )
        let report = analyzer.analyze(email)
        XCTAssertFalse(report.has("link.lookalike_domain"), report.ids.joined(separator: ","))
        XCTAssertFalse(report.has("link.brand_domain_mismatch"), report.ids.joined(separator: ","))
        XCTAssertLessThan(report.score, 0.5, "must not reach the medium (alert) band: \(report.ids)")
    }

    // MARK: - Finding 33: tenant pages on multi-tenant brand hosting

    func testTenantPagesOnBrandHostingAreNotBrandControlled() {
        XCTAssertFalse(DomainAnalysis.isAnyBrandDomain("evil-tenant.sharepoint.com"))
        XCTAssertFalse(DomainAnalysis.isAnyBrandDomain("contoso-my.sharepoint.com"))
        XCTAssertFalse(DomainAnalysis.isAnyBrandDomain("lh3.googleusercontent.com"))
        XCTAssertTrue(DomainAnalysis.isAnyBrandDomain("sharepoint.com"))
        XCTAssertTrue(DomainAnalysis.isAnyBrandDomain("login.microsoftonline.com"))
        XCTAssertTrue(DomainAnalysis.isAnyBrandDomain("accounts.google.com"))
        XCTAssertTrue(DomainAnalysis.isMultiTenantBrandHost("contoso-my.sharepoint.com"))
        XCTAssertFalse(DomainAnalysis.isMultiTenantBrandHost("login.microsoftonline.com"))
        XCTAssertTrue(DomainAnalysis.isLegitimateDomain("contoso.sharepoint.com", for: "microsoft"), "still Microsoft infrastructure for brand-mismatch purposes")
        XCTAssertNil(DomainAnalysis.lookalikeBrand(for: "contoso-my.sharepoint.com"))
        XCTAssertNil(DomainAnalysis.lookalikeBrand(for: "microsoft.sharepoint.com"), "a brand's own tenant")
        XCTAssertNil(DomainAnalysis.lookalikeBrand(for: "mail.notifications.sharepoint.com"))
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "paypa1-login.sharepoint.com"), "paypal")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "paypal-secure.sharepoint.com"), "paypal")
    }

    func testTenantSharePointCredentialPathIsNotExempt() {
        let phish = TestEmailFactory.email(
            from: EmailAddress(name: "Accounts Payable", address: "ap@vendor-partner.example"),
            subject: "Shared document",
            textBody: "Please review the shared document.",
            htmlBody: html([("https://evil-tenant.sharepoint.com/:x:/s/Finance/login/verify-account?e=abc", "Open document")],
                           intro: "<p>Please review the shared document.</p>"),
            authenticationResults: alignedAuth("vendor-partner.example")
        )
        let report = analyzer.analyze(phish)
        XCTAssertTrue(report.has("link.credential_path"), report.ids.joined(separator: ","))

        let legit = TestEmailFactory.email(
            from: EmailAddress(name: "SharePoint Online", address: "no-reply@sharepointonline.com"),
            subject: "Alice shared \"Q3 budget.xlsx\" with you",
            textBody: "Alice shared a file with you.",
            htmlBody: html([("https://contoso.sharepoint.com/:x:/g/personal/alice_contoso_com/EaBcDeF?e=abc", "Open")],
                           intro: "<p>Alice shared a file with you.</p>"),
            authenticationResults: alignedAuth("sharepointonline.com")
        )
        let legitReport = analyzer.analyze(legit)
        XCTAssertFalse(legitReport.has("link.credential_path"), legitReport.ids.joined(separator: ","))
        XCTAssertFalse(legitReport.has("link.brand_domain_mismatch"), legitReport.ids.joined(separator: ","))
        XCTAssertFalse(legitReport.has("link.lookalike_domain"), legitReport.ids.joined(separator: ","))
        XCTAssertFalse(legitReport.has("sender.brand_display_name_mismatch"), legitReport.ids.joined(separator: ","))
        XCTAssertLessThan(legitReport.score, 0.3)
    }

    // MARK: - Finding 34: brand entries that are public suffixes (gov.uk)

    func testPublicSuffixBrandEntriesCoverEveryHostBeneathThem() {
        XCTAssertTrue(DomainAnalysis.isLegitimateDomain("tax.service.gov.uk", for: "hmrc"))
        XCTAssertTrue(DomainAnalysis.isLegitimateDomain("notifications.service.gov.uk", for: "dvla"))
        XCTAssertTrue(DomainAnalysis.isLegitimateDomain("www.gov.uk", for: "hmrc"))
        XCTAssertTrue(DomainAnalysis.isLegitimateDomain("hmrc.gov.uk", for: "hmrc"))
        XCTAssertFalse(DomainAnalysis.isLegitimateDomain("gov.uk.evil.example", for: "hmrc"))
        XCTAssertFalse(DomainAnalysis.isLegitimateDomain("hmrc-gov.uk", for: "hmrc"))
        XCTAssertTrue(DomainAnalysis.isAnyBrandDomain("www.gov.uk"))
        XCTAssertFalse(DomainAnalysis.isAnyBrandDomain("gov.uk.evil.example"))
        XCTAssertNil(DomainAnalysis.brandKey(forRegistrableDomain: "service.gov.uk"), "a generic gov.uk sender is not the HMRC brand")
    }

    func testHMRCMailFromServiceGovUKIsNotImpersonation() {
        let email = TestEmailFactory.email(
            from: EmailAddress(name: "HMRC", address: "noreply@tax.service.gov.uk"),
            subject: "Your Self Assessment statement",
            textBody: "Your Self Assessment statement is now available to view online.",
            htmlBody: html([("https://www.gov.uk/check-income-tax-current-year", "View your statement")],
                           intro: "<p>Your Self Assessment statement is now available to view online.</p>"),
            authenticationResults: alignedAuth("tax.service.gov.uk")
        )
        let report = analyzer.analyze(email)
        XCTAssertFalse(report.has("sender.brand_display_name_mismatch"), report.ids.joined(separator: ","))
        XCTAssertFalse(report.has("link.brand_domain_mismatch"), report.ids.joined(separator: ","))
        XCTAssertLessThan(report.score, 0.3)
    }

    // MARK: - Finding 60: backslash as an authority terminator

    func testBackslashEndsTheAuthorityLikeABrowser() {
        XCTAssertEqual(DomainAnalysis.host(of: "https://evil.example\\@paypal.com/login"), "evil.example")
        XCTAssertEqual(DomainAnalysis.host(of: "https://evil.example\\paypal.com/x"), "evil.example")
        XCTAssertEqual(DomainAnalysis.host(of: "HTTP://evil.example\\@paypal.com"), "evil.example")
        XCTAssertEqual(DomainAnalysis.host(of: "www.evil.example\\@paypal.com/x"), "www.evil.example", "scheme-less input follows the http rule")
        XCTAssertEqual(DomainAnalysis.host(of: "https://evil.example%5C@paypal.com/x"), "paypal.com", "percent-encoded backslash stays userinfo, as in browsers")
        XCTAssertEqual(DomainAnalysis.host(of: "https://example.com/a?b=c\\d"), "example.com")
        XCTAssertEqual(DomainAnalysis.browserNormalizedHref("https://a.example\\b?c=\\d#\\e"), "https://a.example/b?c=\\d#\\e", "only before the query / fragment")
        XCTAssertEqual(DomainAnalysis.browserNormalizedHref("custom:a\\b"), "custom:a\\b", "non-special schemes are untouched")
        XCTAssertNil(DomainAnalysis.host(of: "javascript:alert('\\x')"))
    }

    func testBackslashAuthorityLinkIsFlaggedAsHiddenDestination() {
        let email = TestEmailFactory.email(
            subject: "Action required",
            htmlBody: html([("https://evil.example\\@paypal.com/login", "paypal.com")]),
            authenticationResults: TestEmailFactory.cleanAuth
        )
        let report = analyzer.analyze(email)
        XCTAssertTrue(report.has("link.anchor_host_mismatch"), report.ids.joined(separator: ","))
        XCTAssertTrue(report.has("link.userinfo_url"), report.ids.joined(separator: ","))
        XCTAssertTrue(report.has("link.credential_path"), "evil.example is not a brand domain: \(report.ids)")
    }

    // MARK: - Finding 63: prefix phrases in the automaton

    func testPrefixPhrasesMatchWholeWords() {
        let automaton = PhraseAutomaton(sets: [["prosecut*", "police"], ["masturbat*"]])
        XCTAssertEqual(automaton.scan("If you fail to appear you will be prosecuted."), [["prosecuted"], []])
        XCTAssertEqual(automaton.scan("Pending prosecution; the police were informed"), [["prosecution", "police"], []])
        XCTAssertEqual(automaton.scan("I saw you masturbating on camera"), [[], ["masturbating"]])
        XCTAssertEqual(automaton.scan("prosecut"), [["prosecut"], []], "the bare stem still matches")
        XCTAssertEqual(automaton.scan("policed streets"), [[], []], "non-prefix phrases stay word-bounded")
        XCTAssertEqual(automaton.scan("unprosecuted"), [[], []], "the start boundary still applies")
    }
}

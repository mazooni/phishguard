import XCTest
@testable import PhishCore

final class DomainAnalysisTests: XCTestCase {
    // MARK: registrable domain / public suffixes

    func testRegistrableDomainWithMultiLabelSuffixes() {
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "login.paypal.com"), "paypal.com")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "www.example.co.uk"), "example.co.uk")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "mail.shop.example.com.au"), "example.com.au")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "a.b.example.com.br"), "example.com.br")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "x.example.co.jp"), "example.co.jp")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "hmrc.gov.uk"), "hmrc.gov.uk")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "www.ox.ac.uk"), "ox.ac.uk")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "a.example.com.mx"), "example.com.mx")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "a.example.co.in"), "example.co.in")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "a.example.com.sg"), "example.com.sg")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "a.example.co.nz"), "example.co.nz")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "a.example.com.tr"), "example.com.tr")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "co.uk"), "co.uk")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "localhost"), "localhost")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "EXAMPLE.COM."), "example.com")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "192.168.1.1"), "192.168.1.1")
    }

    func testFreeHostingSuffixesActLikePublicSuffixes() {
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "evil.github.io"), "evil.github.io")
        XCTAssertEqual(DomainAnalysis.registrableDomain(of: "x.blob.core.windows.net"), "x.blob.core.windows.net")
        XCTAssertTrue(DomainAnalysis.isFreeHosting("evil-login.web.app"))
        XCTAssertTrue(DomainAnalysis.isFreeHosting("sites.google.com"))
        XCTAssertFalse(DomainAnalysis.isFreeHosting("www.google.com"))
        XCTAssertEqual(DomainAnalysis.subdomainDepth(of: "a.b.c.example.com"), 3)
        XCTAssertEqual(DomainAnalysis.subdomainDepth(of: "example.co.uk"), 0)
        XCTAssertEqual(DomainAnalysis.registrableLabel(of: "www.paypal.com"), "paypal")
    }

    // MARK: IP literals

    func testIPLiteralForms() {
        XCTAssertTrue(DomainAnalysis.isIPLiteral("192.168.1.1"))
        XCTAssertTrue(DomainAnalysis.isIPLiteral("[2001:db8::1]"))
        XCTAssertTrue(DomainAnalysis.isIPLiteral("2001:db8:85a3:0:0:8a2e:370:7334"))
        XCTAssertTrue(DomainAnalysis.isIPLiteral("::ffff:192.0.2.128"))
        XCTAssertTrue(DomainAnalysis.isIPLiteral("3232235777"), "decimal IPv4")
        XCTAssertTrue(DomainAnalysis.isIPLiteral("0xc0a80101"), "hex IPv4")
        XCTAssertTrue(DomainAnalysis.isIPLiteral("0xC0.0xA8.0x01.0x01"), "dotted hex")
        XCTAssertTrue(DomainAnalysis.isIPLiteral("0300.0250.01.01"), "dotted octal")
        XCTAssertTrue(DomainAnalysis.isIPLiteral("192.168.257"), "three-part form")
        XCTAssertFalse(DomainAnalysis.isIPLiteral("256.1.1.1"))
        XCTAssertFalse(DomainAnalysis.isIPLiteral("example.com"))
        XCTAssertFalse(DomainAnalysis.isIPLiteral("1.2.3.4.5"))
        XCTAssertFalse(DomainAnalysis.isIPLiteral("2001:db8::1::2"))
        XCTAssertFalse(DomainAnalysis.isIPLiteral("99999999999"))
        XCTAssertFalse(DomainAnalysis.isIPLiteral(""))
    }

    func testPunycode() {
        XCTAssertTrue(DomainAnalysis.isPunycode("xn--pypal-4ve.com"))
        XCTAssertTrue(DomainAnalysis.isPunycode("login.XN--80AK6AA92E.com"))
        XCTAssertFalse(DomainAnalysis.isPunycode("paypal.com"))
    }

    // MARK: host extraction

    func testHostOfVariousHrefs() {
        XCTAssertEqual(DomainAnalysis.host(of: "https://WWW.Example.com/path?q=1"), "www.example.com")
        XCTAssertEqual(DomainAnalysis.host(of: "www.example.com/path"), "www.example.com")
        XCTAssertEqual(DomainAnalysis.host(of: "http://user:pw@evil.example:8080/x"), "evil.example")
        XCTAssertEqual(DomainAnalysis.host(of: "https://www.paypal.com@evil.example/login"), "evil.example")
        XCTAssertEqual(DomainAnalysis.host(of: "http://[2001:db8::1]/x"), "[2001:db8::1]")
        XCTAssertEqual(DomainAnalysis.host(of: "https://exa mple.com/a b"), nil)
        XCTAssertEqual(DomainAnalysis.host(of: "https://example.com/a b c"), "example.com", "spaces in the path are tolerated")
        XCTAssertNil(DomainAnalysis.host(of: "mailto:a@b.example"))
        XCTAssertNil(DomainAnalysis.host(of: "javascript:alert(1)"))
        XCTAssertNil(DomainAnalysis.host(of: "#top"))
        XCTAssertNil(DomainAnalysis.host(of: "just words"))
    }

    // MARK: brand lookalikes

    func testLegitimateBrandDomainsAreNotLookalikes() {
        for brand in DomainAnalysis.brands {
            for domain in brand.domains {
                XCTAssertNil(DomainAnalysis.lookalikeBrand(for: domain), "\(domain) is a real \(brand.key) domain")
                XCTAssertNil(DomainAnalysis.lookalikeBrand(for: "www." + domain), "www.\(domain)")
                XCTAssertNil(DomainAnalysis.lookalikeBrand(for: "mail.notifications." + domain), "mail.notifications.\(domain)")
            }
        }
        XCTAssertGreaterThanOrEqual(DomainAnalysis.brands.count, 60)
        XCTAssertEqual(Set(DomainAnalysis.brands.map(\.key)).count, DomainAnalysis.brands.count, "keys are unique")
        XCTAssertTrue(Set(DomainAnalysis.protectedBrands["paypal"] ?? []).isSuperset(of: ["paypal.com", "paypal.me", "paypal-communication.com", "paypal.co.uk"]))
    }

    func testLookalikeDetectionKinds() {
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "paypal.com.account-verify-login.com"), "paypal")
        XCTAssertEqual(DomainAnalysis.lookalikeMatch(for: "paypal.com.secure-login.net")?.kind, .brandToken)
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "paypal-resolution-center.com"), "paypal")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "secure.paypal-login.top"), "paypal")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "paypa1.com"), "paypal")
        XCTAssertEqual(DomainAnalysis.lookalikeMatch(for: "paypa1.com")?.kind, .homoglyph)
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "rnicrosoft.com"), "microsoft")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "g00gle.com"), "google")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "arnazon.de"), "amazon")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "paypall.com"), "paypal")
        XCTAssertEqual(DomainAnalysis.lookalikeMatch(for: "paypall.com")?.kind, .typosquat)
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "microsofft-support.com"), "microsoft")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "netflixx.com"), "netflix")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "paypalsecure.com"), "paypal")
        XCTAssertEqual(DomainAnalysis.lookalikeMatch(for: "mypaypal-billing.com")?.kind, .embedded)
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "apple-id-verify.com"), "apple", "dictionary-word brand + companion token")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "apple.com.secure-login.net"), "apple")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "wise-verify.com"), "wise")
        XCTAssertNil(DomainAnalysis.lookalikeBrand(for: "the-apple-orchard.com"), "dictionary-word brand without a companion token")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "usps-redelivery.click"), "usps")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "login-microsoftonline.secure-verify.top"), "microsoft")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "chase-secure-alerts.com"), "chase")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "paypal1.com"), "paypal")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: "аpple.com".lowercased()), "apple", "Cyrillic а")
    }

    func testDictionaryWordsAndUnrelatedHostsAreNotLookalikes() {
        for host in ["pineapple.com", "purchase-orders.example", "groups.io", "startups.com", "clockwise.app", "applebees.com",
                     "steampowered.com", "upstream.example", "discovery.com", "chasing-dreams.blog", "cups.org", "snapple.com",
                     "news.trailheadoutfitters.com", "example.com", "wise-words.blog", "sitemeta.example", "metadata.example",
                     "targeted.example", "bookings-app.example", "amazonian-rainforest.org"] {
            XCTAssertNil(DomainAnalysis.lookalikeBrand(for: host), host)
        }
    }

    func testHomoglyphNormalizationAndLevenshtein() {
        XCTAssertEqual(DomainAnalysis.homoglyphNormalized("PayPa1"), "paypal")
        XCTAssertEqual(DomainAnalysis.homoglyphNormalized("rnicr0soft"), "microsoft")
        XCTAssertEqual(DomainAnalysis.homoglyphNormalized("vvells"), "wells")
        XCTAssertEqual(DomainAnalysis.levenshtein("kitten", "sitting"), 3)
        XCTAssertEqual(DomainAnalysis.levenshtein("paypal", "paypall", limit: 1), 1)
        XCTAssertEqual(DomainAnalysis.levenshtein("paypal", "amazon", limit: 1), 2, "early exit returns limit + 1")
    }

    // MARK: catalogs

    func testCatalogHelpers() {
        XCTAssertTrue(DomainAnalysis.isFreeMailDomain("gmail.com"))
        XCTAssertTrue(DomainAnalysis.isFreeMailDomain("mail.yahoo.co.uk"))
        XCTAssertFalse(DomainAnalysis.isFreeMailDomain("northwindtraders.example"))
        XCTAssertTrue(DomainAnalysis.isURLShortener("bit.ly"))
        XCTAssertTrue(DomainAnalysis.isURLShortener("www.tinyurl.com"))
        XCTAssertFalse(DomainAnalysis.isURLShortener("example.com"))
        XCTAssertTrue(DomainAnalysis.hasSuspiciousTLD("login.example.top"))
        XCTAssertFalse(DomainAnalysis.hasSuspiciousTLD("example.com"))
        XCTAssertFalse(DomainAnalysis.hasSuspiciousTLD("192.168.0.1"))
        XCTAssertTrue(DomainAnalysis.isLegitimateDomain("mail.paypal.com", for: "paypal"))
        XCTAssertFalse(DomainAnalysis.isLegitimateDomain("paypal.com.evil.example", for: "paypal"))
        XCTAssertTrue(DomainAnalysis.isAnyBrandDomain("accounts.google.com"))
    }

    func testBrandMentionsAreWordBounded() {
        XCTAssertEqual(DomainAnalysis.brandsMentioned(in: "Your PayPal account"), ["paypal"])
        XCTAssertEqual(DomainAnalysis.brandsMentioned(in: "Microsoft 365 Admin Center"), ["microsoft"])
        XCTAssertTrue(DomainAnalysis.brandsMentioned(in: "Bank of America alert").contains("bankofamerica"))
        XCTAssertTrue(DomainAnalysis.brandsMentioned(in: "USPS Package Tracking").contains("usps"))
        XCTAssertFalse(DomainAnalysis.brandsMentioned(in: "Chase Miller").contains("chase"), "bare 'chase' is a common first name")
        XCTAssertTrue(DomainAnalysis.brandsMentioned(in: "Chase Bank statement").contains("chase"))
        XCTAssertFalse(DomainAnalysis.brandsMentioned(in: "join our groups and startups").contains("ups"))
        XCTAssertTrue(DomainAnalysis.brandsMentioned(in: "Your UPS delivery").contains("ups"))
        XCTAssertEqual(DomainAnalysis.brandsMentioned(in: "Trailhead Outfitters"), [])
    }
}

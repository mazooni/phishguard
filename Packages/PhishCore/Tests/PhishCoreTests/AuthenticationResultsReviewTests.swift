import XCTest
@testable import PhishCore

/// Regression tests for the review findings against `AuthenticationResults` (id-less header trust, ARC results).
final class AuthenticationResultsReviewTests: XCTestCase {
    // MARK: - Finding 32: id-less (Exchange Online style) top header

    func testIDLessTopHeaderIsNotMergedWithLaterHeaders() {
        let headers = [
            EmailHeader(name: "From", value: "PayPal <service@paypal.com>"),
            EmailHeader(name: "Authentication-Results", value: "spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=paypal.com; dkim=fail (signature did not verify) header.d=paypal.com; dmarc=fail action=oreject header.from=paypal.com; compauth=fail reason=000"),
            EmailHeader(name: "Authentication-Results", value: "mail.attacker.example; dkim=pass header.d=paypal.com; spf=pass; dmarc=pass"),
            EmailHeader(name: "Authentication-Results", value: "dkim=pass header.d=paypal.com; spf=pass; dmarc=pass"),
        ]
        let results = AuthenticationResults.extract(from: headers)
        XCTAssertNil(results.authservID)
        XCTAssertEqual(results.dkim, .fail)
        XCTAssertEqual(results.dkimDomain, "paypal.com")
        XCTAssertEqual(results.dkimPassDomains, [])
        XCTAssertEqual(results.spf, .fail)
        XCTAssertEqual(results.dmarc, .fail)
        XCTAssertEqual(results.rawHeader, headers[1].value, "only the trusted header is reported")
    }

    func testIDLessHeaderBelowAStampedHeaderIsIgnored() {
        let headers = [
            EmailHeader(name: "From", value: "PayPal <service@paypal.com>"),
            EmailHeader(name: "Authentication-Results", value: "mx.google.com; dkim=fail header.d=paypal.com; spf=fail smtp.mailfrom=x@evil.example; dmarc=fail header.from=paypal.com"),
            EmailHeader(name: "Authentication-Results", value: "dkim=pass header.d=paypal.com; spf=pass; dmarc=pass"),
        ]
        let results = AuthenticationResults.extract(from: headers)
        XCTAssertEqual(results.authservID, "mx.google.com")
        XCTAssertEqual(results.dkim, .fail)
        XCTAssertEqual(results.dkimPassDomains, [])
        XCTAssertEqual(results.spf, .fail)
        XCTAssertEqual(results.dmarc, .fail)
    }

    func testForgedHeaderCannotGrantBrandAuthentication() {
        let email = TestEmailFactory.email(
            from: EmailAddress(name: "PayPal", address: "service@paypal.com"),
            subject: "Your account has been limited",
            textBody: "Please confirm your details.",
            authenticationResults: "spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=paypal.com; dkim=fail (signature did not verify) header.d=paypal.com; dmarc=fail action=oreject header.from=paypal.com; compauth=fail reason=000",
            extraHeaders: [EmailHeader(name: "Authentication-Results", value: "mail.attacker.example; dkim=pass header.d=paypal.com; spf=pass; dmarc=pass")]
        )
        let report = HeuristicAnalyzer().analyze(email)
        XCTAssertTrue(report.has("auth.dkim_fail"), report.ids.joined(separator: ","))
        XCTAssertTrue(report.has("auth.dmarc_fail"), report.ids.joined(separator: ","))
        XCTAssertFalse(report.has("mitigation.brand_authenticated"), report.ids.joined(separator: ","))
    }

    // MARK: - Finding 31: arc= result

    func testARCResultIsParsedFromTheTrustedHeader() {
        let value = "mx.google.com; dkim=fail (signature did not verify) header.i=@corp-example.com header.s=s1 header.b=abc; arc=pass (i=1 spf=pass spfdomain=lists.example.org dkim=pass dkdomain=corp-example.com dmarc=pass fromdomain=corp-example.com); spf=pass (google.com: domain of dev-list-bounces@lists.example.org designates 203.0.113.5 as permitted sender) smtp.mailfrom=dev-list-bounces@lists.example.org; dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=corp-example.com"
        let parsed = AuthenticationResults.parse(value)
        XCTAssertEqual(parsed.arc, .pass)
        XCTAssertEqual(parsed.dkim, .fail, "the provider's own DKIM verdict is kept")
        XCTAssertEqual(parsed.dmarc, .fail)
        XCTAssertEqual(parsed.spf, .pass)
        XCTAssertEqual(parsed.spfDomain, "lists.example.org")
        XCTAssertTrue(parsed.hasAnyResult)

        let headers = [
            EmailHeader(name: "From", value: "Dev <dev@corp-example.com>"),
            EmailHeader(name: "Authentication-Results", value: value),
            EmailHeader(name: "ARC-Authentication-Results", value: "i=1; lists.example.org; spf=pass smtp.mailfrom=dev@corp-example.com; dkim=pass header.d=corp-example.com; dmarc=pass header.from=corp-example.com"),
        ]
        let results = AuthenticationResults.extract(from: headers)
        XCTAssertEqual(results.arc, .pass)
        XCTAssertEqual(results.dkim, .fail, "ARC-sealed values never overwrite the receiver's verdicts")
        XCTAssertEqual(results.dmarc, .fail)
        XCTAssertEqual(AuthenticationResults.parse("mx.google.com; arc=fail (signature failed); spf=pass; dkim=pass header.d=a.example").arc, .fail)
        XCTAssertNil(AuthenticationResults.parse("mx.google.com; spf=pass; dkim=pass header.d=a.example").arc)
    }

    func testARCResultIsNotTakenFromARCAuthenticationResults() {
        let headers = [
            EmailHeader(name: "Authentication-Results", value: "mx.google.com; spf=fail smtp.mailfrom=a@x.example"),
            EmailHeader(name: "ARC-Authentication-Results", value: "i=1; mx.hop.example; arc=pass; spf=pass; dkim=pass header.d=x.example; dmarc=pass"),
        ]
        let results = AuthenticationResults.extract(from: headers)
        XCTAssertNil(results.arc, "an intermediary's own arc claim is not the receiving provider's")
        XCTAssertEqual(results.spf, .fail)
        XCTAssertEqual(results.dkim, .pass, "missing methods are still filled from ARC")
    }

    func testARCReachesTheHeuristicReport() {
        let email = TestEmailFactory.email(
            from: EmailAddress(name: "Dev", address: "dev@corp-example.com"),
            sender: EmailAddress(name: nil, address: "dev-list-bounces@lists.example.org"),
            subject: "[dev-list] Build broken on main",
            textBody: "The nightly build failed again, see the log.",
            authenticationResults: "mx.google.com; dkim=fail header.i=@corp-example.com; arc=pass (i=1 spf=pass dkim=pass dmarc=pass); spf=pass smtp.mailfrom=dev-list-bounces@lists.example.org; dmarc=fail (p=NONE) header.from=corp-example.com",
            extraHeaders: [EmailHeader(name: "List-Id", value: "<dev-list.lists.example.org>"), EmailHeader(name: "List-Unsubscribe", value: "<mailto:dev-list-leave@lists.example.org>")]
        )
        let report = HeuristicAnalyzer().analyze(email)
        XCTAssertEqual(report.authentication.arc, .pass)
        XCTAssertEqual(report.authentication.dkim, .fail)
        XCTAssertEqual(report.authentication.dmarc, .fail)
    }

    func testCodableRoundTripIncludesARCAndToleratesOldPayloads() throws {
        var results = AuthenticationResults(spf: .pass, dkim: .fail, dmarc: .fail, rawHeader: "x")
        results.arc = .pass
        let data = try JSONEncoder().encode(results)
        let decoded = try JSONDecoder().decode(AuthenticationResults.self, from: data)
        XCTAssertEqual(decoded, results)
        XCTAssertEqual(decoded.arc, .pass)
        let old = try JSONDecoder().decode(AuthenticationResults.self, from: Data(#"{"spf":"pass","dkim":"fail"}"#.utf8))
        XCTAssertNil(old.arc)
    }
}

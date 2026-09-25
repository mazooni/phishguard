import XCTest
@testable import PhishCore

final class AuthenticationResultsTests: XCTestCase {
    func testParsesGmailStyleHeaderWithCommentsAndProperties() {
        let value = "mx.google.com; dkim=fail (signature did not verify) header.i=@paypal.com header.s=pp-dkim1 header.b=Zz0/1abc; spf=softfail (google.com: domain of transitioning bounce@secure-mail-notify.com does not designate 198.51.100.77 as permitted sender) smtp.mailfrom=bounce@secure-mail-notify.com; dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=paypal.com"
        let parsed = AuthenticationResults.parse(value)
        XCTAssertEqual(parsed.authservID, "mx.google.com")
        XCTAssertEqual(parsed.dkim, .fail)
        XCTAssertEqual(parsed.dkimDomain, "paypal.com", "header.i=@domain is reduced to the domain")
        XCTAssertEqual(parsed.spf, .softfail)
        XCTAssertEqual(parsed.spfDomain, "secure-mail-notify.com")
        XCTAssertEqual(parsed.dmarc, .fail)
        XCTAssertEqual(parsed.dmarcFromDomain, "paypal.com")
        XCTAssertEqual(parsed.rawHeader, value)
    }

    func testCommentsContainingSemicolonsAndEqualsAreIgnored() {
        let parsed = AuthenticationResults.parse("mx.example.com; spf=pass (sender IP is 203.0.113.9; helo=a.b; x=y) smtp.mailfrom=a@b.example; dkim=pass (2048-bit key; unprotected) header.d=b.example")
        XCTAssertEqual(parsed.spf, .pass)
        XCTAssertEqual(parsed.spfDomain, "b.example")
        XCTAssertEqual(parsed.dkim, .pass)
        XCTAssertEqual(parsed.dkimDomain, "b.example")
    }

    func testMethodVersionAndQuotedValuesAndUnknownTokens() {
        let parsed = AuthenticationResults.parse("mx 1; spf/2=pass smtp.mailfrom=\"quoted@x.example\"; dkim=bogusvalue header.d=x.example; dmarc=bestguesspass")
        XCTAssertEqual(parsed.authservID, "mx")
        XCTAssertEqual(parsed.spf, .pass)
        XCTAssertEqual(parsed.spfDomain, "x.example")
        XCTAssertEqual(parsed.dkim, .unknown)
        XCTAssertEqual(parsed.dmarc, .unknown)
    }

    func testMultipleDKIMSignaturesPreferAlignedPass() {
        let headers = [
            EmailHeader(name: "From", value: "Amazon <order@amazon.com>"),
            EmailHeader(name: "Authentication-Results", value: "mx.google.com; dkim=pass header.i=@amazonses.com header.s=a; dkim=pass header.i=@amazon.com header.s=b; dkim=fail header.d=other.example; spf=pass smtp.mailfrom=x@amazonses.com; dmarc=pass header.from=amazon.com"),
        ]
        let results = AuthenticationResults.extract(from: headers)
        XCTAssertEqual(results.dkim, .pass)
        XCTAssertEqual(results.dkimDomain, "amazon.com", "the signature aligned with From wins")
        XCTAssertEqual(Set(results.dkimPassDomains), ["amazonses.com", "amazon.com"])
    }

    func testAnyPassWinsWhenNoSignatureIsAligned() {
        let parsed = AuthenticationResults.parse("mx; dkim=fail header.d=a.example; dkim=pass header.d=b.example")
        XCTAssertEqual(parsed.dkim, .pass)
        XCTAssertEqual(parsed.dkimDomain, "b.example")
    }

    func testOnlyTheTopMostAuthservIDIsTrusted() {
        let headers = [
            EmailHeader(name: "Authentication-Results", value: "mx.google.com; dkim=fail header.d=paypal.com; spf=fail smtp.mailfrom=x@evil.example; dmarc=fail header.from=paypal.com"),
            EmailHeader(name: "Authentication-Results", value: "mail.attacker.example; dkim=pass header.d=paypal.com; spf=pass; dmarc=pass"),
        ]
        let results = AuthenticationResults.extract(from: headers)
        XCTAssertEqual(results.authservID, "mx.google.com")
        XCTAssertEqual(results.dkim, .fail)
        XCTAssertEqual(results.spf, .fail)
        XCTAssertEqual(results.dmarc, .fail)
    }

    func testHeadersWithTheSameAuthservIDAreMerged() {
        let headers = [
            EmailHeader(name: "Authentication-Results", value: "mx.microsoft.com 1; spf=pass smtp.mailfrom=a.example"),
            EmailHeader(name: "Authentication-Results", value: "mx.microsoft.com; dkim=pass header.d=a.example; dmarc=pass header.from=a.example"),
        ]
        let results = AuthenticationResults.extract(from: headers)
        XCTAssertEqual(results.spf, .pass)
        XCTAssertEqual(results.dkim, .pass)
        XCTAssertEqual(results.dmarc, .pass)
    }

    func testARCFallbackUsesTheNewestInstance() {
        let headers = [
            EmailHeader(name: "ARC-Authentication-Results", value: "i=1; mx.first-hop.example; spf=pass smtp.mailfrom=a@x.example; dkim=none"),
            EmailHeader(name: "ARC-Authentication-Results", value: "i=2; mx.forwarder.example; spf=fail smtp.mailfrom=a@x.example; dkim=pass header.d=x.example; dmarc=pass header.from=x.example"),
        ]
        let results = AuthenticationResults.extract(from: headers)
        XCTAssertEqual(results.authservID, "mx.forwarder.example")
        XCTAssertEqual(results.spf, .fail)
        XCTAssertEqual(results.dkim, .pass)
        XCTAssertEqual(results.dmarc, .pass)
        XCTAssertNotNil(results.rawHeader)
    }

    func testARCFillsOnlyMissingMethods() {
        let headers = [
            EmailHeader(name: "Authentication-Results", value: "mx.google.com; spf=fail smtp.mailfrom=a@x.example"),
            EmailHeader(name: "ARC-Authentication-Results", value: "i=1; mx.hop.example; spf=pass; dkim=pass header.d=x.example; dmarc=pass"),
        ]
        let results = AuthenticationResults.extract(from: headers)
        XCTAssertEqual(results.spf, .fail, "trusted header wins")
        XCTAssertEqual(results.dkim, .pass, "filled from ARC")
        XCTAssertEqual(results.dmarc, .pass)
    }

    func testReceivedSPFFallback() {
        let headers = [EmailHeader(name: "Received-SPF", value: "pass (google.com: domain of bounce@x.example designates 203.0.113.1 as permitted sender) client-ip=203.0.113.1;")]
        let results = AuthenticationResults.extract(from: headers)
        XCTAssertEqual(results.spf, .pass)
        XCTAssertEqual(results.spfDomain, "x.example")
        XCTAssertNil(results.dkim)
    }

    func testNoHeadersGivesEmptyResults() {
        let results = AuthenticationResults.extract(from: [EmailHeader(name: "From", value: "a@b.example")])
        XCTAssertFalse(results.hasAnyResult)
        XCTAssertNil(results.rawHeader)
    }

    func testCodableRoundTripAndOldPayloads() throws {
        var results = AuthenticationResults(spf: .pass, dkim: .pass, dmarc: .pass, rawHeader: "x")
        results.dkimDomain = "a.example"
        results.dkimPassDomains = ["a.example"]
        let data = try JSONEncoder().encode(results)
        XCTAssertEqual(try JSONDecoder().decode(AuthenticationResults.self, from: data), results)
        let old = try JSONDecoder().decode(AuthenticationResults.self, from: Data(#"{"spf":"pass","dkim":"fail"}"#.utf8))
        XCTAssertEqual(old.spf, .pass)
        XCTAssertEqual(old.dkim, .fail)
        XCTAssertEqual(old.dkimPassDomains, [])
    }

    func testHostileHeaderIsCapped() {
        let huge = "mx; " + String(repeating: "dkim=pass header.d=a.example; ", count: 5_000) + "(" + String(repeating: "(", count: 10_000)
        let start = Date()
        let parsed = AuthenticationResults.parse(huge)
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.5)
        XCTAssertEqual(parsed.dkim, .pass)
    }
}

import XCTest
@testable import PhishCore

final class SampleEmailsTests: XCTestCase {
    func testAllFixturesArePresentAndDistinct() {
        XCTAssertEqual(SampleEmails.all.count, 33)
        XCTAssertEqual(SampleEmails.labeled.count, 33)
        XCTAssertEqual(SampleEmails.named.count, 33)
        XCTAssertEqual(SampleEmails.malicious.count, 14)
        XCTAssertEqual(SampleEmails.benign.count, 19)
        XCTAssertEqual(Set(SampleEmails.all.map(\.messageID)).count, 33)
        XCTAssertEqual(Set(SampleEmails.named.map(\.name)).count, 33, "fixture names are unique")
        for id in SampleEmails.benignScoreTolerances.keys {
            XCTAssertTrue(SampleEmails.benign.contains { $0.messageID == id }, "tolerance for an unknown or non-benign fixture: \(id)")
        }
        for email in SampleEmails.all {
            XCTAssertNotNil(email.from, email.subject)
            XCTAssertFalse(email.subject.isEmpty)
            XCTAssertFalse(email.headers.isEmpty)
            XCTAssertNotNil(email.header("from"), "case-insensitive header lookup")
        }
    }

    func testFromHeadersParseToTheSameAddresses() {
        for email in SampleEmails.all {
            let parsed = EmailAddress.parse(email.header("From") ?? "")
            XCTAssertEqual(parsed.first, email.from, email.subject)
            let replyTo = EmailAddress.parse(email.header("Reply-To") ?? "")
            XCTAssertEqual(replyTo, email.replyTo, email.subject)
        }
    }

    func testHeuristicAnalyzerFillsBodyTextAndAuthentication() {
        let analyzer = HeuristicAnalyzer()

        let benign = analyzer.analyze(SampleEmails.benignNewsletter)
        XCTAssertTrue(benign.bodyText.hasPrefix("Hi Sam,"))
        XCTAssertEqual(benign.authentication.spf, .pass)
        XCTAssertEqual(benign.authentication.dkim, .pass)
        XCTAssertEqual(benign.authentication.dmarc, .pass)
        XCTAssertTrue(benign.links.contains { $0.href == "https://news.trailheadoutfitters.com/september-picks" })

        let phish = analyzer.analyze(SampleEmails.paypalPhish)
        XCTAssertEqual(phish.authentication.dkim, .fail)
        XCTAssertEqual(phish.authentication.dmarc, .fail)
        XCTAssertEqual(phish.authentication.spf, .softfail)
        let lookalike = phish.links.first { $0.href.contains("account-verify-login.com") }
        XCTAssertNotNil(lookalike)
        XCTAssertEqual(lookalike?.host, "paypal.com.account-verify-login.com")
        XCTAssertEqual(DomainAnalysis.lookalikeBrand(for: lookalike?.host ?? ""), "paypal")
        XCTAssertNotEqual(SampleEmails.paypalPhish.replyTo.first?.domain, SampleEmails.paypalPhish.from?.domain)
        XCTAssertLessThanOrEqual(phish.bodyExcerpt.count, HeuristicReport.excerptLength)

        let scam = analyzer.analyze(SampleEmails.giftCardScam)
        XCTAssertTrue(scam.bodyText.contains("gift cards"))
        XCTAssertTrue(scam.links.isEmpty)
        XCTAssertEqual(SampleEmails.giftCardScam.replyTo.first?.domain, "outlook.com")
        XCTAssertEqual(SampleEmails.giftCardScam.from?.domain, "gmail.com")
    }

    func testHTMLBodyIsUsedWhenTextBodyMissing() {
        var email = SampleEmails.paypalPhish
        email.textBody = nil
        let report = HeuristicAnalyzer().analyze(email)
        XCTAssertTrue(report.bodyText.contains("Dear Customer"))
        XCTAssertFalse(report.bodyText.contains("<"))
        XCTAssertTrue(report.bodyText.contains("©"), "entities are decoded")
    }

    func testPromptAndParserRoundTrip() throws {
        let report = HeuristicAnalyzer().analyze(SampleEmails.paypalPhish)
        let prompt = PromptBuilder.userPrompt(for: ClassificationInput(email: SampleEmails.paypalPhish, report: report), maxBodyCharacters: 200)
        XCTAssertTrue(prompt.contains("Subject: Action required"))
        XCTAssertTrue(prompt.contains("dkim=fail"))

        let json = """
        Sure, here is the result:
        ```json
        {"isSuspicious": true, "category": "phishing", "riskScore": 140, "reasons": ["a","b","c","d","e","f","g"], "summary": "Credential phish."}
        ```
        """
        let assessment = try ModelOutputParser.parseAssessment(from: json)
        XCTAssertTrue(assessment.isSuspicious)
        XCTAssertEqual(assessment.category, .phishing)
        XCTAssertEqual(assessment.riskScore, 100, "clamped")
        XCTAssertEqual(assessment.reasons.count, 6, "limited to 6")
        XCTAssertThrowsError(try ModelOutputParser.parseAssessment(from: "no json here"))
    }
}

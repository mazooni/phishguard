import Foundation
import PhishCore
import XCTest
@testable import PhishGuard

final class GraphMessageMapperTests: XCTestCase {
    private let accountID = UUID()

    private func data(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object)
    }

    func testMapsHTMLMessageWithHeadersAttachmentsAndAddresses() throws {
        var json = GraphFixtures.fullMessage(
            id: "AAMk1",
            received: "2026-09-21T09:15:30.1234567Z",
            subject: "Verify your account",
            from: "Service@PayPal-Secure.com",
            fromName: "  PayPal  ",
            html: "<html><body><p>Hello <b>there</b></p><p>Click <a href=\"https://evil.example\">here</a></p></body></html>",
            hasAttachments: true,
            headers: [
                ["name": "Authentication-Results", "value": "spf=fail (sender IP is 1.2.3.4)"],
                ["name": "Message-ID", "value": "<original@paypal-secure.com>"],
            ]
        )
        json["attachments"] = [
            ["name": "Invoice.PDF", "contentType": "application/pdf", "size": 12345, "isInline": false],
            ["name": "logo.png", "contentType": "image/png", "size": 100, "isInline": true],
        ]

        let email = try GraphMessageMapper.map(data(json), accountID: accountID)

        XCTAssertEqual(email.provider, .microsoft)
        XCTAssertEqual(email.accountID, accountID.uuidString)
        XCTAssertEqual(email.messageID, "AAMk1")
        XCTAssertEqual(email.threadID, "conv-AAMk1")
        XCTAssertEqual(email.subject, "Verify your account")
        XCTAssertEqual(email.receivedAt.timeIntervalSince1970, 1_789_982_130.123, accuracy: 0.001)
        XCTAssertEqual(email.from, EmailAddress(name: "PayPal", address: "service@paypal-secure.com"))
        XCTAssertEqual(email.from?.domain, "paypal-secure.com")
        XCTAssertEqual(email.sender?.address, "service@paypal-secure.com")
        XCTAssertEqual(email.replyTo, [EmailAddress(name: "Reply", address: "reply@example.com")])
        XCTAssertEqual(email.to, [EmailAddress(name: "Victim", address: "victim@example.com")])
        XCTAssertNil(email.textBody)
        XCTAssertEqual(email.htmlBody?.contains("<b>there</b>"), true)
        XCTAssertEqual(email.headers.map(\.name), ["Authentication-Results", "Message-ID"])
        XCTAssertEqual(email.header("authentication-results"), "spf=fail (sender IP is 1.2.3.4)")
        XCTAssertEqual(email.header("Message-ID"), "<original@paypal-secure.com>", "existing Message-ID header is kept")
        XCTAssertEqual(email.attachments, [EmailAttachment(filename: "Invoice.PDF", mimeType: "application/pdf", sizeBytes: 12345)], "inline parts are dropped")
        XCTAssertEqual(email.attachments.first?.fileExtension, "pdf")
        XCTAssertEqual(email.webLink?.absoluteString, "https://outlook.live.com/mail/0/inbox/id/AAMk1")

        // Plain text is derived downstream by PhishCore's extractor from the HTML body.
        let text = HTMLTextExtractor.plainText(for: email).split(whereSeparator: \.isWhitespace).joined(separator: " ")
        XCTAssertTrue(text.contains("Hello there"), text)
        XCTAssertTrue(text.contains("Click here"), text)
        XCTAssertFalse(text.contains("<"), text)
        XCTAssertEqual(email.dedupeKey, "microsoft:\(accountID.uuidString):AAMk1")
    }

    func testMapsTextBody() throws {
        let json = GraphFixtures.fullMessage(id: "AAMk2", html: nil, text: "Plain body\nline two")
        let email = try GraphMessageMapper.map(data(json), accountID: accountID)

        XCTAssertEqual(email.textBody, "Plain body\nline two")
        XCTAssertNil(email.htmlBody)
        XCTAssertEqual(HTMLTextExtractor.plainText(for: email), "Plain body\nline two")
    }

    func testMissingFieldsAreTolerated() throws {
        let json: [String: Any] = ["id": "AAMk3", "receivedDateTime": "2026-09-21T07:00:00Z"]
        let email = try GraphMessageMapper.map(data(json), accountID: accountID)

        XCTAssertEqual(email.messageID, "AAMk3")
        XCTAssertNil(email.threadID)
        XCTAssertEqual(email.subject, "")
        XCTAssertNil(email.from)
        XCTAssertNil(email.sender)
        XCTAssertEqual(email.replyTo, [])
        XCTAssertEqual(email.to, [])
        XCTAssertNil(email.textBody)
        XCTAssertNil(email.htmlBody)
        XCTAssertEqual(email.headers, [])
        XCTAssertEqual(email.attachments, [])
        XCTAssertNil(email.webLink)
        XCTAssertEqual(HTMLTextExtractor.plainText(for: email), "")
    }

    func testMissingReceivedDateTimeThrowsDecodingError() throws {
        let json: [String: Any] = ["id": "AAMk4", "subject": "no date"]
        XCTAssertThrowsError(try GraphMessageMapper.map(data(json), accountID: accountID)) { error in
            guard case ProviderError.decoding = error else { return XCTFail("unexpected \(error)") }
        }
    }

    func testInvalidJSONThrowsDecodingError() {
        XCTAssertThrowsError(try GraphMessageMapper.map(Data("not json".utf8), accountID: accountID)) { error in
            guard case ProviderError.decoding = error else { return XCTFail("unexpected \(error)") }
        }
    }

    func testInternetMessageIdBecomesMessageIDHeaderWhenAbsent() throws {
        let json = GraphFixtures.fullMessage(id: "AAMk5", headers: [["name": "Received", "value": "from mx.example"]])
        let email = try GraphMessageMapper.map(data(json), accountID: accountID)

        XCTAssertEqual(email.headers.map(\.name), ["Received", "Message-ID"])
        XCTAssertEqual(email.header("message-id"), "<AAMk5@example.com>")
    }

    func testAddressesWithoutAnAddressAreDroppedAndNamesTrimmed() throws {
        var json = GraphFixtures.fullMessage(id: "AAMk6")
        json["from"] = ["emailAddress": ["name": "Nobody"]]
        json["replyTo"] = [["emailAddress": ["address": "  "]], ["emailAddress": ["address": "OK@Example.org", "name": " Ok "]]]
        json["toRecipients"] = [["emailAddress": [String: String]()]]
        let email = try GraphMessageMapper.map(data(json), accountID: accountID)

        XCTAssertNil(email.from)
        XCTAssertEqual(email.replyTo, [EmailAddress(name: "Ok", address: "ok@example.org")])
        XCTAssertEqual(email.to, [])
    }

    func testBodyContentTypeIsCaseInsensitive() throws {
        var json = GraphFixtures.fullMessage(id: "AAMk7")
        json["body"] = ["contentType": "HTML", "content": "<p>x</p>"]
        let email = try GraphMessageMapper.map(data(json), accountID: accountID)
        XCTAssertEqual(email.htmlBody, "<p>x</p>")
        XCTAssertNil(email.textBody)
    }

    func testAttachmentMapperKeepsMetadataOnly() {
        let mapped = GraphMessageMapper.mapAttachments([
            GraphAttachment(name: " report.docx ", contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", size: 42, isInline: nil),
            GraphAttachment(name: nil, contentType: nil, size: nil, isInline: false),
            GraphAttachment(name: "inline.gif", contentType: "image/gif", size: 1, isInline: true),
        ])
        XCTAssertEqual(mapped, [
            EmailAttachment(filename: "report.docx", mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", sizeBytes: 42),
            EmailAttachment(filename: "", mimeType: nil, sizeBytes: nil),
        ])
    }

    // MARK: - Dates

    func testGraphDateParsesAllFractionalVariants() throws {
        let expected = Date(timeIntervalSince1970: 1_789_982_130)
        XCTAssertEqual(try XCTUnwrap(GraphDate.parse("2026-09-21T09:15:30Z")).timeIntervalSince1970, expected.timeIntervalSince1970, accuracy: 0.0005)
        XCTAssertEqual(try XCTUnwrap(GraphDate.parse("2026-09-21T09:15:30.1234567Z")).timeIntervalSince1970, expected.timeIntervalSince1970 + 0.123, accuracy: 0.0005)
        XCTAssertEqual(try XCTUnwrap(GraphDate.parse("2026-09-21T09:15:30.5Z")).timeIntervalSince1970, expected.timeIntervalSince1970 + 0.5, accuracy: 0.0005)
        XCTAssertEqual(try XCTUnwrap(GraphDate.parse("2026-09-21T09:15:30.25Z")).timeIntervalSince1970, expected.timeIntervalSince1970 + 0.25, accuracy: 0.0005)
        XCTAssertEqual(try XCTUnwrap(GraphDate.parse("2026-09-21T09:15:30.000Z")).timeIntervalSince1970, expected.timeIntervalSince1970, accuracy: 0.0005)
        XCTAssertEqual(try XCTUnwrap(GraphDate.parse("2026-09-21T11:15:30+02:00")).timeIntervalSince1970, expected.timeIntervalSince1970, accuracy: 0.0005)
        XCTAssertEqual(try XCTUnwrap(GraphDate.parse(" 2026-09-21T09:15:30.9999999Z ")).timeIntervalSince1970, expected.timeIntervalSince1970 + 0.999, accuracy: 0.0005)
        XCTAssertNil(GraphDate.parse(""))
        XCTAssertNil(GraphDate.parse("yesterday"))
        XCTAssertNil(GraphDate.parse("2026-09-21"))
    }

    func testGraphDateFormatsUTCWithMilliseconds() {
        let date = Date(timeIntervalSince1970: 1_789_982_130.25)
        XCTAssertEqual(GraphDate.string(from: date), "2026-09-21T09:15:30.250Z")
        XCTAssertEqual(GraphDate.parse(GraphDate.string(from: date))?.timeIntervalSince1970 ?? 0, date.timeIntervalSince1970, accuracy: 0.0005)
    }

    func testDecoderRejectsUnparseableDates() {
        let json: [String: Any] = ["id": "AAMk8", "receivedDateTime": "not-a-date"]
        XCTAssertThrowsError(try GraphMessageMapper.map(try data(json), accountID: accountID))
    }
}

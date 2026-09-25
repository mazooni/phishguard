import PhishCore
import XCTest
@testable import PhishGuard

final class GmailPayloadParserTests: XCTestCase {
    private let accountID = UUID()

    private func parse(_ object: [String: Any]) throws -> EmailMessage {
        try GmailPayloadParser.parseMessage(GmailFixtures.data(object), accountID: accountID)
    }

    // MARK: - Fixtures

    func testPlainTextMessage() throws {
        let headers = GmailFixtures.standardHeaders(
            from: "\"Doe, John\" <John@Example.com>",
            to: "a@x.com, Bob <bob@y.org>",
            subject: "  Invoice attached  ",
            extra: [
                GmailFixtures.header("Reply-To", "billing@evil.example"),
                GmailFixtures.header("Sender", "list@example.net"),
                GmailFixtures.header("Authentication-Results", "mx.google.com; spf=pass"),
            ]
        )
        let object = GmailFixtures.message(
            id: "m-plain",
            threadId: "thread-9",
            internalDate: 1_700_000_000_123,
            headers: headers,
            payload: GmailFixtures.part(mimeType: "text/plain", text: "Please pay now.\n", headers: [GmailFixtures.header("Content-Type", "text/plain; charset=\"UTF-8\"")])
        )

        let email = try parse(object)

        XCTAssertEqual(email.provider, .gmail)
        XCTAssertEqual(email.accountID, accountID.uuidString)
        XCTAssertEqual(email.messageID, "m-plain")
        XCTAssertEqual(email.threadID, "thread-9")
        XCTAssertEqual(email.receivedAt.timeIntervalSince1970, 1_700_000_000.123, accuracy: 0.001)
        XCTAssertEqual(email.from, EmailAddress(name: "Doe, John", address: "john@example.com"))
        XCTAssertEqual(email.sender?.address, "list@example.net")
        XCTAssertEqual(email.replyTo.map(\.address), ["billing@evil.example"])
        XCTAssertEqual(email.to.map(\.address), ["a@x.com", "bob@y.org"])
        XCTAssertEqual(email.subject, "Invoice attached")
        XCTAssertEqual(email.textBody, "Please pay now.\n")
        XCTAssertNil(email.htmlBody)
        XCTAssertTrue(email.attachments.isEmpty)
        XCTAssertEqual(email.headers.map(\.name), ["From", "To", "Subject", "Date", "Message-ID", "Reply-To", "Sender", "Authentication-Results"], "all headers in original order")
        XCTAssertEqual(email.header("authentication-results"), "mx.google.com; spf=pass")
        XCTAssertEqual(email.webLink?.absoluteString, "https://mail.google.com/mail/u/0/#search/rfc822msgid:abc123@mail.example.com")
    }

    func testMultipartAlternativeCapturesBothBodies() throws {
        let payload = GmailFixtures.multipart("multipart/alternative", parts: [
            GmailFixtures.part(mimeType: "text/plain", text: "plain version"),
            GmailFixtures.part(mimeType: "text/html", text: "<p>html <b>version</b></p>"),
        ])
        let email = try parse(GmailFixtures.message(id: "m-alt", headers: GmailFixtures.standardHeaders(), payload: payload))

        XCTAssertEqual(email.textBody, "plain version")
        XCTAssertEqual(email.htmlBody, "<p>html <b>version</b></p>")
        XCTAssertTrue(email.attachments.isEmpty)
    }

    func testNestedMixedWithAttachments() throws {
        let alternative = GmailFixtures.multipart("multipart/alternative", parts: [
            GmailFixtures.part(mimeType: "text/plain", text: "See attachment"),
            GmailFixtures.part(mimeType: "text/html", text: "<p>See attachment</p>"),
        ])
        let related = GmailFixtures.multipart("multipart/related", parts: [
            alternative,
            GmailFixtures.part(mimeType: "image/png", filename: "logo.png", headers: [GmailFixtures.header("Content-Disposition", "inline; filename=\"logo.png\"")], attachmentId: "att-1", size: 2048),
        ])
        let payload = GmailFixtures.multipart("multipart/mixed", parts: [
            related,
            GmailFixtures.part(mimeType: "application/pdf", filename: "invoice.pdf", headers: [GmailFixtures.header("Content-Disposition", "attachment; filename=\"invoice.pdf\"")], attachmentId: "att-2", size: 90_000),
            // No `filename` field but an attachment disposition: still an attachment, name from the header.
            GmailFixtures.part(mimeType: "application/octet-stream", headers: [GmailFixtures.header("Content-Disposition", "attachment; filename=payload.exe")], attachmentId: "att-3", size: 5),
            // A text part with a filename is an attachment, not a body.
            GmailFixtures.part(mimeType: "text/plain", text: "not the body", filename: "notes.txt"),
        ])
        let email = try parse(GmailFixtures.message(id: "m-mixed", headers: GmailFixtures.standardHeaders(), payload: payload))

        XCTAssertEqual(email.textBody, "See attachment")
        XCTAssertEqual(email.htmlBody, "<p>See attachment</p>")
        XCTAssertEqual(email.attachments, [
            EmailAttachment(filename: "logo.png", mimeType: "image/png", sizeBytes: 2048),
            EmailAttachment(filename: "invoice.pdf", mimeType: "application/pdf", sizeBytes: 90_000),
            EmailAttachment(filename: "payload.exe", mimeType: "application/octet-stream", sizeBytes: 5),
            EmailAttachment(filename: "notes.txt", mimeType: "text/plain", sizeBytes: 12),
        ])
        XCTAssertEqual(email.attachments.map(\.fileExtension), ["png", "pdf", "exe", "txt"])
    }

    func testMixedWithSeveralTextPartsConcatenates() throws {
        let payload = GmailFixtures.multipart("multipart/mixed", parts: [
            GmailFixtures.part(mimeType: "text/plain", text: "first"),
            GmailFixtures.part(mimeType: "text/plain", text: "second"),
        ])
        let email = try parse(GmailFixtures.message(id: "m-two", headers: GmailFixtures.standardHeaders(), payload: payload))
        XCTAssertEqual(email.textBody, "first\n\nsecond")
    }

    func testHTMLOnlyMessage() throws {
        let payload = GmailFixtures.part(mimeType: "text/html", text: "<html><body><a href=\"http://evil.example\">Login</a></body></html>", headers: [GmailFixtures.header("Content-Type", "text/html; charset=utf-8")])
        let email = try parse(GmailFixtures.message(id: "m-html", headers: GmailFixtures.standardHeaders(), payload: payload))

        XCTAssertNil(email.textBody)
        XCTAssertEqual(email.htmlBody, "<html><body><a href=\"http://evil.example\">Login</a></body></html>")
    }

    func testForwardedRFC822PartIsWalked() throws {
        let inner = GmailFixtures.part(mimeType: "message/rfc822", parts: [
            GmailFixtures.part(mimeType: "text/plain", text: "forwarded body"),
        ])
        let payload = GmailFixtures.multipart("multipart/mixed", parts: [
            GmailFixtures.part(mimeType: "text/plain", text: "outer body"),
            inner,
        ])
        let email = try parse(GmailFixtures.message(id: "m-fwd", headers: GmailFixtures.standardHeaders(), payload: payload))
        XCTAssertEqual(email.textBody, "outer body\n\nforwarded body")
    }

    // MARK: - base64url

    func testBase64URLDecoding() {
        XCTAssertEqual(GmailPayloadParser.decodeBase64URL("aGVsbG8"), Data("hello".utf8), "unpadded")
        XCTAssertEqual(GmailPayloadParser.decodeBase64URL("aGVsbG8="), Data("hello".utf8), "standard padding tolerated")
        XCTAssertEqual(GmailPayloadParser.decodeBase64URL("aGVs\nbG8"), Data("hello".utf8), "whitespace ignored")
        XCTAssertEqual(GmailPayloadParser.decodeBase64URL(""), Data(), "empty")
        XCTAssertNil(GmailPayloadParser.decodeBase64URL("a"), "impossible length")
        XCTAssertNil(GmailPayloadParser.decodeBase64URL("@@@@"), "invalid alphabet")

        // Bytes that hit the url-safe alphabet: 0xFB 0xFF → "-_8" in base64url ("+/8=" in base64).
        let bytes = Data([0xFB, 0xFF])
        XCTAssertEqual(GmailFixtures.base64URL(bytes), "-_8")
        XCTAssertEqual(GmailPayloadParser.decodeBase64URL("-_8"), bytes)
        XCTAssertEqual(GmailPayloadParser.decodeBase64URL("+/8="), bytes)
    }

    func testTextDecodingFallsBackFromUTF8() {
        XCTAssertEqual(GmailPayloadParser.decodeText(Data("héllo".utf8), charset: nil), "héllo")
        XCTAssertEqual(GmailPayloadParser.decodeText(Data([0x68, 0xE9]), charset: nil), "hé", "ISO-8859-1 fallback for invalid UTF-8")
        XCTAssertEqual(GmailPayloadParser.decodeText(Data([0x80]), charset: "windows-1252"), "€", "declared charset wins over ISO-8859-1")
        XCTAssertEqual(GmailPayloadParser.decodeText(Data([0x80]), charset: "unknown-charset"), "\u{80}", "unknown charset → ISO-8859-1")
        XCTAssertEqual(GmailPayloadParser.decodeText(Data("héllo".utf8), charset: "iso-8859-1"), "héllo", "valid UTF-8 wins over a mislabelled 8-bit charset")
    }

    func testSevenBitStatefulCharsetsUseTheDeclaredEncoding() {
        // "こんにちは" in ISO-2022-JP: pure ASCII bytes with ESC sequences, hence always valid UTF-8.
        let iso2022jp = Data([0x1B, 0x24, 0x42, 0x24, 0x33, 0x24, 0x73, 0x24, 0x4B, 0x24, 0x41, 0x24, 0x4F, 0x1B, 0x28, 0x42])
        XCTAssertEqual(GmailPayloadParser.decodeText(iso2022jp, charset: "iso-2022-jp"), "こんにちは", "7-bit ISO-2022-JP must use the declared charset, not UTF-8")
        XCTAssertEqual(GmailPayloadParser.decodeText(iso2022jp, charset: "ISO-2022-JP"), "こんにちは")
        XCTAssertEqual(GmailPayloadParser.decodeText(Data("こんにちは".utf8), charset: "iso-2022-jp"), "こんにちは", "a body already converted to UTF-8 has no ESC and keeps the UTF-8 path")
        XCTAssertEqual(GmailPayloadParser.decodeText(Data("plain ascii".utf8), charset: "iso-2022-jp"), "plain ascii")
        XCTAssertTrue(GmailPayloadParser.isSevenBitStateful(charset: "ISO-2022-KR"))
        XCTAssertTrue(GmailPayloadParser.isSevenBitStateful(charset: "hz-gb-2312"))
        XCTAssertFalse(GmailPayloadParser.isSevenBitStateful(charset: "iso-8859-1"))
        XCTAssertFalse(GmailPayloadParser.isSevenBitStateful(charset: "utf-8"))
        XCTAssertTrue(GmailPayloadParser.containsEscapeMarker(Data("~{abc~}".utf8), charset: "hz-gb-2312"))
        XCTAssertFalse(GmailPayloadParser.containsEscapeMarker(Data("no marker".utf8), charset: "hz-gb-2312"))
    }

    func testISO2022JPBodyDecodesThroughParser() throws {
        let iso2022jp = Data([0x1B, 0x24, 0x42, 0x24, 0x33, 0x24, 0x73, 0x24, 0x4B, 0x24, 0x41, 0x24, 0x4F, 0x1B, 0x28, 0x42])
        // A single-part message: the top-level part's headers ARE the message headers, including Content-Type.
        let payload = GmailFixtures.part(mimeType: "text/plain", rawData: GmailFixtures.base64URL(iso2022jp))
        let headers = GmailFixtures.standardHeaders(extra: [GmailFixtures.header("Content-Type", "text/plain; charset=ISO-2022-JP")])
        let email = try parse(GmailFixtures.message(id: "m-jp", headers: headers, payload: payload))
        XCTAssertEqual(email.textBody, "こんにちは")
        XCTAssertEqual(GmailPayloadParser.charset(fromContentType: "text/plain; charset=\"ISO-8859-1\"; format=flowed"), "ISO-8859-1")
        XCTAssertEqual(GmailPayloadParser.charset(fromContentType: "text/plain; CHARSET=utf-8"), "utf-8")
        XCTAssertNil(GmailPayloadParser.charset(fromContentType: "text/plain"))
    }

    func testLatin1BodyDecodesThroughParser() throws {
        let latin1 = Data([0x50, 0x72, 0x69, 0x78, 0x20, 0xE9, 0x6C, 0x65, 0x76, 0xE9]) // "Prix élevé" in ISO-8859-1
        let payload = GmailFixtures.part(mimeType: "text/plain", rawData: GmailFixtures.base64URL(latin1), headers: [GmailFixtures.header("Content-Type", "text/plain; charset=iso-8859-1")])
        let email = try parse(GmailFixtures.message(id: "m-latin1", headers: GmailFixtures.standardHeaders(), payload: payload))
        XCTAssertEqual(email.textBody, "Prix élevé")
    }

    func testEmptyAndUndecodableBodiesAreIgnored() throws {
        let payload = GmailFixtures.multipart("multipart/alternative", parts: [
            GmailFixtures.part(mimeType: "text/plain", rawData: ""),
            GmailFixtures.part(mimeType: "text/html", rawData: "!!!!"),
        ])
        let email = try parse(GmailFixtures.message(id: "m-empty", headers: GmailFixtures.standardHeaders(), payload: payload))
        XCTAssertNil(email.textBody)
        XCTAssertNil(email.htmlBody)
    }

    // MARK: - Headers, dates, links

    func testMissingHeadersAndDates() throws {
        let before = Date()
        let object = GmailFixtures.message(id: "m-bare", threadId: nil, internalDate: nil, headers: [], payload: GmailFixtures.part(mimeType: "text/plain", text: "x"))
        let email = try parse(object)

        XCTAssertNil(email.threadID)
        XCTAssertNil(email.from)
        XCTAssertNil(email.sender)
        XCTAssertTrue(email.replyTo.isEmpty)
        XCTAssertTrue(email.to.isEmpty)
        XCTAssertEqual(email.subject, "")
        XCTAssertTrue(email.headers.isEmpty)
        XCTAssertGreaterThanOrEqual(email.receivedAt, before, "falls back to now")
        XCTAssertEqual(email.webLink?.absoluteString, "https://mail.google.com/mail/u/0/#all/m-bare", "no Message-ID → #all/<id>")
    }

    func testDateHeaderFallbackWhenInternalDateMissing() throws {
        let object = GmailFixtures.message(
            id: "m-date",
            internalDate: nil,
            headers: [GmailFixtures.header("Date", "Tue, 14 Nov 2023 22:13:20 +0000 (UTC)")],
            payload: GmailFixtures.part(mimeType: "text/plain", text: "x")
        )
        XCTAssertEqual(try parse(object).receivedAt.timeIntervalSince1970, 1_700_000_000, accuracy: 0.5)
        XCTAssertNil(GmailPayloadParser.parseRFC5322Date("not a date"))
    }

    func testMessageIDLinkStripsBracketsAndEncodes() {
        XCTAssertEqual(
            GmailPayloadParser.webLink(messageID: "id1", rfc822MessageID: " <abc123@mail.example.com> ")?.absoluteString,
            "https://mail.google.com/mail/u/0/#search/rfc822msgid:abc123@mail.example.com"
        )
        XCTAssertEqual(
            GmailPayloadParser.webLink(messageID: "id1", rfc822MessageID: "<CA+x/y z@mail.gmail.com>")?.absoluteString,
            "https://mail.google.com/mail/u/0/#search/rfc822msgid:CA+x%2Fy%20z@mail.gmail.com"
        )
        XCTAssertEqual(GmailPayloadParser.webLink(messageID: "id1", rfc822MessageID: "<>")?.absoluteString, "https://mail.google.com/mail/u/0/#all/id1")
        XCTAssertEqual(GmailPayloadParser.webLink(messageID: "id1", rfc822MessageID: nil)?.absoluteString, "https://mail.google.com/mail/u/0/#all/id1")
    }

    func testMultipleToAndReplyToHeadersAreMerged() throws {
        let headers = [
            GmailFixtures.header("To", "a@x.com"),
            GmailFixtures.header("To", "b@x.com"),
            GmailFixtures.header("Reply-To", "r1@x.com, r2@x.com"),
        ]
        let email = try parse(GmailFixtures.message(id: "m-to", headers: headers, payload: GmailFixtures.part(mimeType: "text/plain", text: "x")))
        XCTAssertEqual(email.to.map(\.address), ["a@x.com", "b@x.com"])
        XCTAssertEqual(email.replyTo.map(\.address), ["r1@x.com", "r2@x.com"])
    }

    func testInvalidJSONThrowsDecodingError() async {
        await assertThrowsProviderError("decoding", { if case .decoding = $0 { return true }; return false }) {
            _ = try GmailPayloadParser.parseMessage(Data("{\"nope\": true}".utf8), accountID: accountID)
        }
    }

    func testInt64FieldsAcceptStringsAndNumbers() throws {
        let decoder = JSONDecoder()
        let fromString = try decoder.decode(GmailWatchResponse.self, from: Data("{\"expiration\": \"1700000000000\"}".utf8))
        XCTAssertEqual(fromString.expiration.int64Value, 1_700_000_000_000)
        let fromNumber = try decoder.decode(GmailWatchResponse.self, from: Data("{\"expiration\": 1700000000000}".utf8))
        XCTAssertEqual(fromNumber.expiration.int64Value, 1_700_000_000_000)
    }
}

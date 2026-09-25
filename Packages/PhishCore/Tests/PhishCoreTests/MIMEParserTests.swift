import Foundation
import XCTest
@testable import PhishCore

/// `MIMEParser` parses untrusted bytes, so these tests are split in three: the RFC behaviour it must get right,
/// the real messages Apple Mail / Gmail / Yahoo actually emit, and the hostile input it must survive.
final class MIMEParserTests: XCTestCase {
    // MARK: - Helpers

    private let fixedDate = Date(timeIntervalSince1970: 1_700_000_000)

    private func raw(_ lines: [String]) -> Data {
        Data(lines.joined(separator: "\r\n").utf8)
    }

    private func parse(
        _ data: Data,
        receivedAt: Date? = nil,
        provider: MailProvider = .gmail
    ) throws -> EmailMessage {
        if let receivedAt {
            return try MIMEParser.parse(
                rfc822: data,
                provider: provider,
                accountID: "account-1",
                messageID: "uid-42",
                receivedAt: receivedAt
            )
        }
        return try MIMEParser.parse(
            rfc822: data,
            provider: provider,
            accountID: "account-1",
            messageID: "uid-42",
            receivedAt: fixedDate
        )
    }

    private func encoding(_ charset: String) -> String.Encoding {
        let cf = CFStringConvertIANACharSetNameToEncoding(charset as CFString)
        XCTAssertNotEqual(cf, kCFStringEncodingInvalidId, "no encoding for \(charset)")
        return String.Encoding(rawValue: CFStringConvertEncodingToNSStringEncoding(cf))
    }

    private func encodedWord(_ text: String, charset: String) -> String {
        let data = text.data(using: encoding(charset)) ?? Data()
        return "=?\(charset)?B?\(data.base64EncodedString())?="
    }

    // MARK: - Header block

    func testUnfoldsContinuationLines() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Subject: a very long subject that the",
            "\tsender folded across",
            "  three lines",
            "",
            "body",
        ]))
        XCTAssertEqual(email.subject, "a very long subject that the sender folded across three lines")
    }

    func testHeaderNamesAreCaseInsensitiveAndDuplicatesKeepOrder() throws {
        let email = try parse(raw([
            "Received: from mx1.example.com",
            "received: from mx2.example.com",
            "RECEIVED: from mx3.example.com",
            "From: a@example.com",
            "",
            "body",
        ]))
        XCTAssertEqual(email.headers("Received"), [
            "from mx1.example.com", "from mx2.example.com", "from mx3.example.com",
        ])
        XCTAssertEqual(email.header("received"), "from mx1.example.com")
    }

    func testMalformedHeaderLinesAreSkippedNotFatal() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "this line has no colon at all",
            ": empty name",
            "Bad Name With Spaces: value",
            "Subject: still parsed",
            "",
            "body",
        ]))
        XCTAssertEqual(email.subject, "still parsed")
        XCTAssertEqual(email.from?.address, "a@example.com")
        XCTAssertNil(email.header("Bad Name With Spaces"))
        XCTAssertEqual(email.textBody, "body")
    }

    func testHeaderNameWithSpaceBeforeColonIsAccepted() throws {
        let email = try parse(raw(["Subject : spaced", "", "body"]))
        XCTAssertEqual(email.subject, "spaced")
    }

    func testMboxFromLineIsIgnored() throws {
        let email = try parse(raw([
            "From alice@example.com Mon Sep 22 10:00:00 2026",
            "From: Alice <alice@example.com>",
            "Subject: exported",
            "",
            "body",
        ]))
        XCTAssertEqual(email.subject, "exported")
        XCTAssertEqual(email.from?.address, "alice@example.com")
    }

    func testHeaderCountIsCapped() throws {
        var lines = ["From: a@example.com"]
        for index in 0..<3_000 { lines.append("X-Spam-\(index): \(index)") }
        lines.append(contentsOf: ["", "body"])
        let email = try parse(raw(lines))
        XCTAssertEqual(email.headers.count, MIMEParser.Limits.maxHeaderCount)
    }

    func testHeaderValueLengthIsCapped() throws {
        let long = String(repeating: "x", count: 100_000)
        let email = try parse(raw(["X-Long: \(long)", "From: a@example.com", "", "body"]))
        XCTAssertEqual(email.header("X-Long")?.count, MIMEParser.Limits.maxHeaderValueCharacters)
    }

    func testParseHeadersStopsAtBlankLine() throws {
        let headers = try MIMEParser.parseHeaders(raw([
            "From: a@example.com",
            "Subject: peek",
            "",
            "Subject: this is body text, not a header",
        ]))
        XCTAssertEqual(headers.count, 2)
        XCTAssertEqual(headers.last?.value, "peek")
    }

    func testParseHeadersOnEmptyDataReturnsNoHeaders() throws {
        XCTAssertEqual(try MIMEParser.parseHeaders(Data()), [])
        XCTAssertEqual(try MIMEParser.parseHeaders(Data("\r\n".utf8)), [])
    }

    func testParseHeadersThrowsOnGarbage() {
        XCTAssertThrowsError(try MIMEParser.parseHeaders(Data([0x00, 0xFF, 0xFE, 0x01, 0x02]))) { error in
            XCTAssertEqual(error as? MIMEParserError, .malformedHeaders)
        }
    }

    func testEightBitHeaderBytesDecodeAsUTF8() throws {
        var data = Data("Subject: ".utf8)
        data.append(contentsOf: Array("café ☕".utf8))
        data.append(contentsOf: Array("\r\nFrom: a@example.com\r\n\r\nbody".utf8))
        let email = try parse(data)
        XCTAssertEqual(email.subject, "café ☕")
    }

    // MARK: - RFC 2047 encoded-words

    func testDecodesBase64EncodedWord() {
        XCTAssertEqual(MIMEParser.decodeEncodedWords("=?UTF-8?B?SGVsbG8gd29ybGQ=?="), "Hello world")
    }

    func testDecodesQEncodedWordWithUnderscoreAndHex() {
        XCTAssertEqual(MIMEParser.decodeEncodedWords("=?utf-8?Q?Caf=C3=A9_time?="), "Café time")
    }

    func testAdjacentEncodedWordsJoinWithoutTheInterveningSpace() {
        let value = "=?UTF-8?B?SGVsbG8g?= =?UTF-8?B?d29ybGQ=?="
        XCTAssertEqual(MIMEParser.decodeEncodedWords(value), "Hello world")
    }

    func testAdjacentEncodedWordsSplittingAMultiByteCharacter() {
        // "é" is C3 A9; the sender split it across two words, which only works if bytes are joined before decoding.
        let value = "=?utf-8?Q?Caf=C3?= =?utf-8?Q?=A9?="
        XCTAssertEqual(MIMEParser.decodeEncodedWords(value), "Café")
    }

    func testWhitespaceAroundPlainTextIsPreserved() {
        let value = "Re: =?UTF-8?B?SGVsbG8=?= from =?UTF-8?B?d29ybGQ=?= now"
        XCTAssertEqual(MIMEParser.decodeEncodedWords(value), "Re: Hello from world now")
    }

    func testEncodedWordWithLanguageTag() {
        XCTAssertEqual(MIMEParser.decodeEncodedWords("=?utf-8*en?B?SGk=?="), "Hi")
    }

    func testEncodedWordCharsets() {
        XCTAssertEqual(MIMEParser.decodeEncodedWords(encodedWord("Grüße", charset: "iso-8859-1")), "Grüße")
        XCTAssertEqual(MIMEParser.decodeEncodedWords(encodedWord("Prix 5€", charset: "iso-8859-15")), "Prix 5€")
        XCTAssertEqual(MIMEParser.decodeEncodedWords(encodedWord("“smart”", charset: "windows-1252")), "“smart”")
        XCTAssertEqual(MIMEParser.decodeEncodedWords(encodedWord("日本語", charset: "iso-2022-jp")), "日本語")
        XCTAssertEqual(MIMEParser.decodeEncodedWords(encodedWord("中文测试", charset: "gb2312")), "中文测试")
        XCTAssertEqual(MIMEParser.decodeEncodedWords(encodedWord("简体中文", charset: "gbk")), "简体中文")
        XCTAssertEqual(MIMEParser.decodeEncodedWords(encodedWord("日本語テスト", charset: "shift_jis")), "日本語テスト")
        XCTAssertEqual(MIMEParser.decodeEncodedWords(encodedWord("Привет", charset: "koi8-r")), "Привет")
        XCTAssertEqual(MIMEParser.decodeEncodedWords(encodedWord("繁體中文", charset: "big5")), "繁體中文")
    }

    func testUndecodableEncodedWordsPassThroughVerbatim() {
        // Unknown charset.
        XCTAssertEqual(MIMEParser.decodeEncodedWords("=?x-martian?B?SGk=?="), "=?x-martian?B?SGk=?=")
        // Broken base64.
        XCTAssertEqual(MIMEParser.decodeEncodedWords("=?utf-8?B?not!base64!?="), "=?utf-8?B?not!base64!?=")
        // Never terminated.
        XCTAssertEqual(MIMEParser.decodeEncodedWords("=?utf-8?B?SGk="), "=?utf-8?B?SGk=")
        // Not an encoded word at all.
        XCTAssertEqual(MIMEParser.decodeEncodedWords("2 =? 3 and =?=?=?"), "2 =? 3 and =?=?=?")
        // Unknown encoding letter.
        XCTAssertEqual(MIMEParser.decodeEncodedWords("=?utf-8?X?SGk=?="), "=?utf-8?X?SGk=?=")
    }

    func testEncodedWordsInAddressDisplayNames() throws {
        let email = try parse(raw([
            "From: =?UTF-8?B?QW5uYSBNw7xsbGVy?= <anna@example.de>",
            "To: =?utf-8?Q?Jos=C3=A9?= <jose@example.es>, plain@example.com",
            "Sender: =?utf-8?Q?Bounce?= <bounce@example.de>",
            "Reply-To: =?utf-8?Q?Support?= <support@example.de>",
            "Subject: =?UTF-8?B?UsOoZ2xlbWVudA==?=",
            "",
            "body",
        ]))
        XCTAssertEqual(email.from, EmailAddress(name: "Anna Müller", address: "anna@example.de"))
        XCTAssertEqual(email.to.map(\.address), ["jose@example.es", "plain@example.com"])
        XCTAssertEqual(email.to.first?.name, "José")
        XCTAssertEqual(email.sender?.name, "Bounce")
        XCTAssertEqual(email.replyTo.first?.address, "support@example.de")
        XCTAssertEqual(email.subject, "Règlement")
    }

    func testEncodedWordCannotInjectAddressSyntax() throws {
        // The encoded word decodes to `"PayPal Service" <service@paypal.com>`. If the header were decoded before
        // the address grammar was applied, that fake mailbox would become `from`.
        let spoof = encodedWord("\"PayPal Service\" <service@paypal.com>", charset: "utf-8")
        let email = try parse(raw([
            "From: \(spoof) <attacker@evil.example>",
            "To: \(encodedWord("victim@example.com, extra@evil.example", charset: "utf-8")) <victim@example.com>",
            "",
            "body",
        ]))
        XCTAssertEqual(email.from?.address, "attacker@evil.example")
        XCTAssertEqual(email.from?.name, "\"PayPal Service\" <service@paypal.com>")
        XCTAssertEqual(email.to.map(\.address), ["victim@example.com"])
    }

    func testHeadersKeepTheirWireFormWhileSubjectIsDecoded() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Subject: =?UTF-8?B?SGVsbG8=?=",
            "",
            "body",
        ]))
        XCTAssertEqual(email.subject, "Hello")
        XCTAssertEqual(email.header("Subject"), "=?UTF-8?B?SGVsbG8=?=")
    }

    // MARK: - Bodies and transfer encodings

    func testBase64Body() throws {
        let body = Data("Base64 body ☕".utf8).base64EncodedString()
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: text/plain; charset=utf-8",
            "Content-Transfer-Encoding: base64",
            "",
            body,
        ]))
        XCTAssertEqual(email.textBody, "Base64 body ☕")
    }

    func testQuotedPrintableBodyWithSoftBreaksAndTrailingWhitespace() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: text/plain; charset=utf-8",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "Hello =",
            "world caf=C3=A9   ",
            "second line=",
        ]))
        XCTAssertEqual(email.textBody, "Hello world café\r\nsecond line")
    }

    func testSevenBitAndBinaryBodiesArePassedThrough() throws {
        for encoding in ["7bit", "8bit", "binary", ""] {
            let email = try parse(raw([
                "From: a@example.com",
                "Content-Transfer-Encoding: \(encoding)",
                "",
                "plain text",
            ]))
            XCTAssertEqual(email.textBody, "plain text", "encoding \(encoding)")
        }
    }

    func testUnknownTransferEncodingFallsBackToRawBytes() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Transfer-Encoding: x-uuencode",
            "",
            "still readable",
        ]))
        XCTAssertEqual(email.textBody, "still readable")
    }

    func testDecodeTransferEncodedThrowsForUnsupportedEncoding() {
        XCTAssertThrowsError(
            try MIMEParser.decodeTransferEncoded(Data("x".utf8), contentTransferEncoding: "uuencode")
        ) { error in
            XCTAssertEqual(error as? MIMEParserError, .unsupportedEncoding("uuencode"))
        }
        XCTAssertEqual(
            try? MIMEParser.decodeTransferEncoded(Data("SGk=".utf8), contentTransferEncoding: " BASE64 "),
            Data("Hi".utf8)
        )
    }

    func testWindows1252BodyMislabelledAsUTF8() throws {
        var data = Data(raw([
            "From: billing@example.com",
            "Content-Type: text/plain; charset=\"utf-8\"",
            "",
            "",
        ]))
        // 0x92 is a right single quote in windows-1252 and invalid UTF-8; 0x93/0x94 are smart double quotes.
        data.append(contentsOf: Array("Your account".utf8))
        data.append(0x92)
        data.append(contentsOf: Array("s ".utf8))
        data.append(0x93)
        data.append(contentsOf: Array("invoice".utf8))
        data.append(0x94)
        data.append(contentsOf: Array(" is ready".utf8))

        let email = try parse(data)
        XCTAssertEqual(email.textBody, "Your account’s “invoice” is ready")
    }

    func testDeclaredLatin1BodyWithWindows1252Bytes() throws {
        var data = Data(raw([
            "From: a@example.com",
            "Content-Type: text/plain; charset=iso-8859-1",
            "",
            "",
        ]))
        data.append(contentsOf: Array("Gr".utf8))
        data.append(0xFC)                                   // ü in both latin-1 and cp1252
        data.append(contentsOf: Array("\u{DF}e ".utf8.map { $0 }))
        data.append(0x80)                                   // € in cp1252, undefined in latin-1
        let email = try parse(data)
        XCTAssertEqual(email.textBody?.contains("ü"), true)
        XCTAssertEqual(email.textBody?.contains("€"), true)
    }

    func testISO2022JPBodyIsDecodedDespiteBeingValidUTF8() throws {
        var data = Data(raw([
            "From: a@example.jp",
            "Content-Type: text/plain; charset=ISO-2022-JP",
            "",
            "",
        ]))
        data.append("こんにちは".data(using: .iso2022JP)!)
        let email = try parse(data)
        XCTAssertEqual(email.textBody, "こんにちは")
    }

    func testShiftJISBodyDecodedFromDeclaredCharset() throws {
        var data = Data(raw([
            "From: a@example.jp",
            "Content-Type: text/plain; charset=Shift_JIS",
            "",
            "",
        ]))
        data.append("日本語テスト".data(using: encoding("shift_jis"))!)
        let email = try parse(data)
        XCTAssertEqual(email.textBody, "日本語テスト")
    }

    func testNulAndControlBytesAreStrippedFromText() throws {
        var data = Data(raw(["From: a@example.com", "", ""]))
        data.append(contentsOf: [0x48, 0x00, 0x69, 0x07, 0x21])   // "H\0i\a!"
        let email = try parse(data)
        XCTAssertEqual(email.textBody, "Hi!")
    }

    // MARK: - Multipart

    private func gmailStyleMessage() -> Data {
        raw([
            "Return-Path: <newsletter@shop.example>",
            "Received: by 2002:a05:6000 with SMTP id x1csp123;",
            "        Mon, 22 Sep 2026 03:14:15 -0700 (PDT)",
            "Authentication-Results: mx.google.com; dkim=pass header.d=shop.example; spf=pass",
            "Date: Mon, 22 Sep 2026 10:14:15 +0000",
            "From: Shop <newsletter@shop.example>",
            "To: user@gmail.com",
            "Message-ID: <CA+abc123@mail.gmail.com>",
            "Subject: Your receipt",
            "MIME-Version: 1.0",
            "Content-Type: multipart/alternative; boundary=\"000000000000a1b2c3\"",
            "",
            "--000000000000a1b2c3",
            "Content-Type: text/plain; charset=\"UTF-8\"",
            "",
            "Thanks for your order.",
            "",
            "--000000000000a1b2c3",
            "Content-Type: text/html; charset=\"UTF-8\"",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "<div dir=3D\"ltr\">Thanks for your <b>order</b>.</div>",
            "",
            "--000000000000a1b2c3--",
            "",
        ])
    }

    func testGmailMultipartAlternative() throws {
        let email = try parse(gmailStyleMessage())
        XCTAssertEqual(email.textBody, "Thanks for your order.")
        XCTAssertEqual(email.htmlBody, "<div dir=\"ltr\">Thanks for your <b>order</b>.</div>")
        XCTAssertTrue(email.attachments.isEmpty)
        XCTAssertEqual(email.from?.address, "newsletter@shop.example")
        XCTAssertEqual(email.threadID, "CA+abc123@mail.gmail.com")
        XCTAssertEqual(email.header("Authentication-Results")?.hasPrefix("mx.google.com"), true)
    }

    func testMultipartMixedWithAttachmentMetadataOnly() throws {
        let payload = Data(repeating: 0x41, count: 3_000).base64EncodedString()
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/mixed; boundary=outer",
            "",
            "--outer",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "See the attached invoice.",
            "",
            "--outer",
            "Content-Type: application/pdf; name=\"ignored.pdf\"",
            "Content-Disposition: attachment; filename=\"invoice.pdf\"",
            "Content-Transfer-Encoding: base64",
            "",
            payload,
            "--outer--",
        ]))
        XCTAssertEqual(email.textBody, "See the attached invoice.")
        XCTAssertEqual(email.attachments.count, 1)
        XCTAssertEqual(email.attachments[0].filename, "invoice.pdf")
        XCTAssertEqual(email.attachments[0].mimeType, "application/pdf")
        XCTAssertEqual(email.attachments[0].fileExtension, "pdf")
        // Size is counted from the base64, never decoded, so it lands within a few bytes of the real length.
        let size = try XCTUnwrap(email.attachments[0].sizeBytes)
        XCTAssertEqual(Double(size), 3_000, accuracy: 4)
        // The attachment content must not have leaked into a body.
        XCTAssertFalse(email.textBody?.contains("AAAA") ?? false)
        XCTAssertNil(email.htmlBody)
    }

    func testMultipartRelatedInlineImageWithoutFilename() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/related; boundary=rel",
            "",
            "--rel",
            "Content-Type: text/html; charset=utf-8",
            "",
            "<p>Hi <img src=\"cid:logo\"></p>",
            "",
            "--rel",
            "Content-Type: image/png",
            "Content-ID: <logo>",
            "Content-Transfer-Encoding: base64",
            "",
            "iVBORw0KGgo=",
            "--rel--",
        ]))
        XCTAssertEqual(email.htmlBody, "<p>Hi <img src=\"cid:logo\"></p>")
        XCTAssertEqual(email.attachments.count, 1)
        XCTAssertEqual(email.attachments[0].filename, "attachment.png")
        XCTAssertEqual(email.attachments[0].mimeType, "image/png")
    }

    func testNestedMultipartsThreeDeep() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Subject: nested",
            "Content-Type: multipart/mixed; boundary=L1",
            "",
            "preamble text that must be ignored",
            "--L1",
            "Content-Type: multipart/related; boundary=L2",
            "",
            "--L2",
            "Content-Type: multipart/alternative; boundary=L3",
            "",
            "--L3",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "deep plain",
            "--L3",
            "Content-Type: text/html; charset=utf-8",
            "",
            "<b>deep html</b>",
            "--L3--",
            "",
            "--L2",
            "Content-Type: image/gif",
            "Content-Disposition: inline; filename=\"pixel.gif\"",
            "",
            "GIF89a",
            "--L2--",
            "",
            "--L1",
            "Content-Type: application/zip",
            "Content-Disposition: attachment; filename=\"payload.zip\"",
            "",
            "PK",
            "--L1--",
            "epilogue that must be ignored",
        ]))
        XCTAssertEqual(email.textBody, "deep plain")
        XCTAssertEqual(email.htmlBody, "<b>deep html</b>")
        XCTAssertEqual(email.attachments.map(\.filename), ["pixel.gif", "payload.zip"])
        XCTAssertFalse(email.textBody?.contains("preamble") ?? false)
        XCTAssertFalse(email.textBody?.contains("epilogue") ?? false)
    }

    func testMissingFinalBoundaryStillYieldsTheLastPart() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/alternative; boundary=b",
            "",
            "--b",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "plain part",
            "--b",
            "Content-Type: text/html; charset=utf-8",
            "",
            "<p>truncated html part",
        ]))
        XCTAssertEqual(email.textBody, "plain part")
        XCTAssertEqual(email.htmlBody, "<p>truncated html part")
    }

    func testBoundaryLookalikeInsideBodyTextIsNotADelimiter() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/mixed; boundary=\"sep\"",
            "",
            "--sep",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "the string --sep appears mid-line here",
            "and \"--sep\" is quoted here",
            "--sep--",
        ]))
        XCTAssertEqual(
            email.textBody,
            "the string --sep appears mid-line here\r\nand \"--sep\" is quoted here"
        )
    }

    func testQuotedBoundaryParameterWithSpecialCharacters() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/mixed; boundary=\"----=_NextPart_000_0012; x\"",
            "",
            "------=_NextPart_000_0012; x",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "outlook style",
            "------=_NextPart_000_0012; x--",
        ]))
        XCTAssertEqual(email.textBody, "outlook style")
    }

    func testBase64EncodedMultipartIsStillSplit() throws {
        let inner = [
            "--inner",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "hidden inside base64",
            "--inner--",
        ].joined(separator: "\r\n")
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/mixed; boundary=inner",
            "Content-Transfer-Encoding: base64",
            "",
            Data(inner.utf8).base64EncodedString(),
        ]))
        XCTAssertEqual(email.textBody, "hidden inside base64")
    }

    func testMultipartWithoutBoundaryFallsBackToRawText() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/mixed",
            "",
            "nothing to split on",
        ]))
        XCTAssertEqual(email.textBody, "nothing to split on")
    }

    func testEmptyPartsAndBlankAlternativesAreIgnored() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/alternative; boundary=b",
            "",
            "--b",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "   ",
            "--b",
            "Content-Type: text/html; charset=utf-8",
            "",
            "<p>only html</p>",
            "--b--",
        ]))
        XCTAssertNil(email.textBody)
        XCTAssertEqual(email.htmlBody, "<p>only html</p>")
    }

    func testAttachedMessageIsRecordedAndWalked() throws {
        let email = try parse(raw([
            "From: reporter@example.com",
            "Subject: Fwd: suspicious mail",
            "Content-Type: multipart/mixed; boundary=fwd",
            "",
            "--fwd",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "Is this real?",
            "",
            "--fwd",
            "Content-Type: message/rfc822",
            "",
            "From: \"PayPal\" <service@paypa1-secure.example>",
            "Subject: Verify now",
            "Content-Type: text/html; charset=utf-8",
            "",
            "<a href=\"http://paypa1-secure.example/login\">Verify</a>",
            "--fwd--",
        ]))
        XCTAssertEqual(email.textBody, "Is this real?")
        XCTAssertEqual(email.htmlBody, "<a href=\"http://paypa1-secure.example/login\">Verify</a>")
        XCTAssertEqual(email.attachments.map(\.mimeType), ["message/rfc822"])
        XCTAssertEqual(email.attachments[0].filename, "message.eml")
        // The outer envelope still owns the identity used for classification.
        XCTAssertEqual(email.from?.address, "reporter@example.com")
    }

    func testInlineTextPartIsABodyButAttachmentDispositionIsNot() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/mixed; boundary=b",
            "",
            "--b",
            "Content-Type: text/plain; charset=utf-8",
            "Content-Disposition: inline",
            "",
            "the body",
            "--b",
            "Content-Type: text/plain; charset=utf-8",
            "Content-Disposition: attachment; filename=\"notes.txt\"",
            "",
            "attached notes, not the body",
            "--b--",
        ]))
        XCTAssertEqual(email.textBody, "the body")
        XCTAssertEqual(email.attachments.map(\.filename), ["notes.txt"])
        XCTAssertFalse(email.textBody?.contains("attached notes") ?? true)
    }

    func testUnrenderableTextSubtypeWithoutFilenameIsDropped() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/mixed; boundary=b",
            "",
            "--b",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "meeting request",
            "--b",
            "Content-Type: text/calendar; charset=utf-8; method=REQUEST",
            "",
            "BEGIN:VCALENDAR",
            "--b--",
        ]))
        XCTAssertEqual(email.textBody, "meeting request")
        XCTAssertTrue(email.attachments.isEmpty)
    }

    func testMultipartDigestDefaultsPartsToMessageRFC822() throws {
        let email = try parse(raw([
            "From: list@example.com",
            "Content-Type: multipart/digest; boundary=d",
            "",
            "--d",
            "",
            "From: member@example.com",
            "Subject: digest entry",
            "",
            "entry body",
            "--d--",
        ]))
        XCTAssertEqual(email.attachments.map(\.mimeType), ["message/rfc822"])
        XCTAssertEqual(email.textBody, "entry body")
    }

    func testOnlyTopLevelHeadersAreKept() throws {
        let email = try parse(gmailStyleMessage())
        XCTAssertNil(email.headers.first { $0.name.caseInsensitiveCompare("Content-Transfer-Encoding") == .orderedSame })
        XCTAssertEqual(email.headers("Content-Type").count, 1)
        XCTAssertEqual(email.header("Content-Type")?.hasPrefix("multipart/alternative"), true)
    }

    func testISO885915BodyIsDecodedFromTheDeclaredCharset() throws {
        var data = Data(raw([
            "From: a@example.fr",
            "Content-Type: text/plain; charset=ISO-8859-15",
            "",
            "",
        ]))
        data.append("Prix: 5€ pour l'œuvre".data(using: encoding("iso-8859-15"))!)
        let email = try parse(data)
        XCTAssertEqual(email.textBody, "Prix: 5€ pour l'œuvre")
    }

    func testAdjacentEncodedWordsWithDifferentCharsetsStillDropTheWhitespace() {
        let value = encodedWord("Grüße", charset: "iso-8859-1") + " " + encodedWord("日本", charset: "iso-2022-jp")
        XCTAssertEqual(MIMEParser.decodeEncodedWords(value), "Grüße日本")
    }

    func testEncodedWordAdjacentToPlainTextWithoutWhitespace() {
        XCTAssertEqual(MIMEParser.decodeEncodedWords("[=?utf-8?B?SGk=?=]"), "[Hi]")
    }

    func testRFC2231TrailingPercentIsNotConsumedPastTheEnd() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: application/pdf",
            "Content-Disposition: attachment; filename*=UTF-8''report%",
            "",
            "data",
        ]))
        XCTAssertEqual(email.attachments.map(\.filename), ["report%"])
    }

    func testBase64BodyToleratesWrappingAndPadding() throws {
        let encoded = Data("wrapped base64 body".utf8).base64EncodedString()
        let wrapped = stride(from: 0, to: encoded.count, by: 4).map { offset -> String in
            let start = encoded.index(encoded.startIndex, offsetBy: offset)
            let end = encoded.index(start, offsetBy: min(4, encoded.count - offset))
            return String(encoded[start..<end])
        }
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: text/plain; charset=utf-8",
            "Content-Transfer-Encoding: BASE64",
            "",
        ] + wrapped))
        XCTAssertEqual(email.textBody, "wrapped base64 body")
    }

    // MARK: - Attachment metadata

    func testFilenameFromContentTypeNameParameter() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: application/msword; name=report.doc",
            "",
            "content",
        ]))
        XCTAssertEqual(email.attachments.map(\.filename), ["report.doc"])
        XCTAssertNil(email.textBody)
    }

    func testFilenameFromRFC2231Continuations() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/mixed; boundary=b",
            "",
            "--b",
            "Content-Type: application/pdf",
            "Content-Disposition: attachment;",
            " filename*0=\"a-very-long-invoice-name-\";",
            " filename*1=\"part-two\";",
            " filename*2=\".pdf\"",
            "",
            "data",
            "--b--",
        ]))
        XCTAssertEqual(email.attachments.map(\.filename), ["a-very-long-invoice-name-part-two.pdf"])
    }

    func testFilenameFromRFC2231ExtendedValueWithCharset() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: application/pdf",
            "Content-Disposition: attachment; filename*=UTF-8''Fa%C3%A7ture%20%E2%82%AC.pdf",
            "",
            "data",
        ]))
        XCTAssertEqual(email.attachments.map(\.filename), ["Façture €.pdf"])
    }

    func testFilenameFromRFC2231ExtendedContinuations() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: application/pdf",
            "Content-Disposition: attachment; filename*0*=UTF-8''Re%C3%A7u; filename*1*=%2D2026.pdf",
            "",
            "data",
        ]))
        XCTAssertEqual(email.attachments.map(\.filename), ["Reçu-2026.pdf"])
    }

    func testFilenameWithRFC2047EncodedWord() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: application/pdf",
            "Content-Disposition: attachment; filename=\"=?utf-8?B?UsOoZ2xlbWVudC5wZGY=?=\"",
            "",
            "data",
        ]))
        XCTAssertEqual(email.attachments.map(\.filename), ["Règlement.pdf"])
    }

    func testHostileFilenameIsStrippedOfPathsAndBidiOverrides() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: multipart/mixed; boundary=b",
            "",
            "--b",
            "Content-Type: application/octet-stream",
            "Content-Disposition: attachment; filename=\"../../etc/passwd\"",
            "",
            "x",
            "--b",
            "Content-Type: application/octet-stream",
            "Content-Disposition: attachment; filename=\"invoice\u{202E}fdp.exe\"",
            "",
            "x",
            "--b--",
        ]))
        XCTAssertEqual(email.attachments.map(\.filename), ["passwd", "invoicefdp.exe"])
        XCTAssertEqual(email.attachments[1].fileExtension, "exe")
    }

    func testQuotedPrintableAttachmentSizeIsCountedNotDecoded() throws {
        let email = try parse(raw([
            "From: a@example.com",
            "Content-Type: application/octet-stream; name=blob.bin",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "=00=01=02ABC",
        ]))
        XCTAssertEqual(email.attachments.map(\.sizeBytes), [6])
    }

    func testAttachmentCountIsCapped() throws {
        var lines = [
            "From: a@example.com",
            "Content-Type: multipart/mixed; boundary=b",
            "",
        ]
        for index in 0..<200 {
            lines.append(contentsOf: [
                "--b",
                "Content-Type: application/octet-stream",
                "Content-Disposition: attachment; filename=\"f\(index).bin\"",
                "",
                "x",
            ])
        }
        lines.append("--b--")
        let email = try parse(raw(lines))
        XCTAssertEqual(email.attachments.count, MIMEParser.Limits.maxAttachments)
    }

    // MARK: - Date, addresses and threading

    func testDateHeaderFormats() {
        let reference = DateComponents(
            calendar: Calendar(identifier: .gregorian),
            timeZone: TimeZone(secondsFromGMT: 0),
            year: 2026, month: 9, day: 22, hour: 10, minute: 4, second: 5
        ).date!

        XCTAssertEqual(MIMEParser.parseDate("Tue, 22 Sep 2026 10:04:05 +0000"), reference)
        XCTAssertEqual(MIMEParser.parseDate("22 Sep 2026 10:04:05 GMT"), reference)
        XCTAssertEqual(MIMEParser.parseDate("Tue, 22 Sep 2026 12:04:05 +0200"), reference)
        XCTAssertEqual(MIMEParser.parseDate("Tue, 22 Sep 2026 03:04:05 -0700 (PDT)"), reference)
        XCTAssertEqual(MIMEParser.parseDate("Tue, 22 Sep 2026 03:04:05 PDT"), reference)
        XCTAssertEqual(MIMEParser.parseDate("Tue, 22 Sep 26 10:04:05 UT"), reference)
        XCTAssertEqual(MIMEParser.parseDate("Tue Sep 22 10:04:05 2026"), reference)
        XCTAssertEqual(MIMEParser.parseDate("  Tuesday,  22  Sep  2026  10:04:05  +0000  "), reference)
        XCTAssertEqual(MIMEParser.parseDate("22 Sep 2026 10:04:05"), reference)
        // No seconds, and an hour-only offset.
        XCTAssertEqual(
            MIMEParser.parseDate("Tue, 22 Sep 2026 10:04 +0000"),
            reference.addingTimeInterval(-5)
        )
        XCTAssertEqual(
            MIMEParser.parseDate("Tue, 22 Sep 2026 12:04:05 GMT+02:00"),
            reference
        )
    }

    func testMalformedDatesReturnNil() {
        for value in ["", "not a date", "Tue, 99 Zzz 2026 10:04:05 +0000", "2026-09-22T10:04:05Z",
                      String(repeating: "9", count: 400)] {
            XCTAssertNil(MIMEParser.parseDate(value), "unexpectedly parsed \(value)")
        }
    }

    func testCallerReceivedAtWinsOverDateHeader() throws {
        let data = raw(["From: a@example.com", "Date: Tue, 22 Sep 2026 10:04:05 +0000", "", "body"])
        let email = try parse(data, receivedAt: fixedDate)
        XCTAssertEqual(email.receivedAt, fixedDate)
    }

    func testDateHeaderUsedWhenCallerHasNoReceivedAt() throws {
        let data = raw(["From: a@example.com", "Date: Tue, 22 Sep 2026 10:04:05 +0000", "", "body"])
        let email = try MIMEParser.parse(
            rfc822: data,
            provider: .microsoft,
            accountID: "account-1",
            messageID: "uid-42"
        )
        let expected = DateComponents(
            calendar: Calendar(identifier: .gregorian),
            timeZone: TimeZone(secondsFromGMT: 0),
            year: 2026, month: 9, day: 22, hour: 10, minute: 4, second: 5
        ).date!
        XCTAssertEqual(email.receivedAt, expected)
        XCTAssertEqual(email.provider, .microsoft)
    }

    func testMissingDateHeaderFallsBackToNow() throws {
        let email = try MIMEParser.parse(
            rfc822: raw(["From: a@example.com", "", "body"]),
            provider: .gmail,
            accountID: "account-1",
            messageID: "uid-42"
        )
        XCTAssertEqual(email.receivedAt.timeIntervalSinceNow, 0, accuracy: 60)
    }

    func testThreadIDPrefersReferencesThenInReplyToThenMessageID() throws {
        let withReferences = try parse(raw([
            "From: a@example.com",
            "Message-ID: <c@example.com>",
            "In-Reply-To: <b@example.com>",
            "References: <a@example.com> <b@example.com>",
            "",
            "body",
        ]))
        XCTAssertEqual(withReferences.threadID, "a@example.com")

        let withInReplyTo = try parse(raw([
            "From: a@example.com",
            "Message-ID: <c@example.com>",
            "In-Reply-To: <b@example.com>",
            "",
            "body",
        ]))
        XCTAssertEqual(withInReplyTo.threadID, "b@example.com")

        let standalone = try parse(raw([
            "From: a@example.com",
            "Message-ID: <c@example.com>",
            "",
            "body",
        ]))
        XCTAssertEqual(standalone.threadID, "c@example.com")

        let none = try parse(raw(["From: a@example.com", "", "body"]))
        XCTAssertNil(none.threadID)
    }

    func testMessageIdentityFieldsArePassedThrough() throws {
        let link = URL(string: "https://mail.example.com/msg/42")
        let email = try MIMEParser.parse(
            rfc822: raw(["From: a@example.com", "", "body"]),
            provider: .microsoft,
            accountID: "account-9",
            messageID: "uid-7",
            receivedAt: fixedDate,
            webLink: link
        )
        XCTAssertEqual(email.provider, .microsoft)
        XCTAssertEqual(email.accountID, "account-9")
        XCTAssertEqual(email.messageID, "uid-7")
        XCTAssertEqual(email.webLink, link)
        XCTAssertEqual(email.dedupeKey, "microsoft:account-9:uid-7")
    }

    // MARK: - Realistic messages

    func testAppleMailMessage() throws {
        let email = try parse(raw([
            "Return-Path: <kate@icloud.com>",
            "Received: from [192.0.2.4] (unknown [192.0.2.4])",
            "\tby p01-smtp.mail.icloud.com (Postfix) with ESMTPSA id 4A2B",
            "\tfor <user@example.com>; Mon, 22 Sep 2026 09:12:33 +0000 (UTC)",
            "Content-Type: multipart/alternative; boundary=\"Apple-Mail=_9F1B0A2C-1234\"",
            "Mime-Version: 1.0 (Mac OS X Mail 16.0 \\(3776.700.51\\))",
            "Subject: Lunch on Thursday?",
            "From: Kate Miller <kate@icloud.com>",
            "In-Reply-To: <9911@example.com>",
            "Date: Mon, 22 Sep 2026 11:12:33 +0200",
            "Message-Id: <A0B1C2D3-4E5F@icloud.com>",
            "References: <9911@example.com>",
            "To: Sam <sam@example.com>",
            "X-Mailer: Apple Mail (2.3776.700.51)",
            "",
            "",
            "--Apple-Mail=_9F1B0A2C-1234",
            "Content-Transfer-Encoding: quoted-printable",
            "Content-Type: text/plain;",
            "\tcharset=us-ascii",
            "",
            "Are you free Thursday? The caf=C3=A9 near the office works for me.",
            "",
            "--Apple-Mail=_9F1B0A2C-1234",
            "Content-Transfer-Encoding: quoted-printable",
            "Content-Type: text/html;",
            "\tcharset=us-ascii",
            "",
            "<html><body>Are you free Thursday?</body></html>",
            "",
            "--Apple-Mail=_9F1B0A2C-1234--",
            "",
        ]))
        XCTAssertEqual(email.subject, "Lunch on Thursday?")
        XCTAssertEqual(email.from, EmailAddress(name: "Kate Miller", address: "kate@icloud.com"))
        XCTAssertEqual(email.to, [EmailAddress(name: "Sam", address: "sam@example.com")])
        XCTAssertEqual(email.textBody, "Are you free Thursday? The café near the office works for me.")
        XCTAssertEqual(email.htmlBody, "<html><body>Are you free Thursday?</body></html>")
        XCTAssertEqual(email.threadID, "9911@example.com")
        XCTAssertTrue(email.attachments.isEmpty)
        XCTAssertEqual(email.headers("Received").count, 1)
    }

    func testYahooMessageWithEncodedWordSubject() throws {
        let email = try parse(raw([
            "X-Apparently-To: user@yahoo.com; Mon, 22 Sep 2026 08:00:00 +0000",
            "Authentication-Results: atlas.yahoo.com; dkim=pass header.i=@news.example;",
            " spf=pass smtp.mailfrom=news.example; dmarc=pass header.from=news.example",
            "From: \"News Digest\" <digest@news.example>",
            "To: user@yahoo.com",
            "Subject: =?UTF-8?Q?Votre_r=C3=A9sum=C3=A9_hebdomadaire?= =?UTF-8?B?IOKAlCAyMg==?=",
            "Date: Mon, 22 Sep 2026 08:00:00 +0000",
            "Content-Type: text/plain; charset=UTF-8",
            "Content-Transfer-Encoding: quoted-printable",
            "MIME-Version: 1.0",
            "",
            "Bonjour, voici votre r=C3=A9sum=C3=A9.",
        ]))
        XCTAssertEqual(email.subject, "Votre résumé hebdomadaire — 22")
        XCTAssertEqual(email.textBody, "Bonjour, voici votre résumé.")
        let authentication = AuthenticationResults.extract(from: email.headers)
        XCTAssertEqual(authentication.dkim, .pass)
        XCTAssertEqual(authentication.dmarc, .pass)
    }

    func testPhishingStyleHTMLOnlyMessage() throws {
        let html = "<html><body><p>Your account is locked.</p>"
            + "<a href=\"http://secure-paypa1.example/verify\">Verify now</a></body></html>"
        let email = try parse(raw([
            "From: \"PayPal Service\" <service@secure-paypa1.example>",
            "To: victim@example.com",
            "Subject: =?utf-8?B?VXJnZW50OiBhY2NvdW50IGxvY2tlZA==?=",
            "Date: Mon, 22 Sep 2026 04:00:00 -0400",
            "MIME-Version: 1.0",
            "Content-Type: text/html; charset=utf-8",
            "Content-Transfer-Encoding: base64",
            "",
            Data(html.utf8).base64EncodedString(),
        ]))
        XCTAssertEqual(email.subject, "Urgent: account locked")
        XCTAssertNil(email.textBody)
        XCTAssertEqual(email.htmlBody, html)

        // The parsed message must be usable by the rest of PhishCore.
        let report = HeuristicAnalyzer(organizationDomains: []).analyze(email)
        XCTAssertTrue(report.bodyText.contains("Your account is locked."))
        XCTAssertEqual(report.links.map(\.href), ["http://secure-paypa1.example/verify"])
    }

    // MARK: - Hostile input

    func testEmptyInputThrowsTruncated() {
        XCTAssertThrowsError(try parse(Data())) { error in
            XCTAssertEqual(error as? MIMEParserError, .truncated)
        }
    }

    func testHeaderOnlyMessage() throws {
        let email = try parse(raw(["From: a@example.com", "Subject: no body"]))
        XCTAssertEqual(email.subject, "no body")
        XCTAssertNil(email.textBody)
        XCTAssertNil(email.htmlBody)
        XCTAssertTrue(email.attachments.isEmpty)
    }

    func testBodyWithoutHeadersIsBestEffort() throws {
        let email = try parse(Data("\r\njust a body\r\n".utf8))
        XCTAssertEqual(email.subject, "")
        XCTAssertEqual(email.textBody, "just a body")
    }

    func testBinaryGarbageThrowsRatherThanTrapping() {
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<50 {
            let bytes = (0..<256).map { _ in UInt8.random(in: 0...255, using: &generator) }
            do {
                _ = try parse(Data(bytes))
            } catch let error as MIMEParserError {
                XCTAssertTrue(error == .malformedHeaders || error == .truncated)
            } catch {
                XCTFail("unexpected error \(error)")
            }
        }
    }

    func testTruncatedPrefixesOfAValidMessageNeverCrash() throws {
        let complete = raw([
            "From: =?UTF-8?B?QW5uYSBNw7xsbGVy?= <anna@example.de>",
            "To: victim@example.com",
            "Subject: =?utf-8?Q?Invoice_=E2=82=AC99?=",
            "Date: Mon, 22 Sep 2026 10:04:05 +0200",
            "Message-ID: <abc@example.de>",
            "MIME-Version: 1.0",
            "Content-Type: multipart/mixed; boundary=\"outer-b\"",
            "",
            "preamble",
            "--outer-b",
            "Content-Type: multipart/alternative; boundary=\"inner-b\"",
            "",
            "--inner-b",
            "Content-Type: text/plain; charset=utf-8",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "Please pay =E2=82=AC99 today.",
            "--inner-b",
            "Content-Type: text/html; charset=utf-8",
            "Content-Transfer-Encoding: base64",
            "",
            Data("<p>Please pay &euro;99 today.</p>".utf8).base64EncodedString(),
            "--inner-b--",
            "",
            "--outer-b",
            "Content-Type: application/pdf",
            "Content-Disposition: attachment; filename*=UTF-8''Fa%C3%A7ture.pdf",
            "Content-Transfer-Encoding: base64",
            "",
            Data(repeating: 0x7F, count: 900).base64EncodedString(),
            "--outer-b--",
            "",
        ])

        // Every prefix, plus every prefix with one byte flipped, must either parse or throw a MIMEParserError.
        var offset = 0
        while offset <= complete.count {
            let prefix = complete.prefix(offset)
            do {
                let email = try parse(Data(prefix))
                XCTAssertLessThanOrEqual(email.attachments.count, MIMEParser.Limits.maxAttachments)
            } catch let error as MIMEParserError {
                XCTAssertTrue(error == .malformedHeaders || error == .truncated, "offset \(offset): \(error)")
            } catch {
                XCTFail("offset \(offset): unexpected error \(error)")
            }
            offset += offset < 400 ? 1 : 7
        }

        var generator = SystemRandomNumberGenerator()
        for _ in 0..<200 {
            var mutated = [UInt8](complete)
            let index = Int.random(in: 0..<mutated.count, using: &generator)
            mutated[index] = UInt8.random(in: 0...255, using: &generator)
            let cut = Int.random(in: 1...mutated.count, using: &generator)
            do {
                _ = try parse(Data(mutated.prefix(cut)))
            } catch let error as MIMEParserError {
                XCTAssertTrue(error == .malformedHeaders || error == .truncated)
            } catch {
                XCTFail("unexpected error \(error)")
            }
        }
    }

    func testDeeplyNestedMultipartsAreCappedWithoutRecursingForever() throws {
        var lines = [
            "From: a@example.com",
            "Subject: nesting bomb",
            "Content-Type: multipart/mixed; boundary=b0",
            "",
        ]
        let depth = 200
        for level in 0..<depth {
            lines.append("--b\(level)")
            lines.append("Content-Type: multipart/mixed; boundary=b\(level + 1)")
            lines.append("")
        }
        lines.append("--b\(depth)")
        lines.append("Content-Type: text/plain; charset=utf-8")
        lines.append("")
        lines.append("buried text")
        for level in stride(from: depth, through: 0, by: -1) {
            lines.append("--b\(level)--")
        }

        let email = try parse(raw(lines))
        // Deeper than the cap: the payload is simply not collected, and nothing traps.
        XCTAssertNil(email.textBody)
        XCTAssertEqual(email.subject, "nesting bomb")
    }

    func testPartCountIsCapped() throws {
        var lines = [
            "From: a@example.com",
            "Content-Type: multipart/mixed; boundary=b",
            "",
        ]
        for index in 0..<2_000 {
            lines.append(contentsOf: [
                "--b",
                "Content-Type: text/plain; charset=utf-8",
                "",
                "part \(index)",
            ])
        }
        lines.append("--b--")
        let email = try parse(raw(lines))
        XCTAssertLessThanOrEqual(email.textBody?.count ?? 0, MIMEParser.Limits.maxBodyCharacters)
        XCTAssertTrue(email.textBody?.hasPrefix("part 0") ?? false)
    }

    func testBodyCharacterBudgetIsEnforced() throws {
        let chunk = String(repeating: "A", count: 100_000)
        var lines = [
            "From: a@example.com",
            "Content-Type: multipart/mixed; boundary=b",
            "",
        ]
        for _ in 0..<12 {
            lines.append(contentsOf: ["--b", "Content-Type: text/plain; charset=utf-8", "", chunk])
        }
        lines.append("--b--")
        let email = try parse(raw(lines))
        let textCount = try XCTUnwrap(email.textBody).count
        XCTAssertLessThanOrEqual(textCount, MIMEParser.Limits.maxBodyCharacters + 32)
    }

    func testUnterminatedEncodedWordsInAHeaderAreLinear() throws {
        // 20k "=?" starts that never terminate: the scan budget must keep this from going quadratic.
        let hostile = String(repeating: "=?utf-8?B?", count: 20_000)
        let start = Date()
        let decoded = MIMEParser.decodeEncodedWords(hostile)
        XCTAssertEqual(decoded.count, hostile.count)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2.0)
    }

    func testEightMegabyteMessageParsesWithinTimeAndKeepsNoAttachmentContent() throws {
        var data = Data(raw([
            "From: sender@example.com",
            "Subject: big attachment",
            "Date: Mon, 22 Sep 2026 10:04:05 +0000",
            "Content-Type: multipart/mixed; boundary=big",
            "",
            "--big",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "See attached.",
            "",
            "--big",
            "Content-Type: application/zip",
            "Content-Disposition: attachment; filename=\"archive.zip\"",
            "Content-Transfer-Encoding: base64",
            "",
            "",
        ]))
        let line = Data((String(repeating: "A", count: 76) + "\r\n").utf8)
        data.reserveCapacity(9_000_000)
        while data.count < 8 * 1024 * 1024 { data.append(line) }
        data.append(Data("--big--\r\n".utf8))
        XCTAssertGreaterThanOrEqual(data.count, 8 * 1024 * 1024)

        let start = Date()
        let email = try parse(data)
        let elapsed = Date().timeIntervalSince(start)

        XCTAssertEqual(email.textBody, "See attached.")
        XCTAssertNil(email.htmlBody)
        XCTAssertEqual(email.attachments.count, 1)
        XCTAssertEqual(email.attachments[0].filename, "archive.zip")
        XCTAssertGreaterThan(email.attachments[0].sizeBytes ?? 0, 6_000_000)
        XCTAssertLessThan(elapsed, 5.0, "8 MB message took \(elapsed)s")
    }

    func testOversizeMessageIsTruncatedRatherThanRejected() throws {
        var data = Data(raw([
            "From: a@example.com",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "",
        ]))
        let chunk = Data(repeating: 0x41, count: 1024 * 1024)
        while data.count < MIMEParser.Limits.maxMessageBytes + 2 * 1024 * 1024 { data.append(chunk) }
        let email = try parse(data)
        XCTAssertEqual(email.textBody?.count, MIMEParser.Limits.maxBodyCharacters)
    }

    func testLongUnfoldedHeaderDoesNotExplode() throws {
        var lines = ["From: a@example.com", "X-Folded: start"]
        for _ in 0..<50_000 { lines.append(" continuation") }
        lines.append(contentsOf: ["Subject: after", "", "body"])
        let email = try parse(raw(lines))
        XCTAssertEqual(email.header("X-Folded")?.count, MIMEParser.Limits.maxHeaderValueCharacters)
        XCTAssertEqual(email.subject, "after")
    }
}

import Foundation
import PhishCore
import XCTest
@testable import PhishGuard

/// Parser, command-rendering and settings tests. No sockets: these pin the grammar down on its own.
final class IMAPProtocolTests: XCTestCase {
    private func tokenize(_ text: String) throws -> [IMAPToken] {
        try IMAPTokenizer.tokenize(Array(text.utf8))
    }

    // MARK: - Tokenizer

    func testTokenizesAtomsQuotedStringsAndLists() throws {
        let tokens = try tokenize("FETCH (UID 12 FLAGS (\\Seen \\Answered) INTERNALDATE \"22-Sep-2026 09:00:00 +0000\")")
        XCTAssertEqual(tokens.count, 2)
        XCTAssertEqual(tokens[0], .atom("FETCH"))
        let items = try XCTUnwrap(tokens[1].items)
        XCTAssertEqual(items[0], .atom("UID"))
        XCTAssertEqual(items[1], .atom("12"))
        XCTAssertEqual(items[2], .atom("FLAGS"))
        XCTAssertEqual(items[3].items, [.atom("\\Seen"), .atom("\\Answered")])
        XCTAssertEqual(items[5], .quoted("22-Sep-2026 09:00:00 +0000"))
    }

    func testQuotedStringEscapesAreUnwrapped() throws {
        let tokens = try tokenize("\"a \\\"quoted\\\" \\\\ value\"")
        XCTAssertEqual(tokens, [.quoted("a \"quoted\" \\ value")])
    }

    func testLiteralIsReadAsRawBytes() throws {
        var bytes = Array("BODY[] {12}\r\n".utf8)
        bytes.append(contentsOf: Array("line1\r\nline2".utf8))
        let tokens = try IMAPTokenizer.tokenize(bytes)
        XCTAssertEqual(tokens[0], .atom("BODY[]"))
        XCTAssertEqual(tokens[1].data.map { String(decoding: $0, as: UTF8.self) }, "line1\r\nline2")
    }

    func testSectionSpecifierStaysAttachedToItsAtom() throws {
        let tokens = try tokenize("BODY[HEADER.FIELDS (FROM TO)] NIL BODY[1]<0.512> NIL")
        XCTAssertEqual(tokens[0], .atom("BODY[HEADER.FIELDS (FROM TO)]"))
        XCTAssertTrue(tokens[1].isNil)
        XCTAssertEqual(tokens[2], .atom("BODY[1]<0.512>"))
    }

    func testResponseCodeIsItsOwnToken() throws {
        let line = try IMAPResponseLine.parse(Array("* OK [UIDVALIDITY 1234] UIDs valid\r\n".utf8))
        guard case .untagged(let untagged) = line else { return XCTFail("expected an untagged line") }
        XCTAssertEqual(untagged.keyword, "OK")
        XCTAssertEqual(untagged.responseCodeName, "UIDVALIDITY")
        XCTAssertEqual(untagged.responseCode?.dropFirst().first?.uint32Value, 1234)
    }

    func testUntaggedNumberedLine() throws {
        let line = try IMAPResponseLine.parse(Array("* 17 EXISTS\r\n".utf8))
        guard case .untagged(let untagged) = line else { return XCTFail("expected an untagged line") }
        XCTAssertEqual(untagged.number, 17)
        XCTAssertEqual(untagged.keyword, "EXISTS")
    }

    func testTaggedLineKeepsCodeAndHumanText() throws {
        let line = try IMAPResponseLine.parse(Array("A007 NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)\r\n".utf8))
        guard case .tagged(let tag, let status, let code, let text) = line else { return XCTFail("expected a tagged line") }
        XCTAssertEqual(tag, "A007")
        XCTAssertEqual(status, .no)
        XCTAssertEqual(code?.first?.keyword, "AUTHENTICATIONFAILED")
        XCTAssertEqual(text, "Invalid credentials (Failure)")
    }

    func testContinuationLine() throws {
        let line = try IMAPResponseLine.parse(Array("+ Ready for literal\r\n".utf8))
        XCTAssertEqual(line, .continuation("Ready for literal"))
    }

    func testUnbalancedListIsRejected() {
        XCTAssertThrowsError(try tokenize("FETCH (UID 12"))
    }

    func testDeeplyNestedListIsRejected() {
        let nested = String(repeating: "(", count: 200) + String(repeating: ")", count: 200)
        XCTAssertThrowsError(try tokenize(nested)) { error in
            guard case IMAPError.protocolViolation = error else { return XCTFail("expected a protocol violation") }
        }
    }

    // MARK: - Literal framing

    func testTrailingLiteralLengthIsDetected() {
        XCTAssertEqual(IMAPClient.trailingLiteralLength(Array("* 1 FETCH (BODY[] {42}\r\n".utf8)), 42)
        XCTAssertEqual(IMAPClient.trailingLiteralLength(Array("* 1 FETCH (BODY[] {42+}\r\n".utf8)), 42)
        XCTAssertNil(IMAPClient.trailingLiteralLength(Array("* 1 FETCH (UID 1)\r\n".utf8)))
    }

    func testBraceInsideAQuotedStringIsNotALiteral() {
        let line = Array("* 1 FETCH (ENVELOPE (\"date\" \"a subject {42}\"))\r\n".utf8)
        XCTAssertNil(IMAPClient.trailingLiteralLength(line))
    }

    // MARK: - Commands

    func testUIDSetCompressesRuns() {
        XCTAssertEqual(IMAPCommand.uidSet([1, 2, 3, 7, 9, 10]), "1:3,7,9:10")
        XCTAssertEqual(IMAPCommand.uidSet([5]), "5")
    }

    func testLoginQuotesAndEscapesCredentials() throws {
        let segments = try IMAPCommand.login(username: "a\"b", password: "p\\w").segments()
        guard case .text(let rendered)? = segments.first else { return XCTFail("expected text") }
        XCTAssertEqual(rendered, "LOGIN ")
        let joined = segments.compactMap { segment -> String? in
            if case .text(let text) = segment { return text }
            return nil
        }.joined()
        XCTAssertEqual(joined, "LOGIN \"a\\\"b\" \"p\\\\w\"")
    }

    func testCredentialWithALineBreakIsRefused() {
        XCTAssertThrowsError(try IMAPCommand.login(username: "u", password: "p\r\nA001 STORE 1 +FLAGS (\\Seen)").segments())
    }

    func testNonASCIIPasswordUsesALiteral() throws {
        let segments = try IMAPCommand.login(username: "u", password: "pässwörd").segments()
        let hasLiteral = segments.contains { segment in
            if case .literal = segment { return true }
            return false
        }
        XCTAssertTrue(hasLiteral, "8-bit credentials must be sent as a literal, not a quoted string")
    }

    func testSearchDateUsesTheRFCFormat() throws {
        var components = DateComponents()
        components.year = 2026
        components.month = 9
        components.day = 22
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = try XCTUnwrap(TimeZone(identifier: "UTC"))
        let date = try XCTUnwrap(calendar.date(from: components))
        XCTAssertEqual(IMAPSearchCriteria.since(date).wireText, "SINCE 22-Sep-2026")
        XCTAssertEqual(IMAPSearchCriteria.uidFrom(42).wireText, "UID 42:*")
    }

    func testFetchRendersPeekItems() throws {
        let segments = try IMAPCommand.uidFetch(uids: [1, 2], items: [.uid, .internalDate, .peekHeader, .peekPart("1.2")]).segments()
        guard case .text(let rendered)? = segments.first else { return XCTFail("expected text") }
        XCTAssertEqual(rendered, "UID FETCH 1:2 (UID INTERNALDATE BODY.PEEK[HEADER] BODY.PEEK[1.2])")
        XCTAssertFalse(rendered.contains("BODY["), "every body section must be a .PEEK so nothing is marked read")
    }

    // MARK: - The read-only guard

    func testOnlyReadOnlyVerbsAreAllowed() {
        XCTAssertEqual(IMAPCommand.allowedVerbs, ["CAPABILITY", "STARTTLS", "LOGIN", "AUTHENTICATE", "EXAMINE", "UID", "NOOP", "LOGOUT"])
        for verb in ["SELECT", "STORE", "APPEND", "EXPUNGE", "COPY", "MOVE", "DELETE", "CREATE", "RENAME", "SETACL"] {
            XCTAssertFalse(IMAPCommand.allowedVerbs.contains(verb), "\(verb) must never be sendable")
            XCTAssertThrowsError(try IMAPCommand.assertReadOnly(verb: verb, segments: [.text(verb)])) { error in
                guard case IMAPError.forbiddenCommand = error else { return XCTFail("expected forbiddenCommand for \(verb)") }
            }
        }
    }

    func testMutatingUIDSubcommandsAreRefused() {
        for subcommand in ["STORE", "COPY", "MOVE", "EXPUNGE"] {
            XCTAssertThrowsError(try IMAPCommand.assertReadOnly(verb: "UID", segments: [.text("UID \(subcommand) 1 +FLAGS (\\Seen)")])) { error in
                guard case IMAPError.forbiddenCommand = error else { return XCTFail("expected forbiddenCommand for UID \(subcommand)") }
            }
        }
        XCTAssertNoThrow(try IMAPCommand.assertReadOnly(verb: "UID", segments: [.text("UID FETCH 1 (UID)")]))
        XCTAssertNoThrow(try IMAPCommand.assertReadOnly(verb: "UID", segments: [.text("UID SEARCH ALL")]))
    }

    func testEveryCommandCaseRendersAnAllowedVerb() throws {
        let commands: [IMAPCommand] = [
            .capability, .startTLS, .login(username: "u", password: "p"),
            .authenticatePlain(username: "u", password: "p"), .examine(mailbox: "INBOX"),
            .uidSearch(.all), .uidFetch(uids: [1], items: [.uid]), .noop, .logout,
        ]
        for command in commands {
            let segments = try command.segments()
            XCTAssertNoThrow(try IMAPCommand.assertReadOnly(verb: command.verb, segments: segments))
        }
    }

    func testRedactedDescriptionNeverCarriesCredentials() {
        XCTAssertFalse(IMAPCommand.login(username: "user@example.com", password: "hunter2").redactedDescription.contains("hunter2"))
        XCTAssertFalse(IMAPCommand.login(username: "user@example.com", password: "hunter2").redactedDescription.contains("user@example.com"))
        XCTAssertFalse(IMAPCommand.examine(mailbox: "Private/Folder").redactedDescription.contains("Private"))
    }

    // MARK: - Server directory

    func testPresetsCoverTheCommonProviders() {
        let expected: [String: String] = [
            "someone@icloud.com": "imap.mail.me.com",
            "someone@me.com": "imap.mail.me.com",
            "someone@yahoo.com": "imap.mail.yahoo.com",
            "someone@ymail.com": "imap.mail.yahoo.com",
            "someone@fastmail.com": "imap.fastmail.com",
            "someone@aol.com": "imap.aol.com",
            "someone@gmx.com": "imap.gmx.com",
            "someone@gmx.de": "imap.gmx.net",
            "someone@zoho.com": "imap.zoho.com",
            "someone@outlook.com": "outlook.office365.com",
            "someone@hotmail.com": "outlook.office365.com",
        ]
        for (address, host) in expected {
            let settings = IMAPServerDirectory.suggestedSettings(forEmail: address)
            XCTAssertEqual(settings?.host, host, "wrong preset for \(address)")
            XCTAssertEqual(settings?.port, 993)
            XCTAssertEqual(settings?.security, .tls)
            XCTAssertEqual(settings?.username, address)
        }
    }

    func testUnknownDomainFallsBackToImapDotDomain() {
        let settings = IMAPServerDirectory.suggestedSettings(forEmail: "Person@Example.CO.UK")
        XCTAssertEqual(settings?.host, "imap.example.co.uk")
        XCTAssertEqual(settings?.email, "person@example.co.uk")
        XCTAssertNil(IMAPServerDirectory.suggestedSettings(forEmail: "not-an-address"))
    }

    func testSettingsValidation() {
        var settings = IMAPAccountSettings(host: "imap.example.com", port: 993, security: .tls, username: "", email: " User@Example.com ")
        XCTAssertNil(settings.validationProblem)
        XCTAssertEqual(settings.normalized.email, "user@example.com")
        XCTAssertEqual(settings.normalized.username, "user@example.com", "an empty username falls back to the address")

        settings.email = "nope"
        XCTAssertNotNil(settings.validationProblem)
        settings.email = "user@example.com"
        settings.host = "localhost"
        XCTAssertNotNil(settings.validationProblem)
        settings.host = "imap.example.com"
        settings.port = 0
        XCTAssertNotNil(settings.validationProblem)
    }

    func testAutoFilledServerFieldsAreNotTreatedAsAUserEdit() {
        // What auto-fill itself writes must never count as an override, or the next keystroke in the address
        // would freeze the server on a half-typed domain.
        XCTAssertFalse(IMAPSetupFields.serverWasEditedManually(host: "", port: "993", security: .tls, email: "a@i"))
        XCTAssertFalse(IMAPSetupFields.serverWasEditedManually(host: "imap.i", port: "993", security: .tls, email: "a@i"))
        XCTAssertFalse(IMAPSetupFields.serverWasEditedManually(host: "imap.mail.me.com", port: "993", security: .tls, email: "a@icloud.com"))

        XCTAssertTrue(IMAPSetupFields.serverWasEditedManually(host: "mail.mycompany.com", port: "993", security: .tls, email: "a@icloud.com"))
        XCTAssertTrue(IMAPSetupFields.serverWasEditedManually(host: "imap.mail.me.com", port: "143", security: .startTLS, email: "a@icloud.com"))
        XCTAssertTrue(IMAPSetupFields.serverWasEditedManually(host: "imap.example.com", port: "993", security: .tls, email: "no-domain-yet"))
    }

    func testPlaintextIsNeverOfferedInTheUI() {
        XCTAssertEqual(IMAPSecurity.userSelectable, [.tls, .startTLS])
        XCTAssertFalse(IMAPSecurity.userSelectable.contains(.none))
    }

    // MARK: - Cursor

    func testSyncCursorRoundTrips() {
        let cursor = IMAPSyncCursor(uidValidity: 42, lastUID: 1_000)
        XCTAssertEqual(cursor.opaque, "42:1000")
        XCTAssertEqual(IMAPSyncCursor(opaque: "42:1000"), cursor)
        XCTAssertNil(IMAPSyncCursor(opaque: "garbage"))
        XCTAssertNil(IMAPSyncCursor(opaque: "42"))
    }

    // MARK: - BODYSTRUCTURE

    private func structure(_ text: String) throws -> IMAPBodyStructure {
        let tokens = try tokenize(text)
        let list = try XCTUnwrap(tokens.first?.items)
        return try XCTUnwrap(IMAPBodyStructure.parse(list))
    }

    func testSinglePartStructure() throws {
        let parsed = try structure("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"QUOTED-PRINTABLE\" 1152 23)")
        let leaves = parsed.leaves()
        XCTAssertEqual(leaves.count, 1)
        XCTAssertEqual(leaves[0].number, "1")
        XCTAssertEqual(leaves[0].part.mimeType, "text/plain")
        XCTAssertEqual(leaves[0].part.encoding, "quoted-printable")
        XCTAssertEqual(leaves[0].part.charset, "UTF-8")
        XCTAssertTrue(parsed.attachments.isEmpty)
    }

    func testMultipartWithAnAttachmentRecordsMetadataOnly() throws {
        let text = """
        ((("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 120 4)\
        ("TEXT" "HTML" ("CHARSET" "UTF-8") NIL NIL "BASE64" 400 6) "ALTERNATIVE")\
        ("APPLICATION" "PDF" ("NAME" "invoice.pdf") NIL NIL "BASE64" 40000 NIL ("ATTACHMENT" ("FILENAME" "invoice.pdf")) NIL) "MIXED")
        """
        let parsed = try structure(text)
        let leaves = parsed.leaves()
        XCTAssertEqual(leaves.map(\.number), ["1.1", "1.2", "2"])

        let preferred = parsed.preferredTextParts()
        XCTAssertEqual(preferred.plain?.number, "1.1")
        XCTAssertEqual(preferred.html?.number, "1.2")
        XCTAssertEqual(preferred.html?.part.encoding, "base64")

        XCTAssertEqual(parsed.attachments.count, 1)
        XCTAssertEqual(parsed.attachments[0].filename, "invoice.pdf")
        XCTAssertEqual(parsed.attachments[0].mimeType, "application/pdf")
        XCTAssertEqual(parsed.attachments[0].sizeBytes, 30_000, "base64 size is reported decoded")
    }

    func testBodyStructureOfAnUnexpectedShapeIsIgnored() throws {
        let tokens = try tokenize("(\"TEXT\")")
        XCTAssertNil(IMAPBodyStructure.parse(try XCTUnwrap(tokens.first?.items)))
    }

    // MARK: - Part decoding

    func testPartDecoderHandlesBase64AndQuotedPrintable() {
        let base64 = Data("SGVsbG8sIHdvcmxkIQ==".utf8)
        XCTAssertEqual(IMAPPartDecoder.decode(base64, encoding: "BASE64", charset: "utf-8"), "Hello, world!")

        let quoted = Data("Caf=C3=A9 =\r\nbill".utf8)
        XCTAssertEqual(IMAPPartDecoder.decode(quoted, encoding: "quoted-printable", charset: "utf-8"), "Café bill")

        let latin = Data([0x43, 0x61, 0x66, 0xE9])
        XCTAssertEqual(IMAPPartDecoder.decode(latin, encoding: "8bit", charset: "iso-8859-1"), "Café")
    }

    // MARK: - Errors

    func testLoginFailureNamesAnAppPasswordWhenTheServerDoes() {
        let appPassword = IMAPError.loginFailure(code: "ALERT", message: "Application-specific password required")
        guard case .appPasswordRequired = appPassword else { return XCTFail("expected appPasswordRequired") }
        XCTAssertTrue(appPassword.isAuthenticationFailure)

        let plain = IMAPError.loginFailure(code: "AUTHENTICATIONFAILED", message: "Invalid credentials")
        guard case .authenticationFailed = plain else { return XCTFail("expected authenticationFailed") }
        XCTAssertTrue(plain.isAuthenticationFailure)
        XCTAssertFalse(IMAPError.timedOut.isAuthenticationFailure)
    }

    func testEveryErrorHasAUserFacingMessage() {
        let errors: [IMAPError] = [
            .hostNotFound("imap.example.com"), .connectionFailed("refused"), .tlsFailed("bad cert"),
            .startTLSUnavailable, .timedOut, .connectionClosed, .protocolViolation("nope"),
            .responseTooLarge(limit: 16 * 1024 * 1024), .authenticationFailed(serverMessage: "no"),
            .appPasswordRequired(serverMessage: nil), .commandFailed(command: "EXAMINE", serverMessage: nil),
            .mailboxNotReadOnly, .forbiddenCommand("STORE"), .mailboxNotFound("INBOX"),
            .invalidSettings("Enter the IMAP server address, for example imap.example.com."),
        ]
        for error in errors {
            let message = error.errorDescription ?? ""
            XCTAssertFalse(message.isEmpty, "\(error) needs a message")
            XCTAssertTrue(message.count > 15, "\(error) needs a message a person can act on")
        }
    }

    // MARK: - Provider surface

    func testIMAPProviderHasNoPushSupport() {
        XCTAssertFalse(MailProvider.imap.supportsPushSubscriptions)
        XCTAssertTrue(MailProvider.gmail.supportsPushSubscriptions)
        XCTAssertTrue(MailProvider.microsoft.supportsPushSubscriptions)
    }

    func testPushStatusExplainsHowIMAPAccountsAreChecked() {
        let status = PushSubscriptionStatus.make(expiresAt: nil, supportsPush: false)
        XCTAssertEqual(status, .unsupported)
        XCTAssertFalse(status.label.localizedCaseInsensitiveContains("no push"),
                       "an IMAP account has nothing wrong with it; the row must not read like a fault")
        XCTAssertEqual(PushSubscriptionStatus.make(expiresAt: nil), .none, "OAuth providers are unaffected")
    }

    @MainActor
    func testIMAPIsAlwaysAddable() {
        XCTAssertTrue(AccountLinker.isConfigured(.imap, config: AppConfig()))
        XCTAssertEqual(AccountLinker.addTitle(for: .imap), "Add another mail account (IMAP)")
        XCTAssertFalse(AccountLinker.addTitle(for: .imap).localizedCaseInsensitiveContains("pop3"),
                       "nothing in the UI may promise POP3 while it is not implemented")
    }
}

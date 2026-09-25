import Foundation
import XCTest
@testable import PhishGuard

/// The client against a real socket: a local IMAP server that speaks the protocol, including literals, so the
/// framing and the parser are exercised end to end.
final class IMAPClientTests: XCTestCase {
    private var server: FakeIMAPServer!

    override func setUpWithError() throws {
        try super.setUpWithError()
        server = FakeIMAPServer()
    }

    override func tearDown() {
        server?.stop()
        server = nil
        super.tearDown()
    }

    private func start(_ configure: (inout FakeIMAPServer.Configuration) -> Void = { _ in }) throws {
        server.update(configure)
        try server.start()
    }

    private func makeClient(limits: IMAPClient.Limits = IMAPClient.Limits()) -> IMAPClient {
        IMAPClient(endpoint: server.endpoint, limits: limits, transportFactory: { NWIMAPTransport(endpoint: $0) })
    }

    private func signedInClient(limits: IMAPClient.Limits = IMAPClient.Limits()) async throws -> IMAPClient {
        let client = makeClient(limits: limits)
        try await client.connect()
        try await client.authenticate(username: "user@example.com", password: "app-specific-password")
        return client
    }

    // MARK: - Sign-in

    func testLoginAndExamineOpenTheMailboxReadOnly() async throws {
        try start { $0.messages = [FakeIMAPMessage.make(uid: 10)] }
        let client = try await signedInClient()
        let status = try await client.examine()
        await client.disconnect()

        XCTAssertEqual(status.uidValidity, 1_000)
        XCTAssertEqual(status.exists, 1)
        XCTAssertEqual(status.uidNext, 11)
        XCTAssertTrue(status.isReadOnly)
        XCTAssertTrue(server.receivedCommands.contains { $0.uppercased().contains("EXAMINE \"INBOX\"") || $0.uppercased().contains("EXAMINE INBOX") })
        XCTAssertFalse(server.receivedVerbs.contains("SELECT"))
    }

    func testWrongPasswordIsReportedAsAnAuthenticationFailure() async throws {
        try start()
        let client = makeClient()
        try await client.connect()
        do {
            try await client.authenticate(username: "user@example.com", password: "wrong")
            XCTFail("expected the login to be refused")
        } catch let error as IMAPError {
            guard case .authenticationFailed(let message) = error else { return XCTFail("expected authenticationFailed, got \(error)") }
            XCTAssertEqual(message, "Invalid credentials (Failure)")
            XCTAssertTrue(error.isAuthenticationFailure)
        }
        await client.disconnect()
    }

    func testAppSpecificPasswordIsNamedWhenTheServerSaysSo() async throws {
        try start { $0.loginFailure = (code: "ALERT", text: "Application-specific password required") }
        let client = makeClient()
        try await client.connect()
        do {
            try await client.authenticate(username: "user@example.com", password: "account-password")
            XCTFail("expected the login to be refused")
        } catch let error as IMAPError {
            guard case .appPasswordRequired = error else { return XCTFail("expected appPasswordRequired, got \(error)") }
            XCTAssertTrue(error.errorDescription?.contains("app-specific password") == true)
        }
        await client.disconnect()
    }

    func testAuthenticatePlainIsUsedWhenAdvertised() async throws {
        try start {
            $0.capabilities = ["IMAP4rev1", "AUTH=PLAIN"]
            $0.messages = [FakeIMAPMessage.make(uid: 1)]
        }
        let client = try await signedInClient()
        _ = try await client.examine()
        await client.disconnect()

        XCTAssertTrue(server.receivedVerbs.contains("AUTHENTICATE"))
        XCTAssertFalse(server.receivedVerbs.contains("LOGIN"))
        XCTAssertFalse(server.receivedCommands.contains { $0.contains("app-specific-password") },
                       "the password must go out base64-encoded in the SASL payload, never in the command line")
    }

    func testExamineThatComesBackReadWriteIsRefused() async throws {
        try start { $0.examineReadOnly = false }
        let client = try await signedInClient()
        do {
            _ = try await client.examine()
            XCTFail("a READ-WRITE mailbox must be refused")
        } catch let error as IMAPError {
            XCTAssertEqual(error, .mailboxNotReadOnly)
        }
        await client.disconnect()
    }

    // MARK: - Search and fetch

    func testUIDSearchAndFetchReadBodiesThroughLiterals() async throws {
        let tricky = "Line one\r\n) not a list \"quote\" {12} still body\r\nLine three"
        try start {
            $0.messages = [
                FakeIMAPMessage.make(uid: 5, subject: "First", body: "hello"),
                FakeIMAPMessage.make(uid: 9, subject: "Second", body: tricky),
            ]
        }
        let client = try await signedInClient()
        _ = try await client.examine()
        let uids = try await client.uidSearch(.uidFrom(1))
        XCTAssertEqual(uids, [5, 9])

        let fetched = try await client.uidFetch(uids: uids, items: [.uid, .internalDate, .rfc822Size, .peekWhole])
        await client.disconnect()

        XCTAssertEqual(fetched.count, 2)
        let second = try XCTUnwrap(fetched.first { $0.uid == 9 })
        let raw = try XCTUnwrap(second.sections["BODY[]"])
        XCTAssertTrue(String(decoding: raw, as: UTF8.self).contains(tricky),
                      "a literal body containing CRLF, braces and quotes must survive intact")
        XCTAssertNotNil(second.internalDate)
        XCTAssertEqual(second.size, raw.count)
    }

    func testFetchReadsBodyStructureAndIndividualParts() async throws {
        var message = FakeIMAPMessage.make(uid: 3, body: "ignored")
        message.bodyStructure = "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 11 1)(\"APPLICATION\" \"PDF\" (\"NAME\" \"bill.pdf\") NIL NIL \"BASE64\" 4000 NIL (\"ATTACHMENT\" (\"FILENAME\" \"bill.pdf\")) NIL) \"MIXED\")"
        message.parts = ["1": Data("Hello there".utf8)]
        try start { $0.messages = [message] }

        let client = try await signedInClient()
        _ = try await client.examine()
        let fetched = try await client.uidFetch(uids: [3], items: [.uid, .bodyStructure, .peekPart("1")])
        await client.disconnect()

        let response = try XCTUnwrap(fetched.first)
        let structure = try XCTUnwrap(response.bodyStructure)
        XCTAssertEqual(structure.attachments.map(\.filename), ["bill.pdf"])
        XCTAssertEqual(structure.preferredTextParts().plain?.number, "1")
        XCTAssertEqual(response.sections["BODY[1]"].map { String(decoding: $0, as: UTF8.self) }, "Hello there")
    }

    func testSearchAboveTheHighestUIDStillReportsTheHighest() async throws {
        // Real servers answer "9999:*" with the highest UID; the provider must filter it, not the client.
        try start { $0.messages = [FakeIMAPMessage.make(uid: 7)] }
        let client = try await signedInClient()
        _ = try await client.examine()
        let uids = try await client.uidSearch(.uidFrom(9_999))
        await client.disconnect()
        XCTAssertEqual(uids, [7])
    }

    // MARK: - Nothing mutating, ever

    func testAFullSessionNeverSendsAMutatingCommand() async throws {
        try start { $0.messages = [FakeIMAPMessage.make(uid: 1), FakeIMAPMessage.make(uid: 2)] }
        let client = try await signedInClient()
        _ = try await client.examine()
        let uids = try await client.uidSearch(.uidFrom(1))
        _ = try await client.uidFetch(uids: uids, items: [.uid, .peekWhole])
        await client.disconnect()

        let forbidden = ["SELECT", "STORE", "APPEND", "EXPUNGE", "COPY", "MOVE", "DELETE", "CREATE", "RENAME", "SUBSCRIBE", "SETACL", "CLOSE"]
        for verb in server.receivedVerbs {
            XCTAssertFalse(forbidden.contains(verb), "the client sent \(verb)")
            XCTAssertTrue(IMAPCommand.allowedVerbs.contains(verb), "the client sent an unexpected verb: \(verb)")
        }
        for command in server.receivedCommands {
            XCTAssertFalse(command.uppercased().contains("BODY["),
                           "every body fetch must use BODY.PEEK so the server does not set \\Seen: \(command)")
        }
        XCTAssertTrue(server.receivedCommands.contains { $0.uppercased().contains("BODY.PEEK[") })
        XCTAssertTrue(server.receivedVerbs.contains("LOGOUT"))
    }

    // MARK: - Hostile and broken servers

    func testConnectionDroppedAfterTheGreeting() async throws {
        try start { $0.behavior = .dropAfterGreeting }
        let client = makeClient()
        do {
            try await client.connect()
            try await client.authenticate(username: "user@example.com", password: "app-specific-password")
            XCTFail("expected the dropped connection to surface")
        } catch let error as IMAPError {
            XCTAssertTrue(error == .connectionClosed || error == .timedOut, "unexpected error: \(error)")
        }
        await client.disconnect()
    }

    func testConnectionDroppedInTheMiddleOfAResponse() async throws {
        try start {
            $0.messages = [FakeIMAPMessage.make(uid: 1)]
            $0.behavior = .dropDuring("UID")
        }
        let client = try await signedInClient()
        _ = try await client.examine()
        do {
            _ = try await client.uidFetch(uids: [1], items: [.uid, .peekWhole])
            XCTFail("expected the truncated response to surface")
        } catch let error as IMAPError {
            XCTAssertTrue(error == .connectionClosed || error == .timedOut, "unexpected error: \(error)")
        }
        await client.disconnect()
    }

    func testSilentServerTimesOut() async throws {
        try start { $0.behavior = .silentDuring("EXAMINE") }
        var limits = IMAPClient.Limits()
        limits.commandTimeout = 0.6
        let client = try await signedInClient(limits: limits)
        let started = Date()
        do {
            _ = try await client.examine()
            XCTFail("expected a timeout")
        } catch let error as IMAPError {
            XCTAssertEqual(error, .timedOut)
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5, "the watchdog must give up quickly")
        await client.disconnect()
    }

    func testOversizedLiteralIsRefusedWithoutReadingIt() async throws {
        try start {
            $0.messages = [FakeIMAPMessage.make(uid: 1)]
            $0.behavior = .oversizedLiteralOnFetch
        }
        var limits = IMAPClient.Limits()
        limits.maxLiteralBytes = 64 * 1024
        limits.commandTimeout = 3
        let client = try await signedInClient(limits: limits)
        _ = try await client.examine()
        do {
            _ = try await client.uidFetch(uids: [1], items: [.uid, .peekWhole])
            XCTFail("expected the oversized literal to be refused")
        } catch let error as IMAPError {
            guard case .responseTooLarge(let limit) = error else { return XCTFail("expected responseTooLarge, got \(error)") }
            XCTAssertEqual(limit, 64 * 1024)
        }
        await client.disconnect()
    }

    func testEndlessLineIsRefused() async throws {
        try start { $0.behavior = .hugeLineOn("EXAMINE") }
        var limits = IMAPClient.Limits()
        limits.maxLineBytes = 8 * 1024
        limits.commandTimeout = 3
        let client = try await signedInClient(limits: limits)
        do {
            _ = try await client.examine()
            XCTFail("expected the endless line to be refused")
        } catch let error as IMAPError {
            guard case .responseTooLarge = error else { return XCTFail("expected responseTooLarge, got \(error)") }
        }
        await client.disconnect()
    }

    func testGarbageResponseIsRefused() async throws {
        try start { $0.behavior = .garbageOn("EXAMINE") }
        var limits = IMAPClient.Limits()
        limits.commandTimeout = 3
        let client = try await signedInClient(limits: limits)
        do {
            _ = try await client.examine()
            XCTFail("expected the malformed response to be refused")
        } catch let error as IMAPError {
            guard case .protocolViolation = error else { return XCTFail("expected protocolViolation, got \(error)") }
        }
        await client.disconnect()
    }

    func testCancellationStopsTheCommand() async throws {
        try start { $0.behavior = .silentDuring("EXAMINE") }
        var limits = IMAPClient.Limits()
        limits.commandTimeout = 30
        let client = try await signedInClient(limits: limits)
        let task = Task { try await client.examine() }
        try await Task.sleep(nanoseconds: 200_000_000)
        task.cancel()
        let result = await task.result
        switch result {
        case .success:
            XCTFail("expected the cancelled command to fail")
        case .failure:
            break
        }
        await client.disconnect()
    }

    // MARK: - The Foundation-stream transport (used for STARTTLS)

    func testStreamTransportSpeaksTheSameProtocol() async throws {
        try start { $0.messages = [FakeIMAPMessage.make(uid: 4, subject: "Via streams")] }
        let client = IMAPClient(
            endpoint: server.endpoint,
            limits: IMAPClient.Limits(),
            transportFactory: { StreamIMAPTransport(endpoint: $0) }
        )
        try await client.connect()
        try await client.authenticate(username: "user@example.com", password: "app-specific-password")
        let status = try await client.examine()
        let fetched = try await client.uidFetch(uids: [4], items: [.uid, .peekWhole])
        await client.disconnect()

        XCTAssertTrue(status.isReadOnly)
        let raw = try XCTUnwrap(fetched.first?.sections["BODY[]"])
        XCTAssertTrue(String(decoding: raw, as: UTF8.self).contains("Via streams"))
    }

    func testStartTLSIsRefusedWhenTheServerDoesNotOfferIt() async throws {
        try start { $0.advertiseStartTLS = false }
        let endpoint = IMAPEndpoint(host: "127.0.0.1", port: Int(server.port), security: .startTLS)
        let client = IMAPClient(endpoint: endpoint, limits: IMAPClient.Limits(), transportFactory: { StreamIMAPTransport(endpoint: $0) })
        do {
            try await client.connect()
            XCTFail("expected STARTTLS to be unavailable")
        } catch let error as IMAPError {
            XCTAssertEqual(error, .startTLSUnavailable)
        }
        await client.disconnect()
    }
}

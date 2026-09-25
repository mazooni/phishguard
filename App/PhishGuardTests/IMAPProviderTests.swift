import Foundation
import PhishCore
import XCTest
@testable import PhishGuard

/// `IMAPProvider` against the local IMAP server: cursors, the UIDVALIDITY reset, the skip-before-download hook,
/// the batch cap and the Keychain lifecycle.
final class IMAPProviderTests: XCTestCase {
    private var server: FakeIMAPServer!
    private var keychain: Keychain!
    private var store: IMAPCredentialStore!
    private let accountID = UUID()
    private let password = "app-specific-password"

    override func setUpWithError() throws {
        try super.setUpWithError()
        server = FakeIMAPServer()
        keychain = Keychain(service: "PhishGuardTests.imap.\(UUID().uuidString)")
        store = IMAPCredentialStore(keychain: keychain)
    }

    override func tearDown() {
        try? store?.delete(accountID: accountID)
        server?.stop()
        server = nil
        store = nil
        keychain = nil
        super.tearDown()
    }

    private func start(_ configure: (inout FakeIMAPServer.Configuration) -> Void = { _ in }) throws {
        server.update(configure)
        try server.start()
    }

    private func makeProvider() -> IMAPProvider {
        var limits = IMAPClient.Limits()
        limits.commandTimeout = 10
        limits.greetingTimeout = 10
        return IMAPProvider(keychain: keychain, transportFactory: { NWIMAPTransport(endpoint: $0) }, limits: limits)
    }

    private func storeCredentials() throws {
        try store.store(IMAPCredentials(settings: server.settings, password: password), for: accountID)
    }

    // MARK: - First sync

    func testFirstFetchUsesTheLookbackWindowAndReportsAReset() async throws {
        try start {
            $0.messages = [
                FakeIMAPMessage.make(uid: 4, subject: "Your invoice", body: "Pay now at http://example.invalid"),
                FakeIMAPMessage.make(uid: 9, subject: "Hello"),
            ]
        }
        try storeCredentials()
        let result = try await makeProvider().fetchNewMessages(accountID: accountID, cursor: nil, lookback: 24 * 3600)

        XCTAssertTrue(result.cursorWasReset)
        XCTAssertEqual(result.cursor.opaque, "1000:9")
        XCTAssertEqual(result.messages.count, 2)
        let first = try XCTUnwrap(result.messages.first { $0.messageID == "1000.4" })
        XCTAssertEqual(first.provider, .imap)
        XCTAssertEqual(first.accountID, accountID.uuidString)
        XCTAssertEqual(first.subject, "Your invoice")
        XCTAssertEqual(first.from?.address, "billing@example.com")
        XCTAssertEqual(first.textBody?.trimmingCharacters(in: .whitespacesAndNewlines), "Pay now at http://example.invalid")
        XCTAssertTrue(server.receivedCommands.contains { $0.uppercased().contains("UID SEARCH SINCE") })
    }

    func testIncrementalFetchOnlyTakesUIDsAboveTheCursor() async throws {
        try start {
            $0.messages = [
                FakeIMAPMessage.make(uid: 4),
                FakeIMAPMessage.make(uid: 9),
                FakeIMAPMessage.make(uid: 11, subject: "Newest"),
            ]
        }
        try storeCredentials()
        let result = try await makeProvider().fetchNewMessages(
            accountID: accountID, cursor: SyncCursor(opaque: "1000:9"), lookback: 24 * 3600
        )

        XCTAssertFalse(result.cursorWasReset)
        XCTAssertEqual(result.messages.map(\.messageID), ["1000.11"])
        XCTAssertEqual(result.cursor.opaque, "1000:11")
        XCTAssertTrue(server.receivedCommands.contains { $0.uppercased().contains("UID SEARCH UID 10:*") })
    }

    func testNothingNewLeavesTheCursorWhereItWas() async throws {
        try start { $0.messages = [FakeIMAPMessage.make(uid: 9)] }
        try storeCredentials()
        let result = try await makeProvider().fetchNewMessages(
            accountID: accountID, cursor: SyncCursor(opaque: "1000:9"), lookback: 24 * 3600
        )
        XCTAssertTrue(result.messages.isEmpty)
        XCTAssertEqual(result.cursor.opaque, "1000:9", "the server echoing the highest UID must not move the cursor back")
        XCTAssertFalse(result.cursorWasReset)
    }

    func testUIDValidityChangeResetsTheCursor() async throws {
        try start {
            $0.uidValidity = 2_222
            $0.messages = [FakeIMAPMessage.make(uid: 1), FakeIMAPMessage.make(uid: 2)]
        }
        try storeCredentials()
        let result = try await makeProvider().fetchNewMessages(
            accountID: accountID, cursor: SyncCursor(opaque: "1000:900"), lookback: 24 * 3600
        )

        XCTAssertTrue(result.cursorWasReset, "a renumbered mailbox must be reported as a reset")
        XCTAssertEqual(result.cursor.opaque, "2222:2")
        XCTAssertEqual(result.messages.map(\.messageID).sorted(), ["2222.1", "2222.2"])
        XCTAssertTrue(server.receivedCommands.contains { $0.uppercased().contains("UID SEARCH SINCE") })
        XCTAssertFalse(server.receivedCommands.contains { $0.uppercased().contains("UID SEARCH UID") })
    }

    // MARK: - The skip-before-download hook

    func testProcessedMessagesAreNeverDownloaded() async throws {
        try start {
            $0.messages = [FakeIMAPMessage.make(uid: 1), FakeIMAPMessage.make(uid: 2), FakeIMAPMessage.make(uid: 3)]
        }
        try storeCredentials()
        let result = try await makeProvider().fetchNewMessages(
            accountID: accountID, cursor: nil, lookback: 24 * 3600,
            isProcessed: { $0 == "1000.1" || $0 == "1000.2" }
        )

        XCTAssertEqual(result.messages.map(\.messageID), ["1000.3"])
        let fetches = server.receivedCommands.filter { $0.uppercased().contains("UID FETCH") }
        XCTAssertFalse(fetches.isEmpty)
        for command in fetches {
            XCTAssertFalse(command.contains(" 1:3 "), "already-processed uids must not reach a FETCH: \(command)")
            XCTAssertFalse(command.contains(" 1 "), "already-processed uids must not reach a FETCH: \(command)")
        }
    }

    // MARK: - Batch cap

    func testIncrementalFetchIsCappedAndKeepsTheRestForTheNextScan() async throws {
        let messages = (1...120).map { FakeIMAPMessage.make(uid: UInt32($0), subject: "Message \($0)") }
        try start { $0.messages = messages }
        try storeCredentials()
        let provider = makeProvider()

        let first = try await provider.fetchNewMessages(
            accountID: accountID, cursor: SyncCursor(opaque: "1000:0"), lookback: 24 * 3600
        )
        XCTAssertEqual(first.messages.count, IMAPProvider.maxMessagesPerFetch)
        XCTAssertEqual(first.cursor.opaque, "1000:100", "the cursor only advances over what was fetched")
        XCTAssertEqual(first.messages.map(\.messageID).first, "1000.1")

        let second = try await provider.fetchNewMessages(
            accountID: accountID, cursor: first.cursor, lookback: 24 * 3600
        )
        XCTAssertEqual(second.messages.count, 20)
        XCTAssertEqual(second.cursor.opaque, "1000:120")
    }

    func testFirstSyncCapKeepsTheNewestMail() async throws {
        let messages = (1...120).map { FakeIMAPMessage.make(uid: UInt32($0)) }
        try start { $0.messages = messages }
        try storeCredentials()
        let result = try await makeProvider().fetchNewMessages(accountID: accountID, cursor: nil, lookback: 24 * 3600)

        XCTAssertEqual(result.messages.count, IMAPProvider.maxMessagesPerFetch)
        XCTAssertEqual(result.messages.map(\.messageID).sorted().last, "1000.99")
        XCTAssertTrue(result.messages.contains { $0.messageID == "1000.120" })
        XCTAssertFalse(result.messages.contains { $0.messageID == "1000.1" })
        XCTAssertEqual(result.cursor.opaque, "1000:120")
    }

    // MARK: - Large messages

    func testLargeMessagesAreFetchedAsHeadersAndTextPartsOnly() async throws {
        var large = FakeIMAPMessage.make(uid: 7, subject: "Big one with a PDF")
        large.sizeOverride = 4 * 1024 * 1024
        large.bodyStructure = "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 22 1)(\"APPLICATION\" \"PDF\" (\"NAME\" \"statement.pdf\") NIL NIL \"BASE64\" 4000000 NIL (\"ATTACHMENT\" (\"FILENAME\" \"statement.pdf\")) NIL) \"MIXED\")"
        large.parts = ["1": Data("Please see attached.".utf8)]
        try start { $0.messages = [large] }
        try storeCredentials()

        let result = try await makeProvider().fetchNewMessages(accountID: accountID, cursor: nil, lookback: 24 * 3600)
        let message = try XCTUnwrap(result.messages.first)
        XCTAssertEqual(message.subject, "Big one with a PDF")
        XCTAssertEqual(message.textBody, "Please see attached.")
        XCTAssertEqual(message.attachments.map(\.filename), ["statement.pdf"])
        XCTAssertFalse(server.receivedCommands.contains { $0.contains("BODY.PEEK[]") },
                       "a multi-megabyte message must never be downloaded whole")
        XCTAssertTrue(server.receivedCommands.contains { $0.contains("BODY.PEEK[HEADER]") })
        XCTAssertFalse(server.receivedCommands.contains { $0.contains("BODY.PEEK[2]") },
                       "the attachment part must never be fetched")
    }

    // MARK: - Failures

    func testMissingCredentialsAreReportedAsNotAuthenticated() async throws {
        try start()
        do {
            _ = try await makeProvider().fetchNewMessages(accountID: accountID, cursor: nil, lookback: 3600)
            XCTFail("expected notAuthenticated")
        } catch ProviderError.notAuthenticated {
            // expected
        }
    }

    func testARejectedPasswordBecomesNotAuthenticated() async throws {
        try start { $0.loginFailure = (code: "AUTHENTICATIONFAILED", text: "Invalid credentials") }
        try storeCredentials()
        do {
            _ = try await makeProvider().fetchNewMessages(accountID: accountID, cursor: nil, lookback: 3600)
            XCTFail("expected notAuthenticated")
        } catch ProviderError.notAuthenticated {
            // expected: the scan coordinator flags the account for "Sign in again"
        }
    }

    func testTransportFailuresBecomeNetworkErrors() async throws {
        // Nothing is listening on this port.
        let settings = IMAPAccountSettings(host: "127.0.0.1", port: 9, security: .none, username: "u@example.com", email: "u@example.com")
        try store.store(IMAPCredentials(settings: settings, password: password), for: accountID)
        do {
            _ = try await makeProvider().fetchNewMessages(accountID: accountID, cursor: nil, lookback: 3600)
            XCTFail("expected a network error")
        } catch let error as ProviderError {
            guard case .network = error else { return XCTFail("expected .network, got \(error)") }
        }
    }

    // MARK: - Push, sign-out, binding

    func testPushSubscriptionsAreReportedAsUnsupported() async throws {
        let relay = RelayConfig(baseURL: URL(string: "https://relay.invalid")!, apiKey: "k", gmailPubSubTopic: "t")
        do {
            _ = try await makeProvider().ensurePushSubscription(accountID: accountID, relay: relay, current: nil)
            XCTFail("expected pushNotSupported")
        } catch ProviderError.pushNotSupported {
            // expected
        }
        XCTAssertFalse(MailProvider.imap.supportsPushSubscriptions)
    }

    func testSignOutDeletesTheStoredCredentials() async throws {
        try start()
        try storeCredentials()
        XCTAssertNotNil(try store.credentials(for: accountID))
        try await makeProvider().signOut(accountID: accountID)
        XCTAssertNil(try store.settings(for: accountID))
        XCTAssertNil(try store.password(for: accountID))
    }

    func testLinkAccountBindsThePendingSignIn() async throws {
        try start()
        let settings = server.settings
        try store.storePending(IMAPPendingSignIn(
            credentials: IMAPCredentials(settings: settings, password: password), createdAt: .now
        ))
        let identity = SignedInIdentity(providerAccountID: "id", email: settings.email, displayName: "Test")
        try await makeProvider().linkAccount(accountID: accountID, identity: identity)

        XCTAssertEqual(try store.settings(for: accountID)?.host, settings.host)
        XCTAssertEqual(try store.password(for: accountID), password)
        XCTAssertNil(try store.takePending(email: settings.email), "the pending sign-in is consumed once bound")
    }

    func testLinkAccountWithoutAPendingSignInFails() async throws {
        let identity = SignedInIdentity(providerAccountID: "id", email: "nobody@example.com", displayName: nil)
        do {
            try await makeProvider().linkAccount(accountID: accountID, identity: identity)
            XCTFail("expected notAuthenticated")
        } catch ProviderError.notAuthenticated {
            // expected
        }
    }

    func testAnExpiredPendingSignInIsDiscarded() throws {
        let settings = IMAPAccountSettings(host: "imap.example.com", port: 993, security: .tls, username: "u@example.com", email: "u@example.com")
        try store.storePending(IMAPPendingSignIn(
            credentials: IMAPCredentials(settings: settings, password: password),
            createdAt: Date().addingTimeInterval(-2 * IMAPCredentialStore.pendingLifetime)
        ))
        XCTAssertNil(try store.takePending(email: settings.email))
    }

    // MARK: - Validation (what "Test connection" runs)

    func testValidateSucceedsAgainstAWorkingServer() async throws {
        try start()
        let outcome = await makeProvider().validateForUI(IMAPCredentials(settings: server.settings, password: password))
        XCTAssertEqual(outcome, .success)
        XCTAssertTrue(server.receivedVerbs.contains("EXAMINE"))
        XCTAssertFalse(server.receivedVerbs.contains("SELECT"))
    }

    func testValidateExplainsAWrongPassword() async throws {
        try start()
        let outcome = await makeProvider().validateForUI(IMAPCredentials(settings: server.settings, password: "nope"))
        guard case .failure(let message) = outcome else { return XCTFail("expected a failure") }
        XCTAssertTrue(message.contains("rejected the email address or password"), "unhelpful message: \(message)")
    }

    func testValidateRejectsIncompleteDetailsBeforeConnecting() async throws {
        try start()
        var settings = server.settings
        settings.email = "not-an-address"
        let outcome = await makeProvider().validateForUI(IMAPCredentials(settings: settings, password: password))
        guard case .failure(let message) = outcome else { return XCTFail("expected a failure") }
        XCTAssertTrue(message.contains("full email address"), "unhelpful message: \(message)")
        XCTAssertTrue(server.receivedCommands.isEmpty, "bad details must not open a connection")
    }
}

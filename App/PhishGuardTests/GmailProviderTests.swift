import PhishCore
import Synchronization
import UIKit
import XCTest
@testable import PhishGuard

private let gmail = GmailFixtures.gmailPath

/// Sync semantics of `GmailProvider` driven through a URLProtocol stub session; AppAuth is bypassed with the
/// access-token provider seam.
final class GmailProviderTests: XCTestCase {
    private var server: GmailStubServer!
    private var keychain: Keychain!
    private var config: AppConfig!
    private var provider: GmailProvider!
    private let accountID = UUID()
    private let tokenCalls = GmailLocked(0)

    override func setUp() {
        super.setUp()
        server = GmailStubServer()
        keychain = Keychain(service: "PhishGuardTests.gmail.\(UUID().uuidString)")
        config = AppConfig(relayBaseURL: URL(string: "https://relay.test"), relayAPIKey: "relay-key", relaySalt: "salt")
        let calls = tokenCalls
        provider = GmailProvider(
            config: config,
            keychain: keychain,
            session: server.makeSession(),
            accessTokenProvider: { _ in
                calls.withLock { $0 += 1 }
                return "test-token"
            },
            retryPolicy: .immediate
        )
    }

    override func tearDown() {
        for key in [GmailProvider.authStateKeyPrefix, GmailProvider.emailKeyPrefix] {
            try? keychain.delete(key + accountID.uuidString)
        }
        try? keychain.delete(RelayClient.deviceSecretKey)
        try? keychain.delete(RelayClient.deviceIDKey)
        super.tearDown()
    }

    /// Serves `messages.get` for the given documents (keyed by id) and delegates everything else to `other`.
    private func serve(messages: [String: [String: Any]], other: @escaping GmailStubServer.Handler) {
        let documents = messages.mapValues { GmailFixtures.data($0) }
        let prefix = gmail + "/messages/"
        server.handle { request in
            if request.method == "GET", request.path.hasPrefix(prefix) {
                let id = String(request.path.dropFirst(prefix.count))
                guard let document = documents[id] else { return .notFound }
                return GmailStubServer.Response(status: 200, body: document, headers: ["Content-Type": "application/json"])
            }
            return other(request)
        }
    }

    // MARK: - History

    func testHistoryFiltersLabelsDedupesAndSortsByInternalDate() async throws {
        let history = GmailStubServer.Response.json(GmailFixtures.historyPage(records: [
            (id: "101", messages: [(id: "m1", labels: ["INBOX", "UNREAD"]), (id: "m2", labels: ["INBOX", "DRAFT"])]),
            (id: "102", messages: [(id: "m3", labels: ["SENT", "INBOX"]), (id: "m1", labels: ["INBOX"]), (id: "m4", labels: ["CATEGORY_PROMOTIONS", "INBOX"])]),
            (id: "103", messages: [(id: "m5", labels: ["SPAM"]), (id: "m6", labels: [])]),
        ], historyId: "500"))
        serve(messages: [
            "m1": GmailFixtures.plainMessage(id: "m1", internalDate: 2_000, subject: "second"),
            "m4": GmailFixtures.plainMessage(id: "m4", internalDate: 1_000, subject: "first"),
        ]) { request in
            request.path == gmail + "/history" ? history : .notFound
        }

        let result = try await provider.fetchNewMessages(accountID: accountID, cursor: SyncCursor(opaque: "100"), lookback: 86_400)

        XCTAssertEqual(result.cursor.opaque, "500", "top-level historyId becomes the cursor")
        XCTAssertFalse(result.cursorWasReset)
        XCTAssertEqual(result.messages.map(\.messageID), ["m4", "m1"], "sorted by internalDate ascending")
        XCTAssertEqual(result.messages.map(\.subject), ["first", "second"])
        XCTAssertEqual(result.messages.first?.accountID, accountID.uuidString)

        let historyRequests = server.requests(matching: gmail + "/history")
        XCTAssertEqual(historyRequests.count, 1)
        let query = try XCTUnwrap(historyRequests.first?.query)
        XCTAssertEqual(query["startHistoryId"], "100")
        XCTAssertEqual(query["historyTypes"], "messageAdded")
        XCTAssertEqual(query["labelId"], "INBOX")
        XCTAssertEqual(query["maxResults"], "500")
        XCTAssertNil(query["pageToken"])
        XCTAssertEqual(historyRequests.first?.headers["Authorization"], "Bearer test-token")

        let fetched = server.requests.filter { $0.path.hasPrefix(gmail + "/messages/") }
        XCTAssertEqual(Set(fetched.map { $0.path }), [gmail + "/messages/m1", gmail + "/messages/m4"], "drafts, sent, non-inbox and duplicates are not fetched")
        XCTAssertTrue(fetched.allSatisfy { $0.query["format"] == "full" })
        XCTAssertTrue(server.requests(matching: gmail + "/profile").isEmpty, "no full sync on the history path")
    }

    func testHistoryPaginationFollowsPageTokens() async throws {
        let page1 = GmailStubServer.Response.json(GmailFixtures.historyPage(records: [(id: "1", messages: [(id: "a", labels: ["INBOX"])])], historyId: "10", nextPageToken: "tok-2"))
        let page2 = GmailStubServer.Response.json(GmailFixtures.historyPage(records: [(id: "2", messages: [(id: "b", labels: ["INBOX"])])], historyId: "20", nextPageToken: "tok-3"))
        let page3 = GmailStubServer.Response.json(GmailFixtures.historyPage(records: [], historyId: "30"))
        serve(messages: [
            "a": GmailFixtures.plainMessage(id: "a", internalDate: 1),
            "b": GmailFixtures.plainMessage(id: "b", internalDate: 2),
        ]) { request in
            guard request.path == gmail + "/history" else { return .notFound }
            switch request.query["pageToken"] {
            case nil: return page1
            case "tok-2": return page2
            case "tok-3": return page3
            default: return .notFound
            }
        }

        let result = try await provider.fetchNewMessages(accountID: accountID, cursor: SyncCursor(opaque: "5"), lookback: 3600)

        XCTAssertEqual(result.messages.map(\.messageID), ["a", "b"])
        XCTAssertEqual(result.cursor.opaque, "30", "historyId of the last page")
        let historyRequests = server.requests(matching: gmail + "/history")
        XCTAssertEqual(historyRequests.map { $0.query["pageToken"] }, [nil, "tok-2", "tok-3"])
        XCTAssertTrue(historyRequests.allSatisfy { $0.query["startHistoryId"] == "5" })
    }

    func testEmptyHistoryStillAdvancesCursor() async throws {
        server.handle { request in
            request.path == gmail + "/history" ? .json(["historyId": "777"]) : .notFound
        }
        let result = try await provider.fetchNewMessages(accountID: accountID, cursor: SyncCursor(opaque: "700"), lookback: 3600)
        XCTAssertTrue(result.messages.isEmpty)
        XCTAssertEqual(result.cursor.opaque, "777")
        XCTAssertFalse(result.cursorWasReset)
        XCTAssertEqual(server.requests.count, 1)
    }

    func testHistorySkipsProcessedIdsBeforeDownloadingBodies() async throws {
        let history = GmailStubServer.Response.json(GmailFixtures.historyPage(records: [
            (id: "1", messages: [(id: "old1", labels: ["INBOX"]), (id: "new1", labels: ["INBOX"])]),
            (id: "2", messages: [(id: "old2", labels: ["INBOX"])]),
        ], historyId: "77"))
        serve(messages: [
            "new1": GmailFixtures.plainMessage(id: "new1", internalDate: 1),
            "old1": GmailFixtures.plainMessage(id: "old1", internalDate: 2),
            "old2": GmailFixtures.plainMessage(id: "old2", internalDate: 3),
        ]) { request in
            request.path == gmail + "/history" ? history : .notFound
        }
        let processed: Set<String> = ["old1", "old2"]

        let result = try await provider.fetchNewMessages(accountID: accountID, cursor: SyncCursor(opaque: "0"), lookback: 3600) { processed.contains($0) }

        XCTAssertEqual(result.messages.map(\.messageID), ["new1"])
        XCTAssertEqual(result.cursor.opaque, "77", "the cursor still covers the skipped records")
        XCTAssertEqual(Set(server.requests.filter { $0.path.hasPrefix(gmail + "/messages/") }.map(\.path)), [gmail + "/messages/new1"], "processed ids are never downloaded")
    }

    func testProcessedIdsDoNotCountTowardTheHistoryCap() async throws {
        let cap = GmailProvider.maxMessagesPerFetch
        // One record with `cap` already-processed ids, then `cap` new ones: all new ones must be fetched in one go.
        var records: [(id: String, messages: [(id: String, labels: [String])])] = [
            (id: "1", messages: (0..<cap).map { (id: "old\($0)", labels: ["INBOX"]) }),
        ]
        records += (0..<cap).map { (id: String($0 + 2), messages: [(id: "new\($0)", labels: ["INBOX"])]) }
        let page = GmailStubServer.Response.json(GmailFixtures.historyPage(records: records, historyId: "9999"))
        var documents: [String: [String: Any]] = [:]
        for index in 0..<cap {
            documents["new\(index)"] = GmailFixtures.plainMessage(id: "new\(index)", internalDate: Int64(index))
        }
        serve(messages: documents) { request in
            request.path == gmail + "/history" ? page : .notFound
        }

        let result = try await provider.fetchNewMessages(accountID: accountID, cursor: SyncCursor(opaque: "0"), lookback: 3600) { $0.hasPrefix("old") }

        XCTAssertEqual(result.messages.count, cap)
        XCTAssertEqual(result.cursor.opaque, String(cap + 1), "cap reached exactly at the last new record; cursor = that record")
        XCTAssertEqual(server.requests.filter { $0.path.hasPrefix(gmail + "/messages/") }.count, cap)
    }

    func testFetchCapNeverExceedsTheCoordinatorScanBudget() {
        XCTAssertLessThanOrEqual(GmailProvider.maxMessagesPerFetch, ScanCoordinator.defaultMaxMessagesPerScan, "a capped batch must be consumable in one scan so the cursor advances")
        XCTAssertLessThanOrEqual(GraphMailSync.maxMessagesPerScan, ScanCoordinator.defaultMaxMessagesPerScan)
    }

    func testHistoryCapStopsAtRecordAndAdvancesCursorOnlyThatFar() async throws {
        let cap = GmailProvider.maxMessagesPerFetch
        let records = (1...(cap + 50)).map { (id: String($0), messages: [(id: "m\($0)", labels: ["INBOX"])]) }
        let page = GmailStubServer.Response.json(GmailFixtures.historyPage(records: records, historyId: "9999", nextPageToken: "more"))
        var documents: [String: [String: Any]] = [:]
        for index in 1...(cap + 50) {
            documents["m\(index)"] = GmailFixtures.plainMessage(id: "m\(index)", internalDate: Int64(index))
        }
        serve(messages: documents) { request in
            request.path == gmail + "/history" ? page : .notFound
        }

        let result = try await provider.fetchNewMessages(accountID: accountID, cursor: SyncCursor(opaque: "0"), lookback: 3600)

        XCTAssertEqual(result.messages.count, cap)
        XCTAssertEqual(result.messages.last?.messageID, "m\(cap)")
        XCTAssertEqual(result.cursor.opaque, String(cap), "cursor is the id of the last consumed history record, not the page historyId")
        XCTAssertEqual(server.requests(matching: gmail + "/history").count, 1, "the next page is not requested once capped")
    }

    // MARK: - Full sync

    func testHistory404FallsBackToFullSyncWithProfileFirst() async throws {
        let listing = GmailStubServer.Response.json(GmailFixtures.listPage(ids: ["n1", "n2"]))
        serve(messages: [
            "n1": GmailFixtures.plainMessage(id: "n1", internalDate: 20),
            "n2": GmailFixtures.plainMessage(id: "n2", internalDate: 10),
        ]) { request in
            switch request.path {
            case gmail + "/history": return .notFound
            case gmail + "/profile": return .json(GmailFixtures.profile(historyId: "900"))
            case gmail + "/messages": return listing
            default: return .notFound
            }
        }

        let result = try await provider.fetchNewMessages(accountID: accountID, cursor: SyncCursor(opaque: "1"), lookback: 36 * 3600)

        XCTAssertTrue(result.cursorWasReset)
        XCTAssertEqual(result.cursor.opaque, "900", "profile historyId becomes the cursor after a reset")
        XCTAssertEqual(result.messages.map(\.messageID), ["n2", "n1"])

        let order = server.requests.map { $0.path }.prefix(3)
        XCTAssertEqual(Array(order), [gmail + "/history", gmail + "/profile", gmail + "/messages"], "getProfile is taken BEFORE listing")

        let list = try XCTUnwrap(server.requests(matching: gmail + "/messages").first)
        XCTAssertEqual(list.query["q"], "newer_than:2d", "36 h rounds up to 2 days")
        XCTAssertEqual(list.query["labelIds"], "INBOX")
        XCTAssertEqual(list.query["maxResults"], "100")
    }

    /// Serves `messages.list` pages of `listPageSize` ids named `f0, f1, ...` (newest first) with a page token chain.
    private func serveFullSyncPages(total: Int, historyId: String = "4242", extraRoutes: @escaping GmailStubServer.Handler = { _ in .notFound }) {
        let pageSize = GmailProvider.listPageSize
        var documents: [String: [String: Any]] = [:]
        for index in 0..<total {
            documents["f\(index)"] = GmailFixtures.plainMessage(id: "f\(index)", internalDate: Int64(total - index))
        }
        serve(messages: documents) { request in
            switch request.path {
            case gmail + "/profile": return .json(GmailFixtures.profile(historyId: historyId))
            case gmail + "/messages":
                let pageIndex = request.query["pageToken"].flatMap { Int($0.dropFirst()) } ?? 0
                let start = pageIndex * pageSize
                guard start < total else { return .notFound }
                let end = min(start + pageSize, total)
                let next = end < total ? "p\(pageIndex + 1)" : nil
                return .json(GmailFixtures.listPage(ids: (start..<end).map { "f\($0)" }, nextPageToken: next))
            default: return extraRoutes(request)
            }
        }
    }

    func testNoCursorUsesFullSyncAndCapsAtMaxMessagesPerFetch() async throws {
        let cap = GmailProvider.maxMessagesPerFetch
        let pagesNeeded = Int((Double(cap) / Double(GmailProvider.listPageSize)).rounded(.up))
        serveFullSyncPages(total: cap + 2 * GmailProvider.listPageSize)

        let result = try await provider.fetchNewMessages(accountID: accountID, cursor: nil, lookback: 6 * 3600)

        XCTAssertTrue(result.cursorWasReset)
        XCTAssertEqual(result.cursor.opaque, "4242")
        XCTAssertEqual(result.messages.count, cap)
        XCTAssertEqual(server.requests(matching: gmail + "/messages").count, pagesNeeded, "no page is requested past the cap")
        XCTAssertEqual(server.requests(matching: gmail + "/messages").first?.query["q"], "newer_than:1d", "lookback shorter than a day → 1d")
        XCTAssertEqual(server.requests.filter { $0.path.hasPrefix(gmail + "/messages/") }.count, cap)
        XCTAssertEqual(result.messages.first?.messageID, "f\(cap - 1)", "newest `cap` kept; sorted ascending by internalDate")
        XCTAssertEqual(result.messages.last?.messageID, "f0")
        XCTAssertTrue(server.requests.allSatisfy { $0.path != gmail + "/history" })
    }

    func testFullSyncSkipsProcessedIdsWithoutCountingThemTowardTheCap() async throws {
        let cap = GmailProvider.maxMessagesPerFetch
        let pageSize = GmailProvider.listPageSize
        // The first page is entirely processed; the cap must still be filled from the following pages.
        serveFullSyncPages(total: pageSize + cap + pageSize)
        let processed = Set((0..<pageSize).map { "f\($0)" })

        let result = try await provider.fetchNewMessages(accountID: accountID, cursor: nil, lookback: 6 * 3600) { processed.contains($0) }

        XCTAssertEqual(result.messages.count, cap)
        XCTAssertEqual(result.messages.first?.messageID, "f\(pageSize + cap - 1)")
        XCTAssertEqual(result.messages.last?.messageID, "f\(pageSize)")
        let downloaded = Set(server.requests.filter { $0.path.hasPrefix(gmail + "/messages/") }.map { String($0.path.dropFirst((gmail + "/messages/").count)) })
        XCTAssertTrue(downloaded.isDisjoint(with: processed), "processed ids are never downloaded")
        XCTAssertEqual(downloaded.count, cap)
    }

    func testEmptyCursorIsTreatedAsMissing() async throws {
        server.handle { request in
            switch request.path {
            case gmail + "/profile": return .json(GmailFixtures.profile(historyId: "1"))
            case gmail + "/messages": return .json(GmailFixtures.listPage(ids: []))
            default: return .notFound
            }
        }
        let result = try await provider.fetchNewMessages(accountID: accountID, cursor: SyncCursor(opaque: "  "), lookback: 3600)
        XCTAssertTrue(result.cursorWasReset)
        XCTAssertEqual(result.cursor.opaque, "1")
    }

    // MARK: - messages.get

    func testMessageThatVanishedIsSkipped() async throws {
        let history = GmailStubServer.Response.json(GmailFixtures.historyPage(records: [
            (id: "1", messages: [(id: "gone", labels: ["INBOX"]), (id: "here", labels: ["INBOX"])]),
        ], historyId: "2"))
        serve(messages: ["here": GmailFixtures.plainMessage(id: "here", internalDate: 1)]) { request in
            request.path == gmail + "/history" ? history : .notFound
        }

        let result = try await provider.fetchNewMessages(accountID: accountID, cursor: SyncCursor(opaque: "1"), lookback: 3600)
        XCTAssertEqual(result.messages.map(\.messageID), ["here"])
        XCTAssertEqual(result.cursor.opaque, "2")
    }

    func testUnauthorizedRetriesOnceThenMapsToNotAuthenticated() async {
        server.handle { _ in .googleError(status: 401, reason: "authError", message: "Invalid Credentials") }

        await assertThrowsProviderError("notAuthenticated", { if case .notAuthenticated = $0 { return true }; return false }) {
            _ = try await provider.fetchNewMessages(accountID: accountID, cursor: SyncCursor(opaque: "1"), lookback: 3600)
        }
        XCTAssertEqual(server.requests.count, 2, "one retry with a force-refreshed token")
        XCTAssertEqual(tokenCalls.withLock { $0 }, 2)
    }

    func testRateLimitExhaustionSurfacesAsRateLimited() async {
        server.handle { _ in .googleError(status: 429, reason: "rateLimitExceeded", headers: ["Retry-After": "7"]) }

        await assertThrowsProviderError("rateLimited", { if case .rateLimited(let after) = $0 { return after == 7 }; return false }) {
            _ = try await provider.fetchNewMessages(accountID: accountID, cursor: SyncCursor(opaque: "1"), lookback: 3600)
        }
        XCTAssertEqual(server.requests.count, 3, "three attempts")
    }

    // MARK: - Push subscription

    func testEnsurePushSubscriptionWatchesAndRegistersWithRelay() async throws {
        let expiration: Int64 = 1_800_000_000_000
        server.handle { request in
            switch (request.method, request.path) {
            case ("POST", gmail + "/watch"): return .json(["historyId": "55", "expiration": String(expiration)])
            case ("GET", gmail + "/profile"): return .json(GmailFixtures.profile(email: "User@Example.com", historyId: "55"))
            case ("POST", "/v1/devices/accounts"): return .empty
            default: return .notFound
            }
        }
        let relay = RelayConfig(baseURL: URL(string: "https://relay.test")!, apiKey: "relay-key", gmailPubSubTopic: "projects/p/topics/t")

        let state = try await provider.ensurePushSubscription(accountID: accountID, relay: relay, current: nil)

        XCTAssertEqual(state.id, "watch")
        XCTAssertEqual(state.expiresAt.timeIntervalSince1970, TimeInterval(expiration) / 1000, accuracy: 0.001)
        XCTAssertEqual(state.relayAccountKey, config.accountKey(for: "user@example.com"))

        let watch = try XCTUnwrap(server.requests(matching: gmail + "/watch").first)
        XCTAssertEqual(watch.headers["Authorization"], "Bearer test-token")
        XCTAssertEqual(watch.headers["Content-Type"], "application/json")
        let body = try XCTUnwrap(watch.jsonBody)
        XCTAssertEqual(body["topicName"] as? String, "projects/p/topics/t")
        XCTAssertEqual(body["labelIds"] as? [String], ["INBOX"])
        XCTAssertEqual(body["labelFilterBehavior"] as? String, "INCLUDE")

        let registration = try XCTUnwrap(server.requests(matching: "/v1/devices/accounts").first)
        XCTAssertEqual(registration.url.host, "relay.test")
        XCTAssertEqual(registration.headers["X-API-Key"], "relay-key")
        XCTAssertTrue(registration.headers["Authorization"]?.hasPrefix("Bearer ") ?? false)
        XCTAssertEqual(registration.jsonBody?["accountKey"] as? String, state.relayAccountKey)
        XCTAssertEqual(registration.jsonBody?["provider"] as? String, "gmail")
        XCTAssertEqual(try keychain.getString(GmailProvider.emailKeyPrefix + accountID.uuidString), "User@Example.com")

        // Renewal reuses the cached address.
        _ = try await provider.ensurePushSubscription(accountID: accountID, relay: relay, current: state)
        XCTAssertEqual(server.requests(matching: gmail + "/profile").count, 1)
        XCTAssertEqual(server.requests(matching: gmail + "/watch").count, 2)
    }

    func testEnsurePushSubscriptionRequiresATopic() async {
        for topic in ["", "projects/your-gcp-project/topics/phishguard-gmail"] {
            let relay = RelayConfig(baseURL: URL(string: "https://relay.test")!, apiKey: "k", gmailPubSubTopic: topic)
            await assertThrowsProviderError("notConfigured", { if case .notConfigured = $0 { return true }; return false }) {
                _ = try await provider.ensurePushSubscription(accountID: accountID, relay: relay, current: nil)
            }
        }
        XCTAssertTrue(server.requests.isEmpty)
    }

    func testEnsurePushSubscriptionPropagatesRelayFailure() async {
        server.handle { request in
            switch request.path {
            case gmail + "/watch": return .json(["historyId": "1", "expiration": "1800000000000"])
            case gmail + "/profile": return .json(GmailFixtures.profile(historyId: "1"))
            default: return GmailStubServer.Response(status: 500, body: Data())
            }
        }
        let relay = RelayConfig(baseURL: URL(string: "https://relay.test")!, apiKey: "k", gmailPubSubTopic: "projects/p/topics/t")
        do {
            _ = try await provider.ensurePushSubscription(accountID: accountID, relay: relay, current: nil)
            XCTFail("expected the relay error to propagate so the coordinator retries next scan")
        } catch let error as RelayError {
            guard case .httpStatus(500, _) = error else { return XCTFail("unexpected \(error)") }
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    // MARK: - Sign-in configuration

    @MainActor
    func testSignInRequiresARealClientID() async {
        let placeholderConfig = AppConfig(googleClientID: "1234567890-abcdefghijklmnop.apps.googleusercontent.com", googleReversedClientID: "com.googleusercontent.apps.1234567890-abcdefghijklmnop")
        for config in [AppConfig(), placeholderConfig] {
            let provider = GmailProvider(config: config, keychain: keychain, session: server.makeSession())
            await assertThrowsProviderError("notConfigured", { if case .notConfigured = $0 { return true }; return false }) {
                _ = try await provider.signIn(presenting: UIViewController())
            }
        }
        XCTAssertTrue(server.requests.isEmpty)
    }

    func testReversedClientID() {
        XCTAssertEqual(GmailProvider.reversedClientID("123-abc.apps.googleusercontent.com"), "com.googleusercontent.apps.123-abc")
    }

    func testScopesMatchTheResearchDocExactly() {
        XCTAssertEqual(GmailProvider.scopes.filter { $0.contains("googleapis.com/auth/") }, ["https://www.googleapis.com/auth/gmail.readonly"], "read-only Gmail scope only")
        XCTAssertEqual(Set(GmailProvider.scopes), ["https://www.googleapis.com/auth/gmail.readonly", "openid", "email"], "exactly the docs/research/gmail.md scope set; no `profile`")
    }

    // MARK: - Sign-out without a stored state

    func testSignOutWithoutStateOnlyClearsKeychain() async throws {
        try keychain.setString("someone@example.com", for: GmailProvider.emailKeyPrefix + accountID.uuidString)
        server.handle { request in
            request.method == "DELETE" && request.path.hasPrefix("/v1/devices/accounts/") ? .empty : .notFound
        }

        try await provider.signOut(accountID: accountID)

        XCTAssertNil(try keychain.getString(GmailProvider.emailKeyPrefix + accountID.uuidString))
        XCTAssertEqual(server.requests.map { $0.method }, ["DELETE"], "no stop/revoke without a stored auth state; relay unregistration is attempted")
        XCTAssertEqual(server.requests.first?.path, "/v1/devices/accounts/" + config.accountKey(for: "someone@example.com"))
    }
}

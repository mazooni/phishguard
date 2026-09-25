import Foundation
import PhishCore
import XCTest
@testable import PhishGuard

/// `MicrosoftProvider.fetchNewMessages` end to end through a `URLProtocol` stub (MSAL bypassed by the injected token).
final class GraphDeltaSyncTests: XCTestCase {
    override func tearDown() {
        GraphStubProtocol.state.deactivate()
        super.tearDown()
    }

    private func routeFullMessages(_ harness: MicrosoftHarness, attachmentsFor ids: Set<String> = []) {
        // Generic per-message GET: answers with a full message derived from the id in the URL.
        harness.router.add("GET", contains: "/attachments") { request in
            let id = request.path.components(separatedBy: "/").dropLast().last ?? ""
            return .json(GraphFixtures.attachments([
                ["name": "\(id).pdf", "contentType": "application/pdf", "size": 10, "isInline": false],
                ["name": "pixel.gif", "contentType": "image/gif", "size": 1, "isInline": true],
            ]))
        }
        harness.router.add("GET", contains: "/me/messages/") { request in
            let id = request.path.components(separatedBy: "/").last ?? ""
            let received = "2026-09-21T0\(id.last.flatMap { Int(String($0)) }.map { $0 % 10 } ?? 0):00:00Z"
            return .json(GraphFixtures.fullMessage(id: id, received: received, subject: "Subject \(id)", hasAttachments: ids.contains(id)))
        }
    }

    func testInitialDeltaPagesHydratesAndReturnsDeltaLink() async throws {
        let harness = MicrosoftHarness()
        let deltaLink = "\(GraphFixtures.deltaBase)?$deltatoken=final-token"
        let page2 = "\(GraphFixtures.deltaBase)?$skiptoken=page2"

        harness.router.add("GET", contains: "$skiptoken=page2", response: .json(GraphFixtures.page([
            GraphFixtures.deltaEntry(id: "m3", received: "2026-09-21T03:00:00Z", hasAttachments: true),
            GraphFixtures.deltaEntry(id: "m4", received: "2026-09-21T04:00:00Z", isDraft: true),
            GraphFixtures.deltaEntry(id: "m5", removed: true),
            GraphFixtures.deltaEntry(id: "m6", received: nil), // read/unread echo: no receivedDateTime
        ], deltaLink: deltaLink)))
        harness.router.add("GET", contains: "$filter=receivedDateTime ge", response: .json(GraphFixtures.page([
            GraphFixtures.deltaEntry(id: "m2", received: "2026-09-21T02:00:00Z"),
            GraphFixtures.deltaEntry(id: "m1", received: "2026-09-21T01:00:00Z"),
        ], nextLink: page2)))
        routeFullMessages(harness, attachmentsFor: ["m3"])

        let result = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 24 * 3600)

        XCTAssertEqual(result.messages.map(\.messageID), ["m1", "m2", "m3"], "sorted ascending; draft, tombstone and echo skipped")
        XCTAssertEqual(result.cursor, SyncCursor(opaque: deltaLink))
        XCTAssertFalse(result.cursorWasReset, "a first sync has no cursor to reset")
        XCTAssertEqual(result.messages.map(\.accountID), Array(repeating: harness.accountID.uuidString, count: 3))
        XCTAssertEqual(result.messages[2].attachments, [EmailAttachment(filename: "m3.pdf", mimeType: "application/pdf", sizeBytes: 10)])
        XCTAssertEqual(result.messages[0].attachments, [])
        XCTAssertEqual(result.messages[0].htmlBody?.isEmpty, false)
        XCTAssertEqual(result.messages[0].header("Authentication-Results"), "spf=pass")
        XCTAssertEqual(result.messages[0].threadID, "conv-m1")

        // Initial request shape.
        let initial = try XCTUnwrap(harness.requests.first)
        XCTAssertEqual(initial.method, "GET")
        XCTAssertEqual(initial.path, "/v1.0/me/mailFolders/inbox/messages/delta")
        XCTAssertEqual(initial.query["$select"], GraphMailSync.deltaSelect)
        XCTAssertEqual(initial.query["changeType"], "created")
        let since = MicrosoftHarness.fixedNow.addingTimeInterval(-24 * 3600)
        XCTAssertEqual(initial.query["$filter"], "receivedDateTime ge \(GraphDate.string(from: since))")
        XCTAssertEqual(initial.header("Authorization"), "Bearer test-access-token")
        XCTAssertEqual(initial.header("Prefer"), "IdType=\"ImmutableId\", odata.maxpagesize=50")

        // nextLink followed verbatim (no re-appended query options).
        let second = try XCTUnwrap(harness.requests.dropFirst().first)
        XCTAssertEqual(second.url.absoluteString, page2)

        // Per-message GET selects body + headers, never contentBytes; attachments only for m3.
        let messageGets = harness.requests("GET", containing: "/me/messages/").filter { !$0.decodedURL.contains("/attachments") }
        XCTAssertEqual(Set(messageGets.map { $0.path.components(separatedBy: "/").last ?? "" }), ["m1", "m2", "m3"])
        for get in messageGets {
            XCTAssertEqual(get.query["$select"], GraphMailSync.messageSelect)
            XCTAssertEqual(get.header("Prefer"), "IdType=\"ImmutableId\"")
        }
        let attachmentGets = harness.requests("GET", containing: "/attachments")
        XCTAssertEqual(attachmentGets.map(\.path), ["/v1.0/me/messages/m3/attachments"])
        XCTAssertEqual(attachmentGets.first?.query["$select"], "name,contentType,size,isInline")
        XCTAssertFalse(harness.requests.contains { $0.decodedURL.contains("contentBytes") })
        XCTAssertEqual(harness.router.unmatchedRequests.count, 0)
    }

    func testStoredCursorIsFollowedVerbatim() async throws {
        let harness = MicrosoftHarness()
        let stored = "\(GraphFixtures.deltaBase)?$deltatoken=stored-token"
        let renewed = "\(GraphFixtures.deltaBase)?$deltatoken=renewed-token"
        harness.router.add("GET", contains: "$deltatoken=stored-token", response: .json(GraphFixtures.page([
            GraphFixtures.deltaEntry(id: "m7", received: "2026-09-21T07:00:00Z"),
        ], deltaLink: renewed)))
        routeFullMessages(harness)

        let result = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: SyncCursor(opaque: stored), lookback: 3600)

        XCTAssertEqual(harness.requests.first?.url.absoluteString, stored)
        XCTAssertEqual(result.messages.map(\.messageID), ["m7"])
        XCTAssertEqual(result.cursor.opaque, renewed)
        XCTAssertFalse(result.cursorWasReset)
    }

    func testStaleCursor410RestartsWithLookbackAndFlagsReset() async throws {
        let harness = MicrosoftHarness()
        let stored = "\(GraphFixtures.deltaBase)?$deltatoken=expired"
        let fresh = "\(GraphFixtures.deltaBase)?$deltatoken=fresh"
        harness.router.add("GET", contains: "$deltatoken=expired", response: StubResponse(status: 410, headers: ["Location": GraphFixtures.deltaBase]))
        harness.router.add("GET", contains: "$filter=receivedDateTime ge", response: .json(GraphFixtures.page([
            GraphFixtures.deltaEntry(id: "m8", received: "2026-09-21T06:00:00Z"),
            GraphFixtures.deltaEntry(id: "m9", received: "2026-09-19T06:00:00Z"), // older than the lookback: dropped client-side
        ], deltaLink: fresh)))
        routeFullMessages(harness)

        let result = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: SyncCursor(opaque: stored), lookback: 24 * 3600)

        XCTAssertTrue(result.cursorWasReset)
        XCTAssertEqual(result.messages.map(\.messageID), ["m8"])
        XCTAssertEqual(result.cursor.opaque, fresh)
        XCTAssertEqual(harness.requests.map(\.path).prefix(2), ["/v1.0/me/mailFolders/inbox/messages/delta", "/v1.0/me/mailFolders/inbox/messages/delta"])
        XCTAssertTrue(harness.requests[1].decodedURL.contains("$filter=receivedDateTime ge"))
    }

    func testStaleCursorSyncStateNotFoundRestarts() async throws {
        let harness = MicrosoftHarness()
        let stored = "\(GraphFixtures.deltaBase)?$deltatoken=gone"
        harness.router.add("GET", contains: "$deltatoken=gone", response: .graphError(status: 400, code: "SyncStateNotFound", message: "The sync state is not found"))
        harness.router.add("GET", contains: "$filter=receivedDateTime ge", response: .json(GraphFixtures.page([], deltaLink: "\(GraphFixtures.deltaBase)?$deltatoken=new")))

        let result = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: SyncCursor(opaque: stored), lookback: 3600)

        XCTAssertTrue(result.cursorWasReset)
        XCTAssertEqual(result.messages.count, 0)
        XCTAssertEqual(result.cursor.opaque, "\(GraphFixtures.deltaBase)?$deltatoken=new")
    }

    func testNonCursorErrorsPropagateAsHTTP() async throws {
        let harness = MicrosoftHarness()
        harness.router.add("GET", contains: "messages/delta", response: .graphError(status: 500, code: "InternalServerError"))

        do {
            _ = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 3600)
            XCTFail("expected an error")
        } catch let error as ProviderError {
            guard case .http(let status, let message) = error else { return XCTFail("unexpected \(error)") }
            XCTAssertEqual(status, 500)
            XCTAssertEqual(message?.contains("InternalServerError"), true)
        }
    }

    func testUnauthorizedMapsToNotAuthenticated() async throws {
        let harness = MicrosoftHarness()
        harness.router.add("GET", contains: "messages/delta", response: .graphError(status: 401, code: "InvalidAuthenticationToken"))

        do {
            _ = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 3600)
            XCTFail("expected an error")
        } catch let error as ProviderError {
            guard case .notAuthenticated = error else { return XCTFail("unexpected \(error)") }
        }
    }

    func testRetryAfterIsHonoredOn429() async throws {
        let harness = MicrosoftHarness()
        harness.router.add("GET", contains: "messages/delta", sequence: [
            .graphError(status: 429, code: "TooManyRequests").with(headers: ["Retry-After": "7"]),
            StubResponse(status: 503, headers: ["Retry-After": "2"]),
            .json(GraphFixtures.page([], deltaLink: "\(GraphFixtures.deltaBase)?$deltatoken=ok")),
        ])

        let result = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 3600)

        XCTAssertEqual(harness.sleeps.delays, [7, 2])
        XCTAssertEqual(harness.requests.count, 3)
        XCTAssertEqual(result.cursor.opaque, "\(GraphFixtures.deltaBase)?$deltatoken=ok")
    }

    func testThrottlingGivesUpAfterMaxAttempts() async throws {
        let harness = MicrosoftHarness()
        harness.router.add("GET", contains: "messages/delta", response: .graphError(status: 429, code: "TooManyRequests").with(headers: ["Retry-After": "1"]))

        do {
            _ = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 3600)
            XCTFail("expected an error")
        } catch let error as ProviderError {
            guard case .rateLimited(let retryAfter) = error else { return XCTFail("unexpected \(error)") }
            XCTAssertEqual(retryAfter, 1)
        }
        XCTAssertEqual(harness.requests.count, GraphClient.defaultMaxAttempts)
        XCTAssertEqual(harness.sleeps.delays.count, GraphClient.defaultMaxAttempts - 1)
    }

    func testLongRetryAfterFailsFastWithoutSleeping() async throws {
        let harness = MicrosoftHarness()
        harness.router.add("GET", contains: "messages/delta", response: StubResponse(status: 429, headers: ["Retry-After": "600"]))

        do {
            _ = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 3600)
            XCTFail("expected an error")
        } catch let error as ProviderError {
            guard case .rateLimited(let retryAfter) = error else { return XCTFail("unexpected \(error)") }
            XCTAssertEqual(retryAfter, 600)
        }
        XCTAssertEqual(harness.sleeps.delays, [])
        XCTAssertEqual(harness.requests.count, 1)
    }

    func testMessageThatVanishedBeforeHydrationIsSkipped() async throws {
        let harness = MicrosoftHarness()
        harness.router.add("GET", contains: "messages/delta", response: .json(GraphFixtures.page([
            GraphFixtures.deltaEntry(id: "m1", received: "2026-09-21T01:00:00Z"),
            GraphFixtures.deltaEntry(id: "m2", received: "2026-09-21T02:00:00Z"),
        ], deltaLink: "\(GraphFixtures.deltaBase)?$deltatoken=x")))
        harness.router.add("GET", contains: "/me/messages/m2", response: .graphError(status: 404, code: "ErrorItemNotFound"))
        routeFullMessages(harness)

        let result = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 24 * 3600)
        XCTAssertEqual(result.messages.map(\.messageID), ["m1"])
    }

    func testHydrationFailureAbortsTheRound() async throws {
        let harness = MicrosoftHarness()
        harness.router.add("GET", contains: "messages/delta", response: .json(GraphFixtures.page([
            GraphFixtures.deltaEntry(id: "m1", received: "2026-09-21T01:00:00Z"),
        ], deltaLink: "\(GraphFixtures.deltaBase)?$deltatoken=x")))
        harness.router.add("GET", contains: "/me/messages/m1", response: .graphError(status: 502, code: "BadGateway"))

        do {
            _ = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 24 * 3600)
            XCTFail("expected an error")
        } catch let error as ProviderError {
            guard case .http(502, _) = error else { return XCTFail("unexpected \(error)") }
        }
    }

    func testProcessedIdsAreSkippedBeforeHydrationAndDoNotCountTowardTheCap() async throws {
        let harness = MicrosoftHarness()
        let cap = GraphMailSync.maxMessagesPerScan
        let pageSize = GraphMailSync.pageSize
        // Page 1: only already-processed ids; pages 2...: new ids. The cap must be filled with new ids only.
        let processedIDs = (0..<pageSize).map { "old\($0)" }
        let newPages = cap / pageSize
        harness.router.add("GET", contains: "$filter=receivedDateTime ge", response: .json(GraphFixtures.page(
            processedIDs.map { GraphFixtures.deltaEntry(id: $0) },
            nextLink: "\(GraphFixtures.deltaBase)?$skiptoken=page2"
        )))
        for page in 2...(newPages + 2) {
            let entries = (0..<pageSize).map { GraphFixtures.deltaEntry(id: "new\(page)n\($0)") }
            harness.router.add("GET", contains: "$skiptoken=page\(page)", response: .json(GraphFixtures.page(entries, nextLink: "\(GraphFixtures.deltaBase)?$skiptoken=page\(page + 1)")))
        }
        routeFullMessages(harness)
        let processed = Set(processedIDs)

        let result = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 24 * 3600) { processed.contains($0) }

        XCTAssertEqual(result.messages.count, cap)
        XCTAssertTrue(result.messages.allSatisfy { $0.messageID.hasPrefix("new") })
        XCTAssertEqual(result.cursor.opaque, "\(GraphFixtures.deltaBase)?$skiptoken=page\(newPages + 2)", "resumes after the last page that contributed new ids")
        let hydrated = harness.requests("GET", containing: "/me/messages/").map { $0.path.components(separatedBy: "/").last ?? "" }
        XCTAssertEqual(hydrated.count, cap)
        XCTAssertTrue(Set(hydrated).isDisjoint(with: processed), "processed ids are never downloaded")
    }

    func testCapStopsAtNextLinkAndResumesFromIt() async throws {
        let harness = MicrosoftHarness()
        let pageSize = GraphMailSync.pageSize
        let pagesToFill = GraphMailSync.maxMessagesPerScan / pageSize
        // Pages 1...pagesToFill each carry `pageSize` messages and a nextLink; the page after would carry more.
        for page in 1...(pagesToFill + 1) {
            let entries = (0..<pageSize).map { index in
                GraphFixtures.deltaEntry(id: "p\(page)n\(index)", received: "2026-09-21T0\(index % 10):00:00Z")
            }
            let next = "\(GraphFixtures.deltaBase)?$skiptoken=page\(page + 1)"
            if page == 1 {
                harness.router.add("GET", contains: "$filter=receivedDateTime ge", response: .json(GraphFixtures.page(entries, nextLink: next)))
            } else {
                harness.router.add("GET", contains: "$skiptoken=page\(page)", response: .json(GraphFixtures.page(entries, nextLink: next)))
            }
        }
        routeFullMessages(harness)

        let result = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 24 * 3600)

        XCTAssertEqual(result.messages.count, GraphMailSync.maxMessagesPerScan)
        XCTAssertEqual(result.cursor.opaque, "\(GraphFixtures.deltaBase)?$skiptoken=page\(pagesToFill + 1)", "the unread nextLink becomes the cursor")
        XCTAssertEqual(harness.requests("GET", containing: "messages/delta").count, pagesToFill)
        let received = result.messages.map(\.receivedAt)
        XCTAssertEqual(received, received.sorted())
    }

    func testHydrationRunsAtMostFourRequestsConcurrently() async throws {
        let harness = MicrosoftHarness(responseDelay: 0.03)
        let entries = (0..<12).map { GraphFixtures.deltaEntry(id: "c\($0)", received: "2026-09-21T0\($0 % 10):00:00Z") }
        harness.router.add("GET", contains: "messages/delta", response: .json(GraphFixtures.page(entries, deltaLink: "\(GraphFixtures.deltaBase)?$deltatoken=x")))
        routeFullMessages(harness)

        let result = try await harness.provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 24 * 3600)

        XCTAssertEqual(result.messages.count, 12)
        XCTAssertLessThanOrEqual(GraphStubProtocol.state.peakConcurrency, GraphMailSync.maxConcurrentRequests)
        XCTAssertGreaterThan(GraphStubProtocol.state.peakConcurrency, 1, "hydration should run in parallel")
    }

    func testTokenProviderFailureSurfacesBeforeAnyRequest() async throws {
        let harness = MicrosoftHarness()
        var dependencies = MicrosoftProvider.Dependencies()
        dependencies.session = GraphStubProtocol.makeSession()
        dependencies.secrets = harness.secrets
        dependencies.tokenProvider = { _ in throw ProviderError.notAuthenticated }
        let provider = MicrosoftProvider(config: harness.config, keychain: Keychain(service: "PhishGuardTests.unused"), dependencies: dependencies)

        do {
            _ = try await provider.fetchNewMessages(accountID: harness.accountID, cursor: nil, lookback: 3600)
            XCTFail("expected an error")
        } catch let error as ProviderError {
            guard case .notAuthenticated = error else { return XCTFail("unexpected \(error)") }
        }
        XCTAssertEqual(harness.requests.count, 0)
    }

    // MARK: - Pure helpers

    func testStaleCursorDetection() {
        XCTAssertTrue(GraphMailSync.isStaleCursorError(GraphError(status: 410), followingStoredCursor: false))
        XCTAssertTrue(GraphMailSync.isStaleCursorError(GraphError(status: 400, code: "SyncStateNotFound"), followingStoredCursor: false))
        XCTAssertTrue(GraphMailSync.isStaleCursorError(GraphError(status: 400, code: "ResyncRequired"), followingStoredCursor: false))
        XCTAssertTrue(GraphMailSync.isStaleCursorError(GraphError(status: 400, code: "BadRequest"), followingStoredCursor: true), "a 400 on a stored link means a stale token")
        XCTAssertFalse(GraphMailSync.isStaleCursorError(GraphError(status: 400, code: "BadRequest"), followingStoredCursor: false))
        XCTAssertFalse(GraphMailSync.isStaleCursorError(GraphError(status: 500), followingStoredCursor: true))
    }

    func testRetryAfterHeaderParsing() {
        let now = Date(timeIntervalSince1970: 1_790_000_000)
        XCTAssertEqual(GraphClient.retryAfter(from: "12", now: now), 12)
        XCTAssertEqual(GraphClient.retryAfter(from: " 3 ", now: now), 3)
        XCTAssertEqual(GraphClient.retryAfter(from: "Mon, 21 Sep 2026 14:14:20 GMT", now: now), 60)
        XCTAssertNil(GraphClient.retryAfter(from: nil, now: now))
        XCTAssertNil(GraphClient.retryAfter(from: "soon", now: now))
        XCTAssertEqual(GraphClient.backoffDelay(attempt: 1), 1)
        XCTAssertEqual(GraphClient.backoffDelay(attempt: 2), 2)
        XCTAssertEqual(GraphClient.backoffDelay(attempt: 3), 4)
    }

    func testHandleRedirectURLIgnoresForeignSchemes() async {
        let harness = MicrosoftHarness()
        let handled = await MainActor.run { harness.provider.handleRedirectURL(URL(string: "https://example.com/callback")!) }
        XCTAssertFalse(handled)
        let google = await MainActor.run { harness.provider.handleRedirectURL(URL(string: "com.googleusercontent.apps.123:/oauth2redirect")!) }
        XCTAssertFalse(google)
        XCTAssertTrue(MicrosoftAuthClient.isRedirectURL(URL(string: "msauth.com.mazooni.PhishGuardTests://auth?code=x")!, bundleIdentifier: "com.mazooni.PhishGuardTests"))
        XCTAssertFalse(MicrosoftAuthClient.isRedirectURL(URL(string: "msauth.com.other.app://auth")!, bundleIdentifier: "com.mazooni.PhishGuardTests"))
        XCTAssertEqual(MicrosoftAuthClient.redirectURI(bundleIdentifier: "com.mazooni.PhishGuard"), "msauth.com.mazooni.PhishGuard://auth")
    }
}

private extension StubResponse {
    func with(headers extra: [String: String]) -> StubResponse {
        var copy = self
        for (key, value) in extra { copy.headers[key] = value }
        return copy
    }
}

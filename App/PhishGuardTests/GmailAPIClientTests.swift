import Synchronization
import XCTest
@testable import PhishGuard

/// Backoff and error classification of `GmailAPIClient`.
final class GmailAPIClientTests: XCTestCase {
    private var server: GmailStubServer!
    private let delays = GmailLocked<[TimeInterval]>([])
    private let attempts = GmailLocked(0)

    override func setUp() {
        super.setUp()
        server = GmailStubServer()
    }

    private func makeClient(maxJitter: TimeInterval = 0, maxAttempts: Int = 3) -> GmailAPIClient {
        let delays = delays
        let policy = GmailAPIClient.RetryPolicy(maxAttempts: maxAttempts, baseDelay: 1, maxDelay: 32, maxJitter: maxJitter, sleep: { delay in
            delays.withLock { $0.append(delay) }
        })
        return GmailAPIClient(session: server.makeSession(), retryPolicy: policy) { _ in "tok" }
    }

    /// Answers with `responses` in order; the last one repeats.
    private func respondInSequence(_ responses: [GmailStubServer.Response]) {
        let attempts = attempts
        server.handle { _ in
            let index = attempts.withLock { count -> Int in
                defer { count += 1 }
                return count
            }
            return responses[min(index, responses.count - 1)]
        }
    }

    func testRetriesOn429WithExponentialBackoff() async throws {
        respondInSequence([
            .googleError(status: 429, reason: "rateLimitExceeded"),
            .googleError(status: 429, reason: "rateLimitExceeded"),
            .json(GmailFixtures.profile(historyId: "1")),
        ])
        let profile: GmailProfile = try await makeClient().get("profile")
        XCTAssertEqual(profile.historyId.stringValue, "1")
        XCTAssertEqual(server.requests.count, 3)
        XCTAssertEqual(delays.withLock { $0 }, [1, 2], "1 s, then 2 s (no jitter)")
    }

    func testRetryAfterHeaderRaisesTheDelay() async throws {
        respondInSequence([
            .googleError(status: 429, reason: "rateLimitExceeded", headers: ["Retry-After": "5"]),
            .json(GmailFixtures.profile(historyId: "1")),
        ])
        let _: GmailProfile = try await makeClient().get("profile")
        XCTAssertEqual(delays.withLock { $0 }, [5])
    }

    func testGivesUpAfterMaxAttempts() async {
        respondInSequence([.googleError(status: 429, reason: "rateLimitExceeded")])
        await assertThrowsProviderError("rateLimited", { if case .rateLimited = $0 { return true }; return false }) {
            let _: GmailProfile = try await makeClient().get("profile")
        }
        XCTAssertEqual(server.requests.count, 3)
        XCTAssertEqual(delays.withLock { $0 }.count, 2)
    }

    func testRetriesOn403RateLimitReasonsOnly() async {
        respondInSequence([
            .googleError(status: 403, reason: "userRateLimitExceeded"),
            .googleError(status: 403, reason: "rateLimitExceeded"),
            .googleError(status: 403, reason: "userRateLimitExceeded"),
        ])
        await assertThrowsProviderError("rateLimited", { if case .rateLimited = $0 { return true }; return false }) {
            let _: GmailProfile = try await makeClient().get("profile")
        }
        XCTAssertEqual(server.requests.count, 3)

        server = GmailStubServer()
        attempts.withLock { $0 = 0 }
        respondInSequence([.googleError(status: 403, reason: "insufficientPermissions", message: "Insufficient Permission")])
        await assertThrowsProviderError("http 403", { if case .http(403, let message) = $0 { return message == "Insufficient Permission" }; return false }) {
            let _: GmailProfile = try await makeClient().get("profile")
        }
        XCTAssertEqual(server.requests.count, 1, "a non-rate-limit 403 is not retried")
    }

    func testDailyQuotaIsNotRetried() async {
        respondInSequence([.googleError(status: 403, reason: "dailyLimitExceeded")])
        await assertThrowsProviderError("rateLimited", { if case .rateLimited = $0 { return true }; return false }) {
            let _: GmailProfile = try await makeClient().get("profile")
        }
        XCTAssertEqual(server.requests.count, 1)
    }

    func testServerErrorsAreRetriedThenSurfaceAsHTTP() async {
        respondInSequence([GmailStubServer.Response(status: 503, body: Data())])
        await assertThrowsProviderError("http 503", { if case .http(503, _) = $0 { return true }; return false }) {
            let _: GmailProfile = try await makeClient().get("profile")
        }
        XCTAssertEqual(server.requests.count, 3)
    }

    func testNotFoundIsNotRetried() async {
        respondInSequence([.notFound])
        await assertThrowsProviderError("http 404", { if case .http(404, _) = $0 { return true }; return false }) {
            let _: GmailProfile = try await makeClient().get("profile")
        }
        XCTAssertEqual(server.requests.count, 1)
        XCTAssertTrue(delays.withLock { $0 }.isEmpty)
    }

    func testUnauthorizedRefreshesTokenOnce() async {
        let refreshFlags = GmailLocked<[Bool]>([])
        respondInSequence([.googleError(status: 401, reason: "authError")])
        let client = GmailAPIClient(session: server.makeSession(), retryPolicy: .immediate) { forceRefresh in
            refreshFlags.withLock { $0.append(forceRefresh) }
            return "tok"
        }
        await assertThrowsProviderError("notAuthenticated", { if case .notAuthenticated = $0 { return true }; return false }) {
            let _: GmailProfile = try await client.get("profile")
        }
        XCTAssertEqual(refreshFlags.withLock { $0 }, [false, true])
        XCTAssertEqual(server.requests.count, 2)
    }

    func testRevokePostsFormEncodedToken() async throws {
        server.handle { request in
            request.url.host == "oauth2.googleapis.com" && request.path == "/revoke" ? .json([String: String]()) : .notFound
        }
        try await makeClient().revoke(token: "1//abc+def=")
        let request = try XCTUnwrap(server.requests.first)
        XCTAssertEqual(request.method, "POST")
        XCTAssertEqual(request.headers["Content-Type"], "application/x-www-form-urlencoded")
        XCTAssertNil(request.headers["Authorization"], "revocation is unauthenticated")
        XCTAssertEqual(request.formBody["token"], "1//abc+def=")
    }

    func testBackoffDelayIsTruncatedAndJittered() {
        let policy = GmailAPIClient.RetryPolicy(maxAttempts: 5, baseDelay: 1, maxDelay: 4, maxJitter: 0.5, sleep: { _ in })
        for attempt in 0..<5 {
            let delay = policy.delay(forAttempt: attempt, retryAfter: nil)
            let exponential = min(pow(2, Double(attempt)), 4)
            XCTAssertGreaterThanOrEqual(delay, exponential)
            XCTAssertLessThanOrEqual(delay, min(exponential + 0.5, 4))
        }
        XCTAssertEqual(policy.delay(forAttempt: 0, retryAfter: 3), 3)
        XCTAssertEqual(policy.delay(forAttempt: 0, retryAfter: 100), 4, "Retry-After is capped too")
    }

    func testURLBuilding() {
        XCTAssertEqual(GmailAPIClient.url(path: "profile").absoluteString, "https://gmail.googleapis.com/gmail/v1/users/me/profile")
        XCTAssertEqual(
            GmailAPIClient.url(path: "history", query: [URLQueryItem(name: "startHistoryId", value: "1"), URLQueryItem(name: "labelId", value: "INBOX")]).absoluteString,
            "https://gmail.googleapis.com/gmail/v1/users/me/history?startHistoryId=1&labelId=INBOX"
        )
    }
}

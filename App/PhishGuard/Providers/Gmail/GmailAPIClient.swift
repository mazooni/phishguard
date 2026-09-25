import Foundation
import OSLog

/// Thin Gmail REST transport: bearer auth from a token provider, JSON decoding, Google error classification and
/// truncated exponential backoff with jitter on 429 / 403 rate-limit / 5xx responses. A 401 is retried once with a
/// force-refreshed token and then surfaces as `ProviderError.notAuthenticated` (nothing is ever deleted here).
struct GmailAPIClient: Sendable {
    /// Returns a bearer token; `forceRefresh` is true when the previous token was rejected with HTTP 401.
    typealias TokenProvider = @Sendable (_ forceRefresh: Bool) async throws -> String

    struct RetryPolicy: Sendable {
        /// Total attempts including the first one.
        var maxAttempts: Int = 3
        var baseDelay: TimeInterval = 1
        var maxDelay: TimeInterval = 32
        var maxJitter: TimeInterval = 1
        var sleep: @Sendable (TimeInterval) async throws -> Void = { seconds in
            try await Task.sleep(for: .seconds(seconds))
        }

        static let `default` = RetryPolicy()
        /// Retries without waiting (tests).
        static let immediate = RetryPolicy(sleep: { _ in })

        /// `min(baseDelay * 2^attempt + random jitter, maxDelay)`, never below a server-provided `Retry-After`.
        func delay(forAttempt attempt: Int, retryAfter: TimeInterval?) -> TimeInterval {
            let exponential = baseDelay * pow(2, Double(max(0, attempt)))
            let jitter = maxJitter > 0 ? Double.random(in: 0...maxJitter) : 0
            let candidate = max(exponential + jitter, retryAfter ?? 0)
            return min(candidate, maxDelay)
        }
    }

    static let baseURL = URL(string: "https://gmail.googleapis.com/gmail/v1/users/me")!
    static let revokeURL = URL(string: "https://oauth2.googleapis.com/revoke")!
    static let requestTimeout: TimeInterval = 30

    let session: URLSession
    let retryPolicy: RetryPolicy
    let tokenProvider: TokenProvider
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "gmail.api")

    init(session: URLSession, retryPolicy: RetryPolicy = .default, tokenProvider: @escaping TokenProvider) {
        self.session = session
        self.retryPolicy = retryPolicy
        self.tokenProvider = tokenProvider
    }

    // MARK: - Requests

    func get<T: Decodable>(_ path: String, query: [URLQueryItem] = []) async throws -> T {
        try decode(try await getData(path, query: query))
    }

    func getData(_ path: String, query: [URLQueryItem] = []) async throws -> Data {
        try await perform(method: "GET", url: Self.url(path: path, query: query), body: nil, contentType: nil, authenticated: true)
    }

    func post<Body: Encodable & Sendable, T: Decodable>(_ path: String, body: Body) async throws -> T {
        let data: Data
        do {
            data = try JSONEncoder().encode(body)
        } catch {
            throw ProviderError.decoding("Could not encode the request body: \(error.localizedDescription)")
        }
        let response = try await perform(method: "POST", url: Self.url(path: path), body: data, contentType: "application/json", authenticated: true)
        return try decode(response)
    }

    /// POST without a body whose response content is irrelevant (e.g. `users.stop`).
    func postEmpty(_ path: String) async throws {
        _ = try await perform(method: "POST", url: Self.url(path: path), body: nil, contentType: nil, authenticated: true)
    }

    /// `POST https://oauth2.googleapis.com/revoke` (form-encoded, unauthenticated). Revokes a refresh or access token.
    func revoke(token: String) async throws {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        let encoded = token.addingPercentEncoding(withAllowedCharacters: allowed) ?? token
        _ = try await perform(
            method: "POST",
            url: Self.revokeURL,
            body: Data("token=\(encoded)".utf8),
            contentType: "application/x-www-form-urlencoded",
            authenticated: false
        )
    }

    // MARK: - Transport

    private func perform(method: String, url: URL, body: Data?, contentType: String?, authenticated: Bool) async throws -> Data {
        var attempt = 0
        var forceRefresh = false
        var refreshedOnce = false

        while true {
            try Task.checkCancellation()
            var request = URLRequest(url: url)
            request.httpMethod = method
            request.timeoutInterval = Self.requestTimeout
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            if let body {
                request.httpBody = body
                request.setValue(contentType, forHTTPHeaderField: "Content-Type")
            }
            if authenticated {
                let token = try await tokenProvider(forceRefresh)
                forceRefresh = false
                request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            }

            let data: Data
            let response: URLResponse
            do {
                (data, response) = try await session.data(for: request)
            } catch is CancellationError {
                throw CancellationError()
            } catch let error as URLError where error.code == .cancelled {
                throw CancellationError()
            } catch {
                throw ProviderError.network(error.localizedDescription)
            }
            guard let http = response as? HTTPURLResponse else {
                throw ProviderError.network("Non-HTTP response from Gmail")
            }
            let status = http.statusCode
            if (200..<300).contains(status) { return data }

            let failure = Failure(status: status, data: data, response: http)
            logger.notice("Gmail \(method, privacy: .public) \(url.path, privacy: .private) → \(status) \(failure.reason ?? "-", privacy: .public)")

            if status == 401 {
                if authenticated, !refreshedOnce {
                    refreshedOnce = true
                    forceRefresh = true
                    continue
                }
                throw ProviderError.notAuthenticated
            }

            if failure.isRetryable {
                if attempt + 1 < retryPolicy.maxAttempts {
                    let delay = retryPolicy.delay(forAttempt: attempt, retryAfter: failure.retryAfter)
                    attempt += 1
                    logger.notice("Gmail backoff: attempt \(attempt) in \(delay, format: .fixed(precision: 2)) s")
                    try await retryPolicy.sleep(delay)
                    continue
                }
                if failure.isRateLimit { throw ProviderError.rateLimited(retryAfter: failure.retryAfter) }
            } else if failure.isQuotaExhausted {
                throw ProviderError.rateLimited(retryAfter: failure.retryAfter)
            }
            throw ProviderError.http(status: status, message: failure.message)
        }
    }

    private func decode<T: Decodable>(_ data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw ProviderError.decoding("\(T.self): \(error.localizedDescription)")
        }
    }

    static func url(path: String, query: [URLQueryItem] = []) -> URL {
        let base = baseURL.appending(path: path)
        guard !query.isEmpty, var components = URLComponents(url: base, resolvingAgainstBaseURL: false) else { return base }
        components.queryItems = query
        return components.url ?? base
    }

    // MARK: - Error classification

    /// Classification of a non-2xx Gmail response.
    struct Failure: Sendable {
        static let rateLimitReasons: Set<String> = ["ratelimitexceeded", "userratelimitexceeded"]
        static let quotaReasons: Set<String> = ["dailylimitexceeded", "quotaexceeded"]

        let status: Int
        let reason: String?
        let message: String?
        let retryAfter: TimeInterval?

        init(status: Int, data: Data, response: HTTPURLResponse) {
            self.status = status
            let envelope = try? JSONDecoder().decode(GmailErrorEnvelope.self, from: data)
            reason = envelope?.error.errors?.first?.reason?.lowercased()
                ?? envelope?.error.status?.lowercased()
            message = envelope?.error.message
            retryAfter = response.value(forHTTPHeaderField: "Retry-After").flatMap { TimeInterval($0.trimmingCharacters(in: .whitespaces)) }
        }

        var isRateLimit: Bool {
            status == 429 || (status == 403 && reason.map { Self.rateLimitReasons.contains($0) } == true)
        }

        var isQuotaExhausted: Bool {
            status == 403 && reason.map { Self.quotaReasons.contains($0) } == true
        }

        var isRetryable: Bool {
            isRateLimit || (500...599).contains(status)
        }
    }
}

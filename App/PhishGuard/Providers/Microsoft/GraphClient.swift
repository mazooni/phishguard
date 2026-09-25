import Foundation
import OSLog

/// A non-2xx Microsoft Graph response (after retries). `code` is the OData error code when the body carried one.
struct GraphError: Error, Sendable, Equatable {
    var status: Int
    var code: String?
    var message: String?
    var retryAfter: TimeInterval?

    init(status: Int, code: String? = nil, message: String? = nil, retryAfter: TimeInterval? = nil) {
        self.status = status
        self.code = code
        self.message = message
        self.retryAfter = retryAfter
    }
}

struct GraphErrorEnvelope: Decodable, Sendable {
    struct Body: Decodable, Sendable {
        var code: String?
        var message: String?
    }

    var error: Body
}

extension ProviderError {
    /// Maps a Graph failure onto the provider error vocabulary shared with the scan pipeline.
    init(graph error: GraphError) {
        switch error.status {
        case 401:
            self = .notAuthenticated
        case 429, 503:
            self = .rateLimited(retryAfter: error.retryAfter)
        default:
            let detail = [error.code, error.message].compactMap { $0 }.joined(separator: ": ")
            self = .http(status: error.status, message: detail.isEmpty ? nil : detail)
        }
    }
}

/// Minimal Graph transport: bearer auth, `Prefer` headers, JSON decoding and 429/503 backoff honoring `Retry-After`.
/// The `URLSession` and the sleep function are injectable so tests run against a `URLProtocol` stub without delays.
struct GraphClient: Sendable {
    typealias Sleeper = @Sendable (TimeInterval) async throws -> Void

    static let baseURL = URL(string: "https://graph.microsoft.com/v1.0/")!
    /// Ids that survive folder moves; used consistently on delta, GET and subscription creation (research §4).
    static let immutableIDPreference = "IdType=\"ImmutableId\""
    static let defaultMaxAttempts = 3
    /// Longer `Retry-After` values are not waited for inside a (short) background scan; the scan fails fast instead.
    static let defaultMaxRetryDelay: TimeInterval = 30

    struct Response: Sendable {
        var status: Int
        var data: Data
        var headers: [String: String]

        func header(_ name: String) -> String? {
            headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
        }
    }

    var session: URLSession
    var maxAttempts: Int
    var maxRetryDelay: TimeInterval
    var sleeper: Sleeper

    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "graph")

    init(
        session: URLSession = .shared,
        maxAttempts: Int = GraphClient.defaultMaxAttempts,
        maxRetryDelay: TimeInterval = GraphClient.defaultMaxRetryDelay,
        sleeper: @escaping Sleeper = { try await Task.sleep(for: .seconds($0)) }
    ) {
        self.session = session
        self.maxAttempts = maxAttempts
        self.maxRetryDelay = maxRetryDelay
        self.sleeper = sleeper
    }

    static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let raw = try container.decode(String.self)
            guard let date = GraphDate.parse(raw) else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unrecognized Graph date: \(raw)")
            }
            return date
        }
        return decoder
    }()

    /// Resolves a Graph path (`me/messages/...`) or an absolute URL (nextLink / deltaLink) against the v1.0 base.
    static func url(for pathOrURL: String) -> URL {
        if let absolute = URL(string: pathOrURL), absolute.scheme != nil { return absolute }
        return URL(string: pathOrURL, relativeTo: baseURL)?.absoluteURL ?? baseURL
    }

    // MARK: - Requests

    /// Performs one request, retrying 429/503 (honoring `Retry-After`) and throwing `GraphError` for other non-2xx statuses.
    func request(
        _ url: URL,
        method: String = "GET",
        token: String,
        prefer: [String] = [],
        body: Data? = nil
    ) async throws -> Response {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = 30
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if !prefer.isEmpty { request.setValue(prefer.joined(separator: ", "), forHTTPHeaderField: "Prefer") }
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        var attempt = 0
        while true {
            let data: Data
            let response: URLResponse
            do {
                (data, response) = try await session.data(for: request)
            } catch {
                throw ProviderError.network(error.localizedDescription)
            }
            guard let http = response as? HTTPURLResponse else { throw ProviderError.network("Non-HTTP response from Graph") }
            let headers = http.allHeaderFields.reduce(into: [String: String]()) { result, pair in
                if let key = pair.key as? String, let value = pair.value as? String { result[key] = value }
            }
            let result = Response(status: http.statusCode, data: data, headers: headers)

            if http.statusCode == 429 || http.statusCode == 503 {
                attempt += 1
                let retryAfter = Self.retryAfter(from: result.header("Retry-After"))
                let delay = retryAfter ?? Self.backoffDelay(attempt: attempt)
                if attempt < maxAttempts, delay <= maxRetryDelay {
                    logger.notice("Graph \(method, privacy: .public) throttled (\(http.statusCode)); retrying in \(delay, privacy: .public)s")
                    try await sleeper(delay)
                    continue
                }
                throw GraphError(status: http.statusCode, code: nil, message: "Throttled", retryAfter: retryAfter)
            }

            guard (200..<300).contains(http.statusCode) else {
                let envelope = try? Self.decoder.decode(GraphErrorEnvelope.self, from: data)
                logger.error("Graph \(method, privacy: .public) \(url.path, privacy: .private) → \(http.statusCode) \(envelope?.error.code ?? "", privacy: .public)")
                throw GraphError(status: http.statusCode, code: envelope?.error.code, message: envelope?.error.message, retryAfter: nil)
            }
            return result
        }
    }

    func get<T: Decodable>(_ pathOrURL: String, token: String, prefer: [String] = []) async throws -> T {
        let response = try await request(Self.url(for: pathOrURL), token: token, prefer: prefer)
        return try decode(T.self, from: response.data)
    }

    func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try Self.decoder.decode(type, from: data)
        } catch {
            throw ProviderError.decoding(String(describing: error))
        }
    }

    // MARK: - Backoff helpers

    /// `Retry-After` is either delay-seconds or an HTTP-date.
    static func retryAfter(from header: String?, now: Date = Date()) -> TimeInterval? {
        guard let header = header?.trimmingCharacters(in: .whitespaces), !header.isEmpty else { return nil }
        if let seconds = TimeInterval(header) { return max(0, seconds) }
        if let date = httpDateFormatter.date(from: header) { return max(0, date.timeIntervalSince(now)) }
        return nil
    }

    static func backoffDelay(attempt: Int) -> TimeInterval {
        pow(2, Double(max(0, attempt - 1)))
    }

    private static let httpDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        return formatter
    }()
}

import CryptoKit
import Foundation
import OSLog
import PhishCore
import Synchronization

struct RelayConfig: Sendable, Equatable {
    var baseURL: URL
    var apiKey: String
    var gmailPubSubTopic: String

    init(baseURL: URL, apiKey: String, gmailPubSubTopic: String) {
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.gmailPubSubTopic = gmailPubSubTopic
    }
}

enum RelayError: Error, LocalizedError, Sendable, Equatable {
    case notConfigured
    case invalidResponse
    /// Non-2xx response. `body` is the server's message (`error` / `message` / `reason` JSON field, else the raw
    /// body prefix) when one was returned.
    case httpStatus(Int, body: String?)
    /// Transport failure (offline, timeout, DNS…) after retries were exhausted.
    case network(String)

    var errorDescription: String? {
        switch self {
        case .notConfigured: return "The relay is not configured (RELAY_BASE_URL / RELAY_API_KEY / RELAY_SALT)."
        case .invalidResponse: return "The relay returned an invalid response."
        case .httpStatus(let status, let body): return "Relay HTTP \(status)\(body.map { ": \(String($0.prefix(200)))" } ?? "")"
        case .network(let message): return "Relay unreachable: \(message)"
        }
    }

    var statusCode: Int? {
        if case .httpStatus(let status, _) = self { return status }
        return nil
    }

    /// The message the relay sent with a non-2xx response, if any.
    var serverMessage: String? {
        if case .httpStatus(_, let body) = self { return body }
        return nil
    }

    /// True for failures that are worth retrying (transport errors, 408/425/429, 5xx).
    var isTransient: Bool {
        switch self {
        case .network: return true
        case .httpStatus(let status, _): return status == 408 || status == 425 || status == 429 || status >= 500
        case .notConfigured, .invalidResponse: return false
        }
    }

    /// True when a device-scoped route says the relay no longer knows this device (its row was lost or removed):
    /// `deviceAuthGuard` answers 401 for an unknown device secret and never creates rows.
    var indicatesUnknownDevice: Bool {
        statusCode == 401 || statusCode == 404
    }
}

/// Client for the relay ("doorbell") service. Authentication: `Authorization: Bearer <deviceSecret>` where the secret is
/// random, generated on first use and kept in the Keychain, plus the shared `X-API-Key`. The relay never receives mail
/// content, credentials or plaintext account identifiers — only the salted `accountKey` hash.
///
/// Transient failures are retried with exponential backoff; device registration is idempotent (only sent when the
/// token, environment or relay changed since the last successful registration). When an account route answers
/// 401/404 the relay has forgotten the device (e.g. its database was reset): the remembered registration is dropped,
/// `POST /v1/devices` is re-sent with the token last handed to `registerDevice` (kept in memory only — device tokens
/// are never persisted) and the request is retried once.
struct RelayClient: Sendable {
    static let deviceSecretKey = "relay.deviceSecret"
    static let deviceIDKey = "relay.deviceID"
    /// UserDefaults key holding a fingerprint (not the token) of the last successful device registration.
    static let lastDeviceRegistrationKey = "relay.lastDeviceRegistration"
    static let requestTimeout: TimeInterval = 15
    /// The live WebSocket's request timeout. `URLRequest.timeoutInterval` is an idle timer, so it must sit well
    /// above the 25 s ping cadence (`CallGuardClient.pingInterval`) or a quiet socket — no call in progress — would
    /// be torn down and reopened between pings. 60 s is URLSession's own default.
    static let webSocketTimeout: TimeInterval = 60

    struct RetryPolicy: Sendable, Equatable {
        /// Total attempts including the first one.
        var maxAttempts: Int
        var initialDelay: TimeInterval
        var multiplier: Double

        init(maxAttempts: Int, initialDelay: TimeInterval, multiplier: Double) {
            self.maxAttempts = max(1, maxAttempts)
            self.initialDelay = max(0, initialDelay)
            self.multiplier = max(1, multiplier)
        }

        /// 3 attempts: immediately, after 0.5 s, after another 1.5 s.
        static let `default` = RetryPolicy(maxAttempts: 3, initialDelay: 0.5, multiplier: 3)
        static let none = RetryPolicy(maxAttempts: 1, initialDelay: 0, multiplier: 1)

        /// Delay to wait before `attempt` (1-based; attempt 1 has no delay).
        func delay(beforeAttempt attempt: Int) -> TimeInterval {
            guard attempt > 1 else { return 0 }
            return initialDelay * pow(multiplier, Double(attempt - 2))
        }
    }

    let config: RelayConfig?
    let bundleIdentifier: String

    private let keychain: Keychain
    private let session: URLSession
    private let registrationStore: RegistrationStore
    private let lastRegistration: LastRegistration
    private let retryPolicy: RetryPolicy
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "relay")

    init(
        config: RelayConfig?,
        keychain: Keychain,
        bundleIdentifier: String,
        session: URLSession = .shared,
        defaults: UserDefaults = .standard,
        retryPolicy: RetryPolicy = .default
    ) {
        self.config = config
        self.keychain = keychain
        self.bundleIdentifier = bundleIdentifier
        self.session = session
        self.registrationStore = RegistrationStore(defaults: defaults)
        self.lastRegistration = LastRegistration()
        self.retryPolicy = retryPolicy
    }

    var isConfigured: Bool { config != nil }

    // MARK: - Relay contract

    /// `POST /v1/devices {deviceID, apnsToken?, environment, bundleID}`.
    ///
    /// Idempotent: the request is only sent when the token, environment or relay URL differs from the last
    /// successful registration (or `force` is set). Returns whether a request was sent.
    ///
    /// `apnsToken` is nil when iOS refused APNs registration (no push entitlement: a free Apple team, the
    /// Simulator without a paid key). The device is still registered — without a token — so the relay's
    /// device-scoped routes, and with them Call Guard's line, history, demo and live feed, keep working; only
    /// pushes are impossible, and the relay keeps any token it already has for this device.
    @discardableResult
    func registerDevice(apnsToken: Data?, environment: String, force: Bool = false) async throws -> Bool {
        guard let config else { throw RelayError.notConfigured }
        lastRegistration.remember(apnsToken: apnsToken, environment: environment)
        let tokenHex = apnsToken.map(Self.hexString)
        let fingerprint = Self.registrationFingerprint(baseURL: config.baseURL, environment: environment, tokenHex: tokenHex ?? Self.noTokenMarker)
        if !force, registrationStore.lastFingerprint == fingerprint {
            logger.debug("Device registration unchanged; not re-sending")
            return false
        }
        var body: [String: String] = [
            "deviceID": try deviceID(),
            "environment": environment,
            "bundleID": bundleIdentifier,
        ]
        if let tokenHex { body["apnsToken"] = tokenHex }
        try await send(method: "POST", path: "v1/devices", body: body)
        registrationStore.lastFingerprint = fingerprint
        logger.info("Device registered with relay (environment=\(environment, privacy: .public), token=\(tokenHex != nil, privacy: .public))")
        return true
    }

    /// Stands in for the token in the registration fingerprint when iOS handed out none.
    static let noTokenMarker = "none"

    /// `POST /v1/devices/accounts {accountKey, provider}`
    func registerAccount(accountKey: String, provider: MailProvider) async throws {
        try await sendDeviceScoped(method: "POST", path: "v1/devices/accounts", body: ["accountKey": accountKey, "provider": provider.rawValue])
    }

    /// `DELETE /v1/devices/accounts/:accountKey`
    func unregisterAccount(accountKey: String) async throws {
        try await sendDeviceScoped(method: "DELETE", path: "v1/devices/accounts/\(accountKey)", body: nil)
    }

    /// `POST /v1/devices/graph-subscriptions {subscriptionID, accountKey, clientState}` — lets the relay map Graph
    /// webhook calls to an account and verify the `clientState` Graph echoes back (a per-account random secret).
    func registerGraphSubscription(subscriptionID: String, accountKey: String, clientState: String) async throws {
        try await sendDeviceScoped(method: "POST", path: "v1/devices/graph-subscriptions",
                                   body: ["subscriptionID": subscriptionID, "accountKey": accountKey, "clientState": clientState])
    }

    /// Forgets the remembered device registration so the next `registerDevice` is sent again.
    func resetDeviceRegistration() {
        registrationStore.lastFingerprint = nil
    }

    /// Re-sends `POST /v1/devices` with the token last handed to `registerDevice` in this process. Returns false when
    /// no token was received yet (the registration is then re-sent by the next token callback).
    @discardableResult
    func reregisterDevice() async throws -> Bool {
        resetDeviceRegistration()
        guard let last = lastRegistration.current else { return false }
        return try await registerDevice(apnsToken: last.apnsToken, environment: last.environment, force: true)
    }

    // MARK: - Transport

    /// Routes behind the relay's `deviceAuthGuard`: a 401/404 means the relay no longer knows this device, so the
    /// registration is re-sent and the request retried once. When no token is available the remembered
    /// registration is still dropped and the original error propagates.
    private func sendDeviceScoped(method: String, path: String, body: [String: String]?) async throws {
        _ = try await data(method: method, path: path, body: try Self.encode(body))
    }

    /// A device-scoped request that returns the response body, for clients built on the relay's device auth
    /// (`CallGuardClient`). Same headers, timeout and retry policy as every other relay call, and the same
    /// recovery as `sendDeviceScoped`: a 401 — or a 404 unless `reregisterOnNotFound` is false, for routes where
    /// the relay documents a 404 with another meaning (`no_line`, `not_found`) — re-sends the device registration
    /// and retries once. `body` is already-encoded JSON.
    func data(
        method: String,
        path: String,
        body: Data? = nil,
        queryItems: [URLQueryItem] = [],
        reregisterOnNotFound: Bool = true
    ) async throws -> Data {
        do {
            return try await transmit(method: method, path: path, body: body, queryItems: queryItems)
        } catch let error as RelayError where error.indicatesUnknownDevice && (reregisterOnNotFound || error.statusCode == 401) {
            logger.notice("Relay rejected the device on \(method, privacy: .public) \(path, privacy: .public) (\(error.localizedDescription, privacy: .public)); re-registering")
            let reregistered: Bool
            do {
                reregistered = try await reregisterDevice()
            } catch let registrationError {
                logger.error("Device re-registration failed: \(registrationError.localizedDescription, privacy: .public)")
                throw error
            }
            guard reregistered else { throw error }
            return try await transmit(method: method, path: path, body: body, queryItems: queryItems)
        }
    }

    /// A request carrying the device's credentials (`Authorization: Bearer <deviceSecret>`, `X-API-Key`) without
    /// sending it, for the live WebSocket. `webSocket` swaps the scheme to `wss`/`ws`.
    func authorizedRequest(method: String, path: String, queryItems: [URLQueryItem] = [], webSocket: Bool = false) throws -> URLRequest {
        guard let config else { throw RelayError.notConfigured }
        var url = config.baseURL.appending(path: path)
        if !queryItems.isEmpty {
            url.append(queryItems: queryItems)
        }
        if webSocket, var components = URLComponents(url: url, resolvingAgainstBaseURL: false) {
            switch components.scheme?.lowercased() {
            case "https": components.scheme = "wss"
            case "http": components.scheme = "ws"
            default: break
            }
            url = components.url ?? url
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = webSocket ? Self.webSocketTimeout : Self.requestTimeout
        request.setValue("Bearer \(try deviceSecret())", forHTTPHeaderField: "Authorization")
        request.setValue(config.apiKey, forHTTPHeaderField: "X-API-Key")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }

    private func send(method: String, path: String, body: [String: String]?) async throws {
        _ = try await transmit(method: method, path: path, body: try Self.encode(body), queryItems: [])
    }

    private static func encode(_ body: [String: String]?) throws -> Data? {
        try body.map { try JSONSerialization.data(withJSONObject: $0, options: [.sortedKeys]) }
    }

    private func transmit(method: String, path: String, body: Data?, queryItems: [URLQueryItem]) async throws -> Data {
        var request = try authorizedRequest(method: method, path: path, queryItems: queryItems)
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        var attempt = 1
        while true {
            do {
                return try await perform(request, method: method, path: path)
            } catch let error as RelayError where error.isTransient && attempt < retryPolicy.maxAttempts {
                attempt += 1
                let delay = retryPolicy.delay(beforeAttempt: attempt)
                logger.notice("Relay \(method, privacy: .public) \(path, privacy: .public) failed (\(error.localizedDescription, privacy: .public)); retry \(attempt)/\(self.retryPolicy.maxAttempts) in \(delay, privacy: .public) s")
                if delay > 0 {
                    try await Task.sleep(for: .seconds(delay))
                }
            }
        }
    }

    private func perform(_ request: URLRequest, method: String, path: String) async throws -> Data {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch let urlError as URLError where urlError.code == .cancelled {
            throw CancellationError()
        } catch {
            throw RelayError.network(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else { throw RelayError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            let message = Self.serverMessage(from: data)
            logger.error("Relay \(method, privacy: .public) \(path, privacy: .public) → \(http.statusCode) \(message ?? "", privacy: .public)")
            throw RelayError.httpStatus(http.statusCode, body: message)
        }
        logger.debug("Relay \(method, privacy: .public) \(path, privacy: .public) → \(http.statusCode)")
        return data
    }

    /// Extracts a human-readable message from an error body: `error` / `message` / `reason` (string or object with
    /// `message`) in JSON, else the trimmed body prefix.
    static func serverMessage(from data: Data) -> String? {
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            for key in ["error", "message", "reason", "detail"] {
                if let text = object[key] as? String, !text.isEmpty { return String(text.prefix(200)) }
                if let nested = object[key] as? [String: Any], let text = nested["message"] as? String, !text.isEmpty {
                    return String(text.prefix(200))
                }
            }
        }
        let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : String(text.prefix(200))
    }

    // MARK: - Device identity (Keychain)

    private func deviceSecret() throws -> String {
        try identity(key: Self.deviceSecretKey) { Self.randomHex(byteCount: 32) }
    }

    private func deviceID() throws -> String {
        try identity(key: Self.deviceIDKey) { UUID().uuidString }
    }

    /// Reads a Keychain-backed identity value, creating it on first use. Two callers can race here (iOS delivered
    /// the APNs token twice at one launch): the first writer wins and the loser reads that value back, so both
    /// register the same secret and id. Overwriting would leave the relay knowing a secret the app no longer has.
    private func identity(key: String, make: () -> String) throws -> String {
        if let existing = try keychain.getString(key), !existing.isEmpty { return existing }
        let fresh = make()
        if try keychain.setStringIfAbsent(fresh, for: key) { return fresh }
        guard let stored = try keychain.getString(key), !stored.isEmpty else {
            throw Keychain.KeychainError.unexpectedStatus(errSecItemNotFound)
        }
        return stored
    }

    // MARK: - Helpers

    static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// SHA-256 over relay URL, environment and token hex — remembered instead of the token itself.
    static func registrationFingerprint(baseURL: URL, environment: String, tokenHex: String) -> String {
        let input = Data("\(baseURL.absoluteString)|\(environment)|\(tokenHex)".utf8)
        return SHA256.hash(data: input).map { String(format: "%02x", $0) }.joined()
    }

    private static func randomHex(byteCount: Int) -> String {
        (0..<byteCount).map { _ in String(format: "%02x", UInt8.random(in: .min ... .max)) }.joined()
    }
}

/// The token and environment last handed to `registerDevice`, kept in memory only (per the APNs guidance, device
/// tokens are never cached in local storage) so a forgotten registration can be re-sent without a new token
/// callback. Shared by every copy of the `RelayClient` value.
private final class LastRegistration: Sendable {
    struct Entry: Sendable {
        let apnsToken: Data?
        let environment: String
    }

    private let entry = Mutex<Entry?>(nil)

    var current: Entry? { entry.withLock { $0 } }

    func remember(apnsToken: Data?, environment: String) {
        entry.withLock { $0 = Entry(apnsToken: apnsToken, environment: environment) }
    }
}

/// `UserDefaults` is thread-safe but not marked `Sendable` in the SDK; this box only ever touches one key.
private struct RegistrationStore: @unchecked Sendable {
    let defaults: UserDefaults

    var lastFingerprint: String? {
        get { defaults.string(forKey: RelayClient.lastDeviceRegistrationKey) }
        nonmutating set {
            if let newValue {
                defaults.set(newValue, forKey: RelayClient.lastDeviceRegistrationKey)
            } else {
                defaults.removeObject(forKey: RelayClient.lastDeviceRegistrationKey)
            }
        }
    }
}

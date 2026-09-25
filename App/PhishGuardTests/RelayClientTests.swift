import Foundation
import PhishCore
import Synchronization
import XCTest
@testable import PhishGuard

/// URLProtocol stub: records every request and replays canned responses in order (200 with empty body when exhausted).
final class RelayStubProtocol: URLProtocol {
    struct Response: Sendable {
        var status: Int
        var body: Data

        init(status: Int, body: String = "") {
            self.status = status
            self.body = Data(body.utf8)
        }
    }

    struct Recorded: Sendable {
        let method: String?
        let url: URL?
        let headers: [String: String]
        let body: Data?
        let timeout: TimeInterval

        var json: [String: String]? {
            body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: String] }
        }
    }

    struct State: Sendable {
        var responses: [Response] = []
        var requests: [Recorded] = []
    }

    static let state = Mutex(State())

    static func reset(responses: [Response] = []) {
        state.withLock { $0 = State(responses: responses) }
    }

    static var requests: [Recorded] { state.withLock { $0.requests } }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let request = self.request
        let recorded = Recorded(
            method: request.httpMethod,
            url: request.url,
            headers: request.allHTTPHeaderFields ?? [:],
            body: Self.readBody(request),
            timeout: request.timeoutInterval
        )
        let response = Self.state.withLock { state -> Response in
            state.requests.append(recorded)
            return state.responses.isEmpty ? Response(status: 200) : state.responses.removeFirst()
        }
        guard let url = request.url,
              let http = HTTPURLResponse(url: url, statusCode: response.status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"]) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }
        client?.urlProtocol(self, didReceive: http, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: response.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func readBody(_ request: URLRequest) -> Data? {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let bufferSize = 4096
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: bufferSize)
            if count <= 0 { break }
            data.append(buffer, count: count)
        }
        return data
    }
}

final class RelayClientTests: XCTestCase {
    private static let baseURL = URL(string: "https://relay.test")!
    private let token = Data([0x0a, 0x0b, 0xff, 0x10])

    private var keychain: Keychain!
    private var defaults: UserDefaults!
    private var suite: String!

    override func setUpWithError() throws {
        try super.setUpWithError()
        suite = "PhishGuardTests.relay.\(UUID().uuidString)"
        defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        keychain = Keychain(service: suite)
        RelayStubProtocol.reset()
    }

    override func tearDownWithError() throws {
        defaults.removePersistentDomain(forName: suite)
        try? keychain.delete(RelayClient.deviceSecretKey)
        try? keychain.delete(RelayClient.deviceIDKey)
        RelayStubProtocol.reset()
        try super.tearDownWithError()
    }

    private func makeClient(configured: Bool = true, retry: RelayClient.RetryPolicy = RelayClient.RetryPolicy(maxAttempts: 3, initialDelay: 0, multiplier: 1)) -> RelayClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RelayStubProtocol.self]
        let session = URLSession(configuration: configuration)
        let config = configured ? RelayConfig(baseURL: Self.baseURL, apiKey: "shared-key", gmailPubSubTopic: "projects/p/topics/t") : nil
        return RelayClient(config: config, keychain: keychain, bundleIdentifier: "com.mazooni.PhishGuard", session: session, defaults: defaults, retryPolicy: retry)
    }

    // MARK: - Request shapes

    func testRegisterDeviceRequestShape() async throws {
        let client = makeClient()

        let sent = try await client.registerDevice(apnsToken: token, environment: "sandbox")

        XCTAssertTrue(sent)
        let requests = RelayStubProtocol.requests
        XCTAssertEqual(requests.count, 1)
        let request = try XCTUnwrap(requests.first)
        XCTAssertEqual(request.method, "POST")
        XCTAssertEqual(request.url?.absoluteString, "https://relay.test/v1/devices")
        XCTAssertEqual(request.timeout, RelayClient.requestTimeout)
        XCTAssertEqual(request.timeout, 15)
        XCTAssertEqual(request.headers["X-API-Key"], "shared-key")
        XCTAssertEqual(request.headers["Content-Type"], "application/json")
        XCTAssertEqual(request.headers["Accept"], "application/json")
        let authorization = try XCTUnwrap(request.headers["Authorization"])
        XCTAssertTrue(authorization.hasPrefix("Bearer "))
        let secret = String(authorization.dropFirst("Bearer ".count))
        XCTAssertEqual(secret.count, 64)
        XCTAssertTrue(secret.allSatisfy(\.isHexDigit))

        let body = try XCTUnwrap(request.json)
        XCTAssertEqual(body["apnsToken"], "0a0bff10")
        XCTAssertEqual(body["environment"], "sandbox")
        XCTAssertEqual(body["bundleID"], "com.mazooni.PhishGuard")
        XCTAssertNotNil(UUID(uuidString: try XCTUnwrap(body["deviceID"])))
        XCTAssertEqual(Set(body.keys), ["deviceID", "apnsToken", "environment", "bundleID"])
    }

    func testRegisterDeviceWithoutATokenOmitsTheFieldAndIsRememberedSeparately() async throws {
        let client = makeClient()

        let sent = try await client.registerDevice(apnsToken: nil, environment: "sandbox")
        XCTAssertTrue(sent)
        let body = try XCTUnwrap(RelayStubProtocol.requests.first?.json)
        XCTAssertEqual(Set(body.keys), ["deviceID", "environment", "bundleID"])

        // Same tokenless registration again: nothing to send.
        let repeated = try await client.registerDevice(apnsToken: nil, environment: "sandbox")
        XCTAssertFalse(repeated)
        XCTAssertEqual(RelayStubProtocol.requests.count, 1)

        // A token arriving later is a different registration and is sent.
        let withToken = try await client.registerDevice(apnsToken: token, environment: "sandbox")
        XCTAssertTrue(withToken)
        XCTAssertEqual(RelayStubProtocol.requests.count, 2)
        XCTAssertEqual(RelayStubProtocol.requests.last?.json?["apnsToken"], "0a0bff10")

        // And a tokenless registration after that is re-sent too (the relay keeps the stored token).
        let tokenlessAgain = try await client.registerDevice(apnsToken: nil, environment: "sandbox")
        XCTAssertTrue(tokenlessAgain)
        XCTAssertEqual(RelayStubProtocol.requests.count, 3)
        XCTAssertNil(RelayStubProtocol.requests.last?.json?["apnsToken"])
    }

    func testKeychainSetIfAbsentKeepsTheFirstWriter() async throws {
        XCTAssertTrue(try keychain.setStringIfAbsent("first", for: RelayClient.deviceSecretKey))
        XCTAssertFalse(try keychain.setStringIfAbsent("second", for: RelayClient.deviceSecretKey))
        XCTAssertEqual(try keychain.getString(RelayClient.deviceSecretKey), "first")
        // A device secret created before the client runs is what the client uses, never a fresh one.
        let client = makeClient()
        let sent = try await client.registerDevice(apnsToken: token, environment: "sandbox")
        XCTAssertTrue(sent)
        XCTAssertEqual(RelayStubProtocol.requests.first?.headers["Authorization"], "Bearer first")
    }

    func testDeviceIdentityIsStableAcrossCalls() async throws {
        let client = makeClient()

        try await client.registerDevice(apnsToken: token, environment: "sandbox")
        try await client.registerAccount(accountKey: String(repeating: "a", count: 64), provider: .gmail)

        let requests = RelayStubProtocol.requests
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(requests[0].headers["Authorization"], requests[1].headers["Authorization"])
    }

    func testRegisterAccountUnregisterAccountAndGraphSubscriptionShapes() async throws {
        let client = makeClient()
        let accountKey = String(repeating: "b", count: 64)

        try await client.registerAccount(accountKey: accountKey, provider: .microsoft)
        try await client.unregisterAccount(accountKey: accountKey)
        try await client.registerGraphSubscription(subscriptionID: "sub-123", accountKey: accountKey, clientState: "secret-state")

        let requests = RelayStubProtocol.requests
        XCTAssertEqual(requests.count, 3)

        XCTAssertEqual(requests[0].method, "POST")
        XCTAssertEqual(requests[0].url?.absoluteString, "https://relay.test/v1/devices/accounts")
        XCTAssertEqual(requests[0].json, ["accountKey": accountKey, "provider": "microsoft"])

        XCTAssertEqual(requests[1].method, "DELETE")
        XCTAssertEqual(requests[1].url?.absoluteString, "https://relay.test/v1/devices/accounts/\(accountKey)")
        XCTAssertNil(requests[1].body)
        XCTAssertNil(requests[1].headers["Content-Type"])

        XCTAssertEqual(requests[2].method, "POST")
        XCTAssertEqual(requests[2].url?.absoluteString, "https://relay.test/v1/devices/graph-subscriptions")
        XCTAssertEqual(requests[2].json, ["subscriptionID": "sub-123", "accountKey": accountKey, "clientState": "secret-state"])
        for request in requests {
            XCTAssertEqual(request.headers["X-API-Key"], "shared-key")
            XCTAssertEqual(request.timeout, 15)
        }
    }

    // MARK: - Idempotent device registration

    func testRegisterDeviceIsIdempotentUntilTokenOrEnvironmentChanges() async throws {
        let client = makeClient()

        let first = try await client.registerDevice(apnsToken: token, environment: "sandbox")
        XCTAssertTrue(first)
        let repeated = try await client.registerDevice(apnsToken: token, environment: "sandbox")
        XCTAssertFalse(repeated, "same token + environment is not re-sent")
        XCTAssertEqual(RelayStubProtocol.requests.count, 1)

        let environmentChanged = try await client.registerDevice(apnsToken: token, environment: "production")
        XCTAssertTrue(environmentChanged, "environment change is sent")
        let tokenChanged = try await client.registerDevice(apnsToken: Data([0x01]), environment: "production")
        XCTAssertTrue(tokenChanged, "token change is sent")
        let unchanged = try await client.registerDevice(apnsToken: Data([0x01]), environment: "production")
        XCTAssertFalse(unchanged)
        let forced = try await client.registerDevice(apnsToken: Data([0x01]), environment: "production", force: true)
        XCTAssertTrue(forced, "force always sends")
        XCTAssertEqual(RelayStubProtocol.requests.count, 4)

        let remembered = try XCTUnwrap(defaults.string(forKey: RelayClient.lastDeviceRegistrationKey))
        XCTAssertEqual(remembered.count, 64, "a fingerprint is stored, not the token")
        XCTAssertFalse(remembered.contains("01"))
        XCTAssertEqual(remembered, RelayClient.registrationFingerprint(baseURL: Self.baseURL, environment: "production", tokenHex: "01"))

        client.resetDeviceRegistration()
        let afterReset = try await client.registerDevice(apnsToken: Data([0x01]), environment: "production")
        XCTAssertTrue(afterReset)
    }

    func testFailedRegistrationIsNotRemembered() async throws {
        RelayStubProtocol.reset(responses: [.init(status: 401, body: #"{"error":"bad api key"}"#)])
        let client = makeClient()

        do {
            try await client.registerDevice(apnsToken: token, environment: "sandbox")
            XCTFail("expected an error")
        } catch let error as RelayError {
            XCTAssertEqual(error, .httpStatus(401, body: "bad api key"))
        }
        XCTAssertNil(defaults.string(forKey: RelayClient.lastDeviceRegistrationKey))
        let retried = try await client.registerDevice(apnsToken: token, environment: "sandbox")
        XCTAssertTrue(retried, "retried on the next launch")
    }

    // MARK: - Recovery after the relay forgets the device

    func testDeviceScopedUnauthorizedReregistersAndRetriesOnce() async throws {
        let client = makeClient()
        try await client.registerDevice(apnsToken: token, environment: "sandbox")
        // The relay's database was reset: account routes answer 401 until POST /v1/devices recreates the row.
        RelayStubProtocol.reset(responses: [.init(status: 401, body: #"{"error":"unauthorized"}"#), .init(status: 201), .init(status: 204)])

        try await client.registerAccount(accountKey: String(repeating: "c", count: 64), provider: .gmail)

        let requests = RelayStubProtocol.requests
        XCTAssertEqual(requests.map { $0.url?.path }, ["/v1/devices/accounts", "/v1/devices", "/v1/devices/accounts"])
        XCTAssertEqual(requests[1].json?["apnsToken"], "0a0bff10", "the token last handed to registerDevice is re-sent")
        XCTAssertEqual(requests[1].json?["environment"], "sandbox")
        XCTAssertEqual(
            defaults.string(forKey: RelayClient.lastDeviceRegistrationKey),
            RelayClient.registrationFingerprint(baseURL: Self.baseURL, environment: "sandbox", tokenHex: "0a0bff10"),
            "the successful re-registration is remembered again"
        )
    }

    func testUnknownDeviceWithoutATokenForgetsTheRegistrationAndRethrows() async throws {
        RelayStubProtocol.reset(responses: [.init(status: 401, body: #"{"error":"unauthorized"}"#)])
        defaults.set("stale-fingerprint", forKey: RelayClient.lastDeviceRegistrationKey)
        let client = makeClient()

        do {
            try await client.registerGraphSubscription(subscriptionID: "sub", accountKey: "k", clientState: "state")
            XCTFail("expected an error")
        } catch let error as RelayError {
            XCTAssertEqual(error, .httpStatus(401, body: "unauthorized"))
        }
        XCTAssertEqual(RelayStubProtocol.requests.count, 1, "nothing can be re-sent before a token was received")
        XCTAssertNil(defaults.string(forKey: RelayClient.lastDeviceRegistrationKey), "the next token callback re-sends the registration")
        let sent = try await client.registerDevice(apnsToken: token, environment: "sandbox")
        XCTAssertTrue(sent)
    }

    func testFailedReregistrationSurfacesTheOriginalError() async throws {
        let client = makeClient()
        try await client.registerDevice(apnsToken: token, environment: "sandbox")
        RelayStubProtocol.reset(responses: [.init(status: 404, body: #"{"error":"device_not_found"}"#), .init(status: 401, body: #"{"error":"invalid_api_key"}"#)])

        do {
            try await client.unregisterAccount(accountKey: "k")
            XCTFail("expected an error")
        } catch let error as RelayError {
            XCTAssertEqual(error, .httpStatus(404, body: "device_not_found"))
        }
        XCTAssertEqual(RelayStubProtocol.requests.map { $0.url?.path }, ["/v1/devices/accounts/k", "/v1/devices"], "retried at most once")
        XCTAssertNil(defaults.string(forKey: RelayClient.lastDeviceRegistrationKey))
        XCTAssertTrue(RelayError.httpStatus(401, body: nil).indicatesUnknownDevice)
        XCTAssertTrue(RelayError.httpStatus(404, body: nil).indicatesUnknownDevice)
        XCTAssertFalse(RelayError.httpStatus(400, body: nil).indicatesUnknownDevice)
        XCTAssertFalse(RelayError.network("offline").indicatesUnknownDevice)
    }

    // MARK: - Retry / errors

    func testTransientFailuresAreRetriedWithBackoffPolicy() async throws {
        RelayStubProtocol.reset(responses: [.init(status: 503, body: "busy"), .init(status: 429), .init(status: 200)])
        let client = makeClient()

        try await client.registerAccount(accountKey: "k", provider: .gmail)

        XCTAssertEqual(RelayStubProtocol.requests.count, 3, "two transient failures then success")
    }

    func testRetriesStopAtMaxAttemptsAndSurfaceServerMessage() async throws {
        RelayStubProtocol.reset(responses: [.init(status: 503, body: #"{"message":"maintenance"}"#), .init(status: 503, body: #"{"message":"maintenance"}"#), .init(status: 503, body: #"{"message":"maintenance"}"#), .init(status: 200)])
        let client = makeClient()

        do {
            try await client.registerAccount(accountKey: "k", provider: .gmail)
            XCTFail("expected an error")
        } catch let error as RelayError {
            XCTAssertEqual(error.statusCode, 503)
            XCTAssertEqual(error.serverMessage, "maintenance")
            XCTAssertTrue(error.isTransient)
            XCTAssertEqual(error.errorDescription, "Relay HTTP 503: maintenance")
        }
        XCTAssertEqual(RelayStubProtocol.requests.count, 3)
    }

    func testClientErrorsAreNotRetried() async throws {
        RelayStubProtocol.reset(responses: [.init(status: 400, body: #"{"error":{"message":"invalid token"}}"#), .init(status: 200)])
        let client = makeClient()

        do {
            try await client.registerAccount(accountKey: "k", provider: .gmail)
            XCTFail("expected an error")
        } catch let error as RelayError {
            XCTAssertEqual(error, .httpStatus(400, body: "invalid token"))
            XCTAssertFalse(error.isTransient)
        }
        XCTAssertEqual(RelayStubProtocol.requests.count, 1)
    }

    func testNoRetryPolicySendsOnce() async throws {
        RelayStubProtocol.reset(responses: [.init(status: 500, body: "plain text failure")])
        let client = makeClient(retry: .none)

        do {
            try await client.unregisterAccount(accountKey: "k")
            XCTFail("expected an error")
        } catch let error as RelayError {
            XCTAssertEqual(error, .httpStatus(500, body: "plain text failure"))
        }
        XCTAssertEqual(RelayStubProtocol.requests.count, 1)
    }

    func testNotConfiguredClient() async throws {
        let client = makeClient(configured: false)

        XCTAssertFalse(client.isConfigured)
        do {
            try await client.registerDevice(apnsToken: token, environment: "sandbox")
            XCTFail("expected an error")
        } catch let error as RelayError {
            XCTAssertEqual(error, .notConfigured)
        }
        XCTAssertTrue(RelayStubProtocol.requests.isEmpty)
    }

    // MARK: - Helpers

    func testServerMessageParsing() {
        XCTAssertEqual(RelayClient.serverMessage(from: Data(#"{"error":"nope"}"#.utf8)), "nope")
        XCTAssertEqual(RelayClient.serverMessage(from: Data(#"{"reason":"BadDeviceToken"}"#.utf8)), "BadDeviceToken")
        XCTAssertEqual(RelayClient.serverMessage(from: Data(#"{"error":{"message":"nested"}}"#.utf8)), "nested")
        XCTAssertEqual(RelayClient.serverMessage(from: Data("  raw body \n".utf8)), "raw body")
        XCTAssertNil(RelayClient.serverMessage(from: Data()))
        XCTAssertEqual(RelayClient.serverMessage(from: Data(String(repeating: "x", count: 500).utf8))?.count, 200)
    }

    func testRetryPolicyDelays() {
        let policy = RelayClient.RetryPolicy.default
        XCTAssertEqual(policy.maxAttempts, 3)
        XCTAssertEqual(policy.delay(beforeAttempt: 1), 0)
        XCTAssertEqual(policy.delay(beforeAttempt: 2), 0.5)
        XCTAssertEqual(policy.delay(beforeAttempt: 3), 1.5)
        XCTAssertEqual(RelayClient.RetryPolicy.none.maxAttempts, 1)
        XCTAssertEqual(RelayClient.RetryPolicy(maxAttempts: 0, initialDelay: -1, multiplier: 0).maxAttempts, 1)
    }

    func testTransientClassification() {
        XCTAssertTrue(RelayError.network("offline").isTransient)
        XCTAssertTrue(RelayError.httpStatus(429, body: nil).isTransient)
        XCTAssertTrue(RelayError.httpStatus(502, body: nil).isTransient)
        XCTAssertFalse(RelayError.httpStatus(404, body: nil).isTransient)
        XCTAssertFalse(RelayError.notConfigured.isTransient)
        XCTAssertFalse(RelayError.invalidResponse.isTransient)
        XCTAssertEqual(RelayClient.hexString(Data([0x00, 0xab, 0xff])), "00abff")
    }
}

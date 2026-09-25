import Foundation
import PhishCore
import XCTest
@testable import PhishGuard

// Shared fixtures for the Microsoft/Graph tests: a URLProtocol stub with a tiny router, an in-memory secret
// store standing in for the Keychain, a recording relay, and JSON builders for Graph resources.

struct StubResponse: Sendable {
    var status: Int
    var headers: [String: String]
    var body: Data

    init(status: Int = 200, headers: [String: String] = [:], body: Data = Data()) {
        self.status = status
        self.headers = headers
        self.body = body
    }

    static func json(_ object: Any, status: Int = 200, headers: [String: String] = [:]) -> StubResponse {
        let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        var merged = headers
        merged["Content-Type"] = "application/json"
        return StubResponse(status: status, headers: merged, body: data)
    }

    static func graphError(status: Int, code: String, message: String = "error") -> StubResponse {
        json(["error": ["code": code, "message": message]], status: status)
    }
}

struct RecordedRequest: Sendable {
    var method: String
    var url: URL
    var headers: [String: String]
    var body: Data?

    /// Percent-decoded absolute URL, convenient for `contains` checks on `$select` / `$filter`.
    var decodedURL: String { url.absoluteString.removingPercentEncoding ?? url.absoluteString }
    var path: String { url.path }
    var query: [String: String] {
        (URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []).reduce(into: [:]) { $0[$1.name] = $1.value }
    }
    var jsonBody: [String: Any] {
        guard let body, let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return [:] }
        return object
    }
    func header(_ name: String) -> String? {
        headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
    }
}

/// Route table consulted by `GraphStubProtocol`: first route whose method matches and whose `contains` fragment
/// occurs in the decoded URL wins. A route may answer with a fixed sequence (the last element repeats).
final class StubRouter: @unchecked Sendable {
    typealias Responder = (RecordedRequest) -> StubResponse

    private struct Route {
        var method: String
        var contains: String
        var responder: Responder
    }

    private let lock = NSLock()
    private var routes: [Route] = []
    private var unmatched: [RecordedRequest] = []

    func add(_ method: String, contains: String, _ responder: @escaping Responder) {
        lock.withLock { routes.append(Route(method: method, contains: contains, responder: responder)) }
    }

    func add(_ method: String, contains: String, response: StubResponse) {
        add(method, contains: contains) { _ in response }
    }

    func add(_ method: String, contains: String, sequence: [StubResponse]) {
        precondition(!sequence.isEmpty)
        let box = SequenceBox(sequence)
        add(method, contains: contains) { _ in box.next() }
    }

    func respond(to request: RecordedRequest) -> StubResponse {
        let route = lock.withLock { routes.first { $0.method == request.method && request.decodedURL.contains($0.contains) } }
        guard let route else {
            lock.withLock { unmatched.append(request) }
            return .graphError(status: 404, code: "StubRouter.unmatched", message: request.decodedURL)
        }
        return route.responder(request)
    }

    var unmatchedRequests: [RecordedRequest] { lock.withLock { unmatched } }

    private final class SequenceBox: @unchecked Sendable {
        private let lock = NSLock()
        private var remaining: [StubResponse]
        init(_ responses: [StubResponse]) { remaining = responses }
        func next() -> StubResponse {
            lock.withLock {
                if remaining.count > 1 { return remaining.removeFirst() }
                return remaining[0]
            }
        }
    }
}

/// Serves `URLSession` requests from the active `StubRouter`, recording each one and tracking concurrency.
final class GraphStubProtocol: URLProtocol {
    final class State: @unchecked Sendable {
        private let lock = NSLock()
        private var router: StubRouter?
        private var recorded: [RecordedRequest] = []
        private var inFlight = 0
        private var peakInFlight = 0
        private var delay: TimeInterval = 0

        func activate(_ router: StubRouter, responseDelay: TimeInterval = 0) {
            lock.withLock {
                self.router = router
                recorded = []
                inFlight = 0
                peakInFlight = 0
                delay = responseDelay
            }
        }

        func deactivate() { lock.withLock { router = nil } }

        func begin(_ request: RecordedRequest) -> (StubResponse, TimeInterval) {
            lock.withLock {
                recorded.append(request)
                inFlight += 1
                peakInFlight = max(peakInFlight, inFlight)
                let response = router?.respond(to: request) ?? StubResponse(status: 599)
                return (response, delay)
            }
        }

        func end() { lock.withLock { inFlight -= 1 } }

        var requests: [RecordedRequest] { lock.withLock { recorded } }
        var peakConcurrency: Int { lock.withLock { peakInFlight } }
    }

    static let state = State()

    static func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [GraphStubProtocol.self]
        return URLSession(configuration: configuration)
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let request = self.request
        let recorded = RecordedRequest(
            method: request.httpMethod ?? "GET",
            url: request.url!,
            headers: request.allHTTPHeaderFields ?? [:],
            body: request.httpBody ?? Self.readBody(request.httpBodyStream)
        )
        let (response, delay) = Self.state.begin(recorded)
        // URLProtocol's Sendable conformance is unavailable in the SDK, so hand the instance to the
        // delayed closure through an unchecked box (URLSession serialises protocol callbacks anyway).
        let boxed = UncheckedSendableBox(self)
        let deliver: @Sendable () -> Void = {
            let me = boxed.value
            guard let client = me.client else { return }
            let http = HTTPURLResponse(url: recorded.url, statusCode: response.status, httpVersion: "HTTP/1.1", headerFields: response.headers)!
            client.urlProtocol(me, didReceive: http, cacheStoragePolicy: .notAllowed)
            client.urlProtocol(me, didLoad: response.body)
            client.urlProtocolDidFinishLoading(me)
            Self.state.end()
        }
        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + delay, execute: deliver)
        } else {
            deliver()
        }
    }

    override func stopLoading() {}

    private static func readBody(_ stream: InputStream?) -> Data? {
        guard let stream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }
}

private struct UncheckedSendableBox<Value>: @unchecked Sendable {
    let value: Value
    init(_ value: Value) { self.value = value }
}

final class InMemorySecretStore: MicrosoftSecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String] = [:]

    init(_ initial: [String: String] = [:]) { values = initial }

    func getString(_ key: String) throws -> String? { lock.withLock { values[key] } }
    func setString(_ value: String, for key: String) throws { lock.withLock { values[key] = value } }
    func delete(_ key: String) throws { lock.withLock { values[key] = nil } }
    var all: [String: String] { lock.withLock { values } }
}

final class RecordingRelay: GraphRelayRegistrar, @unchecked Sendable {
    enum Call: Equatable, Sendable {
        case registerAccount(accountKey: String, provider: MailProvider)
        case unregisterAccount(accountKey: String)
        case registerGraphSubscription(subscriptionID: String, accountKey: String, clientState: String)
    }

    struct Failure: Error {}

    private let lock = NSLock()
    private var recorded: [Call] = []
    private var shouldFail = false

    var calls: [Call] { lock.withLock { recorded } }
    func failRegistrations(_ fail: Bool) { lock.withLock { shouldFail = fail } }

    private func record(_ call: Call) throws {
        let fail = lock.withLock { recorded.append(call); return shouldFail }
        if fail { throw Failure() }
    }

    func registerAccount(accountKey: String, provider: MailProvider) async throws {
        try record(.registerAccount(accountKey: accountKey, provider: provider))
    }

    func unregisterAccount(accountKey: String) async throws {
        try record(.unregisterAccount(accountKey: accountKey))
    }

    func registerGraphSubscription(subscriptionID: String, accountKey: String, clientState: String) async throws {
        try record(.registerGraphSubscription(subscriptionID: subscriptionID, accountKey: accountKey, clientState: clientState))
    }
}

final class SleepRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [TimeInterval] = []
    func record(_ delay: TimeInterval) { lock.withLock { recorded.append(delay) } }
    var delays: [TimeInterval] { lock.withLock { recorded } }
}

// MARK: - Provider harness

struct MicrosoftHarness {
    static let fixedNow = Date(timeIntervalSince1970: 1_790_000_000) // Mon 2026-09-21T14:13:20Z
    static let relayBaseURL = URL(string: "https://relay.example.test")!
    static let relaySalt = "unit-test-salt"

    let provider: MicrosoftProvider
    let router: StubRouter
    let secrets: InMemorySecretStore
    let relay: RecordingRelay
    let sleeps: SleepRecorder
    let config: AppConfig
    let accountID: UUID

    init(
        accountID: UUID = UUID(),
        secrets: InMemorySecretStore = InMemorySecretStore(),
        now: Date = MicrosoftHarness.fixedNow,
        randomBytes: (@Sendable (Int) -> [UInt8])? = nil,
        responseDelay: TimeInterval = 0
    ) {
        let router = StubRouter()
        let relay = RecordingRelay()
        let sleeps = SleepRecorder()
        let config = AppConfig(
            microsoftClientID: "11111111-2222-3333-4444-555555555555",
            relayBaseURL: MicrosoftHarness.relayBaseURL,
            relayAPIKey: "api-key",
            relaySalt: MicrosoftHarness.relaySalt,
            bundleIdentifier: "com.mazooni.PhishGuardTests"
        )
        var dependencies = MicrosoftProvider.Dependencies()
        dependencies.session = GraphStubProtocol.makeSession()
        dependencies.secrets = secrets
        dependencies.tokenProvider = { _ in "test-access-token" }
        dependencies.now = { now }
        dependencies.sleeper = { delay in sleeps.record(delay) }
        dependencies.makeRelay = { _ in relay }
        if let randomBytes { dependencies.randomBytes = randomBytes }

        GraphStubProtocol.state.activate(router, responseDelay: responseDelay)
        self.provider = MicrosoftProvider(config: config, keychain: Keychain(service: "PhishGuardTests.unused"), dependencies: dependencies)
        self.router = router
        self.secrets = secrets
        self.relay = relay
        self.sleeps = sleeps
        self.config = config
        self.accountID = accountID
    }

    var relayConfig: RelayConfig { config.relayConfig! }
    var requests: [RecordedRequest] { GraphStubProtocol.state.requests }
    func requests(_ method: String, containing fragment: String) -> [RecordedRequest] {
        requests.filter { $0.method == method && $0.decodedURL.contains(fragment) }
    }
}

// MARK: - Graph JSON builders

enum GraphFixtures {
    static let deltaBase = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta"

    static func recipient(_ address: String, name: String? = nil) -> [String: Any] {
        var emailAddress: [String: Any] = ["address": address]
        if let name { emailAddress["name"] = name }
        return ["emailAddress": emailAddress]
    }

    /// A delta entry (no body). `received` is an ISO 8601 string.
    static func deltaEntry(
        id: String,
        received: String? = "2026-09-21T07:00:00Z",
        subject: String = "Subject",
        from: String = "sender@example.com",
        hasAttachments: Bool = false,
        isDraft: Bool? = nil,
        removed: Bool = false
    ) -> [String: Any] {
        var entry: [String: Any] = ["id": id]
        if removed {
            entry["@removed"] = ["reason": "deleted"]
            return entry
        }
        if let received { entry["receivedDateTime"] = received }
        entry["subject"] = subject
        entry["from"] = recipient(from)
        entry["hasAttachments"] = hasAttachments
        entry["webLink"] = "https://outlook.live.com/mail/0/inbox/id/\(id)"
        entry["internetMessageId"] = "<\(id)@example.com>"
        entry["isDraft"] = isDraft ?? false
        entry["parentFolderId"] = "inbox-folder-id"
        return entry
    }

    static func page(_ entries: [[String: Any]], nextLink: String? = nil, deltaLink: String? = nil) -> [String: Any] {
        var page: [String: Any] = ["value": entries]
        if let nextLink { page["@odata.nextLink"] = nextLink }
        if let deltaLink { page["@odata.deltaLink"] = deltaLink }
        return page
    }

    /// A full message as returned by `GET /me/messages/{id}?$select=...`.
    static func fullMessage(
        id: String,
        received: String = "2026-09-21T07:00:00Z",
        subject: String = "Subject",
        from: String = "sender@example.com",
        fromName: String? = "Sender",
        html: String? = "<p>Hello <b>there</b></p>",
        text: String? = nil,
        hasAttachments: Bool = false,
        isDraft: Bool = false,
        headers: [[String: String]] = [["name": "Authentication-Results", "value": "spf=pass"]]
    ) -> [String: Any] {
        var message: [String: Any] = [
            "id": id,
            "receivedDateTime": received,
            "subject": subject,
            "from": recipient(from, name: fromName),
            "sender": recipient(from, name: fromName),
            "replyTo": [recipient("reply@example.com", name: "Reply")],
            "toRecipients": [recipient("Victim@Example.com", name: "Victim")],
            "hasAttachments": hasAttachments,
            "isDraft": isDraft,
            "webLink": "https://outlook.live.com/mail/0/inbox/id/\(id)",
            "internetMessageId": "<\(id)@example.com>",
            "conversationId": "conv-\(id)",
            "internetMessageHeaders": headers,
        ]
        if let html { message["body"] = ["contentType": "html", "content": html] }
        if let text { message["body"] = ["contentType": "text", "content": text] }
        return message
    }

    static func attachments(_ items: [[String: Any]]) -> [String: Any] {
        ["value": items]
    }

    static func subscription(id: String, expiration: String, notificationUrl: String = "https://relay.example.test/v1/graph/notifications") -> [String: Any] {
        [
            "id": id,
            "resource": "me/mailFolders('Inbox')/messages",
            "changeType": "created",
            "notificationUrl": notificationUrl,
            "expirationDateTime": expiration,
        ]
    }
}

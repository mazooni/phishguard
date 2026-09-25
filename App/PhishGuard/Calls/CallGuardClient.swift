import Foundation
import OSLog
import PhishCore
import Synchronization

// MARK: - WebSocket seam

/// One frame of the live socket.
enum WebSocketFrame: Sendable, Equatable {
    case text(String)
    case data(Data)

    var payload: Data {
        switch self {
        case .text(let text): return Data(text.utf8)
        case .data(let data): return data
        }
    }
}

/// The part of `URLSessionWebSocketTask` the live feed uses, so tests can script connections.
protocol WebSocketConnection: Sendable {
    func receive() async throws -> WebSocketFrame
    func send(text: String) async throws
    func cancel()
}

typealias WebSocketConnector = @Sendable (URLRequest) -> any WebSocketConnection
typealias LiveSleeper = @Sendable (TimeInterval) async throws -> Void

/// `URLSessionWebSocketTask` behind `WebSocketConnection`; resumed on creation. `URLSessionTask` is `Sendable` in
/// the SDK (`NS_SWIFT_SENDABLE`), so this holds nothing that needs unchecked treatment.
final class URLSessionWebSocketConnection: WebSocketConnection, Sendable {
    private let task: URLSessionWebSocketTask

    init(session: URLSession, request: URLRequest) {
        task = session.webSocketTask(with: request)
        task.resume()
    }

    func receive() async throws -> WebSocketFrame {
        switch try await task.receive() {
        case .string(let text): return .text(text)
        case .data(let data): return .data(data)
        @unknown default: throw URLError(.badServerResponse)
        }
    }

    func send(text: String) async throws {
        try await task.send(.string(text))
    }

    func cancel() {
        task.cancel(with: .goingAway, reason: nil)
    }
}

// MARK: - Client

/// The app-facing Call Guard routes (docs/CALLS.md §5.1) over the relay's device auth. Every call is a
/// `RelayClient.data` request — same headers, retries and 401 re-registration — and the live feed is a WebSocket
/// with the same `Authorization` + `X-API-Key` headers. Not configured when the relay is not configured: every
/// method then throws `RelayError.notConfigured`.
struct CallGuardClient: Sendable {
    enum ConnectionState: Sendable, Equatable {
        case disconnected
        case connecting
        case connected
    }

    static let defaultHistoryLimit = 50
    static let historyLimitRange = 1...200
    static let pingInterval: TimeInterval = 25
    static let maxReconnectDelay: TimeInterval = 30
    static let livePath = "v1/devices/calls/live"
    static let pingFrame = #"{"type":"ping"}"#

    let relay: RelayClient

    private let connector: WebSocketConnector
    private let sleeper: LiveSleeper
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "calls")

    /// `connector` and `sleeper` are test seams; the defaults are `URLSessionWebSocketTask` on `session` and
    /// `Task.sleep`.
    init(relay: RelayClient, session: URLSession = .shared, connector: WebSocketConnector? = nil, sleeper: LiveSleeper? = nil) {
        self.relay = relay
        self.connector = connector ?? { request in URLSessionWebSocketConnection(session: session, request: request) }
        self.sleeper = sleeper ?? { seconds in try await Task.sleep(for: .seconds(seconds)) }
    }

    var isConfigured: Bool { relay.isConfigured }

    // MARK: Line

    private struct LineRegistration: Encodable {
        var phoneNumber: String
        var minimumLevel: String
        var spokenWarning: Bool
    }

    /// `PUT /v1/devices/call-line`. A `.safe` level is sent as `.low` (the relay accepts alert levels only).
    func registerLine(phoneNumber: String, minimumLevel: RiskLevel, spokenWarning: Bool) async throws -> CallLine {
        try requireConfigured()
        let body = LineRegistration(phoneNumber: phoneNumber, minimumLevel: max(minimumLevel, .low).rawValue, spokenWarning: spokenWarning)
        let data = try await relay.data(method: "PUT", path: "v1/devices/call-line", body: try Self.encoder.encode(body))
        return try Self.decoder.decode(CallLine.self, from: data)
    }

    /// `GET /v1/devices/call-line`; nil on the relay's 404 `no_line`.
    func fetchLine() async throws -> CallLine? {
        try requireConfigured()
        do {
            let data = try await relay.data(method: "GET", path: "v1/devices/call-line", reregisterOnNotFound: false)
            return try Self.decoder.decode(CallLine.self, from: data)
        } catch let error as RelayError where error.statusCode == 404 {
            return nil
        }
    }

    /// `DELETE /v1/devices/call-line` (idempotent).
    func removeLine() async throws {
        try requireConfigured()
        _ = try await relay.data(method: "DELETE", path: "v1/devices/call-line")
    }

    // MARK: History

    private struct CallsEnvelope: Decodable {
        var calls: [CallSummary]
    }

    private struct CallIDEnvelope: Decodable {
        var callID: String
    }

    /// `GET /v1/devices/calls?limit=N`, newest first. `limit` is clamped to the relay's 1…200.
    func fetchCalls(limit: Int = CallGuardClient.defaultHistoryLimit) async throws -> [CallSummary] {
        try requireConfigured()
        let clamped = min(max(limit, Self.historyLimitRange.lowerBound), Self.historyLimitRange.upperBound)
        let data = try await relay.data(method: "GET", path: "v1/devices/calls", queryItems: [URLQueryItem(name: "limit", value: String(clamped))])
        return try Self.decoder.decode(CallsEnvelope.self, from: data).calls
    }

    /// `GET /v1/devices/calls/:callID`; nil on the relay's 404 `not_found`.
    func fetchCall(id: String) async throws -> CallDetail? {
        try requireConfigured()
        let trimmed = id.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        do {
            let data = try await relay.data(method: "GET", path: "v1/devices/calls/\(trimmed)", reregisterOnNotFound: false)
            return try Self.decoder.decode(CallDetail.self, from: data)
        } catch let error as RelayError where error.statusCode == 404 {
            return nil
        }
    }

    // MARK: Demo and test calls (§7)

    private struct ScenarioRequest: Encodable {
        var scenario: String
        var speed: Double?
    }

    /// `POST /v1/devices/calls/demo {scenario, speed?}` → the new call's id. The relay answers 403 `demo_disabled`
    /// when scripted calls are off.
    func startDemoCall(scenario: DemoScenario, speed: Double? = nil) async throws -> String {
        try requireConfigured()
        let body = ScenarioRequest(scenario: scenario.rawValue, speed: speed.map { min(max($0, 0.25), 4) })
        let data = try await relay.data(method: "POST", path: "v1/devices/calls/demo", body: try Self.encoder.encode(body))
        return try Self.decoder.decode(CallIDEnvelope.self, from: data).callID
    }

    /// `POST /v1/devices/calls/test-call {scenario}` → the new call's id. 409 `no_line` without a line.
    func startTestCall(scenario: DemoScenario) async throws -> String {
        try requireConfigured()
        let body = ScenarioRequest(scenario: scenario.rawValue, speed: nil)
        let data = try await relay.data(method: "POST", path: "v1/devices/calls/test-call", body: try Self.encoder.encode(body))
        return try Self.decoder.decode(CallIDEnvelope.self, from: data).callID
    }

    // MARK: Live feed

    /// `GET /v1/devices/calls/live` as a stream of events. The socket is opened when the stream is first consumed
    /// and closed when the consumer stops (cancelling the consuming task is enough). While it is being consumed it
    /// pings every 25 s and reconnects after a drop with exponential backoff (1 s … 30 s), resetting after a
    /// successful `hello`. Frames of an unknown `type` and malformed frames are skipped. `onConnectionChange` is
    /// called off the main actor.
    func liveEvents(onConnectionChange: (@Sendable (ConnectionState) -> Void)? = nil) -> AsyncThrowingStream<LiveEvent, any Error> {
        AsyncThrowingStream { continuation in
            guard relay.isConfigured else {
                continuation.finish(throwing: RelayError.notConfigured)
                return
            }
            let current = CurrentSocket()
            let task = Task.detached(priority: .utility) {
                await runLiveLoop(current: current, continuation: continuation, onConnectionChange: onConnectionChange)
            }
            continuation.onTermination = { @Sendable _ in
                task.cancel()
                // The loop may be parked in `receive()`, which only returns once the socket is closed.
                current.cancel()
            }
        }
    }

    /// The socket the live loop is currently reading, so a termination can close it from outside the loop.
    private final class CurrentSocket: Sendable {
        private let socket = Mutex<(any WebSocketConnection)?>(nil)

        func set(_ connection: (any WebSocketConnection)?) {
            socket.withLock { $0 = connection }
        }

        func cancel() {
            socket.withLock { $0 }?.cancel()
        }
    }

    /// 1, 2, 4, 8, 16, then 30 s for every further attempt.
    static func reconnectDelay(attempt: Int) -> TimeInterval {
        guard attempt > 0 else { return 0 }
        return min(maxReconnectDelay, pow(2, Double(attempt - 1)))
    }

    private func runLiveLoop(
        current: CurrentSocket,
        continuation: AsyncThrowingStream<LiveEvent, any Error>.Continuation,
        onConnectionChange: (@Sendable (ConnectionState) -> Void)?
    ) async {
        var failures = 0
        while !Task.isCancelled {
            let request: URLRequest
            do {
                request = try relay.authorizedRequest(method: "GET", path: Self.livePath, webSocket: true)
            } catch {
                continuation.finish(throwing: error)
                return
            }
            onConnectionChange?(.connecting)
            let socket = connector(request)
            current.set(socket)
            if Task.isCancelled {
                socket.cancel()
                break
            }
            let pinger = Task { [sleeper] in
                while !Task.isCancelled {
                    try await sleeper(Self.pingInterval)
                    try await socket.send(text: Self.pingFrame)
                }
            }
            do {
                while !Task.isCancelled {
                    let frame = try await socket.receive()
                    let event: LiveEvent?
                    do {
                        event = try LiveEvent.decode(frame.payload)
                    } catch {
                        logger.notice("Live frame ignored: \(error.localizedDescription, privacy: .public)")
                        continue
                    }
                    guard let event else { continue }
                    if case .hello = event {
                        failures = 0
                        onConnectionChange?(.connected)
                    }
                    continuation.yield(event)
                }
            } catch {
                if !Task.isCancelled {
                    logger.notice("Live feed dropped: \(error.localizedDescription, privacy: .public)")
                }
            }
            pinger.cancel()
            socket.cancel()
            current.set(nil)
            // A cancelled loop was stopped by its consumer, which owns the state from here on; reporting
            // `.disconnected` now could land after a replacement loop's `.connected`.
            if Task.isCancelled { break }
            onConnectionChange?(.disconnected)
            failures += 1
            do {
                try await sleeper(Self.reconnectDelay(attempt: failures))
            } catch {
                break
            }
        }
        continuation.finish()
    }

    // MARK: Helpers

    private func requireConfigured() throws {
        guard relay.isConfigured else { throw RelayError.notConfigured }
    }

    static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }

    static var decoder: JSONDecoder { JSONDecoder() }
}

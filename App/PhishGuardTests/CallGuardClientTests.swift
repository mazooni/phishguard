import Foundation
import PhishCore
import Synchronization
import XCTest
@testable import PhishGuard

// MARK: - Fakes for the live feed

/// A scripted WebSocket: the test delivers frames or a failure, the client receives them in order. All state sits
/// behind a `Mutex`, so the class is `Sendable` without unchecked treatment.
final class FakeWebSocket: WebSocketConnection, Sendable {
    private struct State {
        var pending: [Result<WebSocketFrame, any Error>] = []
        var waiter: CheckedContinuation<WebSocketFrame, any Error>?
        var sent: [String] = []
        var isCancelled = false
    }

    let request: URLRequest
    private let state = Mutex(State())

    init(request: URLRequest) {
        self.request = request
    }

    var sent: [String] { state.withLock { $0.sent } }
    var isCancelled: Bool { state.withLock { $0.isCancelled } }

    func deliver(_ text: String) { enqueue(.success(.text(text))) }
    func fail(_ error: any Error = URLError(.networkConnectionLost)) { enqueue(.failure(error)) }

    private func enqueue(_ result: Result<WebSocketFrame, any Error>) {
        let waiter = state.withLock { state -> CheckedContinuation<WebSocketFrame, any Error>? in
            if let waiter = state.waiter {
                state.waiter = nil
                return waiter
            }
            state.pending.append(result)
            return nil
        }
        waiter?.resume(with: result)
    }

    func receive() async throws -> WebSocketFrame {
        try await withCheckedThrowingContinuation { continuation in
            let ready = state.withLock { state -> Result<WebSocketFrame, any Error>? in
                if !state.pending.isEmpty { return state.pending.removeFirst() }
                state.waiter = continuation
                return nil
            }
            if let ready { continuation.resume(with: ready) }
        }
    }

    func send(text: String) async throws {
        state.withLock { $0.sent.append(text) }
    }

    func cancel() {
        let waiter = state.withLock { state -> CheckedContinuation<WebSocketFrame, any Error>? in
            state.isCancelled = true
            let waiter = state.waiter
            state.waiter = nil
            return waiter
        }
        waiter?.resume(throwing: CancellationError())
    }
}

/// Hands out one `FakeWebSocket` per connection attempt and remembers them.
final class FakeSocketFactory: Sendable {
    private let sockets = Mutex<[FakeWebSocket]>([])

    var all: [FakeWebSocket] { sockets.withLock { $0 } }

    var connector: WebSocketConnector {
        { request in
            let socket = FakeWebSocket(request: request)
            self.sockets.withLock { $0.append(socket) }
            return socket
        }
    }

    struct NeverOpened: Error {
        let index: Int
    }

    /// Waits (up to two seconds) for the `index`-th connection attempt.
    func socket(at index: Int) async throws -> FakeWebSocket {
        for _ in 0..<200 {
            if let socket = sockets.withLock({ $0.count > index ? $0[index] : nil }) { return socket }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTFail("socket \(index) was never opened")
        throw NeverOpened(index: index)
    }
}

/// Records every sleep the live loop asks for. Backoff sleeps return at once; ping-interval sleeps return at once
/// `pingPasses` times and then block (cancellably) so the ping loop cannot spin.
final class LiveSleepRecorder: Sendable {
    private struct State {
        var durations: [TimeInterval] = []
        var pingPasses: Int
    }

    private let state: Mutex<State>

    init(pingPasses: Int = 0) {
        state = Mutex(State(pingPasses: pingPasses))
    }

    var durations: [TimeInterval] { state.withLock { $0.durations } }

    var sleeper: LiveSleeper {
        { seconds in
            let passThrough = self.state.withLock { state -> Bool in
                state.durations.append(seconds)
                guard seconds >= CallGuardClient.pingInterval else { return true }
                guard state.pingPasses > 0 else { return false }
                state.pingPasses -= 1
                return true
            }
            if !passThrough {
                try await Task.sleep(for: .seconds(3600))
            }
        }
    }
}

/// Thread-safe collector for values produced off the test's actor.
final class Collector<Value: Sendable>: Sendable {
    private let storage = Mutex<[Value]>([])
    var values: [Value] { storage.withLock { $0 } }
    func append(_ value: Value) { storage.withLock { $0.append(value) } }

    /// Waits (up to two seconds) until at least `count` values were collected.
    func wait(forCount count: Int) async throws {
        for _ in 0..<200 {
            if values.count >= count { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTFail("expected \(count) values, got \(values.count): \(values)")
    }
}

// MARK: - Tests

final class CallGuardClientTests: XCTestCase {
    private static let baseURL = URL(string: "https://relay.test")!
    private let token = Data([0x0a, 0x0b, 0xff, 0x10])

    private var keychain: Keychain!
    private var defaults: UserDefaults!
    private var suite: String!

    override func setUpWithError() throws {
        try super.setUpWithError()
        suite = "PhishGuardTests.calls.\(UUID().uuidString)"
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

    private func makeRelay(configured: Bool = true) -> RelayClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RelayStubProtocol.self]
        let session = URLSession(configuration: configuration)
        let config = configured ? RelayConfig(baseURL: Self.baseURL, apiKey: "shared-key", gmailPubSubTopic: "projects/p/topics/t") : nil
        return RelayClient(
            config: config, keychain: keychain, bundleIdentifier: "com.mazooni.PhishGuard", session: session, defaults: defaults,
            retryPolicy: RelayClient.RetryPolicy(maxAttempts: 3, initialDelay: 0, multiplier: 1)
        )
    }

    private func makeClient(configured: Bool = true, connector: WebSocketConnector? = nil, sleeper: LiveSleeper? = nil) -> CallGuardClient {
        CallGuardClient(relay: makeRelay(configured: configured), connector: connector, sleeper: sleeper)
    }

    private func body(of request: RelayStubProtocol.Recorded) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(request.body)) as? [String: Any])
    }

    // MARK: Line

    func testRegisterLineSendsAPutWithTheContractBodyAndDecodesTheLine() async throws {
        RelayStubProtocol.reset(responses: [.init(status: 200, body: CallFixtures.lineJSON)])
        let client = makeClient()

        let line = try await client.registerLine(phoneNumber: "+14155550100", minimumLevel: .medium, spokenWarning: true)

        XCTAssertEqual(line.lineID, "line-42")
        XCTAssertEqual(line.guardNumber, "+16285550199")
        let request = try XCTUnwrap(RelayStubProtocol.requests.first)
        XCTAssertEqual(request.method, "PUT")
        XCTAssertEqual(request.url?.absoluteString, "https://relay.test/v1/devices/call-line")
        XCTAssertEqual(request.headers["X-API-Key"], "shared-key")
        XCTAssertEqual(request.headers["Content-Type"], "application/json")
        XCTAssertEqual(request.headers["Accept"], "application/json")
        XCTAssertTrue(try XCTUnwrap(request.headers["Authorization"]).hasPrefix("Bearer "))
        XCTAssertEqual(request.timeout, RelayClient.requestTimeout)
        let body = try body(of: request)
        XCTAssertEqual(body["phoneNumber"] as? String, "+14155550100")
        XCTAssertEqual(body["minimumLevel"] as? String, "medium")
        XCTAssertEqual(body["spokenWarning"] as? Bool, true)
        XCTAssertEqual(Set(body.keys), ["phoneNumber", "minimumLevel", "spokenWarning"])
    }

    func testRegisterLineNeverSendsSafe() async throws {
        RelayStubProtocol.reset(responses: [.init(status: 200, body: CallFixtures.lineJSON)])
        let client = makeClient()

        _ = try await client.registerLine(phoneNumber: "+14155550100", minimumLevel: .safe, spokenWarning: false)

        let body = try body(of: try XCTUnwrap(RelayStubProtocol.requests.first))
        XCTAssertEqual(body["minimumLevel"] as? String, "low")
        XCTAssertEqual(body["spokenWarning"] as? Bool, false)
    }

    func testFetchLineReturnsNilOnNoLineWithoutReregistering() async throws {
        RelayStubProtocol.reset(responses: [.init(status: 404, body: #"{"error":"no_line"}"#)])
        let client = makeClient()

        let line = try await client.fetchLine()

        XCTAssertNil(line)
        let requests = RelayStubProtocol.requests
        XCTAssertEqual(requests.map { $0.url?.path }, ["/v1/devices/call-line"], "a 404 here means no line, not an unknown device")
        XCTAssertEqual(requests.first?.method, "GET")
        XCTAssertNil(requests.first?.body)

        RelayStubProtocol.reset(responses: [.init(status: 200, body: CallFixtures.lineJSON)])
        let found = try await client.fetchLine()
        XCTAssertEqual(found?.phoneNumber, "+14155550100")
    }

    func testUnauthorizedOnACallRouteReregistersTheDeviceAndRetriesOnce() async throws {
        let relay = makeRelay()
        try await relay.registerDevice(apnsToken: token, environment: "sandbox")
        RelayStubProtocol.reset(responses: [.init(status: 401, body: #"{"error":"unauthorized"}"#), .init(status: 201), .init(status: 200, body: CallFixtures.lineJSON)])
        let client = CallGuardClient(relay: relay)

        let line = try await client.fetchLine()

        XCTAssertEqual(line?.lineID, "line-42")
        XCTAssertEqual(RelayStubProtocol.requests.map { $0.url?.path }, ["/v1/devices/call-line", "/v1/devices", "/v1/devices/call-line"])
        XCTAssertEqual(RelayStubProtocol.requests[1].json?["apnsToken"], "0a0bff10")
    }

    func testRemoveLineSendsADelete() async throws {
        RelayStubProtocol.reset(responses: [.init(status: 204)])
        let client = makeClient()

        try await client.removeLine()

        let request = try XCTUnwrap(RelayStubProtocol.requests.first)
        XCTAssertEqual(request.method, "DELETE")
        XCTAssertEqual(request.url?.absoluteString, "https://relay.test/v1/devices/call-line")
        XCTAssertNil(request.body)
        XCTAssertNil(request.headers["Content-Type"])
    }

    // MARK: History

    func testFetchCallsSendsTheClampedLimitAndDecodesTheList() async throws {
        let list = #"{"calls": [\#(CallFixtures.summaryJSON()), \#(CallFixtures.summaryJSON(callID: CallFixtures.secondCallID, status: "no_answer", alerted: false, withVerdict: false))]}"#
        RelayStubProtocol.reset(responses: [.init(status: 200, body: list), .init(status: 200, body: #"{"calls": []}"#), .init(status: 200, body: #"{"calls": []}"#)])
        let client = makeClient()

        let calls = try await client.fetchCalls(limit: 25)
        _ = try await client.fetchCalls(limit: 500)
        _ = try await client.fetchCalls(limit: 0)

        XCTAssertEqual(calls.map(\.callID), [CallFixtures.callID, CallFixtures.secondCallID])
        XCTAssertEqual(calls[1].status, .noAnswer)
        XCTAssertNil(calls[1].verdict)
        let urls = RelayStubProtocol.requests.map { $0.url?.absoluteString }
        XCTAssertEqual(urls, [
            "https://relay.test/v1/devices/calls?limit=25",
            "https://relay.test/v1/devices/calls?limit=200",
            "https://relay.test/v1/devices/calls?limit=1",
        ])
        XCTAssertTrue(RelayStubProtocol.requests.allSatisfy { $0.method == "GET" })
        XCTAssertEqual(CallGuardClient.defaultHistoryLimit, 50)
    }

    func testFetchCallDecodesTheTranscriptAndIsNilWhenNotFound() async throws {
        let detail = #"{"callID": "\#(CallFixtures.callID)", "source": "twilio", "callerNumber": "+14155550134", "calledNumber": "+16285550199", "startedAt": 1758600000000, "status": "in_progress", "verdict": \#(CallFixtures.verdictJSON), "alerted": true, "transcript": [\#(CallFixtures.segmentJSON)]}"#
        RelayStubProtocol.reset(responses: [.init(status: 200, body: detail), .init(status: 404, body: #"{"error":"not_found"}"#)])
        let client = makeClient()

        let found = try await client.fetchCall(id: CallFixtures.callID)
        let missing = try await client.fetchCall(id: CallFixtures.secondCallID)

        XCTAssertEqual(found?.summary.callID, CallFixtures.callID)
        XCTAssertEqual(found?.summary.verdict?.level, .high)
        XCTAssertEqual(found?.transcript?.map(\.id), ["seg-7"])
        XCTAssertNil(missing)
        XCTAssertEqual(RelayStubProtocol.requests.map { $0.url?.absoluteString }, [
            "https://relay.test/v1/devices/calls/\(CallFixtures.callID)",
            "https://relay.test/v1/devices/calls/\(CallFixtures.secondCallID)",
        ], "a 404 here is not_found, so no re-registration is attempted")
        let blank = try await client.fetchCall(id: "  ")
        XCTAssertNil(blank, "a blank id never hits the network")
        XCTAssertEqual(RelayStubProtocol.requests.count, 2)
    }

    // MARK: Demo and test calls

    func testDemoAndTestCallRequestShapes() async throws {
        RelayStubProtocol.reset(responses: [
            .init(status: 202, body: #"{"callID": "\#(CallFixtures.callID)"}"#),
            .init(status: 202, body: #"{"callID": "\#(CallFixtures.secondCallID)"}"#),
            .init(status: 202, body: #"{"callID": "x"}"#),
        ])
        let client = makeClient()

        let demo = try await client.startDemoCall(scenario: .grandparent)
        let test = try await client.startTestCall(scenario: .techSupport)
        _ = try await client.startDemoCall(scenario: .irs, speed: 9)

        XCTAssertEqual(demo, CallFixtures.callID)
        XCTAssertEqual(test, CallFixtures.secondCallID)
        let requests = RelayStubProtocol.requests
        XCTAssertEqual(requests.map { $0.url?.absoluteString }, [
            "https://relay.test/v1/devices/calls/demo",
            "https://relay.test/v1/devices/calls/test-call",
            "https://relay.test/v1/devices/calls/demo",
        ])
        XCTAssertTrue(requests.allSatisfy { $0.method == "POST" })
        XCTAssertEqual(try body(of: requests[0]) as NSDictionary, ["scenario": "grandparent"] as NSDictionary, "speed is omitted when not given")
        XCTAssertEqual(try body(of: requests[1]) as NSDictionary, ["scenario": "techSupport"] as NSDictionary)
        let sped = try body(of: requests[2])
        XCTAssertEqual(sped["scenario"] as? String, "irs")
        XCTAssertEqual(sped["speed"] as? Double, 4, "clamped to the relay's 0.25…4")
    }

    func testRelayErrorsSurfaceWithTheServerMessage() async throws {
        RelayStubProtocol.reset(responses: [.init(status: 409, body: #"{"error":"no_line"}"#)])
        let client = makeClient()

        do {
            _ = try await client.startTestCall(scenario: .prize)
            XCTFail("expected an error")
        } catch let error as RelayError {
            XCTAssertEqual(error, .httpStatus(409, body: "no_line"))
            XCTAssertEqual(CallGuardCoordinator.message(for: error), "Set up call protection first: a test call needs your phone number.")
        }
        XCTAssertEqual(CallGuardCoordinator.message(for: RelayError.httpStatus(503, body: "calls_not_configured")), "The relay does not have Call Guard turned on (CALLS_ENABLED).")
        XCTAssertTrue(CallGuardCoordinator.message(for: RelayError.httpStatus(503, body: "twilio_not_configured")).contains("no phone number yet"), "a relay without Twilio (demo-only) is explained, not 'HTTP 503'")
        XCTAssertTrue(CallGuardCoordinator.message(for: RelayError.httpStatus(502, body: "twilio_error")).contains("Twilio refused the call"), "a refused test call is explained, not 'HTTP 502'")
        XCTAssertEqual(CallGuardCoordinator.message(for: RelayError.httpStatus(403, body: "demo_disabled")), "Scripted demo calls are turned off on the relay.")
        XCTAssertEqual(CallGuardCoordinator.message(for: RelayError.notConfigured), "The PhishGuard relay is not configured in this build.")
        XCTAssertTrue(CallGuardCoordinator.message(for: RelayError.httpStatus(401, body: "unauthorized")).contains("does not know this phone"), "an unregistered device is explained, not 'HTTP 401'")
    }

    // MARK: Not configured

    func testEverythingThrowsNotConfiguredWithoutARelay() async throws {
        let client = makeClient(configured: false)
        XCTAssertFalse(client.isConfigured)

        func expectNotConfigured(_ operation: () async throws -> Void, _ name: String) async {
            do {
                try await operation()
                XCTFail("\(name): expected notConfigured")
            } catch let error as RelayError {
                XCTAssertEqual(error, .notConfigured, name)
            } catch {
                XCTFail("\(name): unexpected \(error)")
            }
        }

        await expectNotConfigured({ _ = try await client.registerLine(phoneNumber: "+14155550100", minimumLevel: .medium, spokenWarning: true) }, "registerLine")
        await expectNotConfigured({ _ = try await client.fetchLine() }, "fetchLine")
        await expectNotConfigured({ try await client.removeLine() }, "removeLine")
        await expectNotConfigured({ _ = try await client.fetchCalls() }, "fetchCalls")
        await expectNotConfigured({ _ = try await client.fetchCall(id: "x") }, "fetchCall")
        await expectNotConfigured({ _ = try await client.startDemoCall(scenario: .benign) }, "startDemoCall")
        await expectNotConfigured({ _ = try await client.startTestCall(scenario: .benign) }, "startTestCall")
        await expectNotConfigured({
            for try await _ in client.liveEvents() {}
        }, "liveEvents")
        XCTAssertTrue(RelayStubProtocol.requests.isEmpty)
    }

    // MARK: Live feed

    func testReconnectDelaysBackOffExponentiallyUpTo30Seconds() {
        XCTAssertEqual(CallGuardClient.reconnectDelay(attempt: 1), 1)
        XCTAssertEqual(CallGuardClient.reconnectDelay(attempt: 2), 2)
        XCTAssertEqual(CallGuardClient.reconnectDelay(attempt: 3), 4)
        XCTAssertEqual(CallGuardClient.reconnectDelay(attempt: 5), 16)
        XCTAssertEqual(CallGuardClient.reconnectDelay(attempt: 6), 30)
        XCTAssertEqual(CallGuardClient.reconnectDelay(attempt: 40), 30)
        XCTAssertEqual(CallGuardClient.reconnectDelay(attempt: 0), 0)
        XCTAssertEqual(CallGuardClient.pingInterval, 25)
        XCTAssertEqual(CallGuardClient.maxReconnectDelay, 30)
    }

    func testLiveEventsConnectsWithDeviceAuthYieldsFramesReconnectsAndStopsOnCancel() async throws {
        let sockets = FakeSocketFactory()
        let sleeps = LiveSleepRecorder()
        let client = makeClient(connector: sockets.connector, sleeper: sleeps.sleeper)
        let states = Collector<CallGuardClient.ConnectionState>()
        let events = Collector<LiveEvent>()

        let stream = client.liveEvents { states.append($0) }
        let consumer = Task {
            for try await event in stream {
                events.append(event)
            }
        }

        let first = try await sockets.socket(at: 0)
        XCTAssertEqual(first.request.url?.absoluteString, "wss://relay.test/v1/devices/calls/live")
        XCTAssertEqual(first.request.httpMethod, "GET")
        XCTAssertEqual(first.request.value(forHTTPHeaderField: "X-API-Key"), "shared-key")
        XCTAssertTrue(try XCTUnwrap(first.request.value(forHTTPHeaderField: "Authorization")).hasPrefix("Bearer "))
        XCTAssertEqual(first.request.timeoutInterval, RelayClient.webSocketTimeout)
        XCTAssertGreaterThan(RelayClient.webSocketTimeout, 2 * CallGuardClient.pingInterval, "the idle timer must outlast a missed ping")

        first.deliver(#"{"type": "hello", "activeCalls": [], "serverTime": 1}"#)
        first.deliver(#"{"type": "pong"}"#)
        first.deliver(#"{"type": "call.recording", "callID": "x"}"#)   // unknown: skipped
        first.deliver("not json")                                        // malformed: skipped
        first.deliver(#"{"type": "transcript.segment", "callID": "\#(CallFixtures.callID)", "segment": \#(CallFixtures.segmentJSON)}"#)
        try await events.wait(forCount: 3)
        XCTAssertEqual(events.values[0], .hello(activeCalls: [], serverTime: 1))
        XCTAssertEqual(events.values[1], .pong)
        XCTAssertEqual(events.values[2].callID, CallFixtures.callID)

        // The socket drops: the loop backs off (1 s, fake-sleeps instantly) and opens a new one.
        first.fail()
        let second = try await sockets.socket(at: 1)
        XCTAssertTrue(first.isCancelled)
        second.deliver(#"{"type": "hello", "activeCalls": [], "serverTime": 2}"#)
        try await events.wait(forCount: 4)
        try await states.wait(forCount: 5)
        XCTAssertEqual(states.values, [.connecting, .connected, .disconnected, .connecting, .connected])
        XCTAssertTrue(sleeps.durations.contains(1), "first reconnect waits one second: \(sleeps.durations)")

        // The consumer stops: the socket is closed and no further connection is attempted.
        consumer.cancel()
        _ = try? await consumer.value
        for _ in 0..<50 where !second.isCancelled {
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertTrue(second.isCancelled)
        try await Task.sleep(for: .milliseconds(50))
        XCTAssertEqual(sockets.all.count, 2, "no reconnect after the consumer went away")
        XCTAssertEqual(events.values.count, 4)
    }

    func testLiveEventsPingsEvery25Seconds() async throws {
        let sockets = FakeSocketFactory()
        let sleeps = LiveSleepRecorder(pingPasses: 1)
        let client = makeClient(connector: sockets.connector, sleeper: sleeps.sleeper)

        let consumer = Task {
            for try await _ in client.liveEvents() {}
        }
        let socket = try await sockets.socket(at: 0)
        for _ in 0..<200 where socket.sent.isEmpty {
            try await Task.sleep(for: .milliseconds(10))
        }

        XCTAssertEqual(socket.sent.first, #"{"type":"ping"}"#)
        XCTAssertTrue(sleeps.durations.contains(CallGuardClient.pingInterval))
        consumer.cancel()
        _ = try? await consumer.value
    }
}

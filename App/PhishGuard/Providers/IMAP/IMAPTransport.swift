import Foundation
import Network

/// A byte pipe to an IMAP server. Two implementations: `NWIMAPTransport` (Network.framework) for implicit TLS
/// and plaintext, and `StreamIMAPTransport` (Foundation `Stream`) for STARTTLS, which needs an in-place
/// upgrade of an already-open connection — something `NWConnection` cannot do.
///
/// All methods are async; implementations are actors, so a client's reads and writes are serialised.
protocol IMAPTransport: Sendable {
    /// Connects (and performs the TLS handshake when the endpoint uses implicit TLS).
    func open() async throws
    func write(_ data: Data) async throws
    /// Returns at least one byte, or throws `IMAPError.connectionClosed` at EOF.
    func read() async throws -> Data
    /// Negotiates TLS on the open connection, after the server accepted `STARTTLS`.
    func upgradeToTLS() async throws
    func close() async
}

/// Where and how to connect. `deadline` handling lives in `IMAPClient`.
struct IMAPEndpoint: Sendable, Equatable {
    var host: String
    var port: Int
    var security: IMAPSecurity

    init(host: String, port: Int, security: IMAPSecurity) {
        self.host = host
        self.port = port
        self.security = security
    }

    init(settings: IMAPAccountSettings) {
        self.init(host: settings.host, port: settings.port, security: settings.security)
    }
}

/// Creates the transport for an endpoint. Injected so tests can point the client at a loopback server.
typealias IMAPTransportFactory = @Sendable (IMAPEndpoint) -> any IMAPTransport

enum IMAPTransports {
    /// Network.framework for implicit TLS and plaintext, Foundation streams for STARTTLS.
    static let `default`: IMAPTransportFactory = { endpoint in
        switch endpoint.security {
        case .tls, .none: return NWIMAPTransport(endpoint: endpoint)
        case .startTLS: return StreamIMAPTransport(endpoint: endpoint)
        }
    }
}

// MARK: - Network.framework

/// `NWConnection`-backed transport. Certificate validation is left at the system default: nothing here
/// disables chain or hostname verification (ARCHITECTURE.md — read-only, no downgrade of transport security).
actor NWIMAPTransport: IMAPTransport {
    private let endpoint: IMAPEndpoint
    nonisolated private let connection: NWConnection
    private let queue = DispatchQueue(label: "com.mazooni.PhishGuard.imap.nw")
    private var isOpen = false
    private var isReading = false

    init(endpoint: IMAPEndpoint) {
        self.endpoint = endpoint
        let port = NWEndpoint.Port(rawValue: UInt16(clamping: endpoint.port)) ?? NWEndpoint.Port(rawValue: 993)!
        self.connection = NWConnection(
            host: NWEndpoint.Host(endpoint.host),
            port: port,
            using: Self.parameters(for: endpoint)
        )
    }

    private static func parameters(for endpoint: IMAPEndpoint) -> NWParameters {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.connectionTimeout = 20
        switch endpoint.security {
        case .tls:
            let tls = NWProtocolTLS.Options()
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, endpoint.host)
            sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
            return NWParameters(tls: tls, tcp: tcp)
        case .startTLS, .none:
            return NWParameters(tls: nil, tcp: tcp)
        }
    }

    func open() async throws {
        guard !isOpen else { return }
        let connection = self.connection
        let queue = self.queue
        let host = endpoint.host
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let resume = SingleResume(continuation)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        resume.succeed(())
                    case .failed(let error):
                        resume.fail(NWIMAPTransport.map(error, host: host))
                    case .waiting(let error):
                        // NWConnection retries "waiting" states forever (refused, no route, DNS). A mail client
                        // wants the specific error now, so this counts as a failure.
                        resume.fail(NWIMAPTransport.map(error, host: host))
                    case .cancelled:
                        resume.fail(IMAPError.connectionClosed)
                    case .setup, .preparing:
                        break
                    @unknown default:
                        break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
        isOpen = true
    }

    func write(_ data: Data) async throws {
        guard isOpen else { throw IMAPError.connectionClosed }
        let connection = self.connection
        let host = endpoint.host
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let resume = SingleResume(continuation)
                connection.send(content: data, completion: .contentProcessed { error in
                    if let error {
                        resume.fail(NWIMAPTransport.map(error, host: host))
                    } else {
                        resume.succeed(())
                    }
                })
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func read() async throws -> Data {
        guard isOpen else { throw IMAPError.connectionClosed }
        guard !isReading else { throw IMAPError.protocolViolation("overlapping reads") }
        isReading = true
        defer { isReading = false }
        let connection = self.connection
        let host = endpoint.host
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                let resume = SingleResume(continuation)
                connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, _, error in
                    if let error {
                        resume.fail(NWIMAPTransport.map(error, host: host))
                        return
                    }
                    if let data, !data.isEmpty {
                        resume.succeed(data)
                        return
                    }
                    resume.fail(IMAPError.connectionClosed)
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func upgradeToTLS() async throws {
        // Network.framework cannot add TLS to an established NWConnection; STARTTLS uses StreamIMAPTransport.
        throw IMAPError.tlsFailed("STARTTLS is not available on this connection")
    }

    func close() async {
        guard isOpen else {
            connection.cancel()
            return
        }
        isOpen = false
        connection.stateUpdateHandler = nil
        connection.cancel()
    }

    /// Maps `NWError` onto the user-facing cases. DNS failures and TLS handshake failures get their own case
    /// so the setup screen can say something specific.
    static func map(_ error: NWError, host: String) -> IMAPError {
        switch error {
        case .posix(let code):
            switch code {
            case .ECONNREFUSED: return .connectionFailed("connection refused")
            case .ETIMEDOUT: return .timedOut
            case .ECONNRESET, .EPIPE: return .connectionClosed
            case .EHOSTUNREACH, .ENETUNREACH: return .connectionFailed("the server is unreachable")
            case .ENOTCONN: return .connectionClosed
            default: return .connectionFailed("POSIX \(code.rawValue)")
            }
        case .dns:
            return .hostNotFound(host)
        case .tls(let status):
            return .tlsFailed("TLS status \(status)")
        default:
            return .connectionFailed("connection error")
        }
    }
}

/// Guarantees a continuation is resumed exactly once, from whichever callback fires first.
final class SingleResume<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?

    init(_ continuation: CheckedContinuation<Value, Error>) {
        self.continuation = continuation
    }

    func succeed(_ value: Value) {
        guard let continuation = take() else { return }
        continuation.resume(returning: value)
    }

    func fail(_ error: Error) {
        guard let continuation = take() else { return }
        continuation.resume(throwing: error)
    }

    private func take() -> CheckedContinuation<Value, Error>? {
        lock.lock()
        defer { lock.unlock() }
        let value = continuation
        continuation = nil
        return value
    }
}

// MARK: - Foundation streams (STARTTLS)

/// `Stream`-backed transport used for STARTTLS on port 143: `Stream` is the only API on the platform that can
/// turn an already-open plaintext connection into a TLS one (`socketSecurityLevelKey` set after `open()`).
///
/// The streams are never scheduled on a run loop; `read`/`write` poll `hasBytesAvailable` /
/// `hasSpaceAvailable` so no thread ever blocks in a socket call and a timeout can close the connection
/// safely. Certificate and host-name validation stay at the system default.
actor StreamIMAPTransport: IMAPTransport {
    private let endpoint: IMAPEndpoint
    private var input: InputStream?
    private var output: OutputStream?
    private var isOpen = false

    /// How long a single read or write may wait for the socket. `IMAPClient` applies the real command deadline.
    static let ioTimeout: TimeInterval = 60
    private static let pollInterval: UInt64 = 5_000_000 // 5 ms

    init(endpoint: IMAPEndpoint) {
        self.endpoint = endpoint
    }

    func open() async throws {
        guard !isOpen else { return }
        var input: InputStream?
        var output: OutputStream?
        Stream.getStreamsToHost(withName: endpoint.host, port: endpoint.port, inputStream: &input, outputStream: &output)
        guard let input, let output else {
            throw IMAPError.connectionFailed("could not open a connection to \(endpoint.host)")
        }
        if endpoint.security == .tls {
            try applySecurityLevel(input: input, output: output)
        }
        input.open()
        output.open()
        self.input = input
        self.output = output
        isOpen = true
    }

    func write(_ data: Data) async throws {
        guard isOpen, let output else { throw IMAPError.connectionClosed }
        var remaining = [UInt8](data)
        let deadline = Date().addingTimeInterval(Self.ioTimeout)
        while !remaining.isEmpty {
            try Task.checkCancellation()
            try check(output)
            if output.hasSpaceAvailable {
                let written = remaining.withUnsafeBufferPointer { buffer -> Int in
                    guard let base = buffer.baseAddress else { return 0 }
                    return output.write(base, maxLength: buffer.count)
                }
                if written < 0 { throw mapStreamError(output) }
                if written > 0 { remaining.removeFirst(written) }
                continue
            }
            guard Date() < deadline else { throw IMAPError.timedOut }
            try await Task.sleep(nanoseconds: Self.pollInterval)
        }
    }

    func read() async throws -> Data {
        guard isOpen, let input else { throw IMAPError.connectionClosed }
        let deadline = Date().addingTimeInterval(Self.ioTimeout)
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            try Task.checkCancellation()
            try check(input)
            if input.hasBytesAvailable {
                let count = buffer.withUnsafeMutableBufferPointer { pointer -> Int in
                    guard let base = pointer.baseAddress else { return 0 }
                    return input.read(base, maxLength: pointer.count)
                }
                if count < 0 { throw mapStreamError(input) }
                if count == 0 { throw IMAPError.connectionClosed }
                return Data(buffer[0..<count])
            }
            if input.streamStatus == .atEnd { throw IMAPError.connectionClosed }
            guard Date() < deadline else { throw IMAPError.timedOut }
            try await Task.sleep(nanoseconds: Self.pollInterval)
        }
    }

    /// Sets the socket security level on the open streams, which starts the TLS handshake in place. The
    /// streams were created with the server's host name, so the default chain and host-name checks apply.
    func upgradeToTLS() async throws {
        guard isOpen, let input, let output else { throw IMAPError.connectionClosed }
        try applySecurityLevel(input: input, output: output)
    }

    func close() async {
        isOpen = false
        input?.close()
        output?.close()
        input = nil
        output = nil
    }

    private func applySecurityLevel(input: InputStream, output: OutputStream) throws {
        let level = StreamSocketSecurityLevel.negotiatedSSL.rawValue
        let inputOK = input.setProperty(level, forKey: .socketSecurityLevelKey)
        let outputOK = output.setProperty(level, forKey: .socketSecurityLevelKey)
        guard inputOK, outputOK else {
            throw IMAPError.tlsFailed("the connection could not be switched to TLS")
        }
    }

    private func check(_ stream: Stream) throws {
        switch stream.streamStatus {
        case .error: throw mapStreamError(stream)
        case .closed: throw IMAPError.connectionClosed
        default: return
        }
    }

    private func mapStreamError(_ stream: Stream) -> IMAPError {
        guard let error = stream.streamError as NSError? else { return .connectionFailed("stream error") }
        if error.domain == kCFErrorDomainCFNetwork as String {
            switch CFNetworkErrors(rawValue: Int32(error.code)) {
            case .cfHostErrorHostNotFound, .cfHostErrorUnknown:
                return .hostNotFound(endpoint.host)
            case .cfErrorHTTPSProxyConnectionFailure:
                return .connectionFailed("the proxy refused the connection")
            default:
                break
            }
        }
        if error.domain == NSOSStatusErrorDomain || error.code <= -9800 {
            return .tlsFailed("OSStatus \(error.code)")
        }
        if error.domain == NSPOSIXErrorDomain {
            switch Int32(error.code) {
            case ECONNREFUSED: return .connectionFailed("connection refused")
            case ETIMEDOUT: return .timedOut
            case ECONNRESET, EPIPE, ENOTCONN: return .connectionClosed
            case EHOSTUNREACH, ENETUNREACH: return .connectionFailed("the server is unreachable")
            default: return .connectionFailed("POSIX \(error.code)")
            }
        }
        return .connectionFailed("error \(error.code)")
    }
}

import Foundation
import Network
import XCTest
@testable import PhishGuard

// A real IMAP server on 127.0.0.1 that speaks the protocol over a real socket, so the client's framing,
// literal handling and response parsing are exercised end to end rather than stubbed out.

/// One message the fake server can serve.
struct FakeIMAPMessage: Sendable {
    var uid: UInt32
    var internalDate: Date
    /// Full RFC 822 bytes, CRLF line endings.
    var raw: Data
    /// Text of the `BODYSTRUCTURE` response, if the test wants one.
    var bodyStructure: String?
    /// Content of individual parts, keyed by part number, for `BODY.PEEK[1]`.
    var parts: [String: Data] = [:]
    /// Reported `RFC822.SIZE`, when it should differ from `raw.count` (to exercise the large-message path).
    var sizeOverride: Int?

    var size: Int { sizeOverride ?? raw.count }

    static func make(
        uid: UInt32,
        from: String = "Billing <billing@example.com>",
        to: String = "user@example.com",
        subject: String = "Invoice",
        body: String = "Hello there.",
        /// An hour ago by default, so a `SINCE` search over any sensible lookback window matches.
        date: Date = Date().addingTimeInterval(-3_600),
        extraHeaders: [String] = []
    ) -> FakeIMAPMessage {
        var lines = [
            "From: \(from)",
            "To: \(to)",
            "Subject: \(subject)",
            "Date: Mon, 22 Sep 2026 09:00:00 +0000",
            "Message-ID: <\(uid)@example.com>",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=UTF-8",
        ]
        lines.append(contentsOf: extraHeaders)
        let raw = lines.joined(separator: "\r\n") + "\r\n\r\n" + body + "\r\n"
        return FakeIMAPMessage(
            uid: uid,
            internalDate: date,
            raw: Data(raw.utf8),
            bodyStructure: "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" \(body.utf8.count) 1)"
        )
    }

    /// Header block including the blank line that ends it, which is what `BODY[HEADER]` returns.
    var headerBlock: Data {
        let bytes = [UInt8](raw)
        var index = 0
        while index + 3 < bytes.count {
            if bytes[index] == 0x0D, bytes[index + 1] == 0x0A, bytes[index + 2] == 0x0D, bytes[index + 3] == 0x0A {
                return Data(bytes[0..<(index + 4)])
            }
            index += 1
        }
        return raw
    }
}

/// Ways the fake server can misbehave, so the client's defences are tested.
enum FakeIMAPBehavior: Sendable, Equatable {
    case normal
    /// Closes the socket right after the greeting.
    case dropAfterGreeting
    /// Closes the socket in the middle of the response to the first command whose line starts with this verb.
    case dropDuring(String)
    /// Never answers that command at all.
    case silentDuring(String)
    /// Announces a literal far bigger than the cap.
    case oversizedLiteralOnFetch
    /// Answers with bytes that are not IMAP at all.
    case garbageOn(String)
    /// Sends a single line that never ends.
    case hugeLineOn(String)
}

/// A scripted IMAP server. Not a mock: it accepts a real TCP connection, parses the client's commands
/// (literals included) and writes real IMAP responses.
final class FakeIMAPServer: @unchecked Sendable {
    struct Configuration: Sendable {
        var username = "user@example.com"
        var password = "app-specific-password"
        var capabilities = ["IMAP4rev1", "UIDPLUS"]
        var advertiseStartTLS = false
        var uidValidity: UInt32 = 1_000
        var messages: [FakeIMAPMessage] = []
        var examineReadOnly = true
        var loginFailure: (code: String, text: String)?
        var behavior: FakeIMAPBehavior = .normal
        /// `UID SEARCH <n>:*` returns the highest UID when nothing matches, as real servers do.
        var searchReturnsHighestWhenEmpty = true

        init() {}
    }

    private let lock = NSLock()
    private var configuration: Configuration
    private var listener: NWListener?
    private var connections: [NWConnection] = []
    private var transcript: [String] = []
    private let queue = DispatchQueue(label: "FakeIMAPServer")

    /// Per-connection parse state.
    private final class Session {
        var buffer: [UInt8] = []
        var awaitingLiteral: Int?
        var partial: String = ""
        var literals: [String] = []
        var authenticated = false
        var pendingAuthenticateTag: String?
    }
    private var sessions: [ObjectIdentifier: Session] = [:]

    private(set) var port: UInt16 = 0

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    /// Commands the server received, one line each, in order.
    var receivedCommands: [String] {
        lock.lock()
        defer { lock.unlock() }
        return transcript
    }

    /// Verbs only (the word after the tag), uppercased.
    var receivedVerbs: [String] {
        receivedCommands.compactMap { line in
            let parts = line.split(separator: " ")
            guard parts.count >= 2 else { return nil }
            return parts[1].uppercased()
        }
    }

    func update(_ body: (inout Configuration) -> Void) {
        lock.lock()
        body(&configuration)
        lock.unlock()
    }

    private var config: Configuration {
        lock.lock()
        defer { lock.unlock() }
        return configuration
    }

    func start() throws {
        let parameters = NWParameters.tcp
        // Bound to loopback so the test never opens a port to the network (and never trips a firewall prompt).
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        parameters.allowLocalEndpointReuse = true
        let listener = try NWListener(using: parameters, on: .any)
        self.listener = listener

        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { [weak self] state in
            if case .ready = state {
                self?.port = listener.port?.rawValue ?? 0
                ready.signal()
            }
            if case .failed = state { ready.signal() }
        }
        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success, port != 0 else {
            throw XCTSkip("the loopback listener did not come up")
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        lock.lock()
        let open = connections
        connections = []
        lock.unlock()
        for connection in open { connection.cancel() }
    }

    /// Endpoint pointing at this server, plaintext (TLS is not part of what the fake exercises).
    var endpoint: IMAPEndpoint { IMAPEndpoint(host: "127.0.0.1", port: Int(port), security: .none) }

    var settings: IMAPAccountSettings {
        IMAPAccountSettings(
            host: "127.0.0.1", port: Int(port), security: .none,
            username: config.username, email: config.username, displayName: nil
        )
    }

    // MARK: - Connection handling

    private func accept(_ connection: NWConnection) {
        lock.lock()
        connections.append(connection)
        sessions[ObjectIdentifier(connection)] = Session()
        lock.unlock()

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            if case .ready = state {
                let capabilities = self.capabilityList()
                self.send("* OK [CAPABILITY \(capabilities)] FakeIMAP ready", on: connection)
                if self.config.behavior == .dropAfterGreeting {
                    connection.cancel()
                    return
                }
                self.receive(on: connection)
            }
        }
        connection.start(queue: queue)
    }

    private func capabilityList() -> String {
        var capabilities = config.capabilities
        if config.advertiseStartTLS { capabilities.append("STARTTLS") }
        return capabilities.joined(separator: " ")
    }

    private func receive(on connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.consume(data, on: connection)
            }
            if isComplete || error != nil {
                connection.cancel()
                return
            }
            self.receive(on: connection)
        }
    }

    private func session(for connection: NWConnection) -> Session {
        lock.lock()
        defer { lock.unlock() }
        let key = ObjectIdentifier(connection)
        if let existing = sessions[key] { return existing }
        let fresh = Session()
        sessions[key] = fresh
        return fresh
    }

    private func consume(_ data: Data, on connection: NWConnection) {
        let session = session(for: connection)
        session.buffer.append(contentsOf: data)

        while true {
            if let expected = session.awaitingLiteral {
                guard session.buffer.count >= expected else { return }
                let literal = String(decoding: session.buffer[0..<expected], as: UTF8.self)
                session.buffer.removeFirst(expected)
                session.literals.append(literal)
                session.awaitingLiteral = nil
                continue
            }
            guard let newline = session.buffer.firstIndex(of: 0x0A) else { return }
            var lineBytes = Array(session.buffer[0...newline])
            session.buffer.removeFirst(newline + 1)
            while let last = lineBytes.last, last == 0x0A || last == 0x0D { lineBytes.removeLast() }
            let line = String(decoding: lineBytes, as: UTF8.self)

            if let tag = session.pendingAuthenticateTag {
                session.pendingAuthenticateTag = nil
                handleAuthenticateResponse(tag: tag, payload: line, session: session, connection: connection)
                continue
            }

            // A command line ending in {n} means the argument follows as a literal.
            if let length = Self.trailingLiteral(line) {
                session.partial += String(line.dropLast("{\(length)}".count))
                session.awaitingLiteral = length
                send("+ Ready for literal", on: connection)
                continue
            }

            let full = session.partial + line
            session.partial = ""
            let resolved = Self.substituteLiterals(full, literals: session.literals)
            session.literals = []
            handle(command: resolved, session: session, connection: connection)
        }
    }

    private static func trailingLiteral(_ line: String) -> Int? {
        guard line.hasSuffix("}"), let open = line.lastIndex(of: "{") else { return nil }
        let digits = line[line.index(after: open)..<line.index(before: line.endIndex)]
        let normalized = digits.hasSuffix("+") ? String(digits.dropLast()) : String(digits)
        return Int(normalized)
    }

    /// Puts literal values back where their `{n}` marker was, as a quoted argument.
    private static func substituteLiterals(_ command: String, literals: [String]) -> String {
        var result = command
        for literal in literals {
            result += "\"\(literal.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\""
        }
        return result
    }

    // MARK: - Command dispatch

    private func handle(command: String, session: Session, connection: NWConnection) {
        lock.lock()
        transcript.append(command)
        lock.unlock()

        let tokens = Self.tokenize(command)
        guard tokens.count >= 2 else {
            send("* BAD malformed command", on: connection)
            return
        }
        let tag = tokens[0]
        let verb = tokens[1].uppercased()
        let arguments = Array(tokens.dropFirst(2))

        switch config.behavior {
        case .silentDuring(let target) where target == verb:
            return
        case .dropDuring(let target) where target == verb:
            send("* 1 FETCH (UID 1 BODY[] {5000}", on: connection)
            queue.asyncAfter(deadline: .now() + 0.05) { connection.cancel() }
            return
        case .garbageOn(let target) where target == verb:
            send("this is not an imap response at all ))) {", on: connection)
            send("\(tag) OK done", on: connection)
            return
        case .hugeLineOn(let target) where target == verb:
            sendRaw(Data(String(repeating: "x", count: 300_000).utf8), on: connection)
            return
        case .oversizedLiteralOnFetch where verb == "UID" && arguments.first?.uppercased() == "FETCH":
            send("* 1 FETCH (UID 1 BODY[] {999999999}", on: connection)
            return
        default:
            break
        }

        switch verb {
        case "CAPABILITY":
            send("* CAPABILITY \(capabilityList())", on: connection)
            send("\(tag) OK CAPABILITY completed", on: connection)
        case "LOGIN":
            handleLogin(tag: tag, arguments: arguments, session: session, connection: connection)
        case "AUTHENTICATE":
            guard arguments.first?.uppercased() == "PLAIN" else {
                send("\(tag) NO unsupported mechanism", on: connection)
                return
            }
            session.pendingAuthenticateTag = tag
            send("+ ", on: connection)
        case "EXAMINE":
            handleExamine(tag: tag, session: session, connection: connection)
        case "UID":
            handleUID(tag: tag, arguments: arguments, session: session, connection: connection)
        case "NOOP":
            send("\(tag) OK NOOP completed", on: connection)
        case "LOGOUT":
            send("* BYE logging out", on: connection)
            send("\(tag) OK LOGOUT completed", on: connection)
        case "STARTTLS":
            send("\(tag) OK begin TLS negotiation now", on: connection)
        default:
            send("\(tag) BAD unknown command", on: connection)
        }
    }

    private func handleLogin(tag: String, arguments: [String], session: Session, connection: NWConnection) {
        if let failure = config.loginFailure {
            send("\(tag) NO [\(failure.code)] \(failure.text)", on: connection)
            return
        }
        guard arguments.count >= 2,
              arguments[0].caseInsensitiveCompare(config.username) == .orderedSame,
              arguments[1] == config.password else {
            send("\(tag) NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)", on: connection)
            return
        }
        session.authenticated = true
        send("\(tag) OK [CAPABILITY \(capabilityList())] Logged in", on: connection)
    }

    private func handleAuthenticateResponse(tag: String, payload: String, session: Session, connection: NWConnection) {
        lock.lock()
        transcript.append(payload) // recorded verbatim so a test can prove the password is not sent in the clear
        lock.unlock()
        if let failure = config.loginFailure {
            send("\(tag) NO [\(failure.code)] \(failure.text)", on: connection)
            return
        }
        guard let decoded = Data(base64Encoded: payload) else {
            send("\(tag) NO [AUTHENTICATIONFAILED] bad payload", on: connection)
            return
        }
        let fields = decoded.split(separator: 0, omittingEmptySubsequences: false).map { String(decoding: $0, as: UTF8.self) }
        guard fields.count == 3, fields[1].caseInsensitiveCompare(config.username) == .orderedSame, fields[2] == config.password else {
            send("\(tag) NO [AUTHENTICATIONFAILED] Invalid credentials", on: connection)
            return
        }
        session.authenticated = true
        send("\(tag) OK [CAPABILITY \(capabilityList())] Logged in", on: connection)
    }

    private func handleExamine(tag: String, session: Session, connection: NWConnection) {
        guard session.authenticated else {
            send("\(tag) NO Not authenticated", on: connection)
            return
        }
        let current = config
        send("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)", on: connection)
        send("* \(current.messages.count) EXISTS", on: connection)
        send("* 0 RECENT", on: connection)
        send("* OK [UIDVALIDITY \(current.uidValidity)] UIDs valid", on: connection)
        send("* OK [UIDNEXT \((current.messages.map(\.uid).max() ?? 0) + 1)] Predicted next UID", on: connection)
        send("* OK [PERMANENTFLAGS ()] No permanent flags permitted", on: connection)
        send("\(tag) OK [\(current.examineReadOnly ? "READ-ONLY" : "READ-WRITE")] EXAMINE completed", on: connection)
    }

    private func handleUID(tag: String, arguments: [String], session: Session, connection: NWConnection) {
        guard session.authenticated else {
            send("\(tag) NO Not authenticated", on: connection)
            return
        }
        guard let subcommand = arguments.first?.uppercased() else {
            send("\(tag) BAD missing UID subcommand", on: connection)
            return
        }
        switch subcommand {
        case "SEARCH":
            let uids = search(Array(arguments.dropFirst()))
            send("* SEARCH \(uids.map(String.init).joined(separator: " "))", on: connection)
            send("\(tag) OK UID SEARCH completed", on: connection)
        case "FETCH":
            fetch(tag: tag, arguments: Array(arguments.dropFirst()), connection: connection)
        default:
            send("\(tag) BAD unsupported UID subcommand", on: connection)
        }
    }

    private func search(_ arguments: [String]) -> [UInt32] {
        let current = config
        let all = current.messages.map(\.uid).sorted()
        guard let first = arguments.first?.uppercased() else { return all }
        if first == "UID", arguments.count >= 2 {
            let range = arguments[1].split(separator: ":")
            let lower = UInt32(range.first.map(String.init) ?? "") ?? 0
            let matches = all.filter { $0 >= lower }
            if matches.isEmpty, current.searchReturnsHighestWhenEmpty, let highest = all.last { return [highest] }
            return matches
        }
        if first == "SINCE", arguments.count >= 2 {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(identifier: "UTC")
            formatter.dateFormat = "dd-MMM-yyyy"
            guard let since = formatter.date(from: arguments[1]) else { return all }
            return current.messages.filter { $0.internalDate >= since }.map(\.uid).sorted()
        }
        return all
    }

    private func fetch(tag: String, arguments: [String], connection: NWConnection) {
        let current = config
        guard let set = arguments.first else {
            send("\(tag) BAD missing set", on: connection)
            return
        }
        let wanted = Self.parseUIDSet(set)
        let items = arguments.dropFirst().joined(separator: " ")
            .trimmingCharacters(in: CharacterSet(charactersIn: "()"))
            .split(separator: " ")
            .map(String.init)

        for (index, message) in current.messages.enumerated() where wanted.contains(message.uid) {
            // Simple items first, then the literal sections: every literal interrupts the line and the rest of
            // the response continues after its bytes, exactly as a real server streams it.
            var simple: [String] = ["UID \(message.uid)"]
            var literalSections: [(String, Data)] = []
            for item in items {
                let upper = item.uppercased()
                switch upper {
                case "UID":
                    continue
                case "INTERNALDATE":
                    simple.append("INTERNALDATE \"\(Self.internalDateFormatter.string(from: message.internalDate))\"")
                case "RFC822.SIZE":
                    simple.append("RFC822.SIZE \(message.size)")
                case "BODYSTRUCTURE":
                    if let structure = message.bodyStructure { simple.append("BODYSTRUCTURE \(structure)") }
                case "BODY.PEEK[]":
                    literalSections.append(("BODY[]", message.raw))
                case "BODY.PEEK[HEADER]":
                    literalSections.append(("BODY[HEADER]", message.headerBlock))
                default:
                    if upper.hasPrefix("BODY.PEEK[") {
                        let part = String(upper.dropFirst("BODY.PEEK[".count).dropLast())
                        literalSections.append(("BODY[\(part)]", message.parts[part] ?? Data()))
                    }
                }
            }

            var line = "* \(index + 1) FETCH (" + simple.joined(separator: " ")
            var data = Data()
            for (name, content) in literalSections {
                line += " \(name) {\(content.count)}\r\n"
                data.append(Data(line.utf8))
                data.append(content)
                line = ""
            }
            line += ")\r\n"
            data.append(Data(line.utf8))
            sendRaw(data, on: connection)
        }
        send("\(tag) OK UID FETCH completed", on: connection)
    }

    private static func parseUIDSet(_ set: String) -> Set<UInt32> {
        var result: Set<UInt32> = []
        for group in set.split(separator: ",") {
            let bounds = group.split(separator: ":")
            if bounds.count == 2, let lower = UInt32(bounds[0]), let upper = UInt32(bounds[1]) {
                for uid in lower...max(lower, upper) { result.insert(uid) }
            } else if let uid = UInt32(group) {
                result.insert(uid)
            }
        }
        return result
    }

    static let internalDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "dd-MMM-yyyy HH:mm:ss Z"
        return formatter
    }()

    /// Splits a command line into tokens, unwrapping quoted strings.
    static func tokenize(_ line: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var inQuotes = false
        var escaped = false
        for character in line {
            if escaped {
                current.append(character)
                escaped = false
                continue
            }
            switch character {
            case "\\" where inQuotes:
                escaped = true
            case "\"":
                inQuotes.toggle()
            case " " where !inQuotes:
                if !current.isEmpty { tokens.append(current) }
                current = ""
            default:
                current.append(character)
            }
        }
        if !current.isEmpty { tokens.append(current) }
        return tokens
    }

    // MARK: - Writing

    private func send(_ line: String, on connection: NWConnection) {
        sendRaw(Data((line + "\r\n").utf8), on: connection)
    }

    private func sendRaw(_ data: Data, on connection: NWConnection) {
        connection.send(content: data, completion: .contentProcessed { _ in })
    }
}

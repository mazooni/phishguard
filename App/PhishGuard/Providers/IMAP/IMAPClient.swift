import Foundation
import OSLog

/// A read-only IMAP4rev1 client.
///
/// It speaks only the commands in `IMAPCommand` — `CAPABILITY`, `STARTTLS`, `LOGIN`/`AUTHENTICATE PLAIN`,
/// `EXAMINE`, `UID SEARCH`, `UID FETCH`, `NOOP`, `LOGOUT` — and every body fetch uses `.PEEK`, so no message is
/// ever marked `\Seen` and no mailbox is ever changed (ARCHITECTURE.md rule 1).
///
/// Nothing derived from mail is logged: the logger records command verbs and counts, never addresses,
/// mailbox names, subjects or bytes of a message.
actor IMAPClient {
    /// Hard caps. A server that exceeds one is dropped rather than trusted.
    struct Limits: Sendable, Equatable {
        /// Everything one command may produce, literals included.
        var maxResponseBytes: Int = 24 * 1024 * 1024
        /// The biggest single literal that will be read.
        var maxLiteralBytes: Int = 16 * 1024 * 1024
        /// The longest line without a literal (a subject line, a capability list).
        var maxLineBytes: Int = 128 * 1024
        var greetingTimeout: TimeInterval = 30
        var commandTimeout: TimeInterval = 60

        init() {}
    }

    /// What `EXAMINE` reported.
    struct MailboxStatus: Sendable, Equatable {
        var uidValidity: UInt32
        var uidNext: UInt32?
        var exists: Int
        /// True when the server confirmed `[READ-ONLY]`. Servers that say nothing leave this true: we only ever
        /// send `EXAMINE`. `[READ-WRITE]` is refused before it gets here.
        var isReadOnly: Bool
    }

    /// One message's fetched pieces. `sections` is keyed by the response name (`BODY[]`, `BODY[HEADER]`, `BODY[1]`).
    struct FetchedMessage: Sendable {
        var uid: UInt32
        var internalDate: Date?
        var size: Int?
        var bodyStructure: IMAPBodyStructure?
        var sections: [String: Data] = [:]
    }

    private let endpoint: IMAPEndpoint
    private let limits: Limits
    private let transport: any IMAPTransport
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "imap")

    private var buffer: [UInt8] = []
    private var cursor = 0
    private var bytesThisCommand = 0
    private var tagCounter = 0
    private var isConnected = false
    private var serverClosed = false
    private(set) var capabilities: Set<String> = []
    private(set) var isAuthenticated = false

    init(endpoint: IMAPEndpoint, limits: Limits = Limits(), transportFactory: IMAPTransportFactory = IMAPTransports.default) {
        self.endpoint = endpoint
        self.limits = limits
        self.transport = transportFactory(endpoint)
    }

    static let internalDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "dd-MMM-yyyy HH:mm:ss Z"
        return formatter
    }()

    // MARK: - Session

    /// Connects, reads the greeting, learns the capabilities and performs STARTTLS when the account asks for it.
    func connect() async throws {
        guard !isConnected else { return }
        try await transport.open()
        isConnected = true

        let greeting = try await withWatchdog(limits.greetingTimeout) { try await self.readResponseLine() }
        switch greeting {
        case .untagged(let line):
            switch line.keyword {
            case "OK":
                absorbCapabilities(from: line.responseCode)
            case "PREAUTH":
                absorbCapabilities(from: line.responseCode)
                isAuthenticated = true
            case "BYE":
                throw IMAPError.commandFailed(command: "connect", serverMessage: line.arguments.compactMap(\.text).joined(separator: " "))
            default:
                throw IMAPError.protocolViolation("unexpected greeting")
            }
        default:
            throw IMAPError.protocolViolation("the server did not send an IMAP greeting")
        }

        if capabilities.isEmpty {
            try await refreshCapabilities()
        }
        if endpoint.security == .startTLS {
            try await startTLS()
        }
        let security = endpoint.security.rawValue
        let capabilityCount = capabilities.count
        logger.info("IMAP connected (\(security, privacy: .public)), \(capabilityCount) capabilities")
    }

    private func startTLS() async throws {
        guard capabilities.contains("STARTTLS") else { throw IMAPError.startTLSUnavailable }
        let result = try await execute(.startTLS)
        guard result.status == .ok else {
            throw IMAPError.commandFailed(command: "STARTTLS", serverMessage: result.text)
        }
        try await transport.upgradeToTLS()
        // RFC 3501: capabilities learnt before the handshake must be discarded.
        capabilities = []
        buffer = []
        cursor = 0
        try await refreshCapabilities()
    }

    private func refreshCapabilities() async throws {
        let result = try await execute(.capability)
        guard result.status == .ok else {
            throw IMAPError.commandFailed(command: "CAPABILITY", serverMessage: result.text)
        }
        for line in result.lines(keyword: "CAPABILITY") {
            absorb(capabilityTokens: line.arguments)
        }
        absorbCapabilities(from: result.code)
    }

    /// `AUTHENTICATE PLAIN` where the server advertises it, `LOGIN` otherwise.
    func authenticate(username: String, password: String) async throws {
        guard !isAuthenticated else { return }
        if capabilities.contains("LOGINDISABLED"), !capabilities.contains("AUTH=PLAIN") {
            throw IMAPError.commandFailed(
                command: "LOGIN",
                serverMessage: "this server does not accept password sign-in on this connection"
            )
        }
        let command: IMAPCommand = capabilities.contains("AUTH=PLAIN")
            ? .authenticatePlain(username: username, password: password)
            : .login(username: username, password: password)
        let result = try await execute(command)
        guard result.status == .ok else {
            logger.notice("IMAP authentication refused (\(result.codeName ?? "no code", privacy: .public))")
            throw IMAPError.loginFailure(code: result.codeName, message: result.text)
        }
        isAuthenticated = true
        // Post-login capabilities are usually different (and are what tells us about UIDPLUS, MOVE, …).
        absorbCapabilities(from: result.code)
        for line in result.lines(keyword: "CAPABILITY") {
            absorb(capabilityTokens: line.arguments)
        }
    }

    /// Opens a mailbox **read-only**. Never `SELECT`.
    func examine(mailbox: String = "INBOX") async throws -> MailboxStatus {
        let result = try await execute(.examine(mailbox: mailbox))
        guard result.status == .ok else {
            if result.codeName == "TRYCREATE" || result.codeName == "NONEXISTENT" {
                throw IMAPError.mailboxNotFound(mailbox)
            }
            throw IMAPError.commandFailed(command: "EXAMINE", serverMessage: result.text)
        }
        // A server answering EXAMINE with READ-WRITE is not behaving; stop rather than hold a writable session.
        if result.codeName == "READ-WRITE" { throw IMAPError.mailboxNotReadOnly }

        var uidValidity: UInt32?
        var uidNext: UInt32?
        var exists = 0
        for line in result.untagged {
            if line.keyword == "EXISTS", let number = line.number { exists = number }
            guard let code = line.responseCode, let name = code.first?.keyword else { continue }
            switch name {
            case "UIDVALIDITY": uidValidity = code.dropFirst().first?.uint32Value
            case "UIDNEXT": uidNext = code.dropFirst().first?.uint32Value
            default: break
            }
        }
        guard let uidValidity else {
            throw IMAPError.protocolViolation("EXAMINE did not report UIDVALIDITY")
        }
        logger.info("EXAMINE ok: \(exists) messages, read-only=\(result.codeName == "READ-ONLY", privacy: .public)")
        return MailboxStatus(uidValidity: uidValidity, uidNext: uidNext, exists: exists, isReadOnly: result.codeName != "READ-WRITE")
    }

    func uidSearch(_ criteria: IMAPSearchCriteria) async throws -> [UInt32] {
        let result = try await execute(.uidSearch(criteria))
        guard result.status == .ok else {
            throw IMAPError.commandFailed(command: "UID SEARCH", serverMessage: result.text)
        }
        var uids: [UInt32] = []
        for line in result.lines(keyword: "SEARCH") {
            uids.append(contentsOf: line.arguments.compactMap(\.uint32Value))
        }
        return uids.sorted()
    }

    func uidFetch(uids: [UInt32], items: [IMAPFetchItem]) async throws -> [FetchedMessage] {
        guard !uids.isEmpty else { return [] }
        let result = try await execute(.uidFetch(uids: uids, items: items))
        guard result.status == .ok else {
            throw IMAPError.commandFailed(command: "UID FETCH", serverMessage: result.text)
        }
        var messages: [FetchedMessage] = []
        for line in result.lines(keyword: "FETCH") {
            guard let items = line.arguments.first?.items else { continue }
            if let message = Self.parseFetch(items: items) { messages.append(message) }
        }
        return messages
    }

    /// Best-effort `LOGOUT` followed by closing the socket. Never throws: sign-out and scan teardown must not
    /// fail. The logout gets a short deadline of its own so a server that has stopped answering cannot hold a
    /// scan open for the full command timeout.
    func disconnect() async {
        if isConnected, !serverClosed {
            _ = try? await execute(.logout, timeout: min(5, limits.commandTimeout))
        }
        await transport.close()
        isConnected = false
        isAuthenticated = false
        buffer = []
        cursor = 0
    }

    // MARK: - FETCH parsing

    static func parseFetch(items: [IMAPToken]) -> FetchedMessage? {
        var uid: UInt32?
        var internalDate: Date?
        var size: Int?
        var structure: IMAPBodyStructure?
        var sections: [String: Data] = [:]

        var index = 0
        while index + 1 < items.count {
            guard let key = items[index].keyword else {
                index += 1
                continue
            }
            let value = items[index + 1]
            switch key {
            case "UID":
                uid = value.uint32Value
            case "INTERNALDATE":
                internalDate = value.text.flatMap { internalDateFormatter.date(from: $0) }
            case "RFC822.SIZE":
                size = value.intValue
            case "BODYSTRUCTURE", "BODY":
                if let list = value.items { structure = IMAPBodyStructure.parse(list) }
            default:
                if key.hasPrefix("BODY[") || key.hasPrefix("RFC822") {
                    sections[key] = value.isNil ? Data() : (value.data ?? Data())
                }
            }
            index += 2
        }
        guard let uid else { return nil }
        return FetchedMessage(uid: uid, internalDate: internalDate, size: size, bodyStructure: structure, sections: sections)
    }

    // MARK: - Command execution

    /// Writes one command and reads until its tagged completion.
    @discardableResult
    func execute(_ command: IMAPCommand, timeout: TimeInterval? = nil) async throws -> IMAPCommandResult {
        guard isConnected else { throw IMAPError.connectionClosed }
        let segments = try command.segments()
        try IMAPCommand.assertReadOnly(verb: command.verb, segments: segments)

        tagCounter += 1
        let tag = String(format: "A%03d", tagCounter)
        bytesThisCommand = 0

        return try await withWatchdog(timeout ?? limits.commandTimeout) {
            try await self.write(tag: tag, command: command, segments: segments)
            return try await self.readUntilTagged(tag: tag, command: command)
        }
    }

    private func write(tag: String, command: IMAPCommand, segments: [IMAPCommand.Segment]) async throws {
        var pending = Data("\(tag) ".utf8)
        for segment in segments {
            switch segment {
            case .text(let text):
                pending.append(Data(text.utf8))
            case .literal(let data):
                pending.append(Data("{\(data.count)}\r\n".utf8))
                try await transport.write(pending)
                pending = Data()
                try await awaitContinuation()
                try await transport.write(data)
            }
        }
        pending.append(Data("\r\n".utf8))
        try await transport.write(pending)
        logger.debug("IMAP > \(command.redactedDescription, privacy: .public)")
    }

    /// Reads response lines until the continuation request that a literal (or AUTHENTICATE) is waiting for.
    private func awaitContinuation() async throws {
        while true {
            let line = try await readResponseLine()
            if case .continuation = line { return }
            if case .untagged(let untagged) = line {
                if untagged.keyword == "BYE" { serverClosed = true; throw IMAPError.connectionClosed }
                continue
            }
            throw IMAPError.protocolViolation("expected a continuation request")
        }
    }

    private func readUntilTagged(tag: String, command: IMAPCommand) async throws -> IMAPCommandResult {
        var untagged: [IMAPUntaggedLine] = []
        var sentAuthenticatePayload = false

        while true {
            try Task.checkCancellation()
            let line = try await readResponseLine()
            switch line {
            case .untagged(let value):
                if value.keyword == "BYE" { serverClosed = true }
                untagged.append(value)
            case .continuation:
                guard command.expectsAuthenticateContinuation, !sentAuthenticatePayload,
                      let payload = command.authenticatePayload else {
                    throw IMAPError.protocolViolation("unexpected continuation request")
                }
                sentAuthenticatePayload = true
                var data = payload
                data.append(Data("\r\n".utf8))
                try await transport.write(data)
            case .tagged(let responseTag, let status, let code, let text):
                guard responseTag == tag else {
                    throw IMAPError.protocolViolation("response tag does not match the command")
                }
                logger.debug("IMAP < \(command.verb, privacy: .public) \(status.rawValue, privacy: .public)")
                return IMAPCommandResult(untagged: untagged, status: status, code: code, text: text)
            }
        }
    }

    // MARK: - Reading

    /// Reads one complete logical line: a CRLF-terminated line with every `{n}` literal it announces inlined
    /// behind its own header, so the tokenizer sees the whole thing at once.
    private func readResponseLine() async throws -> IMAPResponseLine {
        var line = try await readLine()
        while let length = Self.trailingLiteralLength(line) {
            guard length <= limits.maxLiteralBytes else {
                logger.error("IMAP literal of \(length) bytes exceeds the cap; dropping the connection")
                throw IMAPError.responseTooLarge(limit: limits.maxLiteralBytes)
            }
            line.append(contentsOf: try await readExactly(length))
            line.append(contentsOf: try await readLine())
        }
        return try IMAPResponseLine.parse(line)
    }

    private func readLine() async throws -> [UInt8] {
        while true {
            if let index = buffer[cursor...].firstIndex(of: 0x0A) {
                let line = Array(buffer[cursor...index])
                cursor = index + 1
                compactIfNeeded()
                return line
            }
            let lineLimit = limits.maxLineBytes
            guard buffer.count - cursor <= lineLimit else {
                logger.error("IMAP line exceeded \(lineLimit) bytes; dropping the connection")
                throw IMAPError.responseTooLarge(limit: lineLimit)
            }
            try await fill()
        }
    }

    private func readExactly(_ count: Int) async throws -> [UInt8] {
        while buffer.count - cursor < count {
            try await fill()
        }
        let bytes = Array(buffer[cursor..<(cursor + count)])
        cursor += count
        compactIfNeeded()
        return bytes
    }

    private func fill() async throws {
        try Task.checkCancellation()
        let data = try await transport.read()
        bytesThisCommand += data.count
        let responseLimit = limits.maxResponseBytes
        guard bytesThisCommand <= responseLimit else {
            logger.error("IMAP response exceeded \(responseLimit) bytes; dropping the connection")
            throw IMAPError.responseTooLarge(limit: responseLimit)
        }
        buffer.append(contentsOf: data)
    }

    private func compactIfNeeded() {
        guard cursor > 0, cursor >= buffer.count || cursor > 1 << 16 else { return }
        buffer.removeFirst(cursor)
        cursor = 0
    }

    /// The length of the literal a response line ends with (`… {1234}CRLF`), or nil. Quoted strings are tracked
    /// so a subject that merely *looks* like `{12}` at the end of a line cannot desynchronise the reader.
    static func trailingLiteralLength(_ line: [UInt8]) -> Int? {
        var end = line.count
        while end > 0, line[end - 1] == 0x0A || line[end - 1] == 0x0D { end -= 1 }
        guard end > 2, line[end - 1] == UInt8(ascii: "}") else { return nil }

        var inQuotes = false
        var lastBrace: Int?
        var index = 0
        while index < end {
            let byte = line[index]
            if inQuotes {
                if byte == UInt8(ascii: "\\") { index += 2; continue }
                if byte == UInt8(ascii: "\"") { inQuotes = false }
            } else if byte == UInt8(ascii: "\"") {
                inQuotes = true
            } else if byte == UInt8(ascii: "{") {
                lastBrace = index
            }
            index += 1
        }
        guard !inQuotes, let start = lastBrace, start + 1 < end - 1 else { return nil }

        var digits: [UInt8] = []
        var position = start + 1
        while position < end - 1 {
            let byte = line[position]
            if byte >= 0x30, byte <= 0x39 {
                digits.append(byte)
            } else if byte == UInt8(ascii: "+"), position == end - 2 {
                // LITERAL+ ("{12+}"): the server will send the bytes without waiting.
            } else {
                return nil
            }
            position += 1
        }
        guard !digits.isEmpty, digits.count <= 12 else { return nil }
        return Int(String(decoding: digits, as: UTF8.self))
    }

    // MARK: - Capabilities

    private func absorbCapabilities(from code: [IMAPToken]?) {
        guard let code, code.first?.keyword == "CAPABILITY" else { return }
        absorb(capabilityTokens: Array(code.dropFirst()))
    }

    private func absorb(capabilityTokens tokens: [IMAPToken]) {
        for token in tokens {
            guard let name = token.keyword else { continue }
            capabilities.insert(name)
        }
    }

    // MARK: - Timeouts

    /// Runs `body` with a watchdog that closes the transport when the deadline passes, which unblocks the read
    /// in flight. The resulting failure is reported as `timedOut`, not as a dropped connection.
    private func withWatchdog<Value: Sendable>(_ seconds: TimeInterval, _ body: () async throws -> Value) async throws -> Value {
        let fired = TimeoutFlag()
        let transport = self.transport
        let watchdog = Task.detached {
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            guard !Task.isCancelled else { return }
            fired.set()
            await transport.close()
        }
        defer { watchdog.cancel() }
        do {
            return try await body()
        } catch {
            if fired.isSet {
                isConnected = false
                throw IMAPError.timedOut
            }
            throw error
        }
    }
}

/// One-way flag shared with a watchdog task.
final class TimeoutFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    func set() {
        lock.lock()
        value = true
        lock.unlock()
    }

    var isSet: Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

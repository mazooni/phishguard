import Foundation

/// What to ask for in a `UID FETCH`. Every body section is a `.PEEK`, so the server never sets `\Seen`.
enum IMAPFetchItem: Sendable, Equatable, Hashable {
    case uid
    case internalDate
    case rfc822Size
    case bodyStructure
    /// `BODY.PEEK[]` — the whole raw message.
    case peekWhole
    /// `BODY.PEEK[HEADER]` — the header block only.
    case peekHeader
    /// `BODY.PEEK[<part>]` — one MIME part's content, e.g. "1.2".
    case peekPart(String)

    var wireText: String {
        switch self {
        case .uid: return "UID"
        case .internalDate: return "INTERNALDATE"
        case .rfc822Size: return "RFC822.SIZE"
        case .bodyStructure: return "BODYSTRUCTURE"
        case .peekWhole: return "BODY.PEEK[]"
        case .peekHeader: return "BODY.PEEK[HEADER]"
        case .peekPart(let part): return "BODY.PEEK[\(part)]"
        }
    }

    /// The data-item name the server answers with (no `.PEEK`).
    var responseKey: String {
        switch self {
        case .uid: return "UID"
        case .internalDate: return "INTERNALDATE"
        case .rfc822Size: return "RFC822.SIZE"
        case .bodyStructure: return "BODYSTRUCTURE"
        case .peekWhole: return "BODY[]"
        case .peekHeader: return "BODY[HEADER]"
        case .peekPart(let part): return "BODY[\(part)]"
        }
    }
}

/// The search keys the provider needs. Read-only by definition.
enum IMAPSearchCriteria: Sendable, Equatable {
    /// `UID <from>:*` — everything at or above `from`. Servers always return at least the highest UID, so the
    /// caller must still drop anything it has seen.
    case uidFrom(UInt32)
    /// `SINCE <date>` — INTERNALDATE on or after that day (whole days only, per RFC 3501).
    case since(Date)
    case all

    var wireText: String {
        switch self {
        case .uidFrom(let uid): return "UID \(uid):*"
        case .since(let date): return "SINCE \(IMAPCommand.searchDateFormatter.string(from: date))"
        case .all: return "ALL"
        }
    }
}

/// Every command PhishGuard can send. There is deliberately no case for `SELECT`, `STORE`, `APPEND`,
/// `EXPUNGE`, `COPY`, `MOVE`, `DELETE` or anything else that could change a mailbox: a mutating command is
/// not representable, so it cannot be sent by accident (ARCHITECTURE.md rule 1). `IMAPClient` additionally
/// checks the rendered verb against `allowedVerbs` before writing a byte.
enum IMAPCommand: Sendable, Equatable {
    case capability
    case startTLS
    case login(username: String, password: String)
    case authenticatePlain(username: String, password: String)
    /// READ-ONLY select. The only way this client opens a mailbox.
    case examine(mailbox: String)
    case uidSearch(IMAPSearchCriteria)
    case uidFetch(uids: [UInt32], items: [IMAPFetchItem])
    case noop
    case logout

    /// One piece of the command on the wire. A `.literal` is written as `{n}\r\n`, then the bytes once the
    /// server sends its continuation request.
    enum Segment: Sendable, Equatable {
        case text(String)
        case literal(Data)
    }

    static let allowedVerbs: Set<String> = ["CAPABILITY", "STARTTLS", "LOGIN", "AUTHENTICATE", "EXAMINE", "UID", "NOOP", "LOGOUT"]
    /// Only these may follow `UID`.
    static let allowedUIDSubcommands: Set<String> = ["SEARCH", "FETCH"]

    static let searchDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "dd-MMM-yyyy"
        return formatter
    }()

    /// The first word on the wire, used for the allow-list check and for logging.
    var verb: String {
        switch self {
        case .capability: return "CAPABILITY"
        case .startTLS: return "STARTTLS"
        case .login: return "LOGIN"
        case .authenticatePlain: return "AUTHENTICATE"
        case .examine: return "EXAMINE"
        case .uidSearch, .uidFetch: return "UID"
        case .noop: return "NOOP"
        case .logout: return "LOGOUT"
        }
    }

    /// Safe to log: never contains the address, the password or a mailbox name.
    var redactedDescription: String {
        switch self {
        case .uidSearch: return "UID SEARCH"
        case .uidFetch(let uids, _): return "UID FETCH (\(uids.count) uids)"
        case .login, .authenticatePlain: return "\(verb) ****"
        case .examine: return "EXAMINE"
        default: return verb
        }
    }

    /// True while the command is allowed to leave a continuation open (AUTHENTICATE sends its response after
    /// the server's `+`).
    var expectsAuthenticateContinuation: Bool {
        if case .authenticatePlain = self { return true }
        return false
    }

    /// Renders the command without its tag or trailing CRLF.
    func segments() throws -> [Segment] {
        switch self {
        case .capability:
            return [.text("CAPABILITY")]
        case .startTLS:
            return [.text("STARTTLS")]
        case .login(let username, let password):
            var segments: [Segment] = [.text("LOGIN ")]
            segments.append(contentsOf: try Self.argument(username))
            segments.append(.text(" "))
            segments.append(contentsOf: try Self.argument(password))
            return segments
        case .authenticatePlain:
            // The SASL payload follows the server's continuation request, not the command line.
            return [.text("AUTHENTICATE PLAIN")]
        case .examine(let mailbox):
            var segments: [Segment] = [.text("EXAMINE ")]
            segments.append(contentsOf: try Self.argument(mailbox))
            return segments
        case .uidSearch(let criteria):
            return [.text("UID SEARCH \(criteria.wireText)")]
        case .uidFetch(let uids, let items):
            guard !uids.isEmpty else { throw IMAPError.protocolViolation("UID FETCH with no uids") }
            guard !items.isEmpty else { throw IMAPError.protocolViolation("UID FETCH with no items") }
            return [.text("UID FETCH \(Self.uidSet(uids)) (\(items.map(\.wireText).joined(separator: " ")))")]
        case .noop:
            return [.text("NOOP")]
        case .logout:
            return [.text("LOGOUT")]
        }
    }

    /// The SASL PLAIN payload (`\0user\0password`, base64), sent only after the server's `+`.
    var authenticatePayload: Data? {
        guard case .authenticatePlain(let username, let password) = self else { return nil }
        var raw = Data([0])
        raw.append(Data(username.utf8))
        raw.append(0)
        raw.append(Data(password.utf8))
        return Data(raw.base64EncodedString().utf8)
    }

    /// An `astring` argument: a quoted string when it is 7-bit and short, otherwise a literal.
    /// CR and LF are rejected outright — they would let a crafted password inject a second command.
    static func argument(_ value: String) throws -> [Segment] {
        let bytes = Array(value.utf8)
        // Checked on the bytes, not on Characters: Swift folds CR LF into a single grapheme, so
        // `value.contains("\r")` would miss the very injection this guards against.
        guard !bytes.contains(0x0D), !bytes.contains(0x0A) else {
            throw IMAPError.protocolViolation("a credential contains a line break")
        }
        let isSevenBit = bytes.allSatisfy { $0 >= 0x20 && $0 < 0x80 }
        if isSevenBit && bytes.count <= 1024 {
            var escaped = ""
            for character in value {
                if character == "\"" || character == "\\" { escaped.append("\\") }
                escaped.append(character)
            }
            return [.text("\"\(escaped)\"")]
        }
        return [.literal(Data(bytes))]
    }

    /// `[1,2,3,7,9]` → `"1:3,7,9"`.
    static func uidSet(_ uids: [UInt32]) -> String {
        let sorted = Array(Set(uids)).sorted()
        var parts: [String] = []
        var index = 0
        while index < sorted.count {
            var end = index
            while end + 1 < sorted.count, sorted[end + 1] == sorted[end] + 1 { end += 1 }
            parts.append(index == end ? "\(sorted[index])" : "\(sorted[index]):\(sorted[end])")
            index = end + 1
        }
        return parts.joined(separator: ",")
    }

    /// Belt and braces: rejects anything outside the read-only allow-list before it reaches the socket.
    static func assertReadOnly(verb: String, segments: [Segment]) throws {
        let upper = verb.uppercased()
        guard allowedVerbs.contains(upper) else { throw IMAPError.forbiddenCommand(upper) }
        guard upper == "UID" else { return }
        guard case .text(let first)? = segments.first else { throw IMAPError.forbiddenCommand("UID") }
        let words = first.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard words.count >= 2, allowedUIDSubcommands.contains(words[1].uppercased()) else {
            throw IMAPError.forbiddenCommand("UID \(words.count >= 2 ? String(words[1]).uppercased() : "?")")
        }
    }
}

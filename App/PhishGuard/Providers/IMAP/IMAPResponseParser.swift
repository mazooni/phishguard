import Foundation

/// One element of an IMAP response.
///
/// `atom` also carries numbers, `NIL`, flags (`\Seen`) and section specifiers (`BODY[HEADER.FIELDS (DATE)]`):
/// the tokenizer keeps a bracketed section attached to the atom that introduced it, which is exactly how
/// `FETCH` data items are addressed.
indirect enum IMAPToken: Sendable, Equatable, Hashable {
    case atom(String)
    case quoted(String)
    case literal(Data)
    /// A parenthesised list.
    case list([IMAPToken])
    /// A bracketed response code, e.g. the `[UIDVALIDITY 42]` in `* OK [UIDVALIDITY 42] ...`.
    case code([IMAPToken])

    /// Text of an atom / quoted string / literal (literals are decoded as UTF-8, replacing invalid bytes).
    /// nil for lists and codes.
    var text: String? {
        switch self {
        case .atom(let value), .quoted(let value): return value
        case .literal(let data): return String(decoding: data, as: UTF8.self)
        case .list, .code: return nil
        }
    }

    /// Like `text`, but the unquoted atom `NIL` reads as nil.
    var stringValue: String? {
        if isNil { return nil }
        return text
    }

    /// Raw bytes of a literal or the UTF-8 of an atom / quoted string.
    var data: Data? {
        switch self {
        case .literal(let data): return data
        case .atom(let value), .quoted(let value): return Data(value.utf8)
        case .list, .code: return nil
        }
    }

    var isNil: Bool {
        if case .atom(let value) = self { return value.caseInsensitiveCompare("NIL") == .orderedSame }
        return false
    }

    var intValue: Int? {
        guard case .atom(let value) = self else { return nil }
        return Int(value)
    }

    var uint32Value: UInt32? {
        guard case .atom(let value) = self else { return nil }
        return UInt32(value)
    }

    /// Elements of a list or a response code.
    var items: [IMAPToken]? {
        switch self {
        case .list(let items), .code(let items): return items
        default: return nil
        }
    }

    /// Uppercased atom text, for keyword comparisons.
    var keyword: String? {
        guard case .atom(let value) = self else { return nil }
        return value.uppercased()
    }
}

/// Turns raw response bytes (with any literals already inlined behind their `{n}` prefix) into tokens.
///
/// Deliberately a hand-written scanner and not a pile of regular expressions: literals are binary and may
/// contain anything, including CRLF, `)` and `"`.
struct IMAPTokenizer {
    /// Guards against a hostile server nesting parentheses until the parser runs out of stack.
    static let maxDepth = 24

    private let bytes: [UInt8]
    private var index: Int

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
        self.index = 0
    }

    static func tokenize(_ bytes: [UInt8]) throws -> [IMAPToken] {
        var tokenizer = IMAPTokenizer(bytes)
        return try tokenizer.parseSequence(depth: 0, terminator: nil)
    }

    // MARK: - Scanning

    private mutating func parseSequence(depth: Int, terminator: UInt8?) throws -> [IMAPToken] {
        guard depth <= Self.maxDepth else { throw IMAPError.protocolViolation("response nested too deeply") }
        var tokens: [IMAPToken] = []
        while true {
            skipSpaces()
            guard index < bytes.count else {
                if terminator != nil { throw IMAPError.protocolViolation("unterminated list") }
                return tokens
            }
            let byte = bytes[index]
            if byte == 0x0D || byte == 0x0A {
                if terminator != nil {
                    // CRLF inside a list is legal only inside a literal, which is consumed as one token.
                    index += 1
                    continue
                }
                index += 1
                continue
            }
            if let terminator, byte == terminator {
                index += 1
                return tokens
            }
            switch byte {
            case UInt8(ascii: "("):
                index += 1
                tokens.append(.list(try parseSequence(depth: depth + 1, terminator: UInt8(ascii: ")"))))
            case UInt8(ascii: "["):
                index += 1
                tokens.append(.code(try parseSequence(depth: depth + 1, terminator: UInt8(ascii: "]"))))
            case UInt8(ascii: ")"), UInt8(ascii: "]"):
                throw IMAPError.protocolViolation("unbalanced \(Character(UnicodeScalar(byte)))")
            case UInt8(ascii: "\""):
                tokens.append(.quoted(try parseQuoted()))
            case UInt8(ascii: "{"):
                tokens.append(.literal(try parseLiteral()))
            default:
                tokens.append(.atom(try parseAtom()))
            }
        }
    }

    private mutating func skipSpaces() {
        while index < bytes.count, bytes[index] == 0x20 || bytes[index] == 0x09 { index += 1 }
    }

    private mutating func parseQuoted() throws -> String {
        index += 1 // opening quote
        var out: [UInt8] = []
        while index < bytes.count {
            let byte = bytes[index]
            if byte == UInt8(ascii: "\\") {
                guard index + 1 < bytes.count else { throw IMAPError.protocolViolation("dangling escape") }
                out.append(bytes[index + 1])
                index += 2
                continue
            }
            if byte == UInt8(ascii: "\"") {
                index += 1
                return String(decoding: out, as: UTF8.self)
            }
            if byte == 0x0D || byte == 0x0A { throw IMAPError.protocolViolation("CRLF in a quoted string") }
            out.append(byte)
            index += 1
        }
        throw IMAPError.protocolViolation("unterminated quoted string")
    }

    /// `{123}CRLF` followed by exactly 123 bytes. `{123+}` (LITERAL+) is accepted too.
    private mutating func parseLiteral() throws -> Data {
        index += 1 // "{"
        var digits: [UInt8] = []
        while index < bytes.count, bytes[index] >= 0x30, bytes[index] <= 0x39 {
            digits.append(bytes[index])
            index += 1
        }
        if index < bytes.count, bytes[index] == UInt8(ascii: "+") { index += 1 }
        guard index < bytes.count, bytes[index] == UInt8(ascii: "}"), !digits.isEmpty,
              let count = Int(String(decoding: digits, as: UTF8.self)) else {
            throw IMAPError.protocolViolation("malformed literal header")
        }
        index += 1 // "}"
        if index < bytes.count, bytes[index] == 0x0D { index += 1 }
        if index < bytes.count, bytes[index] == 0x0A { index += 1 }
        guard index + count <= bytes.count else { throw IMAPError.protocolViolation("truncated literal") }
        let data = Data(bytes[index..<(index + count)])
        index += count
        return data
    }

    /// An atom, absorbing any `[...]` section and `<...>` partial specifier that hangs off it.
    private mutating func parseAtom() throws -> String {
        var out: [UInt8] = []
        while index < bytes.count {
            let byte = bytes[index]
            if byte == UInt8(ascii: "[") {
                out.append(contentsOf: try consumeBracketedSection())
                continue
            }
            if byte == UInt8(ascii: "<"), !out.isEmpty {
                out.append(contentsOf: consumeAngleSuffix())
                continue
            }
            if byte == 0x20 || byte == 0x09 || byte == 0x0D || byte == 0x0A
                || byte == UInt8(ascii: "(") || byte == UInt8(ascii: ")")
                || byte == UInt8(ascii: "]") || byte == UInt8(ascii: "\"")
                || (byte == UInt8(ascii: "{") && !out.isEmpty) {
                break
            }
            out.append(byte)
            index += 1
        }
        guard !out.isEmpty else { throw IMAPError.protocolViolation("empty atom") }
        return String(decoding: out, as: UTF8.self)
    }

    /// `[HEADER.FIELDS (FROM TO)]`, balanced, quotes respected.
    private mutating func consumeBracketedSection() throws -> [UInt8] {
        var out: [UInt8] = []
        var depth = 0
        var inQuotes = false
        while index < bytes.count {
            let byte = bytes[index]
            out.append(byte)
            index += 1
            if inQuotes {
                if byte == UInt8(ascii: "\\"), index < bytes.count {
                    out.append(bytes[index])
                    index += 1
                } else if byte == UInt8(ascii: "\"") {
                    inQuotes = false
                }
                continue
            }
            switch byte {
            case UInt8(ascii: "\""): inQuotes = true
            case UInt8(ascii: "["): depth += 1
            case UInt8(ascii: "]"):
                depth -= 1
                if depth == 0 { return out }
            case 0x0D, 0x0A: throw IMAPError.protocolViolation("CRLF inside a section specifier")
            default: break
            }
        }
        throw IMAPError.protocolViolation("unterminated section specifier")
    }

    /// `<0.2048>` partial-fetch suffix.
    private mutating func consumeAngleSuffix() -> [UInt8] {
        var out: [UInt8] = []
        while index < bytes.count {
            let byte = bytes[index]
            out.append(byte)
            index += 1
            if byte == UInt8(ascii: ">") { break }
            if byte == 0x0D || byte == 0x0A { break }
        }
        return out
    }
}

/// Completion status of a tagged response.
enum IMAPStatus: String, Sendable, Equatable {
    case ok = "OK"
    case no = "NO"
    case bad = "BAD"
}

/// One untagged (`*`) response line.
struct IMAPUntaggedLine: Sendable, Equatable {
    /// Tokens after the leading `*`.
    var tokens: [IMAPToken]

    /// The leading number of `* 12 EXISTS` / `* 12 FETCH (...)`.
    var number: Int? { tokens.first?.intValue }

    /// `EXISTS`, `FETCH`, `OK`, `CAPABILITY`, `SEARCH`, `BYE`, …
    var keyword: String? {
        if number != nil { return tokens.dropFirst().first?.keyword }
        return tokens.first?.keyword
    }

    /// Everything after the keyword.
    var arguments: [IMAPToken] {
        let drop = (number != nil ? 2 : 1)
        return Array(tokens.dropFirst(drop))
    }

    /// The `[...]` response code, if the line carries one.
    var responseCode: [IMAPToken]? {
        for token in tokens {
            if case .code(let items) = token { return items }
        }
        return nil
    }

    /// Uppercased name of the response code (`UIDVALIDITY`, `READ-ONLY`, `ALERT`, …).
    var responseCodeName: String? { responseCode?.first?.keyword }
}

/// A parsed response line: untagged data, a command continuation request, or a tagged completion.
enum IMAPResponseLine: Sendable, Equatable {
    case untagged(IMAPUntaggedLine)
    /// `+ <text>` — the server wants the rest of the command.
    case continuation(String)
    case tagged(tag: String, status: IMAPStatus, code: [IMAPToken]?, text: String)

    /// Parses one complete logical line (literals already inlined).
    static func parse(_ bytes: [UInt8]) throws -> IMAPResponseLine {
        var trimmed = bytes
        while let last = trimmed.last, last == 0x0A || last == 0x0D { trimmed.removeLast() }
        guard let first = trimmed.first else { throw IMAPError.protocolViolation("empty response line") }

        if first == UInt8(ascii: "+") {
            let text = String(decoding: trimmed.dropFirst(), as: UTF8.self).trimmingCharacters(in: .whitespaces)
            return .continuation(text)
        }
        if first == UInt8(ascii: "*") {
            let tokens = try IMAPTokenizer.tokenize(Array(trimmed.dropFirst()))
            guard !tokens.isEmpty else { throw IMAPError.protocolViolation("empty untagged response") }
            return .untagged(IMAPUntaggedLine(tokens: tokens))
        }

        let tokens = try IMAPTokenizer.tokenize(trimmed)
        guard let tag = tokens.first?.text, tokens.count >= 2, let statusWord = tokens[1].keyword,
              let status = IMAPStatus(rawValue: statusWord) else {
            throw IMAPError.protocolViolation("not a tagged response")
        }
        var code: [IMAPToken]?
        for token in tokens.dropFirst(2) where code == nil {
            if case .code(let items) = token { code = items }
        }
        return .tagged(tag: tag, status: status, code: code, text: Self.taggedText(trimmed))
    }

    /// The human-readable remainder of `TAG STATUS [CODE] text…`, taken from the raw bytes so punctuation the
    /// server used (`(Failure)`) survives. Never logged — only shown to the user who owns the account.
    private static func taggedText(_ bytes: [UInt8]) -> String {
        var index = 0
        func skipSpaces() { while index < bytes.count, bytes[index] == 0x20 { index += 1 } }
        func skipWord() { while index < bytes.count, bytes[index] != 0x20 { index += 1 } }
        skipWord() // tag
        skipSpaces()
        skipWord() // status
        skipSpaces()
        if index < bytes.count, bytes[index] == UInt8(ascii: "[") {
            var depth = 0
            while index < bytes.count {
                if bytes[index] == UInt8(ascii: "[") { depth += 1 }
                if bytes[index] == UInt8(ascii: "]") {
                    depth -= 1
                    index += 1
                    if depth == 0 { break }
                    continue
                }
                index += 1
            }
            skipSpaces()
        }
        guard index < bytes.count else { return "" }
        return String(decoding: bytes[index...], as: UTF8.self).trimmingCharacters(in: .whitespaces)
    }
}

/// Everything one command produced: its untagged lines plus the tagged completion.
struct IMAPCommandResult: Sendable {
    var untagged: [IMAPUntaggedLine]
    var status: IMAPStatus
    var code: [IMAPToken]?
    var text: String

    /// Uppercased response-code name of the tagged line (`READ-ONLY`, `AUTHENTICATIONFAILED`, …).
    var codeName: String? { code?.first?.keyword }

    func lines(keyword: String) -> [IMAPUntaggedLine] {
        untagged.filter { $0.keyword?.caseInsensitiveCompare(keyword) == .orderedSame }
    }
}

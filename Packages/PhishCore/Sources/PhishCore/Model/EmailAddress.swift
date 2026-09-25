import Foundation

/// A parsed mailbox. `address` is always normalized to lowercase.
public struct EmailAddress: Hashable, Sendable, Codable {
    public var name: String?
    /// Normalized lowercase address, e.g. "alice@example.com".
    public var address: String

    /// Part after the last "@", lowercased. Empty string when there is no "@".
    public var domain: String {
        guard let at = address.lastIndex(of: "@") else { return "" }
        return String(address[address.index(after: at)...]).lowercased()
    }

    public init(name: String?, address: String) {
        let trimmedName = name?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.name = (trimmedName?.isEmpty ?? true) ? nil : trimmedName
        self.address = address.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// Parses an RFC 5322 style header value such as
    /// `"Doe, John" <John@Example.com>, jane@example.org, Bob (Sales) <bob@x.com>`.
    /// Handles quoted display names (with escaped quotes), angle-bracket addresses, bare addresses,
    /// `(comment)` display names, comma/semicolon separated lists and lowercases every address.
    /// Entries without a usable address are dropped.
    public static func parse(_ headerValue: String) -> [EmailAddress] {
        splitTopLevel(headerValue).compactMap(parseSingle)
    }

    // MARK: - Parsing helpers

    /// Splits on "," and ";" that are not inside quotes, angle brackets or comments.
    private static func splitTopLevel(_ value: String) -> [String] {
        var parts: [String] = []
        var current = ""
        var inQuotes = false
        var inAngle = false
        var escaped = false
        var parenDepth = 0

        for ch in value {
            if escaped {
                current.append(ch)
                escaped = false
                continue
            }
            switch ch {
            case "\\" where inQuotes:
                escaped = true
                current.append(ch)
            case "\"":
                inQuotes.toggle()
                current.append(ch)
            case "<" where !inQuotes:
                inAngle = true
                current.append(ch)
            case ">" where !inQuotes:
                inAngle = false
                current.append(ch)
            case "(" where !inQuotes && !inAngle:
                parenDepth += 1
                current.append(ch)
            case ")" where !inQuotes && !inAngle && parenDepth > 0:
                parenDepth -= 1
                current.append(ch)
            case ",", ";":
                if !inQuotes && !inAngle && parenDepth == 0 {
                    parts.append(current)
                    current = ""
                } else {
                    current.append(ch)
                }
            default:
                current.append(ch)
            }
        }
        parts.append(current)
        return parts
    }

    private static func parseSingle(_ raw: String) -> EmailAddress? {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }

        // RFC 5322 group syntax: "Undisclosed recipients: a@b, c@d;" — strip the group label.
        if !text.contains("<"), let colon = text.firstIndex(of: ":"), !text[..<colon].contains("@"),
           !text[..<colon].contains("\"") {
            text = String(text[text.index(after: colon)...]).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty else { return nil }
        }

        // "Display Name <addr>"
        if let lt = lastUnquotedIndex(of: "<", in: text),
           let gt = text[lt...].firstIndex(of: ">") {
            let inside = String(text[text.index(after: lt)..<gt])
            let namePart = String(text[..<lt])
            let address = normalizeAddress(inside)
            guard address.contains("@") || !address.isEmpty else { return nil }
            guard !address.isEmpty else { return nil }
            return EmailAddress(name: unquote(namePart), address: address)
        }

        // "addr (Display Name)"
        var name: String?
        if let open = text.firstIndex(of: "("), let close = text[open...].lastIndex(of: ")") {
            name = unquote(String(text[text.index(after: open)..<close]))
            text.removeSubrange(open...close)
            text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        }

        let address = normalizeAddress(text)
        guard !address.isEmpty else { return nil }
        return EmailAddress(name: name, address: address)
    }

    private static func lastUnquotedIndex(of target: Character, in text: String) -> String.Index? {
        var inQuotes = false
        var escaped = false
        var result: String.Index?
        var index = text.startIndex
        while index < text.endIndex {
            let ch = text[index]
            if escaped {
                escaped = false
            } else if ch == "\\" && inQuotes {
                escaped = true
            } else if ch == "\"" {
                inQuotes.toggle()
            } else if ch == target && !inQuotes {
                result = index
            }
            index = text.index(after: index)
        }
        return result
    }

    private static func unquote(_ value: String) -> String? {
        var text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("\""), text.hasSuffix("\""), text.count >= 2 {
            text = String(text.dropFirst().dropLast())
            text = text.replacingOccurrences(of: "\\\"", with: "\"")
                .replacingOccurrences(of: "\\\\", with: "\\")
        }
        text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }

    private static func normalizeAddress(_ value: String) -> String {
        var text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.lowercased().hasPrefix("mailto:") {
            text = String(text.dropFirst("mailto:".count))
        }
        text = text.trimmingCharacters(in: CharacterSet(charactersIn: "<>\"' \t\r\n"))
        return text.lowercased()
    }
}

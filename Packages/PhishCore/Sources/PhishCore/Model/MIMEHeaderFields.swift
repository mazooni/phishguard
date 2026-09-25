import Foundation

/// A structured header of the form `value; param=x; param*=utf-8''y` — `Content-Type`, `Content-Disposition`.
///
/// Parameter values are unquoted, RFC 2231 continuations (`name*0`, `name*1*`) are joined and percent-decoded in
/// the charset they declare, and RFC 2047 encoded-words are decoded too: putting them in a parameter is illegal
/// but common, and a phishing attachment called `=?utf-8?B?...?=` must not reach the UI as gibberish.
struct ParameterizedHeader: Sendable, Equatable {
    /// The part before the first `;`, lowercased and unquoted — `"text/plain"`, `"attachment"`, `""`.
    var value: String
    /// Lowercased parameter names → decoded values.
    var parameters: [String: String]

    func parameter(_ name: String) -> String? {
        guard let found = parameters[name.lowercased()], !found.isEmpty else { return nil }
        return found
    }

    /// Longest parameter value kept.
    static let maxParameterCharacters = 2_000
    /// Most `;`-separated segments examined.
    static let maxSegments = 64

    static func parse(_ raw: String) -> ParameterizedHeader {
        let segments = splitSegments(raw)
        guard let first = segments.first else { return ParameterizedHeader(value: "", parameters: [:]) }
        let value = unquote(first).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        var pairs: [(key: String, value: String)] = []
        for segment in segments.dropFirst() {
            guard let equals = segment.firstIndex(of: "=") else { continue }
            let key = segment[..<equals].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !key.isEmpty, key.count <= 100 else { continue }
            pairs.append((key, String(segment[segment.index(after: equals)...])))
        }
        return ParameterizedHeader(value: value, parameters: assemble(pairs))
    }

    // MARK: - Segmenting

    /// Splits on `;` outside quoted strings and `(comments)`; comments are dropped, as RFC 5322 says they may be.
    static func splitSegments(_ text: String) -> [String] {
        var segments: [String] = []
        var current = ""
        var inQuotes = false
        var escaped = false
        var commentDepth = 0

        for ch in text {
            if escaped {
                current.append(ch)
                escaped = false
                continue
            }
            if inQuotes {
                switch ch {
                case "\\": escaped = true; current.append(ch)
                case "\"": inQuotes = false; current.append(ch)
                default: current.append(ch)
                }
                continue
            }
            switch ch {
            case "\"": inQuotes = true; current.append(ch)
            case "(": commentDepth += 1
            case ")": if commentDepth > 0 { commentDepth -= 1 }
            case ";" where commentDepth == 0:
                segments.append(current)
                current = ""
                if segments.count >= maxSegments { return segments }
            default: if commentDepth == 0 { current.append(ch) }
            }
        }
        segments.append(current)
        return segments
    }

    static func unquote(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("\"") else { return trimmed }
        var out = ""
        var escaped = false
        for ch in trimmed.dropFirst() {
            if escaped {
                out.append(ch)
                escaped = false
                continue
            }
            if ch == "\\" { escaped = true; continue }
            if ch == "\"" { break }
            out.append(ch)
        }
        return out
    }

    // MARK: - RFC 2231

    private struct Continuation {
        var index: Int
        var isExtended: Bool
        var raw: String
    }

    static func assemble(_ pairs: [(key: String, value: String)]) -> [String: String] {
        var simple: [String: String] = [:]
        var continued: [String: [Continuation]] = [:]

        for pair in pairs {
            var key = pair.key
            var isExtended = false
            var index: Int?

            if key.hasSuffix("*") {
                isExtended = true
                key.removeLast()
            }
            if let star = key.lastIndex(of: "*") {
                let suffix = key[key.index(after: star)...]
                if !suffix.isEmpty, suffix.count <= 3, suffix.allSatisfy({ $0.isASCII && $0.isNumber }),
                   let parsed = Int(suffix) {
                    index = parsed
                    key = String(key[..<star])
                }
            }
            guard !key.isEmpty else { continue }

            if index == nil, !isExtended {
                if simple[key] == nil {
                    simple[key] = decodeSimple(pair.value)
                }
                continue
            }
            var list = continued[key] ?? []
            guard list.count < 64 else { continue }
            list.append(Continuation(index: index ?? 0, isExtended: isExtended, raw: pair.value))
            continued[key] = list
        }

        for (key, segments) in continued {
            let ordered = segments.sorted { $0.index < $1.index }
            var bytes: [UInt8] = []
            var charset: String?
            for (position, segment) in ordered.enumerated() {
                guard bytes.count < maxParameterCharacters * 4 else { break }
                var raw = unquote(segment.raw)
                if segment.isExtended {
                    if position == 0, let parsed = splitExtendedPrefix(raw) {
                        charset = parsed.charset
                        raw = parsed.remainder
                    }
                    bytes.append(contentsOf: percentDecode(raw))
                } else {
                    bytes.append(contentsOf: Array(raw.utf8))
                }
            }
            let text = charset.flatMap { MIMECharset.decode(bytes, charset: $0) }
                ?? MIMECharset.decodeBody(bytes, declaredCharset: charset)
            // Continuations win over a plain duplicate of the same name.
            simple[key] = clean(text)
        }

        return simple
    }

    /// `utf-8'en'Fa%C3%A7ture.pdf` → charset `utf-8`, remainder `Fa%C3%A7ture.pdf`.
    static func splitExtendedPrefix(_ value: String) -> (charset: String, remainder: String)? {
        guard let firstQuote = value.firstIndex(of: "'") else { return nil }
        let afterFirst = value.index(after: firstQuote)
        guard let secondQuote = value[afterFirst...].firstIndex(of: "'") else { return nil }
        let charset = String(value[..<firstQuote]).trimmingCharacters(in: .whitespaces)
        let remainder = String(value[value.index(after: secondQuote)...])
        guard charset.count <= 80 else { return nil }
        return (charset, remainder)
    }

    static func percentDecode(_ value: String) -> [UInt8] {
        let source = Array(value.utf8)
        var out: [UInt8] = []
        out.reserveCapacity(source.count)
        var i = 0
        while i < source.count {
            if source[i] == 0x25, i + 2 < source.count,
               let high = MIMEParser.hexValue(source[i + 1]), let low = MIMEParser.hexValue(source[i + 2]) {
                out.append(high << 4 | low)
                i += 3
                continue
            }
            out.append(source[i])
            i += 1
        }
        return out
    }

    private static func decodeSimple(_ raw: String) -> String {
        clean(unquote(raw))
    }

    private static func clean(_ value: String) -> String {
        let decoded = value.contains("=?") ? MIMEParser.decodeEncodedWords(value) : value
        return MIMEParser.sanitize(decoded, limit: maxParameterCharacters)
    }
}

/// RFC 2047 encoded-word decoding, as a single forward pass over the header's UTF-8 bytes.
///
/// Two subtleties the naive implementations get wrong and phishing subjects rely on:
/// * whitespace **between** two encoded-words is not part of the text and must be dropped, while whitespace
///   between an encoded-word and ordinary text must be kept;
/// * a multi-byte character may be split across two adjacent encoded-words, so bytes are concatenated across a
///   run of same-charset words and decoded once at the end of the run.
enum EncodedWordDecoder {
    /// Longest encoded payload inside one word.
    static let maxPayloadBytes = 10_000
    /// Longest charset token.
    static let maxCharsetBytes = 80

    static func decode(_ input: [UInt8]) -> String {
        var out: [UInt8] = []
        out.reserveCapacity(input.count)
        var pendingWhitespace: [UInt8] = []
        var lastWasEncodedWord = false
        var groupCharset: String?
        var groupBytes: [UInt8] = []
        var groupRaw: [UInt8] = []
        // Bounds the cost of repeatedly probing "=?" sequences that never terminate.
        var budget = 8 * input.count + 4_096

        func flushGroup() {
            guard let charset = groupCharset else { return }
            if let text = MIMECharset.decode(groupBytes, charset: charset) {
                out.append(contentsOf: Array(text.utf8))
            } else {
                out.append(contentsOf: groupRaw)   // unknown charset: pass the source through untouched
            }
            groupCharset = nil
            groupBytes = []
            groupRaw = []
        }

        var i = 0
        let n = input.count
        while i < n {
            let byte = input[i]

            if byte == 0x3D, i + 1 < n, input[i + 1] == 0x3F, budget > 0,
               let word = parseWord(input, at: i, budget: &budget) {
                guard let payload = word.payload else {
                    // Well-formed delimiters but an undecodable payload: emit it verbatim.
                    flushGroup()
                    out.append(contentsOf: pendingWhitespace)
                    pendingWhitespace = []
                    out.append(contentsOf: input[i..<word.end])
                    lastWasEncodedWord = false
                    i = word.end
                    continue
                }
                if lastWasEncodedWord, groupCharset == word.charset {
                    groupBytes.append(contentsOf: payload)
                    groupRaw.append(contentsOf: input[i..<word.end])
                } else {
                    flushGroup()
                    if !lastWasEncodedWord { out.append(contentsOf: pendingWhitespace) }
                    groupCharset = word.charset
                    groupBytes = payload
                    groupRaw = Array(input[i..<word.end])
                }
                pendingWhitespace = []
                lastWasEncodedWord = true
                i = word.end
                continue
            }

            if byte == 0x20 || byte == 0x09 || byte == 0x0D || byte == 0x0A {
                if pendingWhitespace.count < 1_000 { pendingWhitespace.append(byte) }
                i += 1
                continue
            }

            flushGroup()
            out.append(contentsOf: pendingWhitespace)
            pendingWhitespace = []
            lastWasEncodedWord = false
            out.append(byte)
            i += 1
        }

        flushGroup()
        out.append(contentsOf: pendingWhitespace)
        return String(decoding: out, as: UTF8.self)
    }

    struct Word {
        var charset: String
        /// `nil` when the delimiters were well formed but the payload did not decode.
        var payload: [UInt8]?
        var end: Int
    }

    /// Parses `=?charset?B|Q?text?=` starting at `start`. Returns `nil` when this is not an encoded-word, leaving
    /// the caller to emit the bytes verbatim.
    static func parseWord(_ input: [UInt8], at start: Int, budget: inout Int) -> Word? {
        let n = input.count
        let charsetStart = start + 2
        var charsetEnd = charsetStart
        while charsetEnd < n, input[charsetEnd] != 0x3F {
            budget -= 1
            if budget <= 0 { return nil }
            let byte = input[charsetEnd]
            guard byte > 0x20, byte < 0x7F, charsetEnd - charsetStart < maxCharsetBytes else { return nil }
            charsetEnd += 1
        }
        guard charsetEnd < n, charsetEnd > charsetStart else { return nil }

        var charset = String(decoding: input[charsetStart..<charsetEnd], as: UTF8.self).lowercased()
        // RFC 2231 §5 language suffix: "=?utf-8*en?Q?...?="
        if let star = charset.firstIndex(of: "*") { charset = String(charset[..<star]) }
        guard !charset.isEmpty else { return nil }

        let encodingIndex = charsetEnd + 1
        guard encodingIndex + 1 < n, input[encodingIndex + 1] == 0x3F else { return nil }
        let encoding = input[encodingIndex] | 0x20
        guard encoding == 0x62 || encoding == 0x71 else { return nil }   // 'b' | 'q'

        let payloadStart = encodingIndex + 2
        var j = payloadStart
        while j + 1 < n {
            budget -= 1
            if budget <= 0 { return nil }
            let byte = input[j]
            if byte == 0x3F, input[j + 1] == 0x3D { break }
            guard byte != 0x20, byte != 0x09, byte != 0x0A, byte != 0x0D,
                  j - payloadStart < maxPayloadBytes else { return nil }
            j += 1
        }
        guard j + 1 < n, input[j] == 0x3F, input[j + 1] == 0x3D else { return nil }

        let raw = Array(input[payloadStart..<j])
        let payload = encoding == 0x62 ? decodeBase64Payload(raw) : decodeQPayload(raw)
        return Word(charset: charset, payload: payload, end: j + 2)
    }

    /// Strict base64: anything outside the alphabet means this was not really an encoded-word.
    static func decodeBase64Payload(_ raw: [UInt8]) -> [UInt8]? {
        for byte in raw where byte != 0x3D && MIMEParser.base64Values[Int(byte)] < 0 { return nil }
        return MIMEParser.decodeBase64(raw[...], limit: maxPayloadBytes)
    }

    /// Q-encoding: `_` is a space, `=XX` is a byte, a stray `=` stays literal.
    static func decodeQPayload(_ raw: [UInt8]) -> [UInt8]? {
        var out: [UInt8] = []
        out.reserveCapacity(raw.count)
        var i = 0
        while i < raw.count {
            let byte = raw[i]
            if byte == 0x5F {
                out.append(0x20)
                i += 1
                continue
            }
            if byte == 0x3D, i + 2 < raw.count,
               let high = MIMEParser.hexValue(raw[i + 1]), let low = MIMEParser.hexValue(raw[i + 2]) {
                out.append(high << 4 | low)
                i += 3
                continue
            }
            out.append(byte)
            i += 1
        }
        return out
    }
}

import Foundation

/// Byte → `String` conversion for mail: IANA charset names to `String.Encoding`, plus the fallback ladders
/// `MIMEParser` uses for header bytes, body bytes and RFC 2047 encoded-words.
///
/// Only Foundation + CoreFoundation are used (`CFStringConvertIANACharSetNameToEncoding` covers the charsets
/// `String.Encoding` has no constant for: ISO-8859-15, GBK/GB18030, KOI8-R, Big5, …). Nothing here retains or
/// logs the bytes it is given.
enum MIMECharset {
    /// Lowercased, trimmed, unquoted charset name. `nil` for names that carry no information
    /// (`""`, `unknown-8bit`, `x-unknown`, `none`, `default`, `binary`).
    static func normalize(_ name: String?) -> String? {
        guard let name else { return nil }
        var text = name.trimmingCharacters(in: .whitespacesAndNewlines)
        text = text.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        text = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        // RFC 2231 charset'lang' prefixes and `*` language tags are stripped by the caller; guard anyway.
        if let star = text.firstIndex(of: "*") { text = String(text[..<star]) }
        guard !text.isEmpty else { return nil }
        switch text {
        case "unknown-8bit", "x-unknown", "unknown", "none", "default", "binary", "x-user-defined":
            return nil
        default:
            return text
        }
    }

    /// ISO-2022-* and HZ: escape-sequence encodings whose bytes are all < 0x80, so their bytes are *always*
    /// valid UTF-8 and a UTF-8-first ladder would hand back the raw escapes.
    static func isSevenBitStateful(_ charset: String) -> Bool {
        charset.hasPrefix("iso-2022") || charset.hasPrefix("iso2022") || charset.hasPrefix("csiso2022")
            || charset == "hz" || charset == "hz-gb-2312"
    }

    /// ESC (0x1B) for ISO-2022-*, `~{` for HZ-GB-2312.
    static func containsEscapeMarker(_ bytes: [UInt8], charset: String) -> Bool {
        if charset.hasPrefix("hz") {
            var i = 0
            while i + 1 < bytes.count {
                if bytes[i] == 0x7E, bytes[i + 1] == 0x7B { return true }
                i += 1
            }
            return false
        }
        return bytes.contains(0x1B)
    }

    /// Candidate encodings for a charset name, most specific first. The extra rungs are the real-world supersets
    /// (`windows-1252` for `iso-8859-1`, `gb18030` for `gb2312`/`gbk`, `windows-31j` for `shift_jis`) that decode
    /// everything the narrower label does and more.
    static func encodings(for charset: String) -> [String.Encoding] {
        switch charset {
        case "utf-8", "utf8", "utf_8", "unicode-1-1-utf-8", "csutf8":
            return [.utf8]
        case "us-ascii", "ascii", "ansi_x3.4-1968", "iso-ir-6", "ibm367", "cp367", "646", "csascii":
            // Mislabelled ASCII is almost always UTF-8; Windows-1252 catches the 8-bit strays.
            return [.utf8, .windowsCP1252, .isoLatin1]
        case "iso-8859-1", "iso8859-1", "iso_8859-1", "iso-8859-1-windows-3.1-latin-1", "8859-1",
             "latin1", "latin-1", "l1", "cp819", "ibm819", "iso-ir-100", "csisolatin1",
             "windows-1252", "windows1252", "cp1252", "cp-1252", "x-cp1252", "ms-ansi":
            // WHATWG Encoding: an `iso-8859-1` label is decoded as windows-1252 — the C1 range really carries
            // smart quotes and dashes in mail. `isoLatin1` is the never-fails backstop.
            return [.windowsCP1252, .isoLatin1]
        case "iso-8859-15", "iso8859-15", "iso_8859-15", "latin9", "l9", "csisolatin9":
            return coreFoundation("iso-8859-15") + [.isoLatin1]
        case "gb2312", "gb_2312-80", "csgb2312", "chinese", "gbk", "cp936", "ms936", "x-gbk",
             "windows-936", "gb18030":
            return coreFoundation("gb18030") + coreFoundation(charset)
        case "shift_jis", "shift-jis", "sjis", "s_jis", "ms_kanji", "csshiftjis", "cp932", "windows-31j",
             "x-sjis", "x-ms-cp932":
            return coreFoundation("windows-31j") + [.shiftJIS]
        case "iso-2022-jp", "iso2022jp", "csiso2022jp", "iso-2022-jp-2":
            return [.iso2022JP] + coreFoundation(charset)
        case "koi8-r", "koi8r", "cskoi8r":
            return coreFoundation("koi8-r")
        case "big5", "big-5", "big5-hkscs", "cp950", "csbig5", "x-x-big5":
            return coreFoundation("big5-hkscs") + coreFoundation("big5")
        default:
            return coreFoundation(charset)
        }
    }

    private static func coreFoundation(_ charset: String) -> [String.Encoding] {
        let cf = CFStringConvertIANACharSetNameToEncoding(charset as CFString)
        guard cf != kCFStringEncodingInvalidId else { return [] }
        let ns = CFStringConvertEncodingToNSStringEncoding(cf)
        guard ns != UInt(kCFStringEncodingInvalidId) else { return [] }
        return [String.Encoding(rawValue: ns)]
    }

    /// Decodes with the named charset only. `nil` when the name is unknown or the bytes are invalid in it —
    /// callers fall back or pass the text through verbatim.
    static func decode(_ bytes: [UInt8], charset: String) -> String? {
        guard let name = normalize(charset) else { return nil }
        for encoding in encodings(for: name) {
            if let text = String(bytes: bytes, encoding: encoding) { return stripBOM(text) }
        }
        return nil
    }

    /// Header bytes. Headers are ASCII by the book; 8-bit bytes still arrive, and they are UTF-8 far more often
    /// than anything else.
    static func decodeHeaderBytes<C: Collection>(_ bytes: C) -> String where C.Element == UInt8 {
        let array = Array(bytes)
        if let text = String(bytes: array, encoding: .utf8) { return stripBOM(text) }
        if let text = String(bytes: array, encoding: .windowsCP1252) { return text }
        return String(bytes: array, encoding: .isoLatin1) ?? String(decoding: array, as: UTF8.self)
    }

    /// Body bytes: **UTF-8 → declared charset → windows-1252 → ISO-8859-1**, which never fails.
    ///
    /// UTF-8 leads because mislabelling is the norm (a `charset=utf-8` body that is really windows-1252 is the
    /// classic, and it falls through to the windows-1252 rung). The one exception is a declared 7-bit stateful
    /// charset whose escape marker is present: those bytes are valid UTF-8 by construction, so the declared
    /// charset has to be tried first or the escapes survive into the text.
    static func decodeBody(_ bytes: [UInt8], declaredCharset: String?) -> String {
        let name = normalize(declaredCharset)
        if let name, isSevenBitStateful(name), containsEscapeMarker(bytes, charset: name),
           let text = decode(bytes, charset: name) {
            return text
        }
        if let text = String(bytes: bytes, encoding: .utf8) { return stripBOM(text) }
        if let name, let text = decode(bytes, charset: name) { return text }
        if let text = String(bytes: bytes, encoding: .windowsCP1252) { return text }
        return String(bytes: bytes, encoding: .isoLatin1) ?? String(decoding: bytes, as: UTF8.self)
    }

    private static func stripBOM(_ text: String) -> String {
        text.hasPrefix("\u{FEFF}") ? String(text.dropFirst()) : text
    }
}

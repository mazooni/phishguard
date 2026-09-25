import Foundation

/// Converts an HTML body into readable plain text (no Foundation/AppKit attributed-string parsing,
/// so it works identically on macOS and iOS and never touches WebKit).
///
/// Every pass is a single linear scan over UTF-16 code units — there are no backtracking regular expressions,
/// so hostile input (unclosed tags, thousands of stray `<`, unterminated quotes) costs O(n).
public enum HTMLTextExtractor {
    /// Maximum number of UTF-16 code units examined; longer input is truncated.
    public static let maxHTMLLength = 1_000_000

    /// Plain text for the message: `textBody` when non-empty, otherwise the stripped `htmlBody`, otherwise "".
    public static func plainText(for email: EmailMessage) -> String {
        if let text = email.textBody?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty {
            return normalizeWhitespace(text)
        }
        if let html = email.htmlBody, !html.isEmpty {
            return text(fromHTML: html)
        }
        return ""
    }

    /// Strips comments, `script`/`style`/`head`/`title`/`template` content and all tags, turns block elements and
    /// `<br>` into line breaks, decodes named and numeric entities and normalizes whitespace.
    public static func text(fromHTML html: String) -> String {
        let units = cappedUnits(of: html)
        let normalized = normalizeWhitespace(decodeEntities(stripTags(units)))
        return String(decoding: normalized, as: UTF16.self)
    }

    /// Text of elements that are invisible to the reader: `display:none`, `visibility:hidden`, `opacity:0`,
    /// zero/1px font size, zero-size boxes, `mso-hide:all`, off-screen positioning, text colored like its own
    /// background, or the `hidden` attribute. Returns one entry per hidden element (outermost only), capped.
    public static func hiddenText(inHTML html: String) -> [String] {
        let units = cappedUnits(of: html)
        var results: [String] = []
        var totalLength = 0
        var i = 0
        let n = units.count
        var scanned = 0
        while i < n, results.count < 100, totalLength < 20_000, scanned < 50_000 {
            scanned += 1
            guard let tag = nextTag(in: units, from: i) else { break }
            i = tag.end
            guard !tag.isClosing, !tag.name.isEmpty, !voidElements.contains(tag.name) else { continue }
            guard mayBeHidden(tag, in: units) else { continue }
            let attrs = attributes(in: units, range: tag.attributeRange)
            guard isHiddenElement(name: tag.name, attributes: attrs) else { continue }
            let innerEnd = elementEnd(named: tag.name, in: units, from: tag.end)
            let inner = Array(units[tag.end..<innerEnd.innerEnd])
            let normalized = normalizeWhitespace(decodeEntities(stripTags(inner)))
            let text = String(decoding: normalized, as: UTF16.self)
            if !text.isEmpty {
                results.append(text)
                totalLength += text.utf16.count
            }
            i = innerEnd.outerEnd
        }
        return results
    }

    /// Cheap filter: only tags whose attributes mention style/hidden/size/type can be hidden.
    private static let styleNeedle = Array("style".utf16), hiddenNeedle = Array("hidden".utf16)
    private static func mayBeHidden(_ tag: Tag, in units: [UInt16]) -> Bool {
        guard !tag.attributeRange.isEmpty else { return false }
        if tag.name == "font" || tag.name == "input" { return true }
        let start = tag.attributeRange.lowerBound, end = tag.attributeRange.upperBound
        if find(styleNeedle, in: units, from: start, upTo: end) != nil { return true }
        if find(hiddenNeedle, in: units, from: start, upTo: end) != nil { return true }
        return false
    }

    /// End of an `<a>` element: the next `</a>`, or the next `<a>` (which implicitly closes the previous anchor).
    static func anchorEnd(in units: [UInt16], from: Int) -> (innerEnd: Int, outerEnd: Int) {
        var i = from
        while let tag = nextTag(in: units, from: i) {
            if !tag.isComment, tag.name == "a" {
                return tag.isClosing ? (tag.start, tag.end) : (tag.start, tag.start)
            }
            i = tag.end
        }
        return (units.count, units.count)
    }

    // MARK: - Tokenizer

    struct Tag {
        var name: String            // lowercased, "" for comments/doctype
        var isClosing: Bool
        var start: Int              // index of "<"
        var end: Int                // index after ">" (or units.count)
        var attributeRange: Range<Int>
        var isComment: Bool
    }

    private static let lt: UInt16 = 0x3C, gt: UInt16 = 0x3E, slash: UInt16 = 0x2F, bang: UInt16 = 0x21, question: UInt16 = 0x3F
    private static let dquote: UInt16 = 0x22, squote: UInt16 = 0x27, equals: UInt16 = 0x3D, hyphen: UInt16 = 0x2D
    private static let space: UInt16 = 0x20, newline: UInt16 = 0x0A

    static func cappedUnits(of html: String) -> [UInt16] {
        let all = Array(html.utf16)
        return all.count > maxHTMLLength ? Array(all[0..<maxHTMLLength]) : all
    }

    private static func isTagNameUnit(_ c: UInt16) -> Bool {
        (c >= 0x61 && c <= 0x7A) || (c >= 0x41 && c <= 0x5A) || (c >= 0x30 && c <= 0x39) || c == 0x2D || c == 0x3A || c == 0x5F
    }

    private static func isSpaceUnit(_ c: UInt16) -> Bool {
        c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D || c == 0x0C
    }

    private static func lowercasedASCII(_ slice: ArraySlice<UInt16>) -> String {
        var s = ""
        s.reserveCapacity(slice.count)
        for c in slice {
            if c >= 0x41 && c <= 0x5A { s.unicodeScalars.append(UnicodeScalar(c + 0x20)!) }
            else if let scalar = UnicodeScalar(c) { s.unicodeScalars.append(scalar) }
        }
        return s
    }

    /// Finds `needle` (ASCII, lowercase) case-insensitively in `units[from..<upTo]`.
    static func find(_ needle: [UInt16], in units: [UInt16], from: Int, upTo: Int? = nil) -> Int? {
        let n = min(units.count, upTo ?? units.count), m = needle.count
        guard m > 0, from >= 0, from + m <= n else { return nil }
        let first = needle[0]
        var i = from
        while i + m <= n {
            var c = units[i]
            if c >= 0x41 && c <= 0x5A { c += 0x20 }
            if c == first {
                var j = 1
                while j < m {
                    var u = units[i + j]
                    if u >= 0x41 && u <= 0x5A { u += 0x20 }
                    if u != needle[j] { break }
                    j += 1
                }
                if j == m { return i }
            }
            i += 1
        }
        return nil
    }

    /// The next tag at or after `from`. Text between tags is skipped. Handles comments, doctype, quoted attributes.
    static func nextTag(in units: [UInt16], from: Int) -> Tag? {
        let n = units.count
        var i = from
        while i < n {
            guard units[i] == lt else { i += 1; continue }
            if let tag = parseTag(in: units, at: i) { return tag }
            i += 1
        }
        return nil
    }

    /// Parses the tag starting at `<` (index `at`), or nil when this `<` does not start a tag.
    static func parseTag(in units: [UInt16], at start: Int) -> Tag? {
        let n = units.count
        var j = start + 1
        guard j < n else { return nil }
        // Comment
        if units[j] == bang {
            if j + 2 < n, units[j + 1] == hyphen, units[j + 2] == hyphen {
                let close = find(Array("-->".utf16), in: units, from: j + 3)
                let end = close.map { $0 + 3 } ?? n
                return Tag(name: "", isClosing: false, start: start, end: end, attributeRange: end..<end, isComment: true)
            }
            // <!DOCTYPE ...>
            let close = units[j...].firstIndex(of: gt).map { $0 + 1 } ?? n
            return Tag(name: "", isClosing: false, start: start, end: close, attributeRange: close..<close, isComment: true)
        }
        if units[j] == question {
            let close = units[j...].firstIndex(of: gt).map { $0 + 1 } ?? n
            return Tag(name: "", isClosing: false, start: start, end: close, attributeRange: close..<close, isComment: true)
        }
        var closing = false
        if units[j] == slash { closing = true; j += 1 }
        let nameStart = j
        while j < n, isTagNameUnit(units[j]) { j += 1 }
        guard j > nameStart else { return nil }   // "a < b" — not a tag
        let name = lowercasedASCII(units[nameStart..<j])
        // Attributes up to the closing '>' (quotes may contain '>').
        var k = j
        var quote: UInt16 = 0
        while k < n {
            let c = units[k]
            if quote != 0 {
                if c == quote { quote = 0 }
            } else if c == dquote || c == squote {
                quote = c
            } else if c == gt {
                break
            }
            k += 1
        }
        let end = min(k + 1, n)
        return Tag(name: name, isClosing: closing, start: start, end: end, attributeRange: j..<k, isComment: false)
    }

    /// Attribute name → value (lowercased names, raw values with entities still encoded).
    static func attributes(in units: [UInt16], range: Range<Int>) -> [String: String] {
        var result: [String: String] = [:]
        var i = range.lowerBound
        let end = range.upperBound
        while i < end {
            while i < end, isSpaceUnit(units[i]) || units[i] == slash { i += 1 }
            guard i < end else { break }
            let nameStart = i
            while i < end, !isSpaceUnit(units[i]), units[i] != equals, units[i] != slash { i += 1 }
            guard i > nameStart else { i += 1; continue }
            let name = lowercasedASCII(units[nameStart..<i])
            while i < end, isSpaceUnit(units[i]) { i += 1 }
            var value = ""
            if i < end, units[i] == equals {
                i += 1
                while i < end, isSpaceUnit(units[i]) { i += 1 }
                if i < end, units[i] == dquote || units[i] == squote {
                    let q = units[i]
                    i += 1
                    let valueStart = i
                    while i < end, units[i] != q { i += 1 }
                    value = String(decoding: Array(units[valueStart..<i]), as: UTF16.self)
                    if i < end { i += 1 }
                } else {
                    let valueStart = i
                    while i < end, !isSpaceUnit(units[i]) { i += 1 }
                    value = String(decoding: Array(units[valueStart..<i]), as: UTF16.self)
                }
            }
            if result[name] == nil { result[name] = value }
        }
        return result
    }

    /// Finds the end of the element opened just before `from` (depth-aware for the same tag name).
    static func elementEnd(named name: String, in units: [UInt16], from: Int) -> (innerEnd: Int, outerEnd: Int) {
        let n = units.count
        var depth = 1
        var i = from
        var guardCount = 0
        while i < n, guardCount < 100_000 {
            guardCount += 1
            guard let tag = nextTag(in: units, from: i) else { break }
            if !tag.isComment, tag.name == name {
                if tag.isClosing {
                    depth -= 1
                    if depth == 0 { return (tag.start, tag.end) }
                } else if !voidElements.contains(name) {
                    depth += 1
                }
            }
            i = tag.end
        }
        return (n, n)
    }

    private static let voidElements: Set<String> = [
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr",
    ]

    private static let blockElements: Set<String> = [
        "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote", "section", "article", "header",
        "footer", "ul", "ol", "dl", "dt", "dd", "pre", "address", "form", "fieldset", "nav", "aside", "main", "figure",
        "figcaption", "center", "hr", "br", "caption", "thead", "tbody", "tfoot", "option", "details", "summary",
    ]

    private static let skippedElements: Set<String> = ["script", "style", "head", "title", "template", "noscript", "svg"]

    /// Elements that do not separate words ("Hello <b>Sam</b>," must stay "Hello Sam,").
    private static let inlineElements: Set<String> = [
        "a", "b", "i", "u", "em", "strong", "span", "font", "small", "big", "sub", "sup", "code", "abbr", "cite", "q", "s",
        "strike", "del", "ins", "mark", "time", "var", "kbd", "samp", "tt", "label", "bdi", "bdo", "wbr", "dfn", "acronym",
    ]

    /// Removes tags and hidden-content elements, inserting newlines for block boundaries.
    static func stripTags(_ units: [UInt16]) -> [UInt16] {
        var out: [UInt16] = []
        out.reserveCapacity(units.count)
        let n = units.count
        var i = 0
        while i < n {
            let c = units[i]
            guard c == lt, let tag = parseTag(in: units, at: i) else {
                out.append(c)
                i += 1
                continue
            }
            if tag.isComment {
                out.append(space)
                i = tag.end
                continue
            }
            if !tag.isClosing, skippedElements.contains(tag.name) {
                // Skip to the matching close tag (linear: one search per skipped element).
                let closeNeedle = Array(("</" + tag.name).utf16)
                if let close = find(closeNeedle, in: units, from: tag.end) {
                    let closeTagEnd = units[close...].firstIndex(of: gt).map { $0 + 1 } ?? n
                    i = closeTagEnd
                } else {
                    i = n
                }
                out.append(space)
                continue
            }
            if blockElements.contains(tag.name) {
                out.append(newline)
            } else if !inlineElements.contains(tag.name) {
                out.append(space)
            }
            i = tag.end
        }
        return out
    }

    // MARK: - Hidden-element detection

    static func isHiddenElement(name: String, attributes: [String: String]) -> Bool {
        if attributes["hidden"] != nil { return true }
        if name == "font", let size = attributes["size"]?.trimmingCharacters(in: .whitespaces), size == "0" { return true }
        if name == "input", attributes["type"]?.lowercased() == "hidden" { return true }
        guard let style = attributes["style"] else { return false }
        return isHiddenStyle(style, bgcolorAttribute: attributes["bgcolor"])
    }

    /// Inspects an inline `style` declaration for invisibility.
    public static func isHiddenStyle(_ style: String, bgcolorAttribute: String? = nil) -> Bool {
        let s = decodeEntities(style).lowercased().filter { !$0.isWhitespace }
        guard !s.isEmpty else { return false }
        var declarations: [String: String] = [:]
        for declaration in s.split(separator: ";") {
            guard let colon = declaration.firstIndex(of: ":") else { continue }
            let key = String(declaration[..<colon])
            let value = String(declaration[declaration.index(after: colon)...]).replacingOccurrences(of: "!important", with: "")
            declarations[key] = value
        }
        if declarations["display"] == "none" { return true }
        if declarations["visibility"] == "hidden" || declarations["visibility"] == "collapse" { return true }
        if let opacity = declarations["opacity"], let value = Double(opacity), value <= 0.05 { return true }
        if let fontSize = declarations["font-size"], let px = cssLength(fontSize), px <= 1 { return true }
        if declarations["mso-hide"] == "all" { return true }
        if let maxHeight = declarations["max-height"], let px = cssLength(maxHeight), px <= 0,
           declarations["overflow"] == "hidden" || declarations["overflow-y"] == "hidden" {
            return true
        }
        if let width = declarations["width"], let height = declarations["height"],
           let w = cssLength(width), let h = cssLength(height), w <= 0, h <= 0 {
            return true
        }
        if let indent = declarations["text-indent"], let px = cssLength(indent), px <= -100 { return true }
        if declarations["position"] == "absolute" || declarations["position"] == "fixed" {
            for key in ["left", "top", "right", "bottom"] {
                if let value = declarations[key], let px = cssLength(value), px <= -1000 { return true }
            }
        }
        if let color = declarations["color"].flatMap(normalizedColor) {
            let background = declarations["background-color"].flatMap(normalizedColor)
                ?? declarations["background"].flatMap(normalizedColor)
                ?? bgcolorAttribute.flatMap(normalizedColor)
            if let background, background == color { return true }
        }
        return false
    }

    /// Parses "12px", "0", "1pt", "0.5em" into a pixel-ish number (unit-agnostic magnitude).
    private static func cssLength(_ value: String) -> Double? {
        let digits = value.prefix { $0.isNumber || $0 == "." || $0 == "-" || $0 == "+" }
        guard !digits.isEmpty, let number = Double(digits) else { return nil }
        if value.hasSuffix("em") || value.hasSuffix("rem") { return number * 16 }
        if value.hasSuffix("%") { return number / 100 * 16 }
        return number
    }

    /// Normalizes CSS colors to "#rrggbb" (named basics, #rgb, #rrggbb, rgb()/rgba()).
    static func normalizedColor(_ raw: String) -> String? {
        var value = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if let space = value.firstIndex(where: { $0 == " " }) { value = String(value[..<space]) }   // "#fff url(..)"
        switch value {
        case "white": return "#ffffff"
        case "black": return "#000000"
        case "transparent": return nil
        default: break
        }
        if value.hasPrefix("#") {
            let hex = value.dropFirst()
            if hex.count == 3, hex.allSatisfy(\.isHexDigit) {
                return "#" + hex.map { "\($0)\($0)" }.joined()
            }
            if hex.count == 6 || hex.count == 8, hex.allSatisfy(\.isHexDigit) {
                return "#" + String(hex.prefix(6))
            }
            return nil
        }
        if value.hasPrefix("rgb(") || value.hasPrefix("rgba(") {
            let inner = value.drop { $0 != "(" }.dropFirst().prefix { $0 != ")" }
            let parts = inner.split(whereSeparator: { $0 == "," || $0 == "/" || $0 == " " }).compactMap { Double($0.trimmingCharacters(in: .whitespaces)) }
            guard parts.count >= 3 else { return nil }
            if parts.count >= 4, parts[3] <= 0.05 { return "transparent-ish" }
            let components = parts.prefix(3).map { String(format: "%02x", Int(max(0, min(255, $0)))) }
            return "#" + components.joined()
        }
        return nil
    }

    // MARK: - Entities

    private static let namedEntities: [String: String] = [
        // Basic / special
        "amp": "&", "lt": "<", "gt": ">", "quot": "\"", "apos": "'", "nbsp": "\u{00A0}",
        // Latin-1 (160–255)
        "iexcl": "¡", "cent": "¢", "pound": "£", "curren": "¤", "yen": "¥", "brvbar": "¦", "sect": "§", "uml": "¨", "copy": "©",
        "ordf": "ª", "laquo": "«", "not": "¬", "shy": "\u{00AD}", "reg": "®", "macr": "¯", "deg": "°", "plusmn": "±", "sup2": "²",
        "sup3": "³", "acute": "´", "micro": "µ", "para": "¶", "middot": "·", "cedil": "¸", "sup1": "¹", "ordm": "º", "raquo": "»",
        "frac14": "¼", "frac12": "½", "frac34": "¾", "iquest": "¿", "agrave": "à", "aacute": "á", "acirc": "â", "atilde": "ã",
        "auml": "ä", "aring": "å", "aelig": "æ", "ccedil": "ç", "egrave": "è", "eacute": "é", "ecirc": "ê", "euml": "ë",
        "igrave": "ì", "iacute": "í", "icirc": "î", "iuml": "ï", "eth": "ð", "ntilde": "ñ", "ograve": "ò", "oacute": "ó",
        "ocirc": "ô", "otilde": "õ", "ouml": "ö", "times": "×", "oslash": "ø", "ugrave": "ù", "uacute": "ú", "ucirc": "û",
        "uuml": "ü", "yacute": "ý", "thorn": "þ", "yuml": "ÿ", "szlig": "ß", "divide": "÷",
        "Agrave": "À", "Aacute": "Á", "Acirc": "Â", "Atilde": "Ã", "Auml": "Ä", "Aring": "Å", "AElig": "Æ", "Ccedil": "Ç",
        "Egrave": "È", "Eacute": "É", "Ecirc": "Ê", "Euml": "Ë", "Igrave": "Ì", "Iacute": "Í", "Icirc": "Î", "Iuml": "Ï",
        "ETH": "Ð", "Ntilde": "Ñ", "Ograve": "Ò", "Oacute": "Ó", "Ocirc": "Ô", "Otilde": "Õ", "Ouml": "Ö", "Oslash": "Ø",
        "Ugrave": "Ù", "Uacute": "Ú", "Ucirc": "Û", "Uuml": "Ü", "Yacute": "Ý", "THORN": "Þ",
        // Latin extended / punctuation
        "OElig": "Œ", "oelig": "œ", "Scaron": "Š", "scaron": "š", "Yuml": "Ÿ", "fnof": "ƒ", "circ": "ˆ", "tilde": "˜",
        "ensp": "\u{2002}", "emsp": "\u{2003}", "thinsp": "\u{2009}", "zwnj": "\u{200C}", "zwj": "\u{200D}", "lrm": "\u{200E}",
        "rlm": "\u{200F}", "ndash": "–", "mdash": "—", "lsquo": "‘", "rsquo": "’", "sbquo": "‚", "ldquo": "“", "rdquo": "”",
        "bdquo": "„", "dagger": "†", "Dagger": "‡", "bull": "•", "hellip": "…", "permil": "‰", "prime": "′", "Prime": "″",
        "lsaquo": "‹", "rsaquo": "›", "oline": "‾", "frasl": "⁄", "euro": "€", "image": "ℑ", "weierp": "℘", "real": "ℜ",
        "trade": "™", "alefsym": "ℵ", "larr": "←", "uarr": "↑", "rarr": "→", "darr": "↓", "harr": "↔", "crarr": "↵",
        "lArr": "⇐", "uArr": "⇑", "rArr": "⇒", "dArr": "⇓", "hArr": "⇔", "forall": "∀", "part": "∂", "exist": "∃",
        "empty": "∅", "nabla": "∇", "isin": "∈", "notin": "∉", "ni": "∋", "prod": "∏", "sum": "∑", "minus": "−",
        "lowast": "∗", "radic": "√", "prop": "∝", "infin": "∞", "ang": "∠", "and": "∧", "or": "∨", "cap": "∩", "cup": "∪",
        "int": "∫", "there4": "∴", "sim": "∼", "cong": "≅", "asymp": "≈", "ne": "≠", "equiv": "≡", "le": "≤", "ge": "≥",
        "sub": "⊂", "sup": "⊃", "nsub": "⊄", "sube": "⊆", "supe": "⊇", "oplus": "⊕", "otimes": "⊗", "perp": "⊥",
        "sdot": "⋅", "lceil": "⌈", "rceil": "⌉", "lfloor": "⌊", "rfloor": "⌋", "lang": "〈", "rang": "〉", "loz": "◊",
        "spades": "♠", "clubs": "♣", "hearts": "♥", "diams": "♦", "check": "✓", "cross": "✗", "star": "☆", "starf": "★",
        // Greek
        "Alpha": "Α", "Beta": "Β", "Gamma": "Γ", "Delta": "Δ", "Epsilon": "Ε", "Zeta": "Ζ", "Eta": "Η", "Theta": "Θ",
        "Iota": "Ι", "Kappa": "Κ", "Lambda": "Λ", "Mu": "Μ", "Nu": "Ν", "Xi": "Ξ", "Omicron": "Ο", "Pi": "Π", "Rho": "Ρ",
        "Sigma": "Σ", "Tau": "Τ", "Upsilon": "Υ", "Phi": "Φ", "Chi": "Χ", "Psi": "Ψ", "Omega": "Ω", "alpha": "α", "beta": "β",
        "gamma": "γ", "delta": "δ", "epsilon": "ε", "zeta": "ζ", "eta": "η", "theta": "θ", "iota": "ι", "kappa": "κ",
        "lambda": "λ", "mu": "μ", "nu": "ν", "xi": "ξ", "omicron": "ο", "pi": "π", "rho": "ρ", "sigmaf": "ς", "sigma": "σ",
        "tau": "τ", "upsilon": "υ", "phi": "φ", "chi": "χ", "psi": "ψ", "omega": "ω", "thetasym": "ϑ", "upsih": "ϒ", "piv": "ϖ",
    ]

    /// Lowercase lookup for case-insensitive fallbacks ("&NBSP;", "&Copy;").
    private static let namedEntitiesLowercased: [String: String] = {
        var table: [String: String] = [:]
        for (key, value) in namedEntities where table[key.lowercased()] == nil { table[key.lowercased()] = value }
        return table
    }()

    /// Legacy entities browsers decode even without a trailing semicolon.
    private static let semicolonOptionalEntities: Set<String> = ["amp", "lt", "gt", "quot", "nbsp", "copy", "reg", "apos"]

    /// Decodes `&name;`, `&#NNN;`, `&#xHHH;` (and the legacy semicolon-less forms of a few entities).
    static func decodeEntities(_ text: String) -> String {
        guard text.contains("&") else { return text }
        let decoded = decodeEntities(Array(text.utf16))
        return String(decoding: decoded, as: UTF16.self)
    }

    static func decodeEntities(_ units: [UInt16]) -> [UInt16] {
        guard units.contains(0x26) else { return units }
        var out: [UInt16] = []
        out.reserveCapacity(units.count)
        let n = units.count
        var i = 0
        while i < n {
            let c = units[i]
            guard c == 0x26 /* & */ else { out.append(c); i += 1; continue }
            // Collect up to 32 entity characters.
            var j = i + 1
            var isNumeric = false
            if j < n, units[j] == 0x23 /* # */ { isNumeric = true; j += 1 }
            let bodyStart = j
            while j < n, j - bodyStart < 32 {
                let u = units[j]
                let alnum = (u >= 0x30 && u <= 0x39) || (u >= 0x41 && u <= 0x5A) || (u >= 0x61 && u <= 0x7A)
                if !alnum { break }
                j += 1
            }
            let body = String(decoding: Array(units[bodyStart..<j]), as: UTF16.self)
            let hasSemicolon = j < n && units[j] == 0x3B
            var replacement: String?
            if isNumeric, !body.isEmpty {
                let lower = body.lowercased()
                let codePoint: UInt32?
                if lower.hasPrefix("x") { codePoint = UInt32(lower.dropFirst(), radix: 16) } else { codePoint = UInt32(body) }
                if let codePoint {
                    if codePoint == 0 {
                        replacement = ""
                    } else if (0x80...0x9F).contains(codePoint) {
                        replacement = windows1252[codePoint] ?? ""
                    } else if let scalar = UnicodeScalar(codePoint) {
                        replacement = String(Character(scalar))
                    }
                }
            } else if !body.isEmpty {
                if let exact = namedEntities[body] {
                    if hasSemicolon || semicolonOptionalEntities.contains(body) { replacement = exact }
                } else if let ci = namedEntitiesLowercased[body.lowercased()], hasSemicolon {
                    replacement = ci
                }
            }
            if let replacement {
                out.append(contentsOf: replacement.utf16)
                i = hasSemicolon ? j + 1 : j
            } else {
                out.append(c)
                i += 1
            }
        }
        return out
    }

    /// Windows-1252 mappings for numeric references in the C1 range (browsers decode `&#150;` as an en dash).
    private static let windows1252: [UInt32: String] = [
        0x80: "€", 0x82: "‚", 0x83: "ƒ", 0x84: "„", 0x85: "…", 0x86: "†", 0x87: "‡", 0x88: "ˆ", 0x89: "‰", 0x8A: "Š", 0x8B: "‹",
        0x8C: "Œ", 0x8E: "Ž", 0x91: "‘", 0x92: "’", 0x93: "“", 0x94: "”", 0x95: "•", 0x96: "–", 0x97: "—", 0x98: "˜", 0x99: "™",
        0x9A: "š", 0x9B: "›", 0x9C: "œ", 0x9E: "ž", 0x9F: "Ÿ",
    ]

    // MARK: - Whitespace

    /// Collapses runs of horizontal whitespace to one space, trims spaces around newlines, collapses blank-line runs
    /// to a single newline and removes zero-width / soft-hyphen characters (used to split keywords).
    static func normalizeWhitespace(_ text: String) -> String {
        let normalized = normalizeWhitespace(Array(text.utf16))
        return String(decoding: normalized, as: UTF16.self)
    }

    private static func isRemovedUnit(_ u: UInt16) -> Bool {
        u == 0x200B || u == 0x200C || u == 0x200D || u == 0xFEFF || u == 0x2060 || u == 0x00AD || u == 0x034F
    }

    private static func isNewlineUnit(_ u: UInt16) -> Bool {
        u == 0x0A || u == 0x0D || u == 0x2028 || u == 0x2029 || u == 0x85
    }

    private static func isSpaceLikeUnit(_ u: UInt16) -> Bool {
        u == 0x20 || u == 0x09 || u == 0xA0 || u == 0x0B || u == 0x0C || (u >= 0x2000 && u <= 0x200A) || u == 0x202F || u == 0x205F || u == 0x3000
    }

    static func normalizeWhitespace(_ units: [UInt16]) -> [UInt16] {
        var out: [UInt16] = []
        out.reserveCapacity(units.count)
        var pendingSpace = false
        var pendingNewline = false
        var atLineStart = true
        for u in units {
            if isRemovedUnit(u) { continue }
            if isNewlineUnit(u) {
                pendingNewline = true
                pendingSpace = false
                continue
            }
            if isSpaceLikeUnit(u) {
                pendingSpace = true
                continue
            }
            if pendingNewline {
                if !atLineStart { out.append(0x0A) }
                pendingNewline = false
                pendingSpace = false
            } else if pendingSpace {
                if !atLineStart { out.append(0x20) }
                pendingSpace = false
            }
            out.append(u)
            atLineStart = false
        }
        return out
    }
}

import Foundation

public enum ModelOutputParserError: Error, Equatable, Sendable {
    case noJSONObjectFound
    case invalidJSON(String)
}

/// Turns raw LLM text into a `ModelAssessment`.
///
/// Tolerates the usual small-model quirks: `<think>…</think>` blocks (Qwen3 hybrid thinking), markdown code fences,
/// leading/trailing prose, truncated output (unclosed strings/brackets are repaired), Python-style literals,
/// single-quoted or unquoted keys, trailing commas, `85%` scores, and loose value types (riskScore as Int/Double/
/// String, isSuspicious as Bool/String/Int, category synonyms, reasons as an array, a single string or a newline
/// list, missing summary).
public enum ModelOutputParser {
    /// Finds the first JSON object in `text` and decodes it leniently. Throws `ModelOutputParserError` when no
    /// object can be recovered or the object carries none of the expected keys.
    public static func parseAssessment(from text: String) throws -> ModelAssessment {
        let cleaned = stripFences(stripThinking(String(text.prefix(64_000))))
        var lastDecodeError: String?
        var attempts = 0
        var searchStart = cleaned.startIndex
        while let open = cleaned[searchStart...].firstIndex(of: "{"), attempts < 25 {
            attempts += 1
            let extraction = extractObject(from: cleaned, at: open)
            var candidate = extraction.json
            if extraction.truncated { candidate = repairTruncatedJSON(candidate) }
            if let dictionary = decodeObject(candidate) {
                if let assessment = assessment(from: dictionary) { return assessment }
                lastDecodeError = "object has none of the expected keys"
            } else {
                lastDecodeError = "unparseable object"
            }
            searchStart = cleaned.index(after: open)
        }
        if let lastDecodeError { throw ModelOutputParserError.invalidJSON(lastDecodeError) }
        throw ModelOutputParserError.noJSONObjectFound
    }

    // MARK: - Pre-processing

    /// Removes `<think>…</think>` blocks (and an unterminated `<think>` prefix or a stray `</think>`).
    static func stripThinking(_ text: String) -> String {
        var s = text
        var guardCount = 0
        while let open = s.range(of: "<think>", options: .caseInsensitive), guardCount < 20 {
            guardCount += 1
            if let close = s.range(of: "</think>", options: .caseInsensitive, range: open.upperBound..<s.endIndex) {
                s.removeSubrange(open.lowerBound..<close.upperBound)
            } else {
                // Unterminated thinking: keep whatever follows the last "{" if any, else drop the block.
                s.removeSubrange(open.lowerBound..<s.endIndex)
            }
        }
        if let stray = s.range(of: "</think>", options: .caseInsensitive) {
            s = String(s[stray.upperBound...])
        }
        return s.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Removes markdown code fences (```json … ```), keeping the fenced content.
    static func stripFences(_ text: String) -> String {
        guard text.contains("```") else { return text }
        var s = text
        // Prefer the content of the first fenced block when it contains "{".
        if let start = s.range(of: "```") {
            var content = s[start.upperBound...]
            if let newline = content.firstIndex(of: "\n"), content[..<newline].allSatisfy({ $0.isLetter || $0.isNumber }) {
                content = content[content.index(after: newline)...]   // language tag
            }
            let inner: Substring
            if let end = content.range(of: "```") {
                inner = content[..<end.lowerBound]
            } else {
                inner = content
            }
            if inner.contains("{") { return String(inner) }
        }
        s = s.replacingOccurrences(of: "```json", with: "", options: .caseInsensitive)
        s = s.replacingOccurrences(of: "```", with: "")
        return s
    }

    // MARK: - Object extraction / repair

    /// From the `{` at `open`, returns the balanced object (string-aware) or the remainder when the text ends first.
    static func extractObject(from text: String, at open: String.Index) -> (json: String, truncated: Bool) {
        var depth = 0
        var inString = false
        var escaped = false
        var index = open
        while index < text.endIndex {
            let ch = text[index]
            if inString {
                if escaped { escaped = false }
                else if ch == "\\" { escaped = true }
                else if ch == "\"" { inString = false }
            } else {
                switch ch {
                case "\"": inString = true
                case "{", "[": depth += 1
                case "}", "]":
                    depth -= 1
                    if depth == 0 { return (String(text[open...index]), false) }
                default: break
                }
            }
            index = text.index(after: index)
        }
        return (String(text[open...]), true)
    }

    /// Closes an open string, drops a dangling key / partial literal / trailing comma and closes open brackets.
    static func repairTruncatedJSON(_ json: String) -> String {
        var out = ""
        var stack: [Character] = []
        var inString = false
        var escaped = false
        for ch in json {
            if inString {
                if escaped { escaped = false }
                else if ch == "\\" { escaped = true }
                else if ch == "\"" { inString = false }
            } else {
                switch ch {
                case "\"": inString = true
                case "{", "[": stack.append(ch)
                case "}", "]": if !stack.isEmpty { stack.removeLast() }
                default: break
                }
            }
            out.append(ch)
        }
        if inString {
            if escaped { out.removeLast() }
            out.append("\"")
        }
        out = trimDanglingTail(out)
        for open in stack.reversed() { out.append(open == "{" ? "}" : "]") }
        return out
    }

    /// Removes a trailing partial token, a dangling `"key":` and a trailing comma (outside strings).
    private static func trimDanglingTail(_ json: String) -> String {
        var s = json
        func trimTrailingWhitespace() { while let last = s.last, last.isWhitespace { s.removeLast() } }
        trimTrailingWhitespace()
        // Partial bare literal / number that is not complete ("tr", "fals", "8." ...).
        var token = ""
        var probe = s.endIndex
        while probe > s.startIndex {
            let prev = s.index(before: probe)
            let ch = s[prev]
            guard ch.isLetter || ch.isNumber || ch == "." || ch == "-" || ch == "+" else { break }
            token.insert(ch, at: token.startIndex)
            probe = prev
        }
        if !token.isEmpty {
            let complete = ["true", "false", "null"].contains(token.lowercased()) || Double(token) != nil
            if !complete { s.removeSubrange(probe...) }
        }
        trimTrailingWhitespace()
        if s.hasSuffix(":") {
            s.removeLast()
            trimTrailingWhitespace()
            if s.hasSuffix("\"") {
                s.removeLast()
                while let last = s.last, last != "\"" { s.removeLast() }
                if s.hasSuffix("\"") { s.removeLast() }
            }
            trimTrailingWhitespace()
        }
        if s.hasSuffix(",") { s.removeLast(); trimTrailingWhitespace() }
        return s
    }

    /// Normalizes loose JSON into strict JSON: comments, single-quoted strings, unquoted keys and bare-word values,
    /// Python/JS literals (True/False/None/undefined/NaN), percent-suffixed numbers and trailing commas.
    static func normalizeLooseJSON(_ json: String) -> String {
        let chars = Array(json)
        var out = ""
        out.reserveCapacity(chars.count + 16)
        var i = 0
        var inDouble = false
        var inSingle = false
        var escaped = false
        func nextSignificant(after index: Int) -> Character? {
            var j = index
            while j < chars.count {
                if !chars[j].isWhitespace { return chars[j] }
                j += 1
            }
            return nil
        }
        while i < chars.count {
            let ch = chars[i]
            if inDouble {
                out.append(ch)
                if escaped { escaped = false }
                else if ch == "\\" { escaped = true }
                else if ch == "\"" { inDouble = false }
                i += 1
                continue
            }
            if inSingle {
                if escaped {
                    escaped = false
                    if ch == "'" { out.append("'") } else { out.append("\\"); out.append(ch) }
                } else if ch == "\\" {
                    escaped = true
                } else if ch == "'" {
                    out.append("\""); inSingle = false
                } else if ch == "\"" {
                    out.append("\\\"")
                } else {
                    out.append(ch)
                }
                i += 1
                continue
            }
            switch ch {
            case "\"":
                inDouble = true; out.append(ch); i += 1
            case "'":
                inSingle = true; out.append("\""); i += 1
            case "“", "”":
                inDouble = true; out.append("\""); i += 1
            case "/":
                if i + 1 < chars.count, chars[i + 1] == "/" {
                    while i < chars.count, chars[i] != "\n" { i += 1 }
                } else if i + 1 < chars.count, chars[i + 1] == "*" {
                    i += 2
                    while i + 1 < chars.count, !(chars[i] == "*" && chars[i + 1] == "/") { i += 1 }
                    i += 2
                } else {
                    out.append(ch); i += 1
                }
            case ",":
                if let next = nextSignificant(after: i + 1), next == "}" || next == "]" { i += 1 } else { out.append(ch); i += 1 }
            case _ where ch.isLetter || ch == "_" || ch == "$":
                var j = i
                var identifier = ""
                while j < chars.count, chars[j].isLetter || chars[j].isNumber || chars[j] == "_" || chars[j] == "$" || chars[j] == "-" {
                    identifier.append(chars[j]); j += 1
                }
                let lower = identifier.lowercased()
                switch lower {
                case "true", "false", "null": out.append(lower)
                case "none", "nil", "undefined", "nan", "infinity", "-infinity": out.append("null")
                default: out.append("\"\(identifier)\"")
                }
                i = j
            case _ where ch.isNumber || ((ch == "-" || ch == "+") && i + 1 < chars.count && chars[i + 1].isNumber):
                var j = i
                var number = ""
                while j < chars.count, chars[j].isNumber || chars[j] == "." || chars[j] == "-" || chars[j] == "+" || chars[j] == "e" || chars[j] == "E" {
                    number.append(chars[j]); j += 1
                }
                if j < chars.count, chars[j] == "%" { j += 1 }
                if number.hasPrefix("+") { number.removeFirst() }
                out.append(number)
                i = j
            default:
                out.append(ch); i += 1
            }
        }
        if inDouble || inSingle { out.append("\"") }
        return out
    }

    /// Strict decode first, then the loose-JSON normalization, then normalization plus truncation repair.
    static func decodeObject(_ json: String) -> [String: Any]? {
        if let object = jsonObject(json) { return object }
        let normalized = normalizeLooseJSON(json)
        if let object = jsonObject(normalized) { return object }
        return jsonObject(repairTruncatedJSON(normalized))
    }

    private static func jsonObject(_ json: String) -> [String: Any]? {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) else { return nil }
        return object as? [String: Any]
    }

    // MARK: - Lenient field mapping

    private static let suspiciousKeys = ["issuspicious", "suspicious", "ismalicious", "malicious", "isphishing", "flag", "flagged", "isscam"]
    private static let categoryKeys = ["category", "classification", "class", "type", "label", "verdict", "threatcategory"]
    private static let riskKeys = ["riskscore", "risk", "score", "confidence", "probability", "risklevel", "threatscore"]
    private static let reasonsKeys = ["reasons", "reason", "indicators", "evidence", "findings", "signals", "redflags", "flags", "why"]
    private static let summaryKeys = ["summary", "explanation", "rationale", "description", "conclusion", "assessment", "verdictsummary"]

    private static func normalizedKey(_ key: String) -> String {
        key.lowercased().filter { $0.isLetter || $0.isNumber }
    }

    private static func value(for keys: [String], in dictionary: [String: Any]) -> Any? {
        var normalized: [String: Any] = [:]
        for (key, value) in dictionary where !(value is NSNull) {
            let k = normalizedKey(key)
            if normalized[k] == nil { normalized[k] = value }
        }
        for key in keys {
            if let v = normalized[key] { return v }
        }
        return nil
    }

    static func assessment(from dictionary: [String: Any]) -> ModelAssessment? {
        let rawSuspicious = value(for: suspiciousKeys, in: dictionary)
        let rawCategory = value(for: categoryKeys, in: dictionary)
        let rawRisk = value(for: riskKeys, in: dictionary)
        let rawReasons = value(for: reasonsKeys, in: dictionary)
        let rawSummary = value(for: summaryKeys, in: dictionary)
        guard rawSuspicious != nil || rawCategory != nil || rawRisk != nil || rawReasons != nil || rawSummary != nil else { return nil }

        var suspicious = rawSuspicious.flatMap(bool(from:))
        var category = rawCategory.flatMap(category(from:))
        var risk = rawRisk.flatMap(riskScore(from:))
        // Some models put the category into the isSuspicious slot ("isSuspicious": "phishing").
        if suspicious == nil, category == nil, let text = rawSuspicious as? String, let c = self.category(from: text) {
            category = c
            suspicious = c == .phishing || c == .scam
        }
        let reasons = rawReasons.map(reasons(from:)) ?? []
        var summary = (rawSummary as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if summary.isEmpty, let dict = rawSummary as? [String: Any], let text = dict.values.first(where: { $0 is String }) as? String {
            summary = text
        }

        // Derivations for missing fields.
        if category == nil {
            if let suspicious {
                category = suspicious ? .phishing : .safe
            } else if let risk {
                category = risk >= 50 ? .phishing : .safe
            }
        }
        if suspicious == nil {
            switch category {
            case .phishing?, .scam?: suspicious = true
            case .spam?, .safe?: suspicious = (risk ?? 0) >= 50
            case nil: suspicious = (risk ?? 0) >= 50
            }
        }
        if risk == nil {
            switch (suspicious ?? false, category) {
            case (true, .phishing?), (true, .scam?): risk = 80
            case (true, _): risk = 60
            case (false, .spam?): risk = 30
            case (false, _): risk = 5
            }
        }
        if summary.isEmpty {
            summary = reasons.isEmpty ? "" : reasons.map { $0.hasSuffix(".") ? $0 : $0 + "." }.joined(separator: " ")
        }
        return ModelAssessment(
            isSuspicious: suspicious ?? false,
            category: category ?? .safe,
            riskScore: risk ?? 0,
            reasons: reasons,
            summary: String(summary.prefix(600))
        )
    }

    static func bool(from value: Any) -> Bool? {
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue }
            return number.doubleValue != 0
        }
        if let b = value as? Bool { return b }
        if let text = value as? String {
            switch text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "true", "yes", "y", "1", "suspicious", "malicious", "phishing", "scam", "high", "likely": return true
            case "false", "no", "n", "0", "safe", "legitimate", "legit", "benign", "clean", "not suspicious", "low", "unlikely": return false
            default:
                if let d = Double(text) { return d != 0 }
                return nil
            }
        }
        return nil
    }

    static func riskScore(from value: Any) -> Int? {
        // Values in (0, 1) are probabilities scaled to 0…100. Exactly 1 is ambiguous: written as a fraction ("1.0",
        // a float-typed JSON number) it is "certain", written as the integer 1 it is a score of 1/100.
        func fromDouble(_ d: Double, fractional: Bool) -> Int {
            var v = d
            if v > 0, v < 1 || (v == 1 && fractional) { v *= 100 }
            return Int(v.rounded())
        }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? 80 : 5 }
            return fromDouble(number.doubleValue, fractional: CFNumberIsFloatType(number as CFNumber))
        }
        if let i = value as? Int { return i }
        if let d = value as? Double { return fromDouble(d, fractional: true) }
        if let text = value as? String {
            var t = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let percent = t.contains("%") || t.contains("/100")
            t = t.replacingOccurrences(of: "%", with: "").replacingOccurrences(of: "/100", with: "").trimmingCharacters(in: .whitespaces)
            if let d = Double(t) { return fromDouble(d, fractional: !percent && t.contains(".")) }
            let digits = t.prefix { $0.isNumber || $0 == "." }
            if !digits.isEmpty, let d = Double(digits) { return fromDouble(d, fractional: !percent && digits.contains(".")) }
            switch t {
            case "critical", "very high": return 95
            case "high": return 85
            case "medium", "moderate", "med": return 55
            case "low": return 25
            case "none", "very low", "minimal", "safe": return 5
            default: return nil
            }
        }
        return nil
    }

    static func category(from value: Any) -> ThreatCategory? {
        let text: String
        if let s = value as? String { text = s }
        else if let n = value as? NSNumber { text = n.stringValue }
        else if let dict = value as? [String: Any], let s = dict.values.first(where: { $0 is String }) as? String { text = s }
        else { return nil }
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            .replacingOccurrences(of: "_", with: " ").replacingOccurrences(of: "-", with: " ")
        guard !t.isEmpty else { return nil }
        if let exact = ThreatCategory(rawValue: t) { return exact }
        // Negated labels: the clause before the negation wins when it names a class ("spam, not phishing" → spam,
        // "safe (not phishing)" → safe); otherwise a negated class means the mail is not that class ("not phishing",
        // "legitimate, not a scam", "non-malicious" → safe). "not suspicious" still falls through to the safe keywords.
        if let negation = t.range(of: #"\b(not|no|non|never|isn't|isnt|is not)\b"#, options: .regularExpression) {
            if let positive = keywordCategory(String(t[..<negation.lowerBound])) { return positive }
            if keywordCategory(String(t[negation.upperBound...])) != nil { return .safe }
        }
        return keywordCategory(t)
    }

    /// Keyword synonyms for each category, in priority order; nil when nothing matches.
    private static func keywordCategory(_ t: String) -> ThreatCategory? {
        if t.contains("phish") || t.contains("credential") || t.contains("spoof") || t.contains("malicious") || t.contains("malware")
            || t.contains("impersonat") || t.contains("fraudulent link") {
            return .phishing
        }
        if t.contains("scam") || t.contains("fraud") || t.contains("extort") || t.contains("bec") || t.contains("advance fee")
            || t.contains("gift card") || t.contains("social engineering") {
            return .scam
        }
        if t.contains("spam") || t.contains("junk") || t.contains("marketing") || t.contains("promotional") || t.contains("bulk") {
            return .spam
        }
        if t.contains("safe") || t.contains("legit") || t.contains("benign") || t.contains("clean") || t == "ham" || t == "ok"
            || t == "none" || t.contains("not suspicious") || t.contains("normal") {
            return .safe
        }
        return nil
    }

    static func reasons(from value: Any) -> [String] {
        var items: [String] = []
        if let array = value as? [Any] {
            for element in array {
                if let s = element as? String { items.append(s) }
                else if let dict = element as? [String: Any] {
                    let text = (dict["reason"] ?? dict["text"] ?? dict["detail"] ?? dict["description"] ?? dict.values.first(where: { $0 is String })) as? String
                    if let text { items.append(text) }
                } else if let n = element as? NSNumber { items.append(n.stringValue) }
            }
        } else if let text = value as? String {
            items = splitReasonText(text)
        } else if let dict = value as? [String: Any] {
            items = dict.values.compactMap { $0 as? String }
        }
        return items
            .map { cleanReason($0) }
            .filter { !$0.isEmpty }
            .prefix(6)
            .map { String($0.prefix(200)) }
    }

    private static func splitReasonText(_ text: String) -> [String] {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains("\n") { return trimmed.components(separatedBy: .newlines) }
        if trimmed.contains(";") { return trimmed.components(separatedBy: ";") }
        if trimmed.contains(" - ") || trimmed.contains(" • ") {
            return trimmed.components(separatedBy: " - ").flatMap { $0.components(separatedBy: " • ") }
        }
        return [trimmed]
    }

    private static func cleanReason(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        // Leading bullets / numbering: "- ", "* ", "• ", "1. ", "1) ", "(1) "
        while let first = s.first, "-*•·–—".contains(first) { s.removeFirst(); s = s.trimmingCharacters(in: .whitespaces) }
        if s.hasPrefix("(") { s.removeFirst() }
        let digits = s.prefix { $0.isNumber }
        if !digits.isEmpty, digits.count <= 2 {
            let rest = s.dropFirst(digits.count)
            if rest.hasPrefix(".") || rest.hasPrefix(")") || rest.hasPrefix(":") {
                s = String(rest.dropFirst()).trimmingCharacters(in: .whitespaces)
            }
        }
        return s.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

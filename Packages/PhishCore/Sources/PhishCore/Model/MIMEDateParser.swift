import Foundation

/// RFC 5322 `Date:` header parsing, plus the malformed shapes real mail carries.
///
/// Hand-rolled rather than `DateFormatter`-driven: the obsolete zone names, two-digit years, missing seconds and
/// `ctime` ordering that phishing kits emit each need their own format string, and a formatter pass per shape is
/// both slower and less tolerant. Everything here is a pure function over a bounded-length string.
enum MIMEDateParser {
    /// Longest header value examined; anything longer is not a date.
    static let maxLength = 200

    static func parse(_ value: String) -> Date? {
        guard value.count <= maxLength else { return nil }
        let text = stripComments(value)
        var tokens = text.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\r" || $0 == "\n" })
            .map { String($0) }
        guard !tokens.isEmpty, tokens.count <= 12 else { return nil }

        // Optional leading day-of-week, with or without the comma ("Mon," / "Monday," / "Mon").
        if let first = tokens.first, isDayOfWeek(first) {
            tokens.removeFirst()
        } else if let first = tokens.first, first.hasSuffix(","), isDayOfWeek(String(first.dropLast())) {
            tokens.removeFirst()
        }
        guard !tokens.isEmpty else { return nil }

        var day: Int?
        var month: Int?
        var year: Int?
        var time: (hour: Int, minute: Int, second: Int)?
        var zoneSeconds: Int?

        if let monthValue = monthNumber(tokens[0]) {
            // `ctime` order: "Sep 22 10:04:05 2026 [zone]"
            month = monthValue
            tokens.removeFirst()
            guard !tokens.isEmpty, let dayValue = integer(tokens[0]) else { return nil }
            day = dayValue
            tokens.removeFirst()
            guard !tokens.isEmpty, let parsedTime = parseTime(tokens[0]) else { return nil }
            time = parsedTime
            tokens.removeFirst()
            guard !tokens.isEmpty, let yearValue = integer(tokens[0]) else { return nil }
            year = normalizeYear(yearValue)
            tokens.removeFirst()
        } else {
            // RFC 5322 order: "22 Sep 2026 10:04:05 +0200"
            guard let dayValue = integer(tokens[0]) else { return nil }
            day = dayValue
            tokens.removeFirst()
            guard !tokens.isEmpty, let monthValue = monthNumber(tokens[0]) else { return nil }
            month = monthValue
            tokens.removeFirst()
            guard !tokens.isEmpty, let yearValue = integer(tokens[0]) else { return nil }
            year = normalizeYear(yearValue)
            tokens.removeFirst()
            guard !tokens.isEmpty, let parsedTime = parseTime(tokens[0]) else { return nil }
            time = parsedTime
            tokens.removeFirst()
        }

        // Remaining tokens: zone, possibly split ("GMT +0200") or a name followed by an offset ("GMT+02:00").
        if !tokens.isEmpty {
            zoneSeconds = parseZone(tokens.joined())
        }

        guard let day, let month, let year, let time else { return nil }
        guard (1...31).contains(day), (0...24).contains(time.hour),
              (0...59).contains(time.minute), (0...60).contains(time.second),
              year >= 1900, year <= 2200 else { return nil }

        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.hour = time.hour == 24 ? 0 : time.hour
        components.minute = time.minute
        components.second = min(time.second, 59)

        var calendar = Calendar(identifier: .gregorian)
        guard let utc = TimeZone(secondsFromGMT: 0) else { return nil }
        calendar.timeZone = utc
        guard var date = calendar.date(from: components) else { return nil }
        if time.hour == 24 { date = date.addingTimeInterval(24 * 3600) }
        return date.addingTimeInterval(-TimeInterval(zoneSeconds ?? 0))
    }

    // MARK: - Pieces

    /// Removes RFC 5322 `(comments)`, including nested ones, e.g. `-0700 (PDT)`.
    static func stripComments(_ value: String) -> String {
        guard value.contains("(") else { return value }
        var out = ""
        var depth = 0
        var escaped = false
        for ch in value {
            if escaped { escaped = false; continue }
            if depth > 0 {
                switch ch {
                case "\\": escaped = true
                case "(": depth += 1
                case ")": depth -= 1
                default: break
                }
                continue
            }
            switch ch {
            case "(": depth += 1
            case ")": break // stray close paren
            default: out.append(ch)
            }
        }
        return out
    }

    private static func integer(_ token: String) -> Int? {
        let digits = token.prefix { $0.isASCII && $0.isNumber }
        guard !digits.isEmpty, digits.count <= 4 else { return nil }
        // Tolerate an ordinal suffix or stray punctuation ("22nd", "22,").
        return Int(digits)
    }

    /// RFC 2822 §4.3 obsolete years: two digits 00-49 → 2000s, 50-99 → 1900s, three digits → 1900 + n.
    private static func normalizeYear(_ value: Int) -> Int {
        if value >= 1000 { return value }
        if value >= 100 { return 1900 + value }
        return value < 50 ? 2000 + value : 1900 + value
    }

    private static func parseTime(_ token: String) -> (hour: Int, minute: Int, second: Int)? {
        // "10:04:05", "10:04", "10.04.05" and "100405" all occur.
        let normalized = token.replacingOccurrences(of: ".", with: ":")
        let pieces = normalized.split(separator: ":", omittingEmptySubsequences: false)
        if pieces.count >= 2 {
            guard pieces.count <= 3,
                  let hour = Int(pieces[0].prefix(2)), let minute = Int(pieces[1].prefix(2)) else { return nil }
            var second = 0
            if pieces.count == 3 {
                let digits = pieces[2].prefix { $0.isASCII && $0.isNumber }
                guard !digits.isEmpty, let parsed = Int(digits) else { return nil }
                second = parsed
            }
            return (hour, minute, second)
        }
        let digits = normalized.filter { $0.isASCII && $0.isNumber }
        guard digits.count == 6 || digits.count == 4, digits.count == normalized.count else { return nil }
        let values = Array(digits)
        guard let hour = Int(String(values[0...1])), let minute = Int(String(values[2...3])) else { return nil }
        let second = digits.count == 6 ? Int(String(values[4...5])) ?? 0 : 0
        return (hour, minute, second)
    }

    /// `+HHMM`, `-HH:MM`, `GMT`, `GMT+0200`, obsolete US names, or a military single letter (which RFC 2822
    /// says to read as `-0000`). Unknown zones yield `nil` → treated as UTC by the caller.
    static func parseZone(_ token: String) -> Int? {
        var text = token.trimmingCharacters(in: .whitespaces).uppercased()
        guard !text.isEmpty else { return nil }

        for prefix in ["UTC", "GMT", "UT"] where text.hasPrefix(prefix) {
            let rest = String(text.dropFirst(prefix.count))
            if rest.isEmpty { return 0 }
            text = rest
            break
        }

        if let sign = text.first, sign == "+" || sign == "-" {
            let digits = text.dropFirst().filter { $0.isASCII && $0.isNumber }
            guard digits.count == 4 || digits.count == 2 else { return nil }
            let chars = Array(digits)
            guard let hours = Int(String(chars[0...1])) else { return nil }
            let minutes = digits.count == 4 ? Int(String(chars[2...3])) ?? 0 : 0
            guard hours <= 23, minutes <= 59 else { return nil }
            let seconds = hours * 3600 + minutes * 60
            return sign == "-" ? -seconds : seconds
        }

        switch text {
        case "Z", "UTC", "GMT", "UT": return 0
        case "EST": return -5 * 3600
        case "EDT": return -4 * 3600
        case "CST": return -6 * 3600
        case "CDT": return -5 * 3600
        case "MST": return -7 * 3600
        case "MDT": return -6 * 3600
        case "PST": return -8 * 3600
        case "PDT": return -7 * 3600
        default:
            // Single-letter military zones are unreliable; RFC 2822 §4.3 says treat them as -0000.
            if text.count == 1, let ch = text.first, ch.isLetter { return 0 }
            return nil
        }
    }

    private static let months = [
        "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
        "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
    ]

    private static func monthNumber(_ token: String) -> Int? {
        let letters = token.prefix { $0.isASCII && $0.isLetter }
        guard letters.count >= 3 else { return nil }
        return months[letters.prefix(3).lowercased()]
    }

    private static let daysOfWeek: Set<String> = [
        "mon", "tue", "wed", "thu", "fri", "sat", "sun",
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    ]

    private static func isDayOfWeek(_ token: String) -> Bool {
        daysOfWeek.contains(token.lowercased())
    }
}

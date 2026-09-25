import Foundation

/// Result token of one authentication method as found in `Authentication-Results`.
public enum AuthResult: String, Codable, Sendable {
    case pass, fail, softfail, neutral, none, temperror, permerror, unknown
}

/// Parsed `Authentication-Results` header (RFC 8601). Missing methods are `nil`.
///
/// `extract(from:)` trusts only the top-most `Authentication-Results` header (the receiving provider's own stamp;
/// anything below it may have been forged by the sender): when it carries an authserv-id, every header stamped with
/// exactly that id is merged; when it has none (Exchange Online style), that one header is used alone. It then falls
/// back to the newest `ARC-Authentication-Results` instance, then to `Received-SPF`, when the trusted header lacks
/// a method.
public struct AuthenticationResults: Sendable, Codable, Equatable {
    public var spf: AuthResult?
    public var dkim: AuthResult?
    public var dmarc: AuthResult?
    /// `arc=` result stamped by the trusted receiving provider (RFC 8617): `pass` means the provider validated the
    /// ARC chain of an intermediary (typically a mailing list) that broke the original DKIM signature. Taken only
    /// from the trusted `Authentication-Results` header, never from `ARC-Authentication-Results`. Nil when absent.
    public var arc: AuthResult?
    /// The raw header value(s) this was parsed from, joined by "\n". Nil when no header existed.
    public var rawHeader: String?

    /// authserv-id of the trusted header ("mx.google.com", "protection.outlook.com").
    public var authservID: String?
    /// `header.d` (or the domain of `header.i`) of the DKIM signature that produced `dkim` — the aligned pass when
    /// one exists, otherwise the first passing signature, otherwise the first signature.
    public var dkimDomain: String?
    /// Domains of every DKIM signature that passed.
    public var dkimPassDomains: [String] = []
    /// Domain of `smtp.mailfrom` (falls back to `smtp.helo`) for the SPF result.
    public var spfDomain: String?
    /// `header.from` reported next to the DMARC result.
    public var dmarcFromDomain: String?

    public init(spf: AuthResult? = nil, dkim: AuthResult? = nil, dmarc: AuthResult? = nil, rawHeader: String? = nil) {
        self.spf = spf
        self.dkim = dkim
        self.dmarc = dmarc
        self.rawHeader = rawHeader
    }

    /// True when at least one method was reported.
    public var hasAnyResult: Bool { spf != nil || dkim != nil || dmarc != nil }

    // MARK: Codable (tolerates older payloads without the new keys)

    private enum CodingKeys: String, CodingKey {
        case spf, dkim, dmarc, arc, rawHeader, authservID, dkimDomain, dkimPassDomains, spfDomain, dmarcFromDomain
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        spf = try c.decodeIfPresent(AuthResult.self, forKey: .spf)
        dkim = try c.decodeIfPresent(AuthResult.self, forKey: .dkim)
        dmarc = try c.decodeIfPresent(AuthResult.self, forKey: .dmarc)
        arc = try c.decodeIfPresent(AuthResult.self, forKey: .arc)
        rawHeader = try c.decodeIfPresent(String.self, forKey: .rawHeader)
        authservID = try c.decodeIfPresent(String.self, forKey: .authservID)
        dkimDomain = try c.decodeIfPresent(String.self, forKey: .dkimDomain)
        dkimPassDomains = try c.decodeIfPresent([String].self, forKey: .dkimPassDomains) ?? []
        spfDomain = try c.decodeIfPresent(String.self, forKey: .spfDomain)
        dmarcFromDomain = try c.decodeIfPresent(String.self, forKey: .dmarcFromDomain)
    }

    // MARK: - Parsing

    /// One `method=result` clause with its property/value pairs (RFC 8601 "resinfo").
    public struct Entry: Sendable, Equatable {
        public var method: String
        public var result: AuthResult
        /// Lowercased "ptype.property" → value, e.g. "header.d" → "paypal.com", "smtp.mailfrom" → "bounce@x.com".
        public var properties: [String: String]
    }

    /// Structured view of a header: authserv-id, optional ARC instance, and every entry.
    public struct ParsedHeader: Sendable, Equatable {
        public var authservID: String?
        public var arcInstance: Int?
        public var entries: [Entry]
    }

    /// Parses one `Authentication-Results` / `ARC-Authentication-Results` value into its clauses. Comments in
    /// parentheses are removed first (they may contain ";" and "="), folded whitespace is collapsed, quoted values
    /// are unquoted, and `method/version` tokens lose their version.
    public static func parseHeader(_ headerValue: String) -> ParsedHeader {
        let unfolded = stripComments(String(headerValue.prefix(8_192)))
        var clauses = unfolded.split(separator: ";").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        var parsed = ParsedHeader(authservID: nil, arcInstance: nil, entries: [])

        // ARC: "i=1; mx.example.com; spf=pass ..."
        if let first = clauses.first, first.lowercased().hasPrefix("i="), let instance = Int(first.dropFirst(2).trimmingCharacters(in: .whitespaces)) {
            parsed.arcInstance = instance
            clauses.removeFirst()
        }
        // authserv-id [version]: the first clause when it is not a method=result pair.
        if let first = clauses.first, !first.contains("=") {
            parsed.authservID = first.split(separator: " ").first.map { String($0).lowercased() }
            clauses.removeFirst()
        }

        for clause in clauses {
            let tokens = tokenize(clause)
            guard let head = tokens.first, let eq = head.firstIndex(of: "=") else { continue }
            var method = head[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            if let slash = method.firstIndex(of: "/") { method = String(method[..<slash]) }
            let resultToken = head[head.index(after: eq)...].trimmingCharacters(in: .whitespaces).lowercased()
            guard !method.isEmpty, !resultToken.isEmpty else { continue }
            let result = AuthResult(rawValue: resultToken) ?? .unknown
            var properties: [String: String] = [:]
            for token in tokens.dropFirst() {
                guard let peq = token.firstIndex(of: "=") else { continue }
                let key = token[..<peq].trimmingCharacters(in: .whitespaces).lowercased()
                var value = token[token.index(after: peq)...].trimmingCharacters(in: .whitespaces)
                if value.hasPrefix("\""), value.hasSuffix("\""), value.count >= 2 { value = String(value.dropFirst().dropLast()) }
                guard !key.isEmpty, properties[key] == nil else { continue }
                properties[key] = value.lowercased()
            }
            parsed.entries.append(Entry(method: method, result: result, properties: properties))
        }
        return parsed
    }

    /// Parses a single `Authentication-Results` header value, e.g.
    /// `mx.google.com; dkim=fail header.i=@paypal.com; spf=softfail; dmarc=fail (p=REJECT)`.
    /// With several results for one method, a `pass` wins for DKIM (multiple signatures) and the first entry
    /// otherwise.
    public static func parse(_ headerValue: String) -> AuthenticationResults {
        var results = AuthenticationResults(rawHeader: headerValue)
        let parsed = parseHeader(headerValue)
        results.authservID = parsed.authservID
        results.apply(entries: parsed.entries, fromDomain: nil)
        return results
    }

    /// Merges the message's authentication headers (see the type documentation for the trust rules).
    /// `headers` may contain the `From` header; when it does, DKIM alignment prefers a signature whose domain
    /// matches the From domain.
    public static func extract(from headers: [EmailHeader]) -> AuthenticationResults {
        let fromDomain = headers.first { $0.name.caseInsensitiveCompare("From") == .orderedSame }
            .flatMap { EmailAddress.parse($0.value).first?.domain }
            .flatMap { $0.isEmpty ? nil : DomainAnalysis.registrableDomain(of: $0) }

        let authHeaders = headers.filter { $0.name.caseInsensitiveCompare("Authentication-Results") == .orderedSame }.map(\.value)
        let arcHeaders = headers.filter { $0.name.caseInsensitiveCompare("ARC-Authentication-Results") == .orderedSame }.map(\.value)
        let receivedSPF = headers.first { $0.name.caseInsensitiveCompare("Received-SPF") == .orderedSame }?.value

        var results = AuthenticationResults()
        var rawParts: [String] = []

        // 1. Trusted Authentication-Results: the top-most header, plus every header stamped with the same authserv-id.
        let parsedAuth = authHeaders.prefix(20).map(parseHeader)
        if let first = parsedAuth.first {
            let trustedID = first.authservID
            results.authservID = trustedID
            var entries: [Entry] = []
            for (index, parsed) in parsedAuth.enumerated() {
                // No authserv-id on the top header (Exchange Online style): trust only that header. Otherwise merge
                // only headers carrying exactly the trusted id — an id-less header below a stamped one is not the
                // provider's, and a sender-supplied "dkim=pass" there must not upgrade the provider's "dkim=fail".
                let sameServer = trustedID == nil ? index == 0 : parsed.authservID == trustedID
                guard sameServer else { continue }
                entries.append(contentsOf: parsed.entries)
                rawParts.append(authHeaders[index])
            }
            results.apply(entries: entries, fromDomain: fromDomain)
        }

        // 2. ARC-Authentication-Results (newest instance first) for methods still missing.
        if !results.hasAllMethods, !arcHeaders.isEmpty {
            let parsedARC = arcHeaders.prefix(20).map(parseHeader).sorted { ($0.arcInstance ?? 0) > ($1.arcInstance ?? 0) }
            for parsed in parsedARC where !results.hasAllMethods {
                results.apply(entries: parsed.entries, fromDomain: fromDomain, onlyMissing: true)
            }
            rawParts.append(contentsOf: arcHeaders)
            if results.authservID == nil { results.authservID = parsedARC.first?.authservID }
        }

        // 3. Received-SPF as a last resort for SPF.
        if results.spf == nil, let receivedSPF {
            let token = receivedSPF.trimmingCharacters(in: .whitespacesAndNewlines)
                .prefix { !$0.isWhitespace && $0 != "(" && $0 != ";" }.lowercased()
            if let value = AuthResult(rawValue: token) {
                results.spf = value
                rawParts.append("Received-SPF: " + receivedSPF)
                if let range = receivedSPF.range(of: "envelope-from=", options: .caseInsensitive) ?? receivedSPF.range(of: "domain of ", options: .caseInsensitive) {
                    let rest = receivedSPF[range.upperBound...].prefix { !$0.isWhitespace && $0 != ";" }
                    let domain = rest.split(separator: "@").last.map { String($0).lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "\"<>")) }
                    if let domain, domain.contains(".") { results.spfDomain = domain }
                }
            }
        }

        results.rawHeader = rawParts.isEmpty ? nil : rawParts.joined(separator: "\n")
        return results
    }

    // MARK: - Helpers

    private var hasAllMethods: Bool { spf != nil && dkim != nil && dmarc != nil }

    /// Applies entries: SPF/DMARC take the first reported value (pass preferred over a later non-pass only when the
    /// first is an error state); DKIM prefers an aligned pass, then any pass, then the first signature; ARC takes the
    /// first value and only from the trusted header (never when filling missing methods from ARC-Authentication-Results).
    private mutating func apply(entries: [Entry], fromDomain: String?, onlyMissing: Bool = false) {
        var dkimEntries: [Entry] = []
        for entry in entries {
            switch entry.method {
            case "spf":
                if spf == nil || (!onlyMissing && Self.isErrorState(spf) && entry.result == .pass) {
                    spf = entry.result
                    spfDomain = Self.domain(fromMailbox: entry.properties["smtp.mailfrom"] ?? entry.properties["smtp.helo"] ?? "")
                }
            case "dmarc":
                if dmarc == nil {
                    dmarc = entry.result
                    if let from = entry.properties["header.from"], !from.isEmpty { dmarcFromDomain = from }
                }
            case "dkim":
                dkimEntries.append(entry)
            case "arc":
                if arc == nil, !onlyMissing { arc = entry.result }
            default:
                continue
            }
        }
        guard !dkimEntries.isEmpty, dkim == nil || !onlyMissing else { return }
        if dkim != nil && onlyMissing { return }
        let passing = dkimEntries.filter { $0.result == .pass }
        let passDomains = passing.compactMap(Self.dkimDomain(of:))
        if !passDomains.isEmpty { dkimPassDomains = passDomains }
        let aligned = passing.first { entry in
            guard let fromDomain, let d = Self.dkimDomain(of: entry) else { return false }
            return DomainAnalysis.registrableDomain(of: d) == fromDomain
        }
        if let aligned {
            dkim = .pass
            dkimDomain = Self.dkimDomain(of: aligned)
        } else if let firstPass = passing.first {
            dkim = .pass
            dkimDomain = Self.dkimDomain(of: firstPass)
        } else if dkim == nil, let first = dkimEntries.first {
            dkim = first.result
            dkimDomain = Self.dkimDomain(of: first)
        }
    }

    private static func isErrorState(_ result: AuthResult?) -> Bool {
        guard let result else { return false }
        switch result {
        case .temperror, .permerror, .unknown, .none: return true
        case .pass, .fail, .softfail, .neutral: return false
        }
    }

    private static func dkimDomain(of entry: Entry) -> String? {
        if let d = entry.properties["header.d"], !d.isEmpty { return d }
        if let i = entry.properties["header.i"], !i.isEmpty { return domain(fromMailbox: i) }
        return nil
    }

    private static func domain(fromMailbox value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: CharacterSet(charactersIn: "\"<> "))
        guard !trimmed.isEmpty else { return nil }
        if let at = trimmed.lastIndex(of: "@") { return String(trimmed[trimmed.index(after: at)...]).lowercased() }
        return trimmed.lowercased()
    }

    /// Removes `(...)` comments (nested allowed) and collapses folded whitespace.
    static func stripComments(_ value: String) -> String {
        var out = ""
        out.reserveCapacity(value.count)
        var depth = 0
        var inQuotes = false
        for ch in value {
            if inQuotes {
                out.append(ch)
                if ch == "\"" { inQuotes = false }
                continue
            }
            switch ch {
            case "\"" where depth == 0:
                inQuotes = true
                out.append(ch)
            case "(":
                depth += 1
            case ")":
                if depth > 0 { depth -= 1 } else { out.append(ch) }
            case "\r", "\n", "\t":
                if depth == 0 { out.append(" ") }
            default:
                if depth == 0 { out.append(ch) }
            }
        }
        return out
    }

    /// Whitespace tokenizer that keeps quoted strings intact.
    private static func tokenize(_ clause: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var inQuotes = false
        for ch in clause {
            if ch == "\"" { inQuotes.toggle(); current.append(ch); continue }
            if ch.isWhitespace, !inQuotes {
                if !current.isEmpty { tokens.append(current); current = "" }
            } else {
                current.append(ch)
            }
        }
        if !current.isEmpty { tokens.append(current) }
        return tokens
    }
}

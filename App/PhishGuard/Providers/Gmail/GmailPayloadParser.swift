import Foundation
import PhishCore

/// Converts a Gmail `users.messages.get?format=full` JSON payload into an in-memory `EmailMessage`.
/// Attachment *metadata* only is collected; attachment content is never fetched (ARCHITECTURE.md rule 2).
enum GmailPayloadParser {
    static let webBaseURL = "https://mail.google.com/mail/u/0/"
    /// Guards against pathological nesting in `payload.parts`.
    static let maxPartDepth = 32

    static func parseMessage(_ json: Data, accountID: UUID) throws -> EmailMessage {
        let message: GmailMessage
        do {
            message = try JSONDecoder().decode(GmailMessage.self, from: json)
        } catch {
            throw ProviderError.decoding("Gmail message: \(error.localizedDescription)")
        }
        return map(message, accountID: accountID)
    }

    static func map(_ message: GmailMessage, accountID: UUID) -> EmailMessage {
        let headers = (message.payload?.headers ?? []).map { EmailHeader(name: $0.name, value: $0.value) }
        func header(_ name: String) -> String? {
            headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
        }
        func addresses(_ name: String) -> [EmailAddress] {
            headers.filter { $0.name.caseInsensitiveCompare(name) == .orderedSame }.flatMap { EmailAddress.parse($0.value) }
        }

        var walk = MIMEWalk()
        if let payload = message.payload {
            walk.visit(payload, depth: 0)
        }

        let receivedAt = message.internalDate?.int64Value.map { Date(timeIntervalSince1970: TimeInterval($0) / 1000) }
            ?? header("Date").flatMap(parseRFC5322Date)
            ?? Date()

        return EmailMessage(
            provider: .gmail,
            accountID: accountID.uuidString,
            messageID: message.id,
            threadID: message.threadId,
            receivedAt: receivedAt,
            from: header("From").flatMap { EmailAddress.parse($0).first },
            sender: header("Sender").flatMap { EmailAddress.parse($0).first },
            replyTo: addresses("Reply-To"),
            to: addresses("To"),
            subject: header("Subject")?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "",
            textBody: walk.texts.isEmpty ? nil : walk.texts.joined(separator: "\n\n"),
            htmlBody: walk.htmls.isEmpty ? nil : walk.htmls.joined(separator: "\n"),
            headers: headers,
            attachments: walk.attachments,
            webLink: webLink(messageID: message.id, rfc822MessageID: header("Message-ID"))
        )
    }

    // MARK: - Web link

    /// `#search/rfc822msgid:<Message-ID>` is the only API-derivable link that opens reliably; `#all/<id>` only
    /// works inside an already-loaded Gmail tab and is the fallback when the header is missing.
    static func webLink(messageID: String, rfc822MessageID: String?) -> URL? {
        if let raw = rfc822MessageID?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty {
            let stripped = raw.trimmingCharacters(in: CharacterSet(charactersIn: "<> \t")).trimmingCharacters(in: .whitespaces)
            if !stripped.isEmpty,
               let encoded = stripped.addingPercentEncoding(withAllowedCharacters: rfc822MessageIDAllowed),
               let url = URL(string: "\(webBaseURL)#search/rfc822msgid:\(encoded)") {
                return url
            }
        }
        return URL(string: "\(webBaseURL)#all/\(messageID)")
    }

    private static let rfc822MessageIDAllowed: CharacterSet = {
        var set = CharacterSet.alphanumerics
        set.insert(charactersIn: "-._~@!$'*+=")
        return set
    }()

    // MARK: - Body decoding

    /// Decodes Gmail's base64url body encoding (no padding, `-`/`_` alphabet). Standard base64 and embedded
    /// whitespace are tolerated; an impossible length yields nil.
    static func decodeBase64URL(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .filter { !$0.isWhitespace }
        while base64.hasSuffix("=") { base64.removeLast() }
        if base64.isEmpty { return Data() }
        let remainder = base64.count % 4
        if remainder == 1 { return nil }
        if remainder > 0 { base64 += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: base64)
    }

    /// UTF-8 first (Gmail normally delivers text parts as UTF-8 whatever the part header claims), then the part's
    /// declared charset (when known), then ISO-8859-1 which accepts any byte.
    ///
    /// Exception: 7-bit stateful encodings (ISO-2022-JP/KR/CN, HZ-GB-2312) consist only of ASCII bytes plus escape
    /// sequences, so they are *always* valid UTF-8 and the UTF-8 pass would return the escapes verbatim. When such
    /// a charset is declared AND the body carries its escape marker, the declared charset is tried first; a body
    /// that was already converted to UTF-8 has no marker and still takes the UTF-8 path.
    static func decodeText(_ data: Data, charset: String?) -> String? {
        if let charset, let encoding = stringEncoding(forIANACharset: charset), encoding != .utf8,
           isSevenBitStateful(charset: charset), containsEscapeMarker(data, charset: charset),
           let text = String(data: data, encoding: encoding) {
            return text
        }
        if let utf8 = String(data: data, encoding: .utf8) { return utf8 }
        if let charset, let encoding = stringEncoding(forIANACharset: charset), encoding != .utf8,
           let text = String(data: data, encoding: encoding) {
            return text
        }
        return String(data: data, encoding: .isoLatin1)
    }

    /// ISO-2022-* and HZ: escape-sequence encodings whose bytes are all < 0x80.
    static func isSevenBitStateful(charset: String) -> Bool {
        let name = charset.trimmingCharacters(in: .whitespaces).lowercased()
        return name.hasPrefix("iso-2022-") || name.hasPrefix("iso2022") || name == "hz-gb-2312" || name == "hz"
    }

    /// ESC (0x1B) for ISO-2022-*, `~{` for HZ-GB-2312.
    static func containsEscapeMarker(_ data: Data, charset: String) -> Bool {
        let name = charset.trimmingCharacters(in: .whitespaces).lowercased()
        if name.hasPrefix("hz") {
            return data.range(of: Data([0x7E, 0x7B])) != nil
        }
        return data.contains(0x1B)
    }

    static func stringEncoding(forIANACharset name: String) -> String.Encoding? {
        let cfEncoding = CFStringConvertIANACharSetNameToEncoding(name.trimmingCharacters(in: .whitespaces) as CFString)
        guard cfEncoding != kCFStringEncodingInvalidId else { return nil }
        return String.Encoding(rawValue: CFStringConvertEncodingToNSStringEncoding(cfEncoding))
    }

    /// `charset` parameter of a `Content-Type` header value, unquoted.
    static func charset(fromContentType value: String?) -> String? {
        parameter("charset", in: value)
    }

    static func parameter(_ name: String, in headerValue: String?) -> String? {
        guard let headerValue else { return nil }
        for segment in headerValue.split(separator: ";").dropFirst() {
            let pair = segment.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard pair.count == 2, pair[0].caseInsensitiveCompare(name) == .orderedSame else { continue }
            let value = pair[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            return value.isEmpty ? nil : value
        }
        return nil
    }

    /// RFC 5322 `Date:` header (fallback when `internalDate` is missing). Trailing comments such as `(UTC)` are ignored.
    static func parseRFC5322Date(_ value: String) -> Date? {
        var text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if let paren = text.firstIndex(of: "(") {
            text = String(text[..<paren]).trimmingCharacters(in: .whitespaces)
        }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        for format in ["EEE, d MMM yyyy HH:mm:ss Z", "d MMM yyyy HH:mm:ss Z", "EEE, d MMM yyyy HH:mm Z", "d MMM yyyy HH:mm Z"] {
            formatter.dateFormat = format
            if let date = formatter.date(from: text) { return date }
        }
        return nil
    }

    // MARK: - MIME walk

    /// Depth-first walk over `payload` / `parts`: `multipart/alternative` contributes both its text/plain and
    /// text/html leaves, `multipart/mixed` / `multipart/related` (and `message/rfc822`) recurse; parts with a
    /// filename or `Content-Disposition: attachment` are recorded as attachments (metadata only).
    struct MIMEWalk {
        var texts: [String] = []
        var htmls: [String] = []
        var attachments: [EmailAttachment] = []

        mutating func visit(_ part: GmailMessagePart, depth: Int) {
            guard depth < GmailPayloadParser.maxPartDepth else { return }
            let mime = (part.mimeType ?? "").trimmingCharacters(in: .whitespaces).lowercased()
            let filename = (part.filename ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let contentType = partHeader(part, "Content-Type")
            let disposition = partHeader(part, "Content-Disposition")
            let isAttachmentDisposition = disposition?.lowercased().trimmingCharacters(in: .whitespaces).hasPrefix("attachment") ?? false

            if !filename.isEmpty || isAttachmentDisposition {
                let name = filename.isEmpty
                    ? (GmailPayloadParser.parameter("filename", in: disposition) ?? GmailPayloadParser.parameter("name", in: contentType) ?? "")
                    : filename
                attachments.append(EmailAttachment(filename: name, mimeType: part.mimeType, sizeBytes: part.body?.size))
                return
            }

            if mime.hasPrefix("multipart/") || mime == "message/rfc822" || !(part.parts ?? []).isEmpty {
                for child in part.parts ?? [] {
                    visit(child, depth: depth + 1)
                }
                return
            }

            if mime.hasPrefix("text/plain") || mime.hasPrefix("text/html") || mime.isEmpty {
                guard let encoded = part.body?.data, !encoded.isEmpty,
                      let data = GmailPayloadParser.decodeBase64URL(encoded),
                      let text = GmailPayloadParser.decodeText(data, charset: GmailPayloadParser.charset(fromContentType: contentType)),
                      !text.isEmpty else { return }
                if mime.hasPrefix("text/html") {
                    htmls.append(text)
                } else {
                    texts.append(text)
                }
                return
            }

            // Non-text leaf without a filename (rare): still an attachment when its body lives in a separate resource.
            if part.body?.attachmentId != nil {
                attachments.append(EmailAttachment(filename: "", mimeType: part.mimeType, sizeBytes: part.body?.size))
            }
        }

        private func partHeader(_ part: GmailMessagePart, _ name: String) -> String? {
            part.headers?.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
        }
    }
}

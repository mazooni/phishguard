import Foundation

/// Why a raw message could not be turned into an `EmailMessage`.
public enum MIMEParserError: Error, Sendable, Equatable {
    /// The header block held bytes but not one parseable `Name: value` field.
    case malformedHeaders
    /// A `Content-Transfer-Encoding` this parser does not implement (only thrown by
    /// `MIMEParser.decodeTransferEncoded(_:contentTransferEncoding:)`; the message path falls back to the raw bytes).
    case unsupportedEncoding(String)
    /// Nothing to parse.
    case truncated
}

/// Turns a raw RFC 822 / RFC 5322 message — what an IMAP `BODY.PEEK[]` fetch returns — into an in-memory
/// `EmailMessage`.
///
/// Three things shape every decision in here:
///
/// 1. **The input is hostile.** A message body is attacker-controlled. Nesting is capped, every scan is a single
///    forward pass over bytes, total size / part count / part size / header count all have hard caps, and no
///    input path can trap: the parser returns a best-effort `EmailMessage` or throws `MIMEParserError`.
/// 2. **Attachment content is never decoded or retained** (ARCHITECTURE.md rule 2). Only `EmailAttachment`
///    metadata — filename, mime type, decoded size computed by counting — is recorded, so a 20 MB PDF costs
///    nothing but the bytes already in the caller's buffer.
/// 3. **Nothing is fetched and nothing is logged.** `parse` is a pure function of its arguments.
public enum MIMEParser {
    /// Hard caps. Reached limits truncate or stop the walk; they never throw.
    public enum Limits {
        /// Bytes of a message examined; longer input is parsed as its prefix.
        public static let maxMessageBytes = 32 * 1024 * 1024
        /// Bytes of a header block examined (per entity, so nested parts get their own budget).
        public static let maxHeaderBlockBytes = 1024 * 1024
        /// Header fields kept per entity.
        public static let maxHeaderCount = 1_000
        /// Characters kept per header value.
        public static let maxHeaderValueCharacters = 16_000
        /// `multipart` nesting levels walked; deeper parts are left unparsed.
        public static let maxDepth = 10
        /// MIME parts visited in one message.
        public static let maxParts = 500
        /// `EmailAttachment` entries recorded.
        public static let maxAttachments = 100
        /// Characters kept for `textBody`, and again for `htmlBody`.
        public static let maxBodyCharacters = 400_000
        /// Bytes transfer-decoded for a single *text* part (attachments are never decoded).
        public static let maxDecodedTextBytes = 4 * 1024 * 1024
        /// Addresses kept per address header.
        public static let maxAddresses = 100
        /// Characters kept for `subject`.
        public static let maxSubjectCharacters = 2_000
        /// Characters kept for an attachment filename.
        public static let maxFilenameCharacters = 255
        /// Bytes of a header value scanned for RFC 2047 encoded-words.
        public static let maxEncodedWordInputBytes = 100_000
    }

    // MARK: - Public API

    /// Parses a raw RFC 822 / RFC 5322 message (headers + body, CRLF line endings, 8-bit safe) into an
    /// `EmailMessage`. Never fetches anything; attachment **content** is not decoded, only its metadata recorded.
    ///
    /// - Parameter receivedAt: the delivery time the caller already knows (IMAP `INTERNALDATE`). It wins over the
    ///   `Date:` header, which is sender-controlled. Use ``parse(rfc822:provider:accountID:messageID:webLink:)``
    ///   when there is no such time and the header should be used instead.
    /// - Throws: `MIMEParserError.truncated` for empty input, `.malformedHeaders` when the header block holds
    ///   bytes but no parseable field.
    public static func parse(
        rfc822 data: Data,
        provider: MailProvider,
        accountID: String,
        messageID: String,
        receivedAt: Date,
        webLink: URL? = nil
    ) throws -> EmailMessage {
        try parse(
            rfc822: data,
            provider: provider,
            accountID: accountID,
            messageID: messageID,
            receivedAt: Optional(receivedAt),
            webLink: webLink
        )
    }

    /// Same as ``parse(rfc822:provider:accountID:messageID:receivedAt:webLink:)`` but with no known delivery
    /// time: `receivedAt` comes from the `Date:` header, or from `Date()` when that header is missing or unusable.
    public static func parse(
        rfc822 data: Data,
        provider: MailProvider,
        accountID: String,
        messageID: String,
        webLink: URL? = nil
    ) throws -> EmailMessage {
        try parse(
            rfc822: data,
            provider: provider,
            accountID: accountID,
            messageID: messageID,
            receivedAt: nil,
            webLink: webLink
        )
    }

    /// Parses only a header block — what an IMAP `BODY.PEEK[HEADER]` fetch returns. Stops at the first blank line,
    /// so a full message may be passed in too. Values are *not* RFC 2047 decoded: `EmailMessage.headers` keeps the
    /// wire form, exactly as the Gmail and Graph providers do.
    public static func parseHeaders(_ data: Data) throws -> [EmailHeader] {
        let bytes = [UInt8](data.prefix(Limits.maxHeaderBlockBytes))
        let (block, _) = splitEntity(bytes[...])
        let headers = parseHeaderLines(block)
        if headers.isEmpty, block.contains(where: { !isLinearWhitespace($0) && $0 != 0x0A && $0 != 0x0D }) {
            throw MIMEParserError.malformedHeaders
        }
        return headers
    }

    /// Decodes RFC 2047 encoded-words (`=?UTF-8?B?...?=`) found in header values such as `Subject` and display
    /// names. Adjacent encoded-words are joined without the whitespace between them and, when they share a
    /// charset, their bytes are concatenated *before* decoding so a multi-byte character split across two words
    /// survives. Anything undecodable — unknown charset, broken base64, unterminated word — is passed through
    /// verbatim.
    public static func decodeEncodedWords(_ value: String) -> String {
        guard value.contains("=?") else { return value }
        let bytes = [UInt8](value.utf8)
        guard bytes.count <= Limits.maxEncodedWordInputBytes else {
            let head = EncodedWordDecoder.decode(Array(bytes.prefix(Limits.maxEncodedWordInputBytes)))
            let tail = String(decoding: bytes.dropFirst(Limits.maxEncodedWordInputBytes), as: UTF8.self)
            return head + tail
        }
        return EncodedWordDecoder.decode(bytes)
    }

    /// `Date:` header → `Date`, tolerating the malformed shapes real mail carries (missing seconds, two-digit
    /// years, `ctime` ordering, obsolete zone names, trailing `(PDT)` comments).
    public static func parseDate(_ headerValue: String) -> Date? {
        MIMEDateParser.parse(headerValue)
    }

    /// Reverses a `Content-Transfer-Encoding`. Provided for callers that hold a single decoded part; the message
    /// walk uses the internal, capped variant.
    /// - Throws: `MIMEParserError.unsupportedEncoding` for anything but base64, quoted-printable, 7bit, 8bit and binary.
    public static func decodeTransferEncoded(_ data: Data, contentTransferEncoding: String) throws -> Data {
        let name = normalizedTransferEncoding(contentTransferEncoding)
        let bytes = [UInt8](data)
        switch name {
        case "", "7bit", "8bit", "binary":
            return data
        case "base64":
            return Data(decodeBase64(bytes[...], limit: Limits.maxMessageBytes))
        case "quoted-printable":
            return Data(decodeQuotedPrintable(bytes[...], limit: Limits.maxMessageBytes))
        default:
            throw MIMEParserError.unsupportedEncoding(name)
        }
    }

    // MARK: - Message assembly

    private static func parse(
        rfc822 data: Data,
        provider: MailProvider,
        accountID: String,
        messageID: String,
        receivedAt: Date?,
        webLink: URL?
    ) throws -> EmailMessage {
        var bytes = [UInt8](data.prefix(Limits.maxMessageBytes))
        if bytes.count >= 3, bytes[0] == 0xEF, bytes[1] == 0xBB, bytes[2] == 0xBF {
            bytes.removeFirst(3)
        }
        guard !bytes.isEmpty else { throw MIMEParserError.truncated }

        let (headerBlock, body) = splitEntity(bytes[...])
        let headers = parseHeaderLines(headerBlock)
        if headers.isEmpty, headerBlock.contains(where: { !isLinearWhitespace($0) && $0 != 0x0A && $0 != 0x0D }) {
            throw MIMEParserError.malformedHeaders
        }

        var walker = Walker()
        walk(headers: headers, body: body, depth: 0, defaultType: "text/plain", into: &walker)

        func firstHeader(_ name: String) -> String? {
            headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
        }
        // The address list is parsed from the **wire form**, and only the display name of each result is RFC 2047
        // decoded. Decoding first would let `From: =?utf-8?B?<base64 of "X" <x@evil>>?=` inject angle brackets and
        // commas into the grammar, and the sender PhishGuard shows would be the attacker's choice.
        func addresses(_ name: String) -> [EmailAddress] {
            headers
                .filter { $0.name.caseInsensitiveCompare(name) == .orderedSame }
                .prefix(10)
                .flatMap { EmailAddress.parse($0.value) }
                .prefix(Limits.maxAddresses)
                .map { EmailAddress(name: $0.name.map(decodeEncodedWords), address: $0.address) }
        }

        let subject = String(
            decodeEncodedWords(firstHeader("Subject") ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .prefix(Limits.maxSubjectCharacters)
        )

        let text = walker.texts.isEmpty ? nil : walker.texts.joined(separator: "\n\n")
        let html = walker.htmls.isEmpty ? nil : walker.htmls.joined(separator: "\n")

        return EmailMessage(
            provider: provider,
            accountID: accountID,
            messageID: messageID,
            threadID: threadID(from: headers),
            receivedAt: receivedAt ?? firstHeader("Date").flatMap(MIMEDateParser.parse) ?? Date(),
            from: addresses("From").first,
            sender: addresses("Sender").first,
            replyTo: addresses("Reply-To"),
            to: addresses("To"),
            subject: subject,
            textBody: text,
            htmlBody: html,
            headers: headers,
            attachments: walker.attachments,
            webLink: webLink
        )
    }

    /// Thread root: the first `References` entry (the thread's originating message), else `In-Reply-To`, else this
    /// message's own `Message-ID` — so a message that starts a thread threads with its own replies.
    static func threadID(from headers: [EmailHeader]) -> String? {
        func firstID(_ name: String) -> String? {
            guard let value = headers.first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame })?.value
            else { return nil }
            guard let open = value.firstIndex(of: "<"), let close = value[open...].firstIndex(of: ">") else {
                let bare = value.trimmingCharacters(in: .whitespacesAndNewlines)
                return bare.isEmpty || bare.count > 998 ? nil : bare
            }
            let inner = String(value[value.index(after: open)..<close]).trimmingCharacters(in: .whitespaces)
            return inner.isEmpty ? nil : inner
        }
        return firstID("References") ?? firstID("In-Reply-To") ?? firstID("Message-ID")
    }

    // MARK: - Entity splitting

    /// Splits an entity into its header block (up to, excluding, the first blank line) and its body (everything
    /// after that line). A message with no blank line is all headers.
    static func splitEntity(_ bytes: ArraySlice<UInt8>) -> (header: ArraySlice<UInt8>, body: ArraySlice<UInt8>) {
        let end = bytes.endIndex
        var i = bytes.startIndex
        while i < end, i - bytes.startIndex < Limits.maxHeaderBlockBytes {
            var lineFeed = i
            while lineFeed < end, bytes[lineFeed] != 0x0A { lineFeed += 1 }
            var lineEnd = lineFeed
            if lineEnd > i, bytes[lineEnd - 1] == 0x0D { lineEnd -= 1 }
            if lineEnd == i {
                let bodyStart = lineFeed < end ? lineFeed + 1 : end
                return (bytes[bytes.startIndex..<i], bytes[bodyStart..<end])
            }
            if lineFeed >= end { break }
            i = lineFeed + 1
        }
        let headerEnd = min(end, bytes.startIndex + Limits.maxHeaderBlockBytes)
        return (bytes[bytes.startIndex..<headerEnd], bytes[end..<end])
    }

    /// Unfolds continuation lines, keeps duplicate fields in order, and skips — rather than rejects — lines that
    /// are not `Name: value`.
    static func parseHeaderLines(_ bytes: ArraySlice<UInt8>) -> [EmailHeader] {
        var headers: [EmailHeader] = []
        var currentName: String?
        var currentValue: [UInt8] = []
        let valueByteCap = Limits.maxHeaderValueCharacters * 4

        func flush() {
            defer {
                currentName = nil
                currentValue = []
            }
            guard let name = currentName, headers.count < Limits.maxHeaderCount else { return }
            let decoded = MIMECharset.decodeHeaderBytes(currentValue)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            headers.append(EmailHeader(name: name, value: String(decoded.prefix(Limits.maxHeaderValueCharacters))))
        }

        let end = bytes.endIndex
        var i = bytes.startIndex
        var isFirstLine = true
        while i < end, headers.count < Limits.maxHeaderCount {
            var lineFeed = i
            while lineFeed < end, bytes[lineFeed] != 0x0A { lineFeed += 1 }
            var lineEnd = lineFeed
            if lineEnd > i, bytes[lineEnd - 1] == 0x0D { lineEnd -= 1 }
            let line = bytes[i..<lineEnd]
            i = lineFeed < end ? lineFeed + 1 : end

            if line.isEmpty {
                isFirstLine = false
                continue
            }

            if let first = line.first, isLinearWhitespace(first) {
                // Folded continuation: RFC 5322 unfolding replaces the fold with the whitespace that followed it;
                // one space is enough and keeps adjacent encoded-words recognisable.
                if currentName != nil, currentValue.count < valueByteCap {
                    currentValue.append(0x20)
                    var k = line.startIndex
                    while k < line.endIndex, isLinearWhitespace(line[k]) { k += 1 }
                    currentValue.append(contentsOf: line[k..<line.endIndex].prefix(valueByteCap - currentValue.count))
                }
                isFirstLine = false
                continue
            }

            // An mbox "From " envelope line sometimes rides along on exported messages.
            if isFirstLine, line.starts(with: Array("From ".utf8)) {
                isFirstLine = false
                continue
            }
            isFirstLine = false

            guard let colon = line.firstIndex(of: 0x3A) else { continue }
            var nameEnd = colon
            while nameEnd > line.startIndex, isLinearWhitespace(line[nameEnd - 1]) { nameEnd -= 1 }
            let nameBytes = line[line.startIndex..<nameEnd]
            guard isValidFieldName(nameBytes) else { continue }

            flush()
            currentName = String(decoding: nameBytes, as: UTF8.self)
            var valueStart = colon + 1
            while valueStart < line.endIndex, isLinearWhitespace(line[valueStart]) { valueStart += 1 }
            currentValue = Array(line[valueStart..<line.endIndex].prefix(valueByteCap))
        }
        flush()
        return headers
    }

    /// RFC 5322 `ftext`: printable US-ASCII except `:`.
    static func isValidFieldName(_ bytes: ArraySlice<UInt8>) -> Bool {
        guard !bytes.isEmpty, bytes.count <= 200 else { return false }
        return bytes.allSatisfy { $0 >= 33 && $0 <= 126 && $0 != 0x3A }
    }

    static func isLinearWhitespace(_ byte: UInt8) -> Bool { byte == 0x20 || byte == 0x09 }

    // MARK: - Body walk

    /// Accumulates the pieces of a message as its parts are visited. `inout` rather than a reference type so the
    /// walk stays a plain value computation under strict concurrency.
    struct Walker {
        var texts: [String] = []
        var htmls: [String] = []
        var attachments: [EmailAttachment] = []
        var textCharacters = 0
        var htmlCharacters = 0
        var partCount = 0
    }

    static func walk(
        headers: [EmailHeader],
        body: ArraySlice<UInt8>,
        depth: Int,
        defaultType: String,
        into walker: inout Walker
    ) {
        func firstHeader(_ name: String) -> String? {
            headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
        }

        let rawContentType = firstHeader("Content-Type")
        let contentType = ParameterizedHeader.parse(rawContentType ?? defaultType)
        let (type, subtype) = splitMIMEType(contentType.value.isEmpty ? defaultType : contentType.value)
        let disposition = ParameterizedHeader.parse(firstHeader("Content-Disposition") ?? "")
        let transferEncoding = normalizedTransferEncoding(firstHeader("Content-Transfer-Encoding") ?? "")
        let filename = attachmentFilename(contentType: contentType, disposition: disposition)

        if type == "multipart" {
            // Past the nesting cap the part is left unparsed: a hostile message can nest boundaries forever, and
            // feeding the raw MIME source to the classifier as "body text" would be worse than nothing.
            guard depth < Limits.maxDepth else { return }
            let boundary = contentType.parameter("boundary") ?? ""
            guard !boundary.isEmpty else {
                // A multipart with no boundary is unsplittable; read the raw body as text so the classifier still
                // sees the wording rather than dropping the message.
                appendText(body, transferEncoding: transferEncoding, charset: nil, isHTML: false, into: &walker)
                return
            }
            let childDefault = subtype == "digest" ? "message/rfc822" : "text/plain"
            // RFC 2045 forbids a content-transfer-encoding on a multipart, but malware droppers base64 the whole
            // structure anyway; decoding first is the difference between seeing the parts and seeing nothing.
            let decodedBody = transferEncoding == "base64" || transferEncoding == "quoted-printable"
                ? decodeTransfer(body, encoding: transferEncoding, limit: Limits.maxMessageBytes)[...]
                : body
            for part in splitMultipart(decodedBody, boundary: boundary) {
                guard walker.partCount < Limits.maxParts else { return }
                walker.partCount += 1
                let (partHeaderBlock, partBody) = splitEntity(part)
                let partHeaders = parseHeaderLines(partHeaderBlock)
                walk(
                    headers: partHeaders,
                    body: partBody,
                    depth: depth + 1,
                    defaultType: childDefault,
                    into: &walker
                )
            }
            return
        }

        if type == "message" {
            // An attached message: record it as an attachment, and walk into it (unless it is explicitly an
            // attachment) because forwarded/bounced phishing hides its payload one level down.
            record(
                attachment: filename ?? "message.eml",
                mimeType: "\(type)/\(subtype)",
                size: decodedSize(body, encoding: transferEncoding),
                into: &walker
            )
            let walkable = subtype == "rfc822" || subtype == "global" || subtype == "news" || subtype == "partial"
            guard walkable, depth < Limits.maxDepth, disposition.value != "attachment" else { return }
            let decoded = decodeTransfer(body, encoding: transferEncoding, limit: Limits.maxDecodedTextBytes)
            let (nestedHeaderBlock, nestedBody) = splitEntity(decoded[...])
            let nestedHeaders = parseHeaderLines(nestedHeaderBlock)
            guard !nestedHeaders.isEmpty else { return }
            walker.partCount += 1
            walk(
                headers: nestedHeaders,
                body: nestedBody,
                depth: depth + 1,
                defaultType: "text/plain",
                into: &walker
            )
            return
        }

        let isDisplayableText = type == "text" && (subtype == "plain" || subtype == "html")
        let isAttachment = disposition.value == "attachment" || filename != nil

        if isDisplayableText, !isAttachment {
            appendText(
                body,
                transferEncoding: transferEncoding,
                charset: contentType.parameter("charset"),
                isHTML: subtype == "html",
                into: &walker
            )
            return
        }

        if isAttachment || type != "text" {
            record(
                attachment: filename ?? synthesizedFilename(type: type, subtype: subtype),
                mimeType: contentType.value.isEmpty ? nil : "\(type)/\(subtype)",
                size: decodedSize(body, encoding: transferEncoding),
                into: &walker
            )
        }
        // A `text/*` part that is neither plain nor html and has no filename (text/calendar, text/watch-html)
        // is deliberately dropped: it is neither the body the user reads nor a file they can open.
    }

    private static func appendText(
        _ body: ArraySlice<UInt8>,
        transferEncoding: String,
        charset: String?,
        isHTML: Bool,
        into walker: inout Walker
    ) {
        let budget = isHTML
            ? Limits.maxBodyCharacters - walker.htmlCharacters
            : Limits.maxBodyCharacters - walker.textCharacters
        guard budget > 0 else { return }
        let decoded = decodeTransfer(body, encoding: transferEncoding, limit: Limits.maxDecodedTextBytes)
        guard !decoded.isEmpty else { return }
        var text = sanitize(MIMECharset.decodeBody(decoded, declaredCharset: charset), limit: budget)
        // The CRLF in front of a boundary belongs to the delimiter, but the blank line most mailers leave before
        // it does not: trailing whitespace is never signal, and it would show up in every excerpt.
        while let last = text.last, last.isWhitespace { text.removeLast() }
        guard !text.isEmpty else { return }
        if isHTML {
            walker.htmls.append(text)
            walker.htmlCharacters += text.count
        } else {
            walker.texts.append(text)
            walker.textCharacters += text.count
        }
    }

    private static func record(attachment filename: String, mimeType: String?, size: Int, into walker: inout Walker) {
        guard walker.attachments.count < Limits.maxAttachments else { return }
        let name = String(filename.prefix(Limits.maxFilenameCharacters))
        walker.attachments.append(EmailAttachment(filename: name, mimeType: mimeType, sizeBytes: size))
    }

    /// `Content-Disposition: filename` wins over the `Content-Type: name` parameter (RFC 2183).
    static func attachmentFilename(contentType: ParameterizedHeader, disposition: ParameterizedHeader) -> String? {
        let raw = disposition.parameter("filename") ?? contentType.parameter("name")
        guard let raw else { return nil }
        let cleaned = sanitizeFilename(raw)
        return cleaned.isEmpty ? nil : cleaned
    }

    /// Strips the path components, control characters and line breaks a hostile filename can carry. The name is
    /// only ever displayed and extension-checked, never used to open a file, but it must not carry a fake
    /// directory or a right-to-left override into the UI.
    static func sanitizeFilename(_ value: String) -> String {
        var out = ""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "/", "\\":
                out = ""             // keep only the last path component
            case "\u{202E}", "\u{202D}", "\u{202B}", "\u{202A}", "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}":
                continue             // bidi overrides: "invoice\u{202E}fdp.exe" reads as "invoice exe.pdf"
            default:
                if scalar.value < 0x20 || scalar.value == 0x7F { continue }
                out.unicodeScalars.append(scalar)
            }
            if out.unicodeScalars.count > Limits.maxFilenameCharacters { break }
        }
        return out.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func synthesizedFilename(type: String, subtype: String) -> String {
        guard let ext = commonExtensions[subtype] else { return "attachment" }
        return "attachment.\(ext)"
    }

    private static let commonExtensions: [String: String] = [
        "pdf": "pdf", "png": "png", "jpeg": "jpg", "jpg": "jpg", "gif": "gif", "webp": "webp",
        "zip": "zip", "x-zip-compressed": "zip", "html": "html", "plain": "txt", "csv": "csv",
        "rtf": "rtf", "calendar": "ics", "svg+xml": "svg", "x-icon": "ico",
    ]

    static func splitMIMEType(_ value: String) -> (type: String, subtype: String) {
        let lowered = value.lowercased()
        guard let slash = lowered.firstIndex(of: "/") else {
            return (lowered.trimmingCharacters(in: .whitespaces), "")
        }
        return (
            String(lowered[..<slash]).trimmingCharacters(in: .whitespaces),
            String(lowered[lowered.index(after: slash)...]).trimmingCharacters(in: .whitespaces)
        )
    }

    /// Splits a multipart body on its boundary delimiter lines. Preamble (before the first delimiter) and
    /// epilogue (after the closing one) are dropped; a missing closing delimiter ends the last part at the end of
    /// the body. Matching is anchored to the start of a line, so the boundary string appearing inside a quoted
    /// string, an HTML attribute or mid-line prose is not a delimiter.
    static func splitMultipart(_ body: ArraySlice<UInt8>, boundary: String) -> [ArraySlice<UInt8>] {
        let marker = Array("--\(boundary)".utf8)
        guard marker.count > 2, marker.count < 1024 else { return [] }
        var parts: [ArraySlice<UInt8>] = []
        var partStart: Int?
        let end = body.endIndex
        var i = body.startIndex

        while i < end {
            var lineFeed = i
            while lineFeed < end, body[lineFeed] != 0x0A { lineFeed += 1 }
            var lineEnd = lineFeed
            if lineEnd > i, body[lineEnd - 1] == 0x0D { lineEnd -= 1 }
            let nextLine = lineFeed < end ? lineFeed + 1 : end

            if let kind = boundaryKind(body[i..<lineEnd], marker: marker) {
                if let start = partStart {
                    // The CRLF in front of the delimiter belongs to the delimiter, not to the part.
                    var contentEnd = i
                    if contentEnd > start, body[contentEnd - 1] == 0x0A {
                        contentEnd -= 1
                        if contentEnd > start, body[contentEnd - 1] == 0x0D { contentEnd -= 1 }
                    }
                    parts.append(body[start..<contentEnd])
                }
                if kind == .closing { return parts }
                guard parts.count < Limits.maxParts else { return parts }
                partStart = nextLine
            }
            i = nextLine
        }

        if let start = partStart, start < end {
            parts.append(body[start..<end])
        }
        return parts
    }

    private enum BoundaryKind { case delimiter, closing }

    private static func boundaryKind(_ line: ArraySlice<UInt8>, marker: [UInt8]) -> BoundaryKind? {
        guard line.count >= marker.count, line.starts(with: marker) else { return nil }
        var i = line.startIndex + marker.count
        var closing = false
        if i + 1 < line.endIndex, line[i] == 0x2D, line[i + 1] == 0x2D {
            closing = true
            i += 2
        }
        while i < line.endIndex, isLinearWhitespace(line[i]) { i += 1 }
        guard i == line.endIndex else { return nil }
        return closing ? .closing : .delimiter
    }

    // MARK: - Transfer decoding

    static func normalizedTransferEncoding(_ value: String) -> String {
        var text = value
        if let semicolon = text.firstIndex(of: ";") { text = String(text[..<semicolon]) }
        return text
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    /// Never throws: an unknown encoding is treated as `8bit`, because a body we cannot decode is still better
    /// read as bytes than dropped.
    static func decodeTransfer(_ bytes: ArraySlice<UInt8>, encoding: String, limit: Int) -> [UInt8] {
        switch encoding {
        case "base64": return decodeBase64(bytes, limit: limit)
        case "quoted-printable": return decodeQuotedPrintable(bytes, limit: limit)
        default: return Array(bytes.prefix(limit))
        }
    }

    /// Decoded byte count **without decoding**: attachment sizes are counted, never materialised.
    static func decodedSize(_ bytes: ArraySlice<UInt8>, encoding: String) -> Int {
        switch encoding {
        case "base64":
            var alphabet = 0
            for byte in bytes where base64Values[Int(byte)] >= 0 { alphabet += 1 }
            return alphabet * 3 / 4
        case "quoted-printable":
            var size = 0
            var i = bytes.startIndex
            let end = bytes.endIndex
            while i < end {
                if bytes[i] == 0x3D {
                    if i + 1 < end, bytes[i + 1] == 0x0A { i += 2; continue }
                    if i + 2 < end, bytes[i + 1] == 0x0D, bytes[i + 2] == 0x0A { i += 3; continue }
                    if i + 2 < end, hexValue(bytes[i + 1]) != nil, hexValue(bytes[i + 2]) != nil {
                        size += 1
                        i += 3
                        continue
                    }
                }
                size += 1
                i += 1
            }
            return size
        default:
            return bytes.count
        }
    }

    static let base64Values: [Int8] = {
        var table = [Int8](repeating: -1, count: 256)
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
        for (index, byte) in alphabet.enumerated() { table[Int(byte)] = Int8(index) }
        return table
    }()

    /// Linear, whitespace-tolerant base64. Characters outside the alphabet are skipped (mailers wrap, indent and
    /// occasionally corrupt these blocks); a trailing partial group is dropped rather than guessed at.
    static func decodeBase64(_ bytes: ArraySlice<UInt8>, limit: Int) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(min(bytes.count * 3 / 4 + 3, limit))
        var accumulator: UInt32 = 0
        var count = 0
        for byte in bytes {
            if byte == 0x3D { break }                     // padding ends the stream
            let value = base64Values[Int(byte)]
            if value < 0 { continue }
            accumulator = (accumulator << 6) | UInt32(UInt8(value))
            count += 1
            if count == 4 {
                out.append(UInt8((accumulator >> 16) & 0xFF))
                out.append(UInt8((accumulator >> 8) & 0xFF))
                out.append(UInt8(accumulator & 0xFF))
                accumulator = 0
                count = 0
                if out.count >= limit { return Array(out.prefix(limit)) }
            }
        }
        switch count {
        case 3:
            out.append(UInt8((accumulator >> 10) & 0xFF))
            out.append(UInt8((accumulator >> 2) & 0xFF))
        case 2:
            out.append(UInt8((accumulator >> 4) & 0xFF))
        default:
            break
        }
        return out.count > limit ? Array(out.prefix(limit)) : out
    }

    static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: return byte - 0x30
        case 0x41...0x46: return byte - 0x41 + 10
        case 0x61...0x66: return byte - 0x61 + 10
        default: return nil
        }
    }

    /// RFC 2045 quoted-printable: `=XX` escapes, `=` soft line breaks, and trailing whitespace stripped from every
    /// line (transport may have added it). A stray `=` is kept verbatim rather than swallowing the next bytes.
    static func decodeQuotedPrintable(_ bytes: ArraySlice<UInt8>, limit: Int) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(min(bytes.count, limit))
        var lineStart = 0

        func trimTrailingWhitespace() {
            while out.count > lineStart, let last = out.last, isLinearWhitespace(last) { out.removeLast() }
        }

        var i = bytes.startIndex
        let end = bytes.endIndex
        while i < end, out.count < limit {
            let byte = bytes[i]
            if byte == 0x3D {
                // Soft line break. Whitespace in front of the `=` is *not* end-of-line whitespace — it is content
                // the sender wrapped on — so it must survive.
                if i + 1 < end, bytes[i + 1] == 0x0A {
                    lineStart = out.count
                    i += 2
                    continue
                }
                if i + 2 < end, bytes[i + 1] == 0x0D, bytes[i + 2] == 0x0A {
                    lineStart = out.count
                    i += 3
                    continue
                }
                if i + 2 < end, let high = hexValue(bytes[i + 1]), let low = hexValue(bytes[i + 2]) {
                    out.append(high << 4 | low)
                    i += 3
                    continue
                }
                if i + 1 >= end { break }                 // truncated soft break at the very end
                out.append(byte)
                i += 1
                continue
            }
            if byte == 0x0A {
                trimTrailingWhitespace()
                out.append(0x0A)
                lineStart = out.count
                i += 1
                continue
            }
            if byte == 0x0D, i + 1 < end, bytes[i + 1] == 0x0A {
                trimTrailingWhitespace()
                out.append(0x0D)
                out.append(0x0A)
                lineStart = out.count
                i += 2
                continue
            }
            out.append(byte)
            i += 1
        }
        return out
    }

    // MARK: - Text hygiene

    /// Drops the C0 controls that carry no meaning in mail text (NUL especially, which truncates C string APIs
    /// downstream) and clamps the length.
    static func sanitize(_ text: String, limit: Int) -> String {
        var out = ""
        out.reserveCapacity(min(text.count, limit))
        var count = 0
        for scalar in text.unicodeScalars {
            if count >= limit { break }
            if scalar.value < 0x20, scalar != "\t", scalar != "\n", scalar != "\r" { continue }
            if scalar.value == 0x7F { continue }
            out.unicodeScalars.append(scalar)
            count += 1
        }
        return out
    }
}

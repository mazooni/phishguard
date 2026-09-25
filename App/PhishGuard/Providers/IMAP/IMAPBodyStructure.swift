import Foundation
import PhishCore

/// `Content-Disposition` as `BODYSTRUCTURE` reports it.
struct IMAPDisposition: Sendable, Equatable {
    var kind: String
    var parameters: [String: String]

    var filename: String? { parameters["filename"] ?? parameters["filename*"] }
    var isAttachment: Bool { kind.caseInsensitiveCompare("attachment") == .orderedSame }
}

/// One leaf part of a message.
struct IMAPBodyPart: Sendable, Equatable {
    /// Lowercased, e.g. "text".
    var type: String
    /// Lowercased, e.g. "plain".
    var subtype: String
    var parameters: [String: String]
    /// Lowercased transfer encoding, e.g. "base64".
    var encoding: String
    /// Size in bytes as the server reports it (i.e. still encoded).
    var size: Int
    var disposition: IMAPDisposition?

    var mimeType: String { "\(type)/\(subtype)" }
    var charset: String? { parameters["charset"] }
    var filename: String? { disposition?.filename ?? parameters["name"] }
    var isText: Bool { type == "text" }
    /// Inline text is body copy; anything with an `attachment` disposition or a filename is an attachment.
    var isAttachment: Bool {
        if disposition?.isAttachment == true { return true }
        return !isText && filename != nil
    }
}

/// A parsed `BODYSTRUCTURE`. Used to pick the text parts worth downloading and to record attachment metadata
/// without ever fetching an attachment's bytes.
indirect enum IMAPBodyStructure: Sendable, Equatable {
    case single(IMAPBodyPart)
    case multipart(subtype: String, parts: [IMAPBodyStructure])

    /// Parses the token list inside the `BODYSTRUCTURE (...)` value. Returns nil when the shape is not one the
    /// RFC describes; callers then fall back to fetching the whole message.
    static func parse(_ tokens: [IMAPToken]) -> IMAPBodyStructure? {
        guard let first = tokens.first else { return nil }

        if first.items != nil {
            var parts: [IMAPBodyStructure] = []
            var index = 0
            while index < tokens.count, let nested = tokens[index].items {
                guard let child = parse(nested) else { return nil }
                parts.append(child)
                index += 1
            }
            let subtype = (index < tokens.count ? tokens[index].stringValue : nil) ?? "mixed"
            guard !parts.isEmpty else { return nil }
            return .multipart(subtype: subtype.lowercased(), parts: parts)
        }

        guard tokens.count >= 7,
              let type = tokens[0].stringValue?.lowercased(),
              let subtype = tokens[1].stringValue?.lowercased() else { return nil }
        let parameters = Self.parameters(tokens[2])
        let encoding = tokens[5].stringValue?.lowercased() ?? "7bit"
        let size = tokens[6].intValue ?? 0

        // Where the extension fields start depends on the body type (RFC 3501 §7.4.2): basic bodies have no
        // extra field, text bodies carry a line count, message/rfc822 carries an envelope, a body and lines.
        var extensionStart = 7
        if type == "text" {
            extensionStart = 8
        } else if type == "message", subtype == "rfc822" {
            extensionStart = 10
        }
        // extensionStart points at body-fld-md5; the disposition is the field after it.
        var disposition: IMAPDisposition?
        let dispositionIndex = extensionStart + 1
        if dispositionIndex < tokens.count, let items = tokens[dispositionIndex].items, let kind = items.first?.stringValue {
            disposition = IMAPDisposition(kind: kind.lowercased(), parameters: Self.parameters(items.count > 1 ? items[1] : .atom("NIL")))
        }

        return .single(IMAPBodyPart(
            type: type, subtype: subtype, parameters: parameters,
            encoding: encoding, size: size, disposition: disposition
        ))
    }

    /// `("CHARSET" "UTF-8" "NAME" "x.pdf")` → `["charset": "UTF-8", "name": "x.pdf"]`, names lowercased.
    private static func parameters(_ token: IMAPToken) -> [String: String] {
        guard let items = token.items else { return [:] }
        var result: [String: String] = [:]
        var index = 0
        while index + 1 < items.count {
            if let name = items[index].stringValue?.lowercased(), let value = items[index + 1].stringValue {
                result[name] = value
            }
            index += 2
        }
        return result
    }

    /// Every leaf with the part number `BODY.PEEK[<number>]` expects.
    /// A single-part message's body is part "1"; multipart children are "1", "2", "2.1", …
    func leaves(prefix: String = "") -> [(number: String, part: IMAPBodyPart)] {
        switch self {
        case .single(let part):
            return [(prefix.isEmpty ? "1" : prefix, part)]
        case .multipart(_, let parts):
            var result: [(number: String, part: IMAPBodyPart)] = []
            for (index, child) in parts.enumerated() {
                let number = prefix.isEmpty ? "\(index + 1)" : "\(prefix).\(index + 1)"
                result.append(contentsOf: child.leaves(prefix: number))
            }
            return result
        }
    }

    /// Attachment metadata only — the bytes are never fetched (ARCHITECTURE.md rule 2).
    var attachments: [EmailAttachment] {
        leaves().compactMap { leaf in
            guard leaf.part.isAttachment else { return nil }
            return EmailAttachment(
                filename: MIMEParser.decodeEncodedWords(leaf.part.filename ?? "attachment"),
                mimeType: leaf.part.mimeType,
                sizeBytes: leaf.part.encoding == "base64" ? (leaf.part.size / 4) * 3 : leaf.part.size
            )
        }
    }

    /// The first inline `text/plain` and `text/html` leaves — the only parts worth downloading for
    /// classification when the whole message is too big to fetch.
    func preferredTextParts() -> (plain: (number: String, part: IMAPBodyPart)?, html: (number: String, part: IMAPBodyPart)?) {
        var plain: (number: String, part: IMAPBodyPart)?
        var html: (number: String, part: IMAPBodyPart)?
        for leaf in leaves() where leaf.part.isText && !leaf.part.isAttachment {
            if leaf.part.subtype == "html" {
                if html == nil { html = leaf }
            } else if plain == nil {
                plain = leaf
            }
        }
        return (plain, html)
    }
}

/// Decodes one fetched MIME part: `Content-Transfer-Encoding` first, then the part's charset.
/// Only used for the large-message path, where PhishGuard fetches individual text parts instead of the whole
/// message so an attachment's bytes are never downloaded.
enum IMAPPartDecoder {
    static func decode(_ data: Data, encoding: String, charset: String?) -> String? {
        let raw: Data
        switch encoding.lowercased() {
        case "base64":
            guard let decoded = Data(base64Encoded: data, options: [.ignoreUnknownCharacters]) else { return nil }
            raw = decoded
        case "quoted-printable":
            raw = decodeQuotedPrintable(data)
        default:
            raw = data
        }
        return string(from: raw, charset: charset)
    }

    static func decodeQuotedPrintable(_ data: Data) -> Data {
        let bytes = [UInt8](data)
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            guard byte == UInt8(ascii: "=") else {
                out.append(byte)
                index += 1
                continue
            }
            if index + 2 < bytes.count, let high = hex(bytes[index + 1]), let low = hex(bytes[index + 2]) {
                out.append(high << 4 | low)
                index += 3
                continue
            }
            if index + 2 < bytes.count, bytes[index + 1] == 0x0D, bytes[index + 2] == 0x0A { index += 3; continue }
            if index + 1 < bytes.count, bytes[index + 1] == 0x0A { index += 2; continue }
            index += 1
        }
        return Data(out)
    }

    private static func hex(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: return byte - 0x30
        case 0x41...0x46: return byte - 0x41 + 10
        case 0x61...0x66: return byte - 0x61 + 10
        default: return nil
        }
    }

    static func string(from data: Data, charset: String?) -> String? {
        let name = (charset ?? "utf-8").trimmingCharacters(in: CharacterSet(charactersIn: "\" ")).lowercased()
        let encoding: String.Encoding
        switch name {
        case "utf-8", "utf8", "us-ascii", "ascii", "": encoding = .utf8
        case "iso-8859-1", "latin1", "iso8859-1": encoding = .isoLatin1
        case "iso-8859-2": encoding = .isoLatin2
        case "windows-1252", "cp1252": encoding = .windowsCP1252
        case "windows-1251", "cp1251": encoding = .windowsCP1251
        case "utf-16": encoding = .utf16
        default: encoding = .utf8
        }
        if let text = String(data: data, encoding: encoding) { return text }
        return String(data: data, encoding: .isoLatin1)
    }
}

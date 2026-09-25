import Foundation
import PhishCore

/// Maps a Microsoft Graph `message` resource (JSON) to an `EmailMessage`.
///
/// Bodies stay as delivered: an HTML body goes to `htmlBody` (PhishCore's `HTMLTextExtractor` derives the plain
/// text downstream), a text body to `textBody`. Nothing here is persisted.
enum GraphMessageMapper {
    static func map(_ json: Data, accountID: UUID) throws -> EmailMessage {
        let message: GraphMessage
        do {
            message = try GraphClient.decoder.decode(GraphMessage.self, from: json)
        } catch {
            throw ProviderError.decoding("Graph message: \(error)")
        }
        return try map(message, accountID: accountID, attachments: message.attachments.map(mapAttachments))
    }

    /// `attachments` overrides whatever the message JSON embedded (the sync lists them with a separate request).
    static func map(_ message: GraphMessage, accountID: UUID, attachments: [EmailAttachment]? = nil) throws -> EmailMessage {
        guard let receivedAt = message.receivedDateTime else {
            throw ProviderError.decoding("Graph message \(message.id) has no receivedDateTime")
        }

        var headers = (message.internetMessageHeaders ?? []).map { EmailHeader(name: $0.name, value: $0.value ?? "") }
        if let internetMessageId = message.internetMessageId?.trimmingCharacters(in: .whitespacesAndNewlines),
           !internetMessageId.isEmpty,
           !headers.contains(where: { $0.name.caseInsensitiveCompare("Message-ID") == .orderedSame }) {
            headers.append(EmailHeader(name: "Message-ID", value: internetMessageId))
        }

        let isHTML = message.body?.contentType?.lowercased() == "html"
        let content = message.body?.content

        return EmailMessage(
            provider: .microsoft,
            accountID: accountID.uuidString,
            messageID: message.id,
            threadID: message.conversationId,
            receivedAt: receivedAt,
            from: address(message.from),
            sender: address(message.sender),
            replyTo: (message.replyTo ?? []).compactMap(address),
            to: (message.toRecipients ?? []).compactMap(address),
            subject: message.subject ?? "",
            textBody: isHTML ? nil : content,
            htmlBody: isHTML ? content : nil,
            headers: headers,
            attachments: attachments ?? [],
            webLink: message.webLink.flatMap { URL(string: $0) }
        )
    }

    /// Inline parts (embedded images) are not user-visible attachments and are dropped.
    static func mapAttachments(_ items: [GraphAttachment]) -> [EmailAttachment] {
        items.compactMap { item in
            if item.isInline == true { return nil }
            let name = item.name?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return EmailAttachment(filename: name, mimeType: item.contentType, sizeBytes: item.size)
        }
    }

    static func address(_ recipient: GraphRecipient?) -> EmailAddress? {
        guard let raw = recipient?.emailAddress?.address?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return nil
        }
        return EmailAddress(name: recipient?.emailAddress?.name, address: raw)
    }
}

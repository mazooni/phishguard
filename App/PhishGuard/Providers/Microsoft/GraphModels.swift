import Foundation

// Decodable views of the Microsoft Graph resources the provider touches. Every field is optional except `id`
// because delta rounds return partial objects (update echoes, `@removed` tombstones).

struct GraphEmailAddress: Decodable, Sendable {
    var name: String?
    var address: String?
}

struct GraphRecipient: Decodable, Sendable {
    var emailAddress: GraphEmailAddress?
}

struct GraphItemBody: Decodable, Sendable {
    var contentType: String?
    var content: String?
}

struct GraphInternetMessageHeader: Decodable, Sendable {
    var name: String
    var value: String?
}

struct GraphRemoved: Decodable, Sendable {
    var reason: String?
}

/// Attachment **metadata** only (`contentBytes` is never selected).
struct GraphAttachment: Decodable, Sendable {
    var name: String?
    var contentType: String?
    var size: Int?
    var isInline: Bool?
}

struct GraphMessage: Decodable, Sendable {
    var id: String
    var removed: GraphRemoved?
    var receivedDateTime: Date?
    var subject: String?
    var from: GraphRecipient?
    var sender: GraphRecipient?
    var replyTo: [GraphRecipient]?
    var toRecipients: [GraphRecipient]?
    var hasAttachments: Bool?
    var webLink: String?
    var internetMessageId: String?
    var conversationId: String?
    var isDraft: Bool?
    var parentFolderId: String?
    var body: GraphItemBody?
    var internetMessageHeaders: [GraphInternetMessageHeader]?
    /// Present only when the JSON embeds attachments (`$expand=attachments`); the sync fetches them separately.
    var attachments: [GraphAttachment]?

    enum CodingKeys: String, CodingKey {
        case id, receivedDateTime, subject, from, sender, replyTo, toRecipients, hasAttachments, webLink
        case internetMessageId, conversationId, isDraft, parentFolderId, body, internetMessageHeaders, attachments
        case removed = "@removed"
    }

    /// True for entries the sync must skip: tombstones, drafts and update echoes without a received date.
    var isTombstoneOrDraft: Bool {
        removed != nil || isDraft == true || receivedDateTime == nil
    }
}

struct GraphCollectionPage<Item: Decodable & Sendable>: Decodable, Sendable {
    var value: [Item]
    var nextLink: String?
    var deltaLink: String?

    enum CodingKeys: String, CodingKey {
        case value
        case nextLink = "@odata.nextLink"
        case deltaLink = "@odata.deltaLink"
    }
}

struct GraphSubscription: Decodable, Sendable {
    var id: String?
    var resource: String?
    var changeType: String?
    var notificationUrl: String?
    var expirationDateTime: String?
    var clientState: String?
}

struct GraphUser: Decodable, Sendable {
    var id: String?
    var mail: String?
    var userPrincipalName: String?
    var displayName: String?

    /// Graph's `mail` is nil for some consumer accounts; `userPrincipalName` is the login address then.
    var emailAddress: String? {
        [mail, userPrincipalName]
            .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .first { !$0.isEmpty }
    }
}

/// Graph emits ISO 8601 UTC timestamps with up to seven fractional digits (`2026-09-21T09:15:30.1234567Z`),
/// sometimes without a fraction, sometimes with a `+00:00` offset. Foundation's parser accepts at most three digits.
enum GraphDate {
    // `Date.ISO8601FormatStyle` is a Sendable value type (unlike `ISO8601DateFormatter`), so it can be shared.
    private static let fractionalStyle = Date.ISO8601FormatStyle(includingFractionalSeconds: true)
    private static let plainStyle = Date.ISO8601FormatStyle()

    static func parse(_ raw: String) -> Date? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        let normalized = normalizeFraction(text)
        if let date = try? fractionalStyle.parse(normalized) { return date }
        return try? plainStyle.parse(normalized)
    }

    /// Rewrites any fractional-seconds part to exactly three digits (Foundation accepts only milliseconds).
    static func normalizeFraction(_ text: String) -> String {
        guard let dot = text.lastIndex(of: ".") else { return text }
        let afterDot = text.index(after: dot)
        let end = text[afterDot...].firstIndex { !$0.isNumber } ?? text.endIndex
        let digits = text[afterDot..<end]
        guard !digits.isEmpty else { return text }
        let milliseconds = String(digits.prefix(3)).padding(toLength: 3, withPad: "0", startingAt: 0)
        return String(text[..<dot]) + "." + milliseconds + String(text[end...])
    }

    /// UTC ISO 8601 with milliseconds, the form Graph accepts for `expirationDateTime` and `$filter` values.
    static func string(from date: Date) -> String {
        date.formatted(fractionalStyle)
    }
}

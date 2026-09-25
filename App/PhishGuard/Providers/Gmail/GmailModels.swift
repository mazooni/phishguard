import Foundation

// Decodable views of the Gmail REST responses PhishGuard consumes. They are in-memory only and never persisted
// (ARCHITECTURE.md rule 2). Google encodes int64/uint64 fields (historyId, internalDate, expiration) as JSON
// strings; `GmailInt64String` decodes them leniently in case a number slips through.

/// A Gmail int64/uint64 field: normally a decimal string, tolerated as a JSON number.
struct GmailInt64String: Decodable, Sendable, Equatable {
    var stringValue: String

    init(_ stringValue: String) {
        self.stringValue = stringValue
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let string = try? container.decode(String.self) {
            stringValue = string
        } else if let integer = try? container.decode(Int64.self) {
            stringValue = String(integer)
        } else if let double = try? container.decode(Double.self) {
            stringValue = String(Int64(double))
        } else {
            throw DecodingError.typeMismatch(
                String.self,
                DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Expected an int64 string")
            )
        }
    }

    var int64Value: Int64? { Int64(stringValue) }
}

/// `users.getProfile`
struct GmailProfile: Decodable, Sendable {
    var emailAddress: String
    var historyId: GmailInt64String
    var messagesTotal: Int?
}

/// `users.history.list` page
struct GmailHistoryPage: Decodable, Sendable {
    var history: [GmailHistoryRecord]?
    var nextPageToken: String?
    /// The mailbox's current history id (the new cursor once every page was consumed).
    var historyId: GmailInt64String?
}

struct GmailHistoryRecord: Decodable, Sendable {
    /// The mailbox sequence id of this record; a valid `startHistoryId` for resuming after it.
    var id: GmailInt64String?
    var messagesAdded: [GmailMessageAdded]?
}

struct GmailMessageAdded: Decodable, Sendable {
    var message: GmailMessageStub
}

/// Message reference as returned by history/list responses (only `id` is guaranteed).
struct GmailMessageStub: Decodable, Sendable {
    var id: String
    var threadId: String?
    var labelIds: [String]?
}

/// `users.messages.list` page
struct GmailMessageListPage: Decodable, Sendable {
    var messages: [GmailMessageStub]?
    var nextPageToken: String?
    var resultSizeEstimate: Int?
}

/// `users.watch` request body
struct GmailWatchRequest: Encodable, Sendable {
    var topicName: String
    var labelIds: [String]
    var labelFilterBehavior: String
}

/// `users.watch` response
struct GmailWatchResponse: Decodable, Sendable {
    var historyId: GmailInt64String?
    /// Epoch milliseconds.
    var expiration: GmailInt64String
}

/// `users.messages.get?format=full`
struct GmailMessage: Decodable, Sendable {
    var id: String
    var threadId: String?
    var labelIds: [String]?
    var historyId: GmailInt64String?
    /// Epoch milliseconds of Gmail's internal receipt time (orders the inbox).
    var internalDate: GmailInt64String?
    var payload: GmailMessagePart?
}

struct GmailMessagePart: Decodable, Sendable {
    var partId: String?
    var mimeType: String?
    /// Only present when the part is an attachment.
    var filename: String?
    var headers: [GmailHeaderField]?
    var body: GmailMessagePartBody?
    var parts: [GmailMessagePart]?
}

struct GmailHeaderField: Decodable, Sendable {
    var name: String
    var value: String
}

struct GmailMessagePartBody: Decodable, Sendable {
    /// Present when the content lives in a separate attachment resource (never fetched by PhishGuard).
    var attachmentId: String?
    var size: Int?
    /// base64url-encoded content; empty/absent for container parts.
    var data: String?
}

/// Google API error envelope: `{ "error": { "code", "message", "status", "errors": [{ "domain", "reason", "message" }] } }`
struct GmailErrorEnvelope: Decodable, Sendable {
    var error: GmailErrorBody
}

struct GmailErrorBody: Decodable, Sendable {
    var code: Int?
    var message: String?
    var status: String?
    var errors: [GmailErrorDetail]?
}

struct GmailErrorDetail: Decodable, Sendable {
    var domain: String?
    var reason: String?
    var message: String?
}

import Foundation

/// A fetched email held **in memory only** while it is being classified.
/// Intentionally NOT `Codable`: nothing in the app may serialize bodies or raw messages.
public struct EmailMessage: Sendable {
    public var provider: MailProvider
    /// App-local `LinkedAccount` id (UUID string).
    public var accountID: String
    /// Provider message id (Gmail message id / Graph message id).
    public var messageID: String
    public var threadID: String?
    public var receivedAt: Date
    public var from: EmailAddress?
    /// The "Sender:" header if present.
    public var sender: EmailAddress?
    public var replyTo: [EmailAddress]
    public var to: [EmailAddress]
    public var subject: String
    public var textBody: String?
    public var htmlBody: String?
    /// All headers in original order.
    public var headers: [EmailHeader]
    public var attachments: [EmailAttachment]
    /// Opens the mail in the provider's web UI.
    public var webLink: URL?

    public init(
        provider: MailProvider,
        accountID: String,
        messageID: String,
        threadID: String? = nil,
        receivedAt: Date,
        from: EmailAddress? = nil,
        sender: EmailAddress? = nil,
        replyTo: [EmailAddress] = [],
        to: [EmailAddress] = [],
        subject: String = "",
        textBody: String? = nil,
        htmlBody: String? = nil,
        headers: [EmailHeader] = [],
        attachments: [EmailAttachment] = [],
        webLink: URL? = nil
    ) {
        self.provider = provider
        self.accountID = accountID
        self.messageID = messageID
        self.threadID = threadID
        self.receivedAt = receivedAt
        self.from = from
        self.sender = sender
        self.replyTo = replyTo
        self.to = to
        self.subject = subject
        self.textBody = textBody
        self.htmlBody = htmlBody
        self.headers = headers
        self.attachments = attachments
        self.webLink = webLink
    }

    /// First header value whose name matches case-insensitively.
    public func header(_ name: String) -> String? {
        headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    /// All header values whose name matches case-insensitively, in original order.
    public func headers(_ name: String) -> [String] {
        headers.filter { $0.name.caseInsensitiveCompare(name) == .orderedSame }.map(\.value)
    }

    /// Stable key used by the app's `ProcessedMessage` table: "\(provider):\(accountID):\(messageID)".
    public var dedupeKey: String { "\(provider.rawValue):\(accountID):\(messageID)" }
}

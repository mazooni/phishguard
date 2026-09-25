import Foundation

/// The mail providers PhishGuard can watch. Raw values are persisted (SwiftData `providerRaw`) and
/// used in the relay push payload, so they must never change.
public enum MailProvider: String, Codable, Sendable, CaseIterable, Hashable {
    case gmail
    case microsoft
    /// Any other mailbox reached over IMAP (iCloud, Yahoo, Fastmail, AOL, GMX, Zoho, a custom domain).
    /// Read-only by construction: the client only ever issues `EXAMINE` and `.PEEK` fetches.
    case imap

    /// User-facing name.
    public var displayName: String {
        switch self {
        case .gmail: return "Gmail"
        case .microsoft: return "Outlook / Hotmail"
        case .imap: return "IMAP"
        }
    }

    /// True when the provider can notify the relay of new mail (Gmail `users.watch`, Graph subscriptions).
    /// IMAP has no webhook, so those accounts are scanned in the foreground and by background refresh only;
    /// callers must not register them with the relay or report a missing subscription as an error.
    public var supportsPushSubscriptions: Bool {
        switch self {
        case .gmail, .microsoft: return true
        case .imap: return false
        }
    }
}

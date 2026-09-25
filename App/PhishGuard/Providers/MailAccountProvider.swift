import Foundation
import PhishCore
import UIKit

/// Opaque incremental-sync position. Gmail: `historyId`; Microsoft Graph: `deltaLink`.
struct SyncCursor: Codable, Sendable, Equatable {
    var opaque: String

    init(opaque: String) {
        self.opaque = opaque
    }
}

/// Messages received since the cursor. `cursorWasReset` is true when the provider had to fall back to a
/// lookback query (expired historyId / deltaLink), so callers should not assume gap-free delivery.
struct FetchResult: Sendable {
    var messages: [EmailMessage]
    var cursor: SyncCursor
    var cursorWasReset: Bool

    init(messages: [EmailMessage], cursor: SyncCursor, cursorWasReset: Bool = false) {
        self.messages = messages
        self.cursor = cursor
        self.cursorWasReset = cursorWasReset
    }
}

/// State of the provider-side push subscription (Gmail `users.watch` / Graph subscription) that rings the relay.
struct PushSubscriptionState: Codable, Sendable, Equatable {
    var id: String
    var expiresAt: Date
    var relayAccountKey: String

    init(id: String, expiresAt: Date, relayAccountKey: String) {
        self.id = id
        self.expiresAt = expiresAt
        self.relayAccountKey = relayAccountKey
    }
}

/// Result of an interactive sign-in.
struct SignedInIdentity: Sendable, Equatable {
    var providerAccountID: String
    var email: String
    var displayName: String?

    init(providerAccountID: String, email: String, displayName: String? = nil) {
        self.providerAccountID = providerAccountID
        self.email = email
        self.displayName = displayName
    }
}

enum ProviderError: Error, LocalizedError, Sendable {
    case notImplemented(String)
    case notConfigured(String)
    case notAuthenticated
    case cancelled
    case network(String)
    case http(status: Int, message: String?)
    case invalidCursor
    case rateLimited(retryAfter: TimeInterval?)
    case decoding(String)
    /// The provider has no push mechanism at all (IMAP). Expected, not a failure: the caller must not report it
    /// as a scan error and must not retry it as if it were transient.
    case pushNotSupported

    var errorDescription: String? {
        switch self {
        case .notImplemented(let what): return "Not implemented: \(what)"
        case .notConfigured(let what): return "Missing configuration: \(what)"
        case .notAuthenticated: return "The account needs to be signed in again."
        case .cancelled: return "Sign-in was cancelled."
        case .network(let message): return "Network error: \(message)"
        case .http(let status, let message): return "HTTP \(status)\(message.map { ": \($0)" } ?? "")"
        case .invalidCursor: return "The sync cursor is no longer valid."
        case .rateLimited(let retryAfter): return "Rate limited\(retryAfter.map { ", retry after \(Int($0)) s" } ?? "")."
        case .decoding(let message): return "Could not decode the provider response: \(message)"
        case .pushNotSupported: return "This provider cannot notify PhishGuard of new mail; it is scanned when the app opens and in the background."
        }
    }
}

/// A mail provider integration. Implementations must request **read-only** scopes only
/// (Gmail: gmail.readonly; Graph: Mail.Read, User.Read, offline_access) and keep tokens in the Keychain.
protocol MailAccountProvider: Sendable {
    var provider: MailProvider { get }

    /// Interactive OAuth sign-in. Returns the identity; the caller creates the `LinkedAccount`.
    @MainActor func signIn(presenting: UIViewController) async throws -> SignedInIdentity

    /// Revokes/forgets tokens for the account.
    func signOut(accountID: UUID) async throws

    /// Binds the identity returned by the most recent `signIn` to the `LinkedAccount` id the caller created or
    /// reused for it. Called by `AccountLinker` synchronously after `signIn`, before the first scan. Must REPLACE any
    /// credentials already stored for `accountID` (re-sign-in after a revoked/expired grant) and drop cached state,
    /// and must never bind a sign-in for a different mailbox. The default implementation does nothing.
    func linkAccount(accountID: UUID, identity: SignedInIdentity) async throws

    /// Fetches messages received after `cursor` (or within `lookback` seconds when there is no cursor / it expired).
    func fetchNewMessages(accountID: UUID, cursor: SyncCursor?, lookback: TimeInterval) async throws -> FetchResult

    /// Like `fetchNewMessages(accountID:cursor:lookback:)`, but message ids for which `isProcessed` returns true
    /// are dropped BEFORE their bodies are downloaded and do not count toward the per-fetch cap, so a backlog is not
    /// re-downloaded scan after scan. The default implementation ignores the predicate.
    func fetchNewMessages(
        accountID: UUID,
        cursor: SyncCursor?,
        lookback: TimeInterval,
        isProcessed: @escaping @Sendable (_ messageID: String) -> Bool
    ) async throws -> FetchResult

    /// Creates or renews the provider push subscription that notifies the relay. Called by every scan when the
    /// current subscription is missing or expires within 24 h, and whenever the coordinator forces a renewal
    /// (Graph lifecycle notification, cursor reset). Implementations must contact the provider on every call
    /// and never short-circuit on the stored expiry: the caller already applies the 24 h gate.
    func ensurePushSubscription(accountID: UUID, relay: RelayConfig, current: PushSubscriptionState?) async throws -> PushSubscriptionState

    /// Delivers an incoming URL from SwiftUI's `onOpenURL` (OAuth redirects, e.g. MSAL broker callbacks).
    /// Return true when this provider consumed the URL. The default implementation returns false.
    @MainActor func handleRedirectURL(_ url: URL) -> Bool
}

extension MailAccountProvider {
    func linkAccount(accountID: UUID, identity: SignedInIdentity) async throws {}

    func fetchNewMessages(
        accountID: UUID,
        cursor: SyncCursor?,
        lookback: TimeInterval,
        isProcessed: @escaping @Sendable (_ messageID: String) -> Bool
    ) async throws -> FetchResult {
        try await fetchNewMessages(accountID: accountID, cursor: cursor, lookback: lookback)
    }

    @MainActor func handleRedirectURL(_ url: URL) -> Bool { false }
}

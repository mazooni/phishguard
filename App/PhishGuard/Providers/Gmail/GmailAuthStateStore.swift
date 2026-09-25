import AppAuth
import Foundation
import OSLog
import Synchronization

// AppAuth glue for GmailProvider: the in-flight sign-in session, `OIDAuthState` (un)archiving, the per-account
// auth-state box that re-saves refreshed tokens, and AppAuth → ProviderError mapping.

/// Holds the `OIDExternalUserAgentSession` of the sign-in in progress. AppAuth requires it to stay alive until the
/// `ASWebAuthenticationSession` callback fires (otherwise the flow silently dies). It is UI state, so main-actor.
@MainActor
final class GmailAuthFlow {
    private(set) var session: (any OIDExternalUserAgentSession)?
    private var activeToken: UUID?

    nonisolated init() {}

    var isActive: Bool { session != nil }

    func begin(_ session: any OIDExternalUserAgentSession, token: UUID) {
        self.session = session
        activeToken = token
    }

    /// Releases the session, but only when `token` still identifies the active flow.
    func finish(token: UUID) {
        guard activeToken == token else { return }
        session = nil
        activeToken = nil
    }

    /// Cancels a stale flow (its callback then fails with a "program cancelled" error).
    func cancelActive() {
        session?.cancel()
        session = nil
        activeToken = nil
    }
}

/// What `signIn` keeps from the AppAuth callback. Only `Sendable` values cross from the callback into the actor;
/// the `OIDAuthState` itself travels as its secure-coding archive.
struct GmailAuthorizationOutcome: Sendable {
    var archivedState: Data
    var accessToken: String
    var idToken: String?
}

/// A completed sign-in that has not yet been attached to a `LinkedAccount` id (the caller creates the account
/// after `signIn` returns). Stored in the Keychain under a key derived from `email` until
/// `GmailProvider.linkAccount(accountID:identity:)` moves it under the account's keys.
struct GmailPendingSignIn: Codable, Sendable {
    var email: String
    var authState: Data
    var createdAt: Date
}

/// Secure-coding archive helpers for `OIDAuthState`.
enum GmailAuthStateArchiver {
    static func archive(_ state: OIDAuthState) throws -> Data {
        try NSKeyedArchiver.archivedData(withRootObject: state, requiringSecureCoding: true)
    }

    /// Unarchives with `ofClass:` first and falls back to an explicit class set (AppAuth issue #684 reports the
    /// single-class variant failing on some versions).
    static func unarchive(_ data: Data) throws -> OIDAuthState {
        if let state = try? NSKeyedUnarchiver.unarchivedObject(ofClass: OIDAuthState.self, from: data) {
            return state
        }
        let classes: [AnyClass] = [
            OIDAuthState.self, OIDAuthorizationRequest.self, OIDAuthorizationResponse.self,
            OIDTokenRequest.self, OIDTokenResponse.self, OIDServiceConfiguration.self, OIDServiceDiscovery.self,
            OIDRegistrationRequest.self, OIDRegistrationResponse.self,
            NSDictionary.self, NSArray.self, NSString.self, NSURL.self, NSDate.self, NSNumber.self,
        ]
        let object: Any?
        do {
            object = try NSKeyedUnarchiver.unarchivedObject(ofClasses: classes, from: data)
        } catch {
            throw ProviderError.decoding("Stored Gmail auth state could not be unarchived: \(error.localizedDescription)")
        }
        guard let state = object as? OIDAuthState else {
            throw ProviderError.decoding("Stored Gmail auth state is not an OIDAuthState")
        }
        return state
    }
}

/// Owns one account's `OIDAuthState`, acts as its change/error delegate and re-archives it into the Keychain
/// whenever AppAuth refreshes the tokens. AppAuth invokes the delegates on the main queue while the box lives
/// inside `GmailProvider`; it only touches immutable properties, a mutex-guarded flag and the thread-safe
/// Keychain, hence `@unchecked`.
///
/// A box that `GmailProvider` evicted (sign-out, or a re-sign-in that replaced the stored state) is *retired*:
/// its delegates no longer persist, so a refresh that was in flight cannot write the old state over the new one.
final class GmailAuthStateBox: NSObject, OIDAuthStateChangeDelegate, OIDAuthStateErrorDelegate, @unchecked Sendable {
    let accountID: UUID
    let state: OIDAuthState
    private let keychain: Keychain
    private let key: String
    private let retired = Mutex(false)
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "gmail.auth")

    init(state: OIDAuthState, accountID: UUID, keychain: Keychain, key: String) {
        self.state = state
        self.accountID = accountID
        self.keychain = keychain
        self.key = key
        super.init()
        state.stateChangeDelegate = self
        state.errorDelegate = self
    }

    /// `performAction(freshTokens:)` → bearer token, refreshing transparently. `forceRefresh` discards the cached
    /// access token first (used after Gmail answered 401).
    func freshAccessToken(forceRefresh: Bool) async throws -> String {
        if forceRefresh { state.setNeedsTokenRefresh() }
        return try await withCheckedThrowingContinuation { continuation in
            state.performAction(freshTokens: { accessToken, _, error in
                if let accessToken, error == nil {
                    continuation.resume(returning: accessToken)
                } else {
                    continuation.resume(throwing: GmailAuthErrorMapper.map(error))
                }
            })
        }
    }

    /// True once the provider replaced or removed this box; nothing is persisted from then on.
    var isRetired: Bool { retired.withLock { $0 } }

    /// Stops the box from persisting (the provider dropped it in favour of a new state or a sign-out).
    func retire() {
        retired.withLock { $0 = true }
    }

    /// Re-archives the state (called after every token refresh) unless the box was retired.
    func persist() {
        guard !isRetired else { return }
        do {
            try keychain.set(try GmailAuthStateArchiver.archive(state), for: key)
        } catch {
            logger.error("Could not save the refreshed Gmail auth state: \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - OIDAuthStateChangeDelegate / OIDAuthStateErrorDelegate

    func didChange(_ state: OIDAuthState) {
        persist()
    }

    func authState(_ state: OIDAuthState, didEncounterAuthorizationError error: any Error) {
        // Never delete anything here (the account stays; the next scan reports notAuthenticated).
        logger.error("Gmail authorization error: \((error as NSError).domain, privacy: .public)/\((error as NSError).code)")
        persist()
    }

    func authState(_ state: OIDAuthState, didEncounterTransientError error: any Error) {
        logger.notice("Gmail transient token error: \(error.localizedDescription, privacy: .private)")
    }
}

/// Maps AppAuth `NSError`s to `ProviderError` where the app has a matching case; other errors pass through.
enum GmailAuthErrorMapper {
    static func map(_ error: (any Error)?) -> any Error {
        guard let error else { return ProviderError.notAuthenticated }
        let nsError = error as NSError
        if isUserCancellation(nsError) { return ProviderError.cancelled }
        if isInvalidGrant(nsError) { return ProviderError.notAuthenticated }
        switch (nsError.domain, nsError.code) {
        case (OIDGeneralErrorDomain, OIDErrorCode.tokenRefreshError.rawValue):
            return ProviderError.notAuthenticated
        case (OIDGeneralErrorDomain, OIDErrorCode.networkError.rawValue), (NSURLErrorDomain, _):
            return ProviderError.network(nsError.localizedDescription)
        default:
            return error
        }
    }

    static func isUserCancellation(_ error: NSError) -> Bool {
        switch (error.domain, error.code) {
        case (OIDGeneralErrorDomain, OIDErrorCode.userCanceledAuthorizationFlow.rawValue),
             (OIDGeneralErrorDomain, OIDErrorCode.programCanceledAuthorizationFlow.rawValue),
             (OIDOAuthAuthorizationErrorDomain, OIDErrorCodeOAuth.accessDenied.rawValue):
            return true
        default:
            return false
        }
    }

    /// `invalid_grant` from the token endpoint: the refresh token was revoked/expired → sign in again.
    static func isInvalidGrant(_ error: NSError) -> Bool {
        if error.domain == OIDOAuthTokenErrorDomain, error.code == OIDErrorCodeOAuth.invalidGrant.rawValue { return true }
        if let response = error.userInfo[OIDOAuthErrorResponseErrorKey] as? [String: Any],
           let code = response[OIDOAuthErrorFieldError] as? String {
            return code == "invalid_grant"
        }
        return false
    }
}

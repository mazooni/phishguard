import Foundation
import MSAL
import OSLog
import PhishCore
import UIKit

/// Outlook/Hotmail integration: MSAL (token cache in the Keychain, access group com.microsoft.adalcache) +
/// Microsoft Graph (`/me/mailFolders/inbox/messages/delta`, `/subscriptions` pointing at the relay webhook).
///
/// Only read-only scopes are requested, bodies never leave memory, and nothing mail-derived is logged publicly.
///
/// Account binding: `signIn` returns the MSAL account identifier and address as the `SignedInIdentity`;
/// `AccountLinker` then calls `linkAccount(accountID:identity:)`, which stores both under the `LinkedAccount.id`.
/// An id without a stored identifier is `notAuthenticated` — the provider never guesses from the MSAL cache.
actor MicrosoftProvider: MailAccountProvider {
    nonisolated let provider: MailProvider = .microsoft

    /// Read-only scopes. `offline_access` is added by MSAL automatically. Never add more (ARCHITECTURE.md rule 1).
    static let scopes = ["Mail.Read", "User.Read"]
    static let accountIdentifierKeyPrefix = MicrosoftKeychainKeys.accountIdentifierPrefix

    /// Returns a Graph access token for the account. Production uses MSAL `acquireTokenSilent`; tests inject one.
    typealias TokenProvider = @Sendable (_ accountID: UUID) async throws -> String

    /// Test seams. Production code uses the defaults (MSAL, `URLSession.shared`, the app Keychain, `RelayClient`).
    struct Dependencies: Sendable {
        var session: URLSession = .shared
        var secrets: (any MicrosoftSecretStore)?
        var tokenProvider: TokenProvider?
        var now: @Sendable () -> Date = { Date() }
        var randomBytes: @Sendable (Int) -> [UInt8] = { count in
            var generator = SystemRandomNumberGenerator()
            return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        }
        var sleeper: GraphClient.Sleeper = { try await Task.sleep(for: .seconds($0)) }
        var makeRelay: (@Sendable (RelayConfig) -> any GraphRelayRegistrar)?

        init() {}
    }

    private let config: AppConfig
    private let keychain: Keychain
    private let secrets: any MicrosoftSecretStore
    private let graph: GraphClient
    private let tokenProvider: TokenProvider?
    private let now: @Sendable () -> Date
    private let randomBytes: @Sendable (Int) -> [UInt8]
    private let makeRelay: @Sendable (RelayConfig) -> any GraphRelayRegistrar
    private var authClient: MicrosoftAuthClient?
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "microsoft")

    init(config: AppConfig, keychain: Keychain) {
        self.init(config: config, keychain: keychain, dependencies: Dependencies())
    }

    init(config: AppConfig, keychain: Keychain, dependencies: Dependencies) {
        self.config = config
        self.keychain = keychain
        self.secrets = dependencies.secrets ?? keychain
        self.graph = GraphClient(session: dependencies.session, sleeper: dependencies.sleeper)
        self.tokenProvider = dependencies.tokenProvider
        self.now = dependencies.now
        self.randomBytes = dependencies.randomBytes
        let session = dependencies.session
        let bundleIdentifier = config.bundleIdentifier
        self.makeRelay = dependencies.makeRelay ?? { relay in
            RelayClient(config: relay, keychain: keychain, bundleIdentifier: bundleIdentifier, session: session)
        }
    }

    // MARK: - MailAccountProvider

    /// MSAL interactive sign-in (auth code + PKCE, `ASWebAuthenticationSession`), then `GET /me` for the address.
    /// Nothing is stored yet: the caller creates the `LinkedAccount` and binds the returned identity to it with
    /// `linkAccount(accountID:identity:)`.
    @MainActor
    func signIn(presenting: UIViewController) async throws -> SignedInIdentity {
        guard config.isMicrosoftConfigured else { throw ProviderError.notConfigured("MS_CLIENT_ID") }
        let auth = try await authClient()
        let result: MicrosoftAuthClient.SignInResult
        do {
            result = try await auth.signIn(presenting: presenting)
        } catch let error as MicrosoftAuthError {
            throw ProviderError(auth: error)
        }

        var email = result.username ?? ""
        var displayName = result.displayName
        do {
            let me = try await fetchMe(token: result.accessToken)
            if let address = me.emailAddress { email = address }
            if let name = me.displayName, !name.isEmpty { displayName = name }
        } catch {
            logger.notice("GET /me failed after sign-in; falling back to the MSAL username: \(error.localizedDescription, privacy: .private)")
        }
        email = email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !email.isEmpty else { throw ProviderError.decoding("Microsoft did not return an email address for the account") }

        return SignedInIdentity(providerAccountID: result.accountIdentifier, email: email, displayName: displayName)
    }

    /// Stores the MSAL account identifier and address under the `LinkedAccount.id`, replacing any previous record
    /// (a re-sign-in of the same mailbox refreshes MSAL's cache for the same identifier; a different mailbox would
    /// be a caller bug and is rejected so an account can never silently switch mailboxes).
    func linkAccount(accountID: UUID, identity: SignedInIdentity) async throws {
        let identifier = identity.providerAccountID.trimmingCharacters(in: .whitespacesAndNewlines)
        let email = identity.email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !identifier.isEmpty, !email.isEmpty else { throw ProviderError.notAuthenticated }
        if let stored = try secrets.getString(MicrosoftKeychainKeys.email(accountID)), !stored.isEmpty,
           stored.caseInsensitiveCompare(email) != .orderedSame {
            logger.error("Refusing to bind a Microsoft sign-in for a different mailbox to an existing account")
            throw ProviderError.notAuthenticated
        }
        try secrets.setString(identifier, for: MicrosoftKeychainKeys.accountIdentifier(accountID))
        try secrets.setString(email, for: MicrosoftKeychainKeys.email(accountID))
        logger.info("Bound the Microsoft sign-in to account \(accountID.uuidString, privacy: .private)")
    }

    /// Best-effort teardown: delete the Graph subscription, unregister with the relay, drop the MSAL account and
    /// every Keychain entry. Never throws for remote failures — the local state is always cleared.
    func signOut(accountID: UUID) async throws {
        let record = try? resolveStoredRecord(accountID: accountID)
        let subscriptionID = try? secrets.getString(MicrosoftKeychainKeys.subscriptionID(accountID))

        if let subscriptionID, !subscriptionID.isEmpty {
            do {
                let token = try await accessToken(for: accountID)
                try await GraphSubscriptionManager(client: graph, now: now).delete(id: subscriptionID, token: token)
            } catch {
                logger.notice("Could not delete the Graph subscription at sign-out: \(error.localizedDescription, privacy: .private)")
            }
        }

        if let relay = config.relayConfig, let email = record?.email, !email.isEmpty {
            do {
                try await makeRelay(relay).unregisterAccount(accountKey: config.accountKey(for: email))
            } catch {
                logger.notice("Relay unregister failed at sign-out: \(error.localizedDescription, privacy: .private)")
            }
        }

        if tokenProvider == nil, let identifier = record?.identifier {
            do {
                try await authClient().removeAccount(identifier: identifier)
            } catch {
                logger.error("MSAL account removal failed: \(error.localizedDescription, privacy: .private)")
            }
        }

        for key in [
            MicrosoftKeychainKeys.accountIdentifier(accountID),
            MicrosoftKeychainKeys.email(accountID),
            MicrosoftKeychainKeys.clientState(accountID),
            MicrosoftKeychainKeys.subscriptionID(accountID),
        ] {
            do {
                try secrets.delete(key)
            } catch {
                logger.error("Keychain delete failed at sign-out: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    func fetchNewMessages(accountID: UUID, cursor: SyncCursor?, lookback: TimeInterval) async throws -> FetchResult {
        try await fetchNewMessages(accountID: accountID, cursor: cursor, lookback: lookback, isProcessed: { _ in false })
    }

    /// Entries for which `isProcessed` is true are dropped before hydration and do not count toward the cap.
    func fetchNewMessages(
        accountID: UUID,
        cursor: SyncCursor?,
        lookback: TimeInterval,
        isProcessed: @escaping @Sendable (_ messageID: String) -> Bool
    ) async throws -> FetchResult {
        let token = try await accessToken(for: accountID)
        let sync = GraphMailSync(client: graph, now: now)
        return try await sync.fetchNewMessages(accountID: accountID, token: token, cursor: cursor, lookback: lookback, isProcessed: isProcessed)
    }

    func ensurePushSubscription(accountID: UUID, relay: RelayConfig, current: PushSubscriptionState?) async throws -> PushSubscriptionState {
        let token = try await accessToken(for: accountID)
        let subscriptions = GraphSubscriptionManager(client: graph, now: now)
        let currentDate = now()

        // The coordinator only calls this when the subscription is missing, expires within 24 h, or a renewal was
        // explicitly requested (lifecycle notification, cursor reset), so always talk to Graph: a PATCH proves the
        // subscription still exists (404 → recreate) and refreshes its expiry and webhook authorization.
        if let current, current.expiresAt > currentDate {
            do {
                let expiresAt = try await subscriptions.renew(id: current.id, token: token)
                try? secrets.setString(current.id, for: MicrosoftKeychainKeys.subscriptionID(accountID))
                return PushSubscriptionState(id: current.id, expiresAt: expiresAt, relayAccountKey: current.relayAccountKey)
            } catch let error as GraphError where error.status == 404 {
                logger.notice("Graph subscription no longer exists; creating a new one")
            } catch let error as GraphError {
                throw ProviderError(graph: error)
            }
        }

        let accountKey: String
        if let current {
            accountKey = current.relayAccountKey
        } else {
            accountKey = try await resolveAccountKey(accountID: accountID, token: token)
        }
        return try await createSubscription(accountID: accountID, token: token, relay: relay, accountKey: accountKey, manager: subscriptions)
    }

    @MainActor
    func handleRedirectURL(_ url: URL) -> Bool {
        guard MicrosoftAuthClient.isRedirectURL(url, bundleIdentifier: config.bundleIdentifier) else { return false }
        return MicrosoftAuthClient.handleRedirect(url)
    }

    // MARK: - Subscriptions

    private func createSubscription(
        accountID: UUID,
        token: String,
        relay: RelayConfig,
        accountKey: String,
        manager: GraphSubscriptionManager
    ) async throws -> PushSubscriptionState {
        let clientState = GraphSubscriptionManager.clientState(randomBytes: randomBytes(GraphSubscriptionManager.clientStateByteCount))
        try secrets.setString(clientState, for: MicrosoftKeychainKeys.clientState(accountID))
        let notificationURL = GraphSubscriptionManager.notificationURL(relayBaseURL: relay.baseURL)
        let lifecycleURL = GraphSubscriptionManager.lifecycleURL(relayBaseURL: relay.baseURL)

        let created: GraphSubscriptionManager.Created
        do {
            created = try await manager.create(token: token, notificationURL: notificationURL, lifecycleURL: lifecycleURL, clientState: clientState)
        } catch let error as GraphError where error.status == 409 {
            logger.notice("Graph reported an existing subscription; replacing it")
            do {
                try await manager.deleteConflicting(notificationURL: notificationURL, token: token)
                created = try await manager.create(token: token, notificationURL: notificationURL, lifecycleURL: lifecycleURL, clientState: clientState)
            } catch let error as GraphError {
                throw ProviderError(graph: error)
            }
        } catch let error as GraphError {
            throw ProviderError(graph: error)
        }
        try secrets.setString(created.id, for: MicrosoftKeychainKeys.subscriptionID(accountID))

        let relayClient = makeRelay(relay)
        do {
            try await relayClient.registerAccount(accountKey: accountKey, provider: .microsoft)
            try await relayClient.registerGraphSubscription(subscriptionID: created.id, accountKey: accountKey, clientState: clientState)
        } catch {
            // The relay does not know this subscription, so its notifications would be rejected: undo it.
            logger.error("Relay registration failed; deleting the new Graph subscription: \(error.localizedDescription, privacy: .private)")
            try? await manager.delete(id: created.id, token: token)
            try? secrets.delete(MicrosoftKeychainKeys.subscriptionID(accountID))
            throw error
        }
        return PushSubscriptionState(id: created.id, expiresAt: created.expiresAt, relayAccountKey: accountKey)
    }

    // MARK: - Tokens & identity

    private func accessToken(for accountID: UUID) async throws -> String {
        if let tokenProvider { return try await tokenProvider(accountID) }
        // Only an explicitly bound identifier is used: never "whichever account MSAL has cached".
        guard let record = try resolveStoredRecord(accountID: accountID) else { throw ProviderError.notAuthenticated }
        do {
            return try await authClient().silentAccessToken(accountIdentifier: record.identifier)
        } catch let error as MicrosoftAuthError {
            throw ProviderError(auth: error)
        }
    }

    private func authClient() async throws -> MicrosoftAuthClient {
        if let authClient { return authClient }
        guard let clientID = config.microsoftClientID else { throw ProviderError.notConfigured("MS_CLIENT_ID") }
        let bundleIdentifier = config.bundleIdentifier
        let scopes = Self.scopes
        let created = try await MainActor.run {
            try MicrosoftAuthClient(clientID: clientID, bundleIdentifier: bundleIdentifier, scopes: scopes)
        }
        authClient = created
        return created
    }

    private func fetchMe(token: String) async throws -> GraphUser {
        try await graph.get("me?$select=id,mail,userPrincipalName,displayName", token: token)
    }

    /// The relay `accountKey` for the account: derived from the address stored at sign-in, or from `GET /me`.
    private func resolveAccountKey(accountID: UUID, token: String) async throws -> String {
        if let email = try resolveStoredRecord(accountID: accountID)?.email, !email.isEmpty {
            return config.accountKey(for: email)
        }
        let me: GraphUser
        do {
            me = try await fetchMe(token: token)
        } catch let error as GraphError {
            throw ProviderError(graph: error)
        }
        guard let email = me.emailAddress else { throw ProviderError.decoding("GET /me returned no email address") }
        try secrets.setString(email, for: MicrosoftKeychainKeys.email(accountID))
        return config.accountKey(for: email)
    }

    // MARK: - Keychain records

    struct StoredRecord: Sendable, Equatable {
        var identifier: String
        var email: String?
    }

    /// The MSAL account identifier stored at sign-in, nil when the account was never signed in on this device.
    func storedAccountIdentifier(accountID: UUID) -> String? {
        do {
            return try resolveStoredRecord(accountID: accountID)?.identifier
        } catch {
            logger.error("Failed to read Microsoft account identifier: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    /// The record stored by `linkAccount` for `accountID`, or nil when the account was never bound on this device.
    private func resolveStoredRecord(accountID: UUID) throws -> StoredRecord? {
        guard let identifier = try secrets.getString(MicrosoftKeychainKeys.accountIdentifier(accountID)), !identifier.isEmpty else {
            return nil
        }
        return StoredRecord(identifier: identifier, email: try secrets.getString(MicrosoftKeychainKeys.email(accountID)))
    }

    // MARK: - Helpers

    /// Builds the MSAL client for `MS_CLIENT_ID`. Throws when the app is not configured.
    func makePublicClientApplication() throws -> MSALPublicClientApplication {
        guard let clientID = config.microsoftClientID else { throw ProviderError.notConfigured("MS_CLIENT_ID") }
        return try MicrosoftAuthClient.makeApplication(clientID: clientID, bundleIdentifier: config.bundleIdentifier)
    }
}

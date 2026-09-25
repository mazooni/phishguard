import AppAuth
import Foundation
import OSLog
import PhishCore
import UIKit

/// Gmail integration: AppAuth (OIDAuthState in the Keychain) + Gmail REST API (`users.history.list`,
/// `users.messages.get` format=full, `users.watch` to the relay's Pub/Sub topic).
///
/// Sign-in uses `ASWebAuthenticationSession` through AppAuth, so the OAuth redirect never reaches
/// `onOpenURL`; `handleRedirectURL` keeps the protocol default (false).
///
/// Account binding: `signIn` returns before the caller creates the `LinkedAccount`, so the fresh `OIDAuthState`
/// is parked in the Keychain as a *pending sign-in* keyed by the signed-in address, and `AccountLinker` moves it
/// under the account's own keys with `linkAccount(accountID:identity:)` right away (replacing any stored state,
/// so a re-sign-in repairs a revoked grant). An account id without stored state is simply `notAuthenticated`;
/// nothing is ever claimed lazily, so a sign-in can never be bound to the wrong account.
actor GmailProvider: MailAccountProvider {
    nonisolated let provider: MailProvider = .gmail

    /// Read-only Gmail scope plus `openid`/`email` so the id_token carries the subject and address
    /// (docs/research/gmail.md). Never add more (ARCHITECTURE.md rule 1).
    static let scopes = ["https://www.googleapis.com/auth/gmail.readonly", "openid", "email"]
    static let authStateKeyPrefix = "gmail.authState."
    static let emailKeyPrefix = "gmail.email."
    /// Pending sign-ins are keyed by the lowercased address, so two back-to-back sign-ins cannot clobber each other.
    static let pendingSignInKeyPrefix = "gmail.pendingSignIn."
    /// A pending sign-in that was never bound (the app died between `signIn` and `linkAccount`) is discarded after this.
    static let pendingSignInLifetime: TimeInterval = 3600

    static func pendingSignInKey(for email: String) -> String {
        pendingSignInKeyPrefix + email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    static let authorizationEndpoint = URL(string: "https://accounts.google.com/o/oauth2/v2/auth")!
    static let tokenEndpoint = URL(string: "https://oauth2.googleapis.com/token")!
    static let redirectPath = ":/oauth2redirect"

    static let historyPageSize = 500
    static let listPageSize = 100
    /// Upper bound on NEW (not yet processed) message ids per fetch: the full sync cap, and the history walk stops
    /// after the record that crosses it while advancing the cursor only to that record. Must not exceed
    /// `ScanCoordinator.defaultMaxMessagesPerScan` (100), otherwise a capped batch can never be finished in one
    /// scan and every body is downloaded twice before the cursor advances.
    static let maxMessagesPerFetch = 100
    static let fetchConcurrency = 4
    static let watchSubscriptionID = "watch"

    /// Test seam: returns a bearer token for an account, bypassing AppAuth and the Keychain.
    typealias AccessTokenProvider = @Sendable (UUID) async throws -> String

    private let config: AppConfig
    private let keychain: Keychain
    private let session: URLSession
    private let retryPolicy: GmailAPIClient.RetryPolicy
    private let accessTokenOverride: AccessTokenProvider?
    private let authFlow = GmailAuthFlow()
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "gmail")
    private var authStates: [UUID: GmailAuthStateBox] = [:]

    init(
        config: AppConfig,
        keychain: Keychain,
        session: URLSession = .shared,
        accessTokenProvider: AccessTokenProvider? = nil,
        retryPolicy: GmailAPIClient.RetryPolicy = .default
    ) {
        self.config = config
        self.keychain = keychain
        self.session = session
        self.accessTokenOverride = accessTokenProvider
        self.retryPolicy = retryPolicy
    }

    // MARK: - Sign-in

    @MainActor
    func signIn(presenting: UIViewController) async throws -> SignedInIdentity {
        guard let clientID = config.googleClientID, !AppConfig.isPlaceholder(clientID) else {
            throw ProviderError.notConfigured("GOOGLE_CLIENT_ID")
        }
        let reversedClientID = config.googleReversedClientID.flatMap { AppConfig.isPlaceholder($0) ? nil : $0 }
            ?? Self.reversedClientID(clientID)
        guard let redirectURL = URL(string: reversedClientID + Self.redirectPath) else {
            throw ProviderError.notConfigured("GOOGLE_REVERSED_CLIENT_ID")
        }

        let configuration = OIDServiceConfiguration(authorizationEndpoint: Self.authorizationEndpoint, tokenEndpoint: Self.tokenEndpoint)
        let request = OIDAuthorizationRequest(
            configuration: configuration,
            clientId: clientID,
            clientSecret: nil,
            scopes: Self.scopes,
            redirectURL: redirectURL,
            responseType: OIDResponseTypeCode,
            additionalParameters: ["prompt": "select_account"]
        )

        let outcome = try await Self.authorize(request, presenting: presenting, flow: authFlow)

        let client = GmailAPIClient(session: session, retryPolicy: retryPolicy) { _ in outcome.accessToken }
        let profile: GmailProfile = try await client.get("profile")

        // `subject` (openid) identifies the Google account. A display name is only used when the id_token happens to
        // carry `name`; the `profile` scope is deliberately not requested, so this is normally nil.
        var displayName: String?
        var subject: String?
        if let idToken = outcome.idToken, let parsed = OIDIDToken(idTokenString: idToken) {
            displayName = (parsed.claims["name"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
            subject = parsed.subject
        }

        try await storePendingSignIn(GmailPendingSignIn(email: profile.emailAddress, authState: outcome.archivedState, createdAt: .now))
        logger.info("Google sign-in completed for \(profile.emailAddress, privacy: .private); historyId \(profile.historyId.stringValue, privacy: .private)")
        return SignedInIdentity(
            providerAccountID: subject ?? profile.emailAddress,
            email: profile.emailAddress,
            displayName: (displayName?.isEmpty ?? true) ? nil : displayName
        )
    }

    /// Runs the AppAuth flow. The `OIDExternalUserAgentSession` is retained by `flow` until the callback fires.
    @MainActor
    private static func authorize(_ request: OIDAuthorizationRequest, presenting: UIViewController, flow: GmailAuthFlow) async throws -> GmailAuthorizationOutcome {
        if flow.isActive { flow.cancelActive() }
        let token = UUID()
        defer { flow.finish(token: token) }
        return try await withCheckedThrowingContinuation { continuation in
            let session = OIDAuthState.authState(byPresenting: request, presenting: presenting) { authState, error in
                guard let authState else {
                    continuation.resume(throwing: GmailAuthErrorMapper.map(error))
                    return
                }
                do {
                    guard let accessToken = authState.lastTokenResponse?.accessToken, !accessToken.isEmpty else {
                        throw ProviderError.notAuthenticated
                    }
                    let archived = try GmailAuthStateArchiver.archive(authState)
                    continuation.resume(returning: GmailAuthorizationOutcome(
                        archivedState: archived,
                        accessToken: accessToken,
                        idToken: authState.lastTokenResponse?.idToken
                    ))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
            flow.begin(session, token: token)
        }
    }

    /// `123-abc.apps.googleusercontent.com` → `com.googleusercontent.apps.123-abc`
    static func reversedClientID(_ clientID: String) -> String {
        clientID.split(separator: ".", omittingEmptySubsequences: false).reversed().joined(separator: ".")
    }

    // MARK: - Sign-out

    /// Best-effort `users.stop`, token revocation and relay unregistration, then the Keychain entries are deleted.
    /// Remote failures never prevent the local cleanup.
    func signOut(accountID: UUID) async throws {
        defer { evictAuthState(for: accountID) }
        let client = makeClient(for: accountID)

        if let box = try? loadAuthStateBox(for: accountID) {
            do {
                try await client.postEmpty("stop")
            } catch {
                logger.notice("users.stop failed during sign-out: \(error.localizedDescription, privacy: .private)")
            }
            if let token = box.state.refreshToken ?? box.state.lastTokenResponse?.accessToken {
                do {
                    try await client.revoke(token: token)
                } catch {
                    logger.notice("Token revocation failed during sign-out: \(error.localizedDescription, privacy: .private)")
                }
            }
        }

        if let relay = config.relayConfig, let email = try? keychain.getString(Self.emailKeyPrefix + accountID.uuidString), !email.isEmpty {
            let relayClient = RelayClient(config: relay, keychain: keychain, bundleIdentifier: config.bundleIdentifier, session: session)
            do {
                try await relayClient.unregisterAccount(accountKey: config.accountKey(for: email))
            } catch {
                logger.notice("Relay unregistration failed during sign-out: \(error.localizedDescription, privacy: .private)")
            }
        }

        try keychain.delete(Self.authStateKeyPrefix + accountID.uuidString)
        try keychain.delete(Self.emailKeyPrefix + accountID.uuidString)
        logger.info("Gmail account signed out")
    }

    // MARK: - Fetch

    func fetchNewMessages(accountID: UUID, cursor: SyncCursor?, lookback: TimeInterval) async throws -> FetchResult {
        try await fetchNewMessages(accountID: accountID, cursor: cursor, lookback: lookback, isProcessed: { _ in false })
    }

    /// Ids for which `isProcessed` is true are dropped before `messages.get` and do not count toward the cap.
    func fetchNewMessages(
        accountID: UUID,
        cursor: SyncCursor?,
        lookback: TimeInterval,
        isProcessed: @escaping @Sendable (_ messageID: String) -> Bool
    ) async throws -> FetchResult {
        let client = makeClient(for: accountID)
        let listing: (ids: [String], cursor: String)
        var reset = false

        if let cursor, !cursor.opaque.trimmingCharacters(in: .whitespaces).isEmpty {
            do {
                listing = try await listHistory(since: cursor.opaque, client: client, isProcessed: isProcessed)
            } catch ProviderError.http(let status, _) where status == 404 {
                logger.notice("Gmail history cursor expired (404); performing a full sync over the lookback window")
                listing = try await fullSync(lookback: lookback, client: client, isProcessed: isProcessed)
                reset = true
            }
        } else {
            listing = try await fullSync(lookback: lookback, client: client, isProcessed: isProcessed)
            reset = true
        }

        let messages = try await fetchMessages(ids: listing.ids, accountID: accountID, client: client)
        logger.info("Gmail fetch: \(listing.ids.count) candidate ids, \(messages.count) messages, reset=\(reset)")
        return FetchResult(messages: messages, cursor: SyncCursor(opaque: listing.cursor), cursorWasReset: reset)
    }

    /// `users.history.list` since `startHistoryId`: INBOX additions that are neither drafts nor sent mail, deduped
    /// and minus already-processed ids. Returns the response's top-level `historyId` as the cursor, or the id of
    /// the last consumed record when the per-fetch cap stopped the walk early.
    private func listHistory(
        since startHistoryId: String,
        client: GmailAPIClient,
        isProcessed: @escaping @Sendable (String) -> Bool
    ) async throws -> (ids: [String], cursor: String) {
        var ids: [String] = []
        var seen = Set<String>()
        var pageToken: String?
        var cursor = startHistoryId
        var capped = false

        repeat {
            var query = [
                URLQueryItem(name: "startHistoryId", value: startHistoryId),
                URLQueryItem(name: "historyTypes", value: "messageAdded"),
                URLQueryItem(name: "labelId", value: "INBOX"),
                URLQueryItem(name: "maxResults", value: String(Self.historyPageSize)),
            ]
            if let pageToken { query.append(URLQueryItem(name: "pageToken", value: pageToken)) }
            let page: GmailHistoryPage = try await client.get("history", query: query)

            for record in page.history ?? [] {
                for added in record.messagesAdded ?? [] {
                    let labels = added.message.labelIds ?? []
                    guard labels.contains("INBOX"), !labels.contains("DRAFT"), !labels.contains("SENT"),
                          seen.insert(added.message.id).inserted, !isProcessed(added.message.id) else { continue }
                    ids.append(added.message.id)
                }
                if ids.count >= Self.maxMessagesPerFetch, let recordID = record.id?.stringValue {
                    cursor = recordID
                    capped = true
                    break
                }
            }
            if capped { break }
            if let historyID = page.historyId?.stringValue { cursor = historyID }
            pageToken = page.nextPageToken
        } while pageToken != nil

        if capped {
            logger.warning("Gmail history walk stopped at the \(Self.maxMessagesPerFetch)-message cap; the cursor advances to the last consumed record")
        }
        return (ids, cursor)
    }

    /// Full sync: `users.getProfile().historyId` is taken FIRST (so nothing that arrives during the listing is
    /// lost), then `users.messages.list` over the lookback window, newest first, capped at `maxMessagesPerFetch`
    /// new (not yet processed) ids.
    private func fullSync(
        lookback: TimeInterval,
        client: GmailAPIClient,
        isProcessed: @escaping @Sendable (String) -> Bool
    ) async throws -> (ids: [String], cursor: String) {
        let profile: GmailProfile = try await client.get("profile")
        let days = max(1, Int((lookback / 86_400).rounded(.up)))

        var ids: [String] = []
        var seen = Set<String>()
        var pageToken: String?
        var capped = false

        repeat {
            var query = [
                URLQueryItem(name: "q", value: "newer_than:\(days)d"),
                URLQueryItem(name: "labelIds", value: "INBOX"),
                URLQueryItem(name: "maxResults", value: String(min(Self.listPageSize, Self.maxMessagesPerFetch - ids.count))),
            ]
            if let pageToken { query.append(URLQueryItem(name: "pageToken", value: pageToken)) }
            let page: GmailMessageListPage = try await client.get("messages", query: query)
            let stubs = page.messages ?? []

            for (index, stub) in stubs.enumerated() where seen.insert(stub.id).inserted && !isProcessed(stub.id) {
                ids.append(stub.id)
                if ids.count >= Self.maxMessagesPerFetch {
                    capped = index + 1 < stubs.count || page.nextPageToken != nil
                    break
                }
            }
            pageToken = ids.count >= Self.maxMessagesPerFetch ? nil : page.nextPageToken
        } while pageToken != nil

        if capped {
            logger.warning("Gmail full sync hit the \(Self.maxMessagesPerFetch)-message cap; older messages in the lookback window were not fetched")
        }
        return (ids, profile.historyId.stringValue)
    }

    /// `users.messages.get?format=full` for every id, at most `fetchConcurrency` in flight; ids that 404 are skipped.
    private func fetchMessages(ids: [String], accountID: UUID, client: GmailAPIClient) async throws -> [EmailMessage] {
        guard !ids.isEmpty else { return [] }
        var messages: [EmailMessage] = []
        messages.reserveCapacity(ids.count)

        try await withThrowingTaskGroup(of: EmailMessage?.self) { group in
            var pending = ids.makeIterator()
            var inFlight = 0
            while inFlight < Self.fetchConcurrency, let id = pending.next() {
                group.addTask { try await self.fetchMessage(id: id, accountID: accountID, client: client) }
                inFlight += 1
            }
            while let result = try await group.next() {
                inFlight -= 1
                if let result { messages.append(result) }
                if let id = pending.next() {
                    group.addTask { try await self.fetchMessage(id: id, accountID: accountID, client: client) }
                    inFlight += 1
                }
            }
        }
        return messages.sorted { $0.receivedAt < $1.receivedAt }
    }

    nonisolated private func fetchMessage(id: String, accountID: UUID, client: GmailAPIClient) async throws -> EmailMessage? {
        do {
            let data = try await client.getData("messages/\(id)", query: [URLQueryItem(name: "format", value: "full")])
            return try GmailPayloadParser.parseMessage(data, accountID: accountID)
        } catch ProviderError.http(let status, _) where status == 404 {
            logger.notice("Gmail message \(id, privacy: .private) vanished before it could be fetched; skipping")
            return nil
        }
    }

    // MARK: - Push subscription

    func ensurePushSubscription(accountID: UUID, relay: RelayConfig, current: PushSubscriptionState?) async throws -> PushSubscriptionState {
        let topic = relay.gmailPubSubTopic.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !topic.isEmpty, !AppConfig.isPlaceholder(topic) else {
            throw ProviderError.notConfigured("GMAIL_PUBSUB_TOPIC")
        }
        let client = makeClient(for: accountID)

        let response: GmailWatchResponse = try await client.post(
            "watch",
            body: GmailWatchRequest(topicName: topic, labelIds: ["INBOX"], labelFilterBehavior: "INCLUDE")
        )
        guard let expirationMilliseconds = response.expiration.int64Value else {
            throw ProviderError.decoding("users.watch expiration")
        }
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(expirationMilliseconds) / 1000)

        let email = try await email(for: accountID, client: client)
        let accountKey = config.accountKey(for: email)
        let relayClient = RelayClient(config: relay, keychain: keychain, bundleIdentifier: config.bundleIdentifier, session: session)
        try await relayClient.registerAccount(accountKey: accountKey, provider: .gmail)

        logger.info("Gmail watch renewed; expires \(expiresAt.formatted(.iso8601), privacy: .public)")
        return PushSubscriptionState(id: Self.watchSubscriptionID, expiresAt: expiresAt, relayAccountKey: accountKey)
    }

    // MARK: - Account binding

    /// Moves the pending sign-in for `identity.email` under the account's Keychain keys, REPLACING whatever was
    /// stored for `accountID` (a re-sign-in after a revoked or expired grant) and dropping the cached auth box so
    /// the next token request uses the new state. Throws `notAuthenticated` when no live pending sign-in exists for
    /// that address; a pending sign-in for another address is never touched.
    ///
    /// Deliberate: the superseded `OIDAuthState` is overwritten but NOT revoked. Google's revoke endpoint revokes the
    /// user's whole grant for this client (every access and refresh token for that Google account), which would also
    /// kill the credentials we just bound. Google expires the old refresh token on its own. See docs/PRIVACY.md.
    func linkAccount(accountID: UUID, identity: SignedInIdentity) async throws {
        let pendingKey = Self.pendingSignInKey(for: identity.email)
        guard let raw = try keychain.get(pendingKey) else {
            logger.error("No pending Gmail sign-in to bind to account \(accountID.uuidString, privacy: .private)")
            throw ProviderError.notAuthenticated
        }
        let pending: GmailPendingSignIn
        do {
            pending = try JSONDecoder().decode(GmailPendingSignIn.self, from: raw)
        } catch {
            try keychain.delete(pendingKey)
            throw ProviderError.decoding("Pending Gmail sign-in: \(error.localizedDescription)")
        }
        guard pending.email.caseInsensitiveCompare(identity.email) == .orderedSame else {
            try keychain.delete(pendingKey)
            logger.error("Pending Gmail sign-in does not match the identity being linked; discarded")
            throw ProviderError.notAuthenticated
        }
        guard Date.now.timeIntervalSince(pending.createdAt) < Self.pendingSignInLifetime else {
            try keychain.delete(pendingKey)
            logger.notice("Discarded an expired pending Gmail sign-in")
            throw ProviderError.notAuthenticated
        }
        // Retire the cached box first: an in-flight refresh of the old state must not re-persist it over the new one.
        evictAuthState(for: accountID)
        try keychain.set(pending.authState, for: Self.authStateKeyPrefix + accountID.uuidString)
        try keychain.setString(pending.email, for: Self.emailKeyPrefix + accountID.uuidString)
        try keychain.delete(pendingKey)
        logger.info("Bound the pending Gmail sign-in to account \(accountID.uuidString, privacy: .private)")
    }

    /// True when a stored `OIDAuthState` exists and reports `isAuthorized`.
    func hasStoredAuthorization(accountID: UUID) -> Bool {
        do {
            guard let data = try keychain.get(Self.authStateKeyPrefix + accountID.uuidString) else { return false }
            return try GmailAuthStateArchiver.unarchive(data).isAuthorized
        } catch {
            logger.error("Failed to read Gmail auth state: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    // MARK: - Helpers

    private func storePendingSignIn(_ pending: GmailPendingSignIn) throws {
        try keychain.set(try JSONEncoder().encode(pending), for: Self.pendingSignInKey(for: pending.email))
    }

    /// Drops the cached auth box for `accountID` and retires it so its AppAuth delegates stop persisting.
    private func evictAuthState(for accountID: UUID) {
        authStates.removeValue(forKey: accountID)?.retire()
    }

    private func makeClient(for accountID: UUID) -> GmailAPIClient {
        GmailAPIClient(session: session, retryPolicy: retryPolicy) { forceRefresh in
            try await self.accessToken(for: accountID, forceRefresh: forceRefresh)
        }
    }

    private func accessToken(for accountID: UUID, forceRefresh: Bool) async throws -> String {
        if let accessTokenOverride { return try await accessTokenOverride(accountID) }
        let box = try loadAuthStateBox(for: accountID)
        return try await box.freshAccessToken(forceRefresh: forceRefresh)
    }

    /// Loads (and caches) the account's auth state. A missing state maps to `notAuthenticated`: nothing is ever
    /// claimed lazily, binding happens only through `linkAccount(accountID:identity:)`.
    private func loadAuthStateBox(for accountID: UUID) throws -> GmailAuthStateBox {
        if let box = authStates[accountID] { return box }
        let key = Self.authStateKeyPrefix + accountID.uuidString
        guard let data = try keychain.get(key) else { throw ProviderError.notAuthenticated }
        let state = try GmailAuthStateArchiver.unarchive(data)
        let box = GmailAuthStateBox(state: state, accountID: accountID, keychain: keychain, key: key)
        authStates[accountID] = box
        return box
    }

    private func email(for accountID: UUID, client: GmailAPIClient) async throws -> String {
        let key = Self.emailKeyPrefix + accountID.uuidString
        if let stored = try? keychain.getString(key), !stored.isEmpty { return stored }
        let profile: GmailProfile = try await client.get("profile")
        do {
            try keychain.setString(profile.emailAddress, for: key)
        } catch {
            logger.error("Could not cache the Gmail address: \(error.localizedDescription, privacy: .public)")
        }
        return profile.emailAddress
    }
}

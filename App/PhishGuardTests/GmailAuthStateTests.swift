import AppAuth
import XCTest
@testable import PhishGuard

/// `OIDAuthState` persistence, explicit sign-in binding (`linkAccount`) and sign-out cleanup (AppAuth 3.0.0, no network).
final class GmailAuthStateTests: XCTestCase {
    private var keychain: Keychain!
    private let accountID = UUID()
    private let otherAccountID = UUID()
    private let email = "person@example.com"
    private let otherEmail = "other@example.com"

    override func setUp() {
        super.setUp()
        keychain = Keychain(service: "PhishGuardTests.gmail.auth.\(UUID().uuidString)")
    }

    override func tearDown() {
        for id in [accountID, otherAccountID] {
            for key in [GmailProvider.authStateKeyPrefix, GmailProvider.emailKeyPrefix] {
                try? keychain.delete(key + id.uuidString)
            }
        }
        for address in [email, otherEmail] {
            try? keychain.delete(GmailProvider.pendingSignInKey(for: address))
        }
        try? keychain.delete(RelayClient.deviceSecretKey)
        try? keychain.delete(RelayClient.deviceIDKey)
        super.tearDown()
    }

    /// A fully authorized state as AppAuth would produce after the code exchange.
    static func makeAuthState(accessToken: String = "access-1", refreshToken: String? = "refresh-1", expiresIn: TimeInterval = 3600) -> OIDAuthState {
        let configuration = OIDServiceConfiguration(authorizationEndpoint: GmailProvider.authorizationEndpoint, tokenEndpoint: GmailProvider.tokenEndpoint)
        let request = OIDAuthorizationRequest(
            configuration: configuration,
            clientId: "client-id",
            clientSecret: nil,
            scopes: GmailProvider.scopes,
            redirectURL: URL(string: "com.googleusercontent.apps.client-id:/oauth2redirect")!,
            responseType: OIDResponseTypeCode,
            additionalParameters: nil
        )
        let authorizationResponse = OIDAuthorizationResponse(request: request, parameters: [
            "code": "auth-code" as NSString,
            "state": (request.state ?? "") as NSString,
        ])
        let tokenRequest = OIDTokenRequest(
            configuration: configuration,
            grantType: OIDGrantTypeAuthorizationCode,
            authorizationCode: "auth-code",
            redirectURL: request.redirectURL,
            clientID: "client-id",
            clientSecret: nil,
            scope: nil,
            refreshToken: nil,
            codeVerifier: request.codeVerifier,
            additionalParameters: nil
        )
        var parameters: [String: NSObject & NSCopying] = [
            "access_token": accessToken as NSString,
            "token_type": "Bearer" as NSString,
            "expires_in": NSNumber(value: expiresIn),
            "scope": GmailProvider.scopes.joined(separator: " ") as NSString,
        ]
        if let refreshToken { parameters["refresh_token"] = refreshToken as NSString }
        let tokenResponse = OIDTokenResponse(request: tokenRequest, parameters: parameters)
        return OIDAuthState(authorizationResponse: authorizationResponse, tokenResponse: tokenResponse)
    }

    func testAuthStateArchiveRoundTrip() throws {
        let state = Self.makeAuthState()
        XCTAssertTrue(state.isAuthorized)

        let data = try GmailAuthStateArchiver.archive(state)
        let restored = try GmailAuthStateArchiver.unarchive(data)

        XCTAssertTrue(restored.isAuthorized)
        XCTAssertEqual(restored.refreshToken, "refresh-1")
        XCTAssertEqual(restored.lastTokenResponse?.accessToken, "access-1")
        XCTAssertEqual(restored.scope, GmailProvider.scopes.joined(separator: " "))
        XCTAssertEqual(restored.lastAuthorizationResponse.request.clientID, "client-id")
    }

    func testUnarchiveRejectsGarbage() {
        XCTAssertThrowsError(try GmailAuthStateArchiver.unarchive(Data("not an archive".utf8)))
    }

    func testBoxReturnsFreshTokenAndPersistsOnChange() async throws {
        let key = GmailProvider.authStateKeyPrefix + accountID.uuidString
        let box = GmailAuthStateBox(state: Self.makeAuthState(), accountID: accountID, keychain: keychain, key: key)

        let token = try await box.freshAccessToken(forceRefresh: false)
        XCTAssertEqual(token, "access-1", "a fresh access token is returned without a refresh")

        XCTAssertNil(try keychain.get(key))
        box.didChange(box.state)
        let saved = try XCTUnwrap(try keychain.get(key))
        XCTAssertEqual(try GmailAuthStateArchiver.unarchive(saved).refreshToken, "refresh-1")
    }

    func testRetiredBoxNoLongerPersists() throws {
        let key = GmailProvider.authStateKeyPrefix + accountID.uuidString
        let box = GmailAuthStateBox(state: Self.makeAuthState(accessToken: "old"), accountID: accountID, keychain: keychain, key: key)
        let replacement = try GmailAuthStateArchiver.archive(Self.makeAuthState(accessToken: "new"))
        try keychain.set(replacement, for: key)

        box.retire()
        XCTAssertTrue(box.isRetired)
        box.didChange(box.state)
        box.authState(box.state, didEncounterAuthorizationError: NSError(domain: "test", code: 1))

        let stored = try XCTUnwrap(try keychain.get(key))
        XCTAssertEqual(try GmailAuthStateArchiver.unarchive(stored).lastTokenResponse?.accessToken, "new", "a retired box must not overwrite the replacement state")
    }

    func testStateWithoutRefreshTokenAndExpiredAccessTokenMapsToNotAuthenticated() async {
        let box = GmailAuthStateBox(state: Self.makeAuthState(refreshToken: nil, expiresIn: -60), accountID: accountID, keychain: keychain, key: "unused")
        do {
            _ = try await box.freshAccessToken(forceRefresh: true)
            XCTFail("expected an error")
        } catch let error as ProviderError {
            guard case .notAuthenticated = error else { return XCTFail("unexpected \(error)") }
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testErrorMapping() {
        let cancelled = NSError(domain: OIDGeneralErrorDomain, code: OIDErrorCode.userCanceledAuthorizationFlow.rawValue)
        XCTAssertTrue(GmailAuthErrorMapper.isUserCancellation(cancelled))
        guard case ProviderError.cancelled = GmailAuthErrorMapper.map(cancelled) else { return XCTFail("cancelled") }

        let denied = NSError(domain: OIDOAuthAuthorizationErrorDomain, code: OIDErrorCodeOAuth.accessDenied.rawValue)
        guard case ProviderError.cancelled = GmailAuthErrorMapper.map(denied) else { return XCTFail("access_denied → cancelled") }

        let invalidGrant = NSError(domain: OIDOAuthTokenErrorDomain, code: OIDErrorCodeOAuth.invalidGrant.rawValue,
                                   userInfo: [OIDOAuthErrorResponseErrorKey: [OIDOAuthErrorFieldError: "invalid_grant"]])
        XCTAssertTrue(GmailAuthErrorMapper.isInvalidGrant(invalidGrant))
        guard case ProviderError.notAuthenticated = GmailAuthErrorMapper.map(invalidGrant) else { return XCTFail("invalid_grant") }

        let network = NSError(domain: OIDGeneralErrorDomain, code: OIDErrorCode.networkError.rawValue)
        guard case ProviderError.network = GmailAuthErrorMapper.map(network) else { return XCTFail("network") }

        guard case ProviderError.notAuthenticated = GmailAuthErrorMapper.map(nil) else { return XCTFail("nil error") }

        let other = NSError(domain: OIDOAuthAuthorizationErrorDomain, code: OIDErrorCodeOAuth.invalidClient.rawValue)
        XCTAssertEqual((GmailAuthErrorMapper.map(other) as NSError).code, OIDErrorCodeOAuth.invalidClient.rawValue, "unknown errors pass through")
    }

    // MARK: - Sign-in binding

    private func makeProvider(server: GmailStubServer, tokenOverride: Bool) -> GmailProvider {
        let config = AppConfig(relayBaseURL: URL(string: "https://relay.test"), relayAPIKey: "k", relaySalt: "salt")
        let override: GmailProvider.AccessTokenProvider? = tokenOverride ? { @Sendable _ in "override-token" } : nil
        return GmailProvider(
            config: config,
            keychain: keychain,
            session: server.makeSession(),
            accessTokenProvider: override,
            retryPolicy: .immediate
        )
    }

    /// Parks a sign-in the way `GmailProvider.signIn` does, under the key derived from the address.
    private func storePending(email: String = "person@example.com", accessToken: String = "access-1", createdAt: Date = .now) throws {
        let state = Self.makeAuthState(accessToken: accessToken)
        let pending = GmailPendingSignIn(email: email, authState: try GmailAuthStateArchiver.archive(state), createdAt: createdAt)
        try keychain.set(try JSONEncoder().encode(pending), for: GmailProvider.pendingSignInKey(for: email))
    }

    private func identity(_ email: String) -> SignedInIdentity {
        SignedInIdentity(providerAccountID: "sub-\(email)", email: email)
    }

    private func stubEmptyMailbox(_ server: GmailStubServer) {
        server.handle { request in
            switch request.path {
            case GmailFixtures.gmailPath + "/profile": return .json(GmailFixtures.profile(historyId: "1"))
            case GmailFixtures.gmailPath + "/messages": return .json(GmailFixtures.listPage(ids: []))
            default: return .notFound
            }
        }
    }

    func testPendingSignInKeyIsDerivedFromTheLowercasedAddress() {
        XCTAssertEqual(GmailProvider.pendingSignInKey(for: " Person@Example.COM "), "gmail.pendingSignIn.person@example.com")
        XCTAssertNotEqual(GmailProvider.pendingSignInKey(for: "a@example.com"), GmailProvider.pendingSignInKey(for: "b@example.com"))
    }

    func testLinkAccountMovesPendingStateUnderAccountKeys() async throws {
        let server = GmailStubServer()
        let provider = makeProvider(server: server, tokenOverride: true)
        try storePending()

        let storedBefore = await provider.hasStoredAuthorization(accountID: accountID)
        XCTAssertFalse(storedBefore)
        try await provider.linkAccount(accountID: accountID, identity: identity("Person@Example.com"))

        let storedAfter = await provider.hasStoredAuthorization(accountID: accountID)
        XCTAssertTrue(storedAfter)
        XCTAssertEqual(try keychain.getString(GmailProvider.emailKeyPrefix + accountID.uuidString), "person@example.com")
        XCTAssertNil(try keychain.get(GmailProvider.pendingSignInKey(for: email)), "consumed")

        // Nothing is left for a second account id.
        await assertThrowsProviderError("notAuthenticated", { if case .notAuthenticated = $0 { return true }; return false }) {
            try await provider.linkAccount(accountID: self.otherAccountID, identity: self.identity(self.email))
        }
        let otherStored = await provider.hasStoredAuthorization(accountID: otherAccountID)
        XCTAssertFalse(otherStored)
    }

    func testLinkAccountReplacesStaleStateAndDropsTheCachedBox() async throws {
        let server = GmailStubServer()
        stubEmptyMailbox(server)
        let provider = makeProvider(server: server, tokenOverride: false)
        let key = GmailProvider.authStateKeyPrefix + accountID.uuidString
        try keychain.set(try GmailAuthStateArchiver.archive(Self.makeAuthState(accessToken: "access-old")), for: key)

        // Prime the in-memory box with the old (about to be revoked) state.
        _ = try await provider.fetchNewMessages(accountID: accountID, cursor: nil, lookback: 3600)
        XCTAssertEqual(server.requests.first?.headers["Authorization"], "Bearer access-old")

        // The user signs in again as the same address; the linker binds it to the SAME account id.
        try storePending(accessToken: "access-new")
        try await provider.linkAccount(accountID: accountID, identity: identity(email))

        _ = try await provider.fetchNewMessages(accountID: accountID, cursor: nil, lookback: 3600)
        XCTAssertEqual(server.requests.last?.headers["Authorization"], "Bearer access-new", "the re-sign-in replaces the stored state and the cached box")
        let stored = try XCTUnwrap(try keychain.get(key))
        XCTAssertEqual(try GmailAuthStateArchiver.unarchive(stored).lastTokenResponse?.accessToken, "access-new")
        XCTAssertNil(try keychain.get(GmailProvider.pendingSignInKey(for: email)))
    }

    func testLinkAccountNeverBindsAPendingSignInForAnotherAddress() async throws {
        let server = GmailStubServer()
        let provider = makeProvider(server: server, tokenOverride: true)
        try storePending(email: otherEmail)

        await assertThrowsProviderError("notAuthenticated", { if case .notAuthenticated = $0 { return true }; return false }) {
            try await provider.linkAccount(accountID: self.accountID, identity: self.identity(self.email))
        }
        let stored = await provider.hasStoredAuthorization(accountID: accountID)
        XCTAssertFalse(stored)
        XCTAssertNotNil(try keychain.get(GmailProvider.pendingSignInKey(for: otherEmail)), "the other account's sign-in is untouched")
        XCTAssertNil(try keychain.getString(GmailProvider.emailKeyPrefix + accountID.uuidString))
    }

    func testBackToBackSignInsAreBoundToTheirOwnAccounts() async throws {
        let provider = makeProvider(server: GmailStubServer(), tokenOverride: true)
        try storePending(email: email, accessToken: "access-a")
        try storePending(email: otherEmail, accessToken: "access-b")

        // Bound in the opposite order to the sign-ins: keys, not ordering, decide.
        try await provider.linkAccount(accountID: otherAccountID, identity: identity(otherEmail))
        try await provider.linkAccount(accountID: accountID, identity: identity(email))

        XCTAssertEqual(try keychain.getString(GmailProvider.emailKeyPrefix + accountID.uuidString), email)
        XCTAssertEqual(try keychain.getString(GmailProvider.emailKeyPrefix + otherAccountID.uuidString), otherEmail)
        let stateA = try GmailAuthStateArchiver.unarchive(XCTUnwrap(try keychain.get(GmailProvider.authStateKeyPrefix + accountID.uuidString)))
        let stateB = try GmailAuthStateArchiver.unarchive(XCTUnwrap(try keychain.get(GmailProvider.authStateKeyPrefix + otherAccountID.uuidString)))
        XCTAssertEqual(stateA.lastTokenResponse?.accessToken, "access-a")
        XCTAssertEqual(stateB.lastTokenResponse?.accessToken, "access-b")
    }

    func testExpiredPendingSignInIsDiscardedAndNotBound() async throws {
        let provider = makeProvider(server: GmailStubServer(), tokenOverride: true)
        try storePending(createdAt: Date().addingTimeInterval(-GmailProvider.pendingSignInLifetime - 1))

        await assertThrowsProviderError("notAuthenticated", { if case .notAuthenticated = $0 { return true }; return false }) {
            try await provider.linkAccount(accountID: self.accountID, identity: self.identity(self.email))
        }
        XCTAssertNil(try keychain.get(GmailProvider.pendingSignInKey(for: email)))
        let stored = await provider.hasStoredAuthorization(accountID: accountID)
        XCTAssertFalse(stored)
    }

    func testFetchWithoutStoredStateIsNotAuthenticatedAndNeverClaimsAPendingSignIn() async throws {
        let server = GmailStubServer()
        let provider = makeProvider(server: server, tokenOverride: false)
        try storePending(email: otherEmail)

        // No lazy adoption: an id without bound state stays notAuthenticated even though a sign-in is pending.
        await assertThrowsProviderError("notAuthenticated", { if case .notAuthenticated = $0 { return true }; return false }) {
            _ = try await provider.fetchNewMessages(accountID: accountID, cursor: nil, lookback: 3600)
        }
        XCTAssertNotNil(try keychain.get(GmailProvider.pendingSignInKey(for: otherEmail)), "still pending for the right account")
        let stored = await provider.hasStoredAuthorization(accountID: accountID)
        XCTAssertFalse(stored)
        XCTAssertTrue(server.requests.isEmpty)

        // Binding it explicitly to that id is what makes it usable.
        try await provider.linkAccount(accountID: accountID, identity: identity(otherEmail))
        stubEmptyMailbox(server)
        _ = try await provider.fetchNewMessages(accountID: accountID, cursor: nil, lookback: 3600)
        XCTAssertEqual(server.requests.first?.headers["Authorization"], "Bearer access-1", "token from the bound OIDAuthState")
    }

    // MARK: - Sign-out

    func testSignOutStopsRevokesUnregistersAndDeletes() async throws {
        let server = GmailStubServer()
        server.handle { request in
            switch (request.method, request.url.host ?? "", request.path) {
            case ("POST", "gmail.googleapis.com", GmailFixtures.gmailPath + "/stop"): return .empty
            case ("POST", "oauth2.googleapis.com", "/revoke"): return .json([String: String]())
            case ("DELETE", "relay.test", _): return .empty
            default: return .notFound
            }
        }
        let provider = makeProvider(server: server, tokenOverride: false)
        try keychain.set(try GmailAuthStateArchiver.archive(Self.makeAuthState()), for: GmailProvider.authStateKeyPrefix + accountID.uuidString)
        try keychain.setString("person@example.com", for: GmailProvider.emailKeyPrefix + accountID.uuidString)

        try await provider.signOut(accountID: accountID)

        let calls = server.requests.map { "\($0.method) \($0.url.host ?? "")\($0.path)" }
        let expectedKey = AppConfig(relaySalt: "salt").accountKey(for: "person@example.com")
        XCTAssertEqual(calls, [
            "POST gmail.googleapis.com/gmail/v1/users/me/stop",
            "POST oauth2.googleapis.com/revoke",
            "DELETE relay.test/v1/devices/accounts/\(expectedKey)",
        ])
        XCTAssertEqual(server.requests[0].headers["Authorization"], "Bearer access-1")
        XCTAssertEqual(server.requests[1].formBody["token"], "refresh-1", "the refresh token is revoked")
        XCTAssertNil(try keychain.get(GmailProvider.authStateKeyPrefix + accountID.uuidString))
        XCTAssertNil(try keychain.getString(GmailProvider.emailKeyPrefix + accountID.uuidString))
        let stored = await provider.hasStoredAuthorization(accountID: accountID)
        XCTAssertFalse(stored)
    }

    func testSignOutStillDeletesWhenRemoteCallsFail() async throws {
        let server = GmailStubServer()
        server.handle { _ in GmailStubServer.Response(status: 500, body: Data()) }
        let provider = makeProvider(server: server, tokenOverride: false)
        try keychain.set(try GmailAuthStateArchiver.archive(Self.makeAuthState()), for: GmailProvider.authStateKeyPrefix + accountID.uuidString)

        try await provider.signOut(accountID: accountID)

        XCTAssertNil(try keychain.get(GmailProvider.authStateKeyPrefix + accountID.uuidString))
        XCTAssertFalse(server.requests.isEmpty)
    }
}

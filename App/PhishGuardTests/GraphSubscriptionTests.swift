import Foundation
import PhishCore
import XCTest
@testable import PhishGuard

/// `MicrosoftProvider.ensurePushSubscription` / `linkAccount` / `signOut` through the URLProtocol stub and a
/// recording relay.
final class GraphSubscriptionTests: XCTestCase {
    private let email = "Someone@Outlook.com"
    private let now = MicrosoftHarness.fixedNow
    private let lifecycleURL = "https://relay.example.test/v1/graph/lifecycle"

    override func tearDown() {
        GraphStubProtocol.state.deactivate()
        super.tearDown()
    }

    private func seededSecrets(accountID: UUID) -> InMemorySecretStore {
        InMemorySecretStore([
            MicrosoftKeychainKeys.accountIdentifier(accountID): "uid.utid",
            MicrosoftKeychainKeys.email(accountID): email,
        ])
    }

    private var expectedAccountKey: String {
        AppConfig(relaySalt: MicrosoftHarness.relaySalt).accountKey(for: email)
    }

    // MARK: - Pure helpers

    func testExpirationMathIsMaxLifetimeMinusOneHour() {
        XCTAssertEqual(GraphSubscriptionManager.maxLifetime, 7 * 24 * 3600)
        XCTAssertEqual(GraphSubscriptionManager.requestedLifetime, (6 * 24 + 23) * 3600)
        XCTAssertEqual(GraphSubscriptionManager.expiration(from: now), now.addingTimeInterval(GraphSubscriptionManager.requestedLifetime))
    }

    func testNotificationURLIsRelayBaseWithGraphPath() {
        XCTAssertEqual(GraphSubscriptionManager.notificationURL(relayBaseURL: URL(string: "https://relay.example.test")!).absoluteString,
                       "https://relay.example.test/v1/graph/notifications")
        XCTAssertEqual(GraphSubscriptionManager.notificationURL(relayBaseURL: URL(string: "https://relay.example.test/")!).absoluteString,
                       "https://relay.example.test/v1/graph/notifications")
    }

    func testLifecycleURLIsRelayBaseWithLifecyclePath() {
        XCTAssertEqual(GraphSubscriptionManager.lifecycleURL(relayBaseURL: URL(string: "https://relay.example.test")!).absoluteString, lifecycleURL)
        XCTAssertEqual(GraphSubscriptionManager.lifecycleURL(relayBaseURL: URL(string: "https://relay.example.test/")!).absoluteString, lifecycleURL)
        XCTAssertNotEqual(GraphSubscriptionManager.lifecyclePath, GraphSubscriptionManager.notificationPath)
    }

    func testCreateBodyShape() throws {
        let body = try GraphSubscriptionManager.createBody(
            notificationURL: URL(string: "https://relay.example.test/v1/graph/notifications")!,
            lifecycleURL: URL(string: lifecycleURL)!,
            clientState: "abc",
            expiration: Date(timeIntervalSince1970: 1_790_000_000)
        )
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: String])
        XCTAssertEqual(json, [
            "changeType": "created",
            "notificationUrl": "https://relay.example.test/v1/graph/notifications",
            "lifecycleNotificationUrl": lifecycleURL,
            "resource": "me/mailFolders('Inbox')/messages",
            "expirationDateTime": "2026-09-21T14:13:20.000Z",
            "clientState": "abc",
        ])
    }

    func testClientStateIsHexOfRandomBytes() {
        XCTAssertEqual(GraphSubscriptionManager.clientState(randomBytes: [0, 1, 255, 16]), "0001ff10")
        let bytes = MicrosoftProvider.Dependencies().randomBytes(GraphSubscriptionManager.clientStateByteCount)
        XCTAssertEqual(bytes.count, 32)
        let state = GraphSubscriptionManager.clientState(randomBytes: bytes)
        XCTAssertEqual(state.count, 64)
        XCTAssertLessThanOrEqual(state.count, 128, "Graph caps clientState at 128 characters")
        XCTAssertTrue(state.allSatisfy { $0.isHexDigit })
        XCTAssertNotEqual(state, GraphSubscriptionManager.clientState(randomBytes: MicrosoftProvider.Dependencies().randomBytes(32)))
    }

    // MARK: - Create

    func testCreatesSubscriptionRegistersRelayAndPersistsSecrets() async throws {
        let accountID = UUID()
        let fixedBytes: [UInt8] = Array(repeating: 0xAB, count: 32)
        let harness = MicrosoftHarness(accountID: accountID, secrets: seededSecrets(accountID: accountID), randomBytes: { _ in fixedBytes })
        let expectedExpiry = now.addingTimeInterval(GraphSubscriptionManager.requestedLifetime)
        let graphExpiry = GraphDate.string(from: expectedExpiry.addingTimeInterval(-1)) // Graph may round; trust the response
        harness.router.add("POST", contains: "/v1.0/subscriptions", response: .json(GraphFixtures.subscription(id: "sub-1", expiration: graphExpiry), status: 201))

        let state = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: nil)

        let expectedClientState = String(repeating: "ab", count: 32)
        XCTAssertEqual(state.id, "sub-1")
        XCTAssertEqual(state.expiresAt.timeIntervalSince1970, expectedExpiry.timeIntervalSince1970 - 1, accuracy: 0.001)
        XCTAssertEqual(state.relayAccountKey, expectedAccountKey)

        let post = try XCTUnwrap(harness.requests("POST", containing: "/subscriptions").first)
        XCTAssertEqual(post.header("Authorization"), "Bearer test-access-token")
        XCTAssertEqual(post.header("Content-Type"), "application/json")
        XCTAssertEqual(post.header("Prefer"), "IdType=\"ImmutableId\"")
        let body = post.jsonBody
        XCTAssertEqual(body["changeType"] as? String, "created")
        XCTAssertEqual(body["notificationUrl"] as? String, "https://relay.example.test/v1/graph/notifications")
        XCTAssertEqual(body["lifecycleNotificationUrl"] as? String, lifecycleURL, "lifecycle events must be routed to the relay; the URL can only be set at creation")
        XCTAssertEqual(body["resource"] as? String, "me/mailFolders('Inbox')/messages")
        XCTAssertEqual(body["clientState"] as? String, expectedClientState)
        XCTAssertEqual(body["expirationDateTime"] as? String, GraphDate.string(from: expectedExpiry))
        XCTAssertEqual(Set(body.keys), ["changeType", "notificationUrl", "lifecycleNotificationUrl", "resource", "clientState", "expirationDateTime"])

        XCTAssertEqual(harness.relay.calls, [
            .registerAccount(accountKey: expectedAccountKey, provider: .microsoft),
            .registerGraphSubscription(subscriptionID: "sub-1", accountKey: expectedAccountKey, clientState: expectedClientState),
        ])
        XCTAssertEqual(harness.secrets.all[MicrosoftKeychainKeys.clientState(accountID)], expectedClientState)
        XCTAssertEqual(harness.secrets.all[MicrosoftKeychainKeys.subscriptionID(accountID)], "sub-1")
        XCTAssertEqual(harness.requests.count, 1, "no /me call when the address is stored")
    }

    func testClientStateIsRegeneratedPerCreate() async throws {
        let accountID = UUID()
        let harness = MicrosoftHarness(accountID: accountID, secrets: seededSecrets(accountID: accountID))
        harness.router.add("POST", contains: "/v1.0/subscriptions", sequence: [
            .json(GraphFixtures.subscription(id: "sub-a", expiration: GraphDate.string(from: now.addingTimeInterval(3600))), status: 201),
            .json(GraphFixtures.subscription(id: "sub-b", expiration: GraphDate.string(from: now.addingTimeInterval(3600))), status: 201),
        ])

        _ = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: nil)
        let first = try XCTUnwrap(harness.secrets.all[MicrosoftKeychainKeys.clientState(accountID)])
        let expired = PushSubscriptionState(id: "sub-a", expiresAt: now.addingTimeInterval(-60), relayAccountKey: expectedAccountKey)
        _ = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: expired)
        let second = try XCTUnwrap(harness.secrets.all[MicrosoftKeychainKeys.clientState(accountID)])

        XCTAssertEqual(first.count, 64)
        XCTAssertEqual(second.count, 64)
        XCTAssertNotEqual(first, second)
        let sent = harness.requests("POST", containing: "/subscriptions").map { $0.jsonBody["clientState"] as? String }
        XCTAssertEqual(sent, [first, second])
        XCTAssertEqual(harness.requests("PATCH", containing: "/subscriptions").count, 0, "an expired subscription is recreated, not renewed")
    }

    func testMissingStoredEmailIsFetchedFromMeAndPersisted() async throws {
        let accountID = UUID()
        let secrets = InMemorySecretStore([MicrosoftKeychainKeys.accountIdentifier(accountID): "uid.utid"])
        let harness = MicrosoftHarness(accountID: accountID, secrets: secrets)
        harness.router.add("GET", contains: "/v1.0/me?", response: .json(["id": "user-1", "mail": NSNull(), "userPrincipalName": email, "displayName": "Some One"]))
        harness.router.add("POST", contains: "/v1.0/subscriptions", response: .json(GraphFixtures.subscription(id: "sub-2", expiration: GraphDate.string(from: now.addingTimeInterval(3600))), status: 201))

        let state = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: nil)

        XCTAssertEqual(state.relayAccountKey, expectedAccountKey, "userPrincipalName is used when mail is null")
        let me = try XCTUnwrap(harness.requests("GET", containing: "/me?").first)
        XCTAssertEqual(me.query["$select"], "id,mail,userPrincipalName,displayName")
        XCTAssertEqual(secrets.all[MicrosoftKeychainKeys.email(accountID)], email)
    }

    // MARK: - Account binding

    func testLinkAccountStoresIdentifierAndAddressUnderTheAccountID() async throws {
        let accountID = UUID()
        let secrets = InMemorySecretStore()
        let harness = MicrosoftHarness(accountID: accountID, secrets: secrets)
        harness.router.add("POST", contains: "/v1.0/subscriptions", response: .json(GraphFixtures.subscription(id: "sub-3", expiration: GraphDate.string(from: now.addingTimeInterval(3600))), status: 201))

        try await harness.provider.linkAccount(accountID: accountID, identity: SignedInIdentity(providerAccountID: "uid.utid", email: email, displayName: "Some One"))

        XCTAssertEqual(secrets.all[MicrosoftKeychainKeys.accountIdentifier(accountID)], "uid.utid")
        XCTAssertEqual(secrets.all[MicrosoftKeychainKeys.email(accountID)], email)
        let identifier = await harness.provider.storedAccountIdentifier(accountID: accountID)
        XCTAssertEqual(identifier, "uid.utid")

        let state = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: nil)
        XCTAssertEqual(state.relayAccountKey, expectedAccountKey, "the bound address derives the relay key without a /me call")
        XCTAssertEqual(harness.requests("GET", containing: "/me?").count, 0)
    }

    func testLinkAccountReplacesTheStoredIdentifierForTheSameMailbox() async throws {
        let accountID = UUID()
        let secrets = InMemorySecretStore([
            MicrosoftKeychainKeys.accountIdentifier(accountID): "old-uid.utid",
            MicrosoftKeychainKeys.email(accountID): email,
        ])
        let harness = MicrosoftHarness(accountID: accountID, secrets: secrets)

        try await harness.provider.linkAccount(accountID: accountID, identity: SignedInIdentity(providerAccountID: "new-uid.utid", email: email.lowercased()))

        XCTAssertEqual(secrets.all[MicrosoftKeychainKeys.accountIdentifier(accountID)], "new-uid.utid", "a re-sign-in replaces the record")
        XCTAssertEqual(secrets.all[MicrosoftKeychainKeys.email(accountID)], email.lowercased())
    }

    func testLinkAccountRefusesADifferentMailboxForAnExistingAccount() async throws {
        let accountID = UUID()
        let secrets = seededSecrets(accountID: accountID)
        let harness = MicrosoftHarness(accountID: accountID, secrets: secrets)

        do {
            try await harness.provider.linkAccount(accountID: accountID, identity: SignedInIdentity(providerAccountID: "other-uid.utid", email: "someone.else@outlook.com"))
            XCTFail("expected notAuthenticated")
        } catch let error as ProviderError {
            guard case .notAuthenticated = error else { return XCTFail("unexpected \(error)") }
        }
        XCTAssertEqual(secrets.all[MicrosoftKeychainKeys.accountIdentifier(accountID)], "uid.utid", "the existing binding is untouched")
        XCTAssertEqual(secrets.all[MicrosoftKeychainKeys.email(accountID)], email)
    }

    func testUnboundAccountIsNotAuthenticatedAndNothingIsClaimed() async throws {
        // No injected token provider: the real `accessToken` path runs, which must fail BEFORE consulting MSAL.
        let accountID = UUID()
        let secrets = InMemorySecretStore([
            MicrosoftKeychainKeys.accountIdentifier(UUID()): "someone-elses-uid.utid",
        ])
        var dependencies = MicrosoftProvider.Dependencies()
        dependencies.session = GraphStubProtocol.makeSession()
        dependencies.secrets = secrets
        dependencies.makeRelay = { _ in RecordingRelay() }
        let config = AppConfig(microsoftClientID: "11111111-2222-3333-4444-555555555555", relayBaseURL: MicrosoftHarness.relayBaseURL, relayAPIKey: "k", relaySalt: MicrosoftHarness.relaySalt, bundleIdentifier: "com.mazooni.PhishGuardTests")
        let provider = MicrosoftProvider(config: config, keychain: Keychain(service: "PhishGuardTests.unused"), dependencies: dependencies)
        GraphStubProtocol.state.activate(StubRouter())

        for _ in 0..<2 {
            do {
                _ = try await provider.fetchNewMessages(accountID: accountID, cursor: nil, lookback: 3600)
                XCTFail("expected notAuthenticated")
            } catch let error as ProviderError {
                guard case .notAuthenticated = error else { return XCTFail("unexpected \(error)") }
            }
        }
        XCTAssertNil(secrets.all[MicrosoftKeychainKeys.accountIdentifier(accountID)], "never bound to another account's identifier")
        XCTAssertEqual(secrets.all.count, 1)
        XCTAssertEqual(GraphStubProtocol.state.requests.count, 0)
        let identifier = await provider.storedAccountIdentifier(accountID: accountID)
        XCTAssertNil(identifier)
    }

    func testRelayRegistrationFailureDeletesTheNewSubscription() async throws {
        let accountID = UUID()
        let harness = MicrosoftHarness(accountID: accountID, secrets: seededSecrets(accountID: accountID))
        harness.relay.failRegistrations(true)
        harness.router.add("POST", contains: "/v1.0/subscriptions", response: .json(GraphFixtures.subscription(id: "sub-4", expiration: GraphDate.string(from: now.addingTimeInterval(3600))), status: 201))
        harness.router.add("DELETE", contains: "/v1.0/subscriptions/sub-4", response: StubResponse(status: 204))

        do {
            _ = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: nil)
            XCTFail("expected the relay failure to propagate")
        } catch is RecordingRelay.Failure {
            // expected
        }
        XCTAssertEqual(harness.requests("DELETE", containing: "/subscriptions/sub-4").count, 1)
        XCTAssertNil(harness.secrets.all[MicrosoftKeychainKeys.subscriptionID(accountID)])
    }

    func testConflictDeletesExistingSubscriptionAndRetries() async throws {
        let accountID = UUID()
        let harness = MicrosoftHarness(accountID: accountID, secrets: seededSecrets(accountID: accountID))
        harness.router.add("POST", contains: "/v1.0/subscriptions", sequence: [
            .graphError(status: 409, code: "ExtensionError", message: "Subscription Id old-sub already exists for the requested combination"),
            .json(GraphFixtures.subscription(id: "sub-5", expiration: GraphDate.string(from: now.addingTimeInterval(3600))), status: 201),
        ])
        harness.router.add("GET", contains: "/v1.0/subscriptions", response: .json(["value": [
            GraphFixtures.subscription(id: "old-sub", expiration: GraphDate.string(from: now.addingTimeInterval(3600))),
            GraphFixtures.subscription(id: "other-app", expiration: GraphDate.string(from: now.addingTimeInterval(3600)), notificationUrl: "https://elsewhere.example/hook"),
        ]]))
        harness.router.add("DELETE", contains: "/v1.0/subscriptions/old-sub", response: StubResponse(status: 204))

        let state = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: nil)

        XCTAssertEqual(state.id, "sub-5")
        XCTAssertEqual(harness.requests.map { "\($0.method) \($0.path)" }, [
            "POST /v1.0/subscriptions",
            "GET /v1.0/subscriptions",
            "DELETE /v1.0/subscriptions/old-sub",
            "POST /v1.0/subscriptions",
        ])
        XCTAssertEqual(harness.relay.calls.count, 2)
    }

    // MARK: - Renew

    func testRenewsWhenExpiringWithin24Hours() async throws {
        let accountID = UUID()
        let harness = MicrosoftHarness(accountID: accountID, secrets: seededSecrets(accountID: accountID))
        let current = PushSubscriptionState(id: "sub-6", expiresAt: now.addingTimeInterval(2 * 3600), relayAccountKey: "existing-key")
        let renewedExpiry = now.addingTimeInterval(GraphSubscriptionManager.requestedLifetime)
        harness.router.add("PATCH", contains: "/v1.0/subscriptions/sub-6", response: .json(GraphFixtures.subscription(id: "sub-6", expiration: GraphDate.string(from: renewedExpiry))))

        let state = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: current)

        XCTAssertEqual(state.id, "sub-6")
        XCTAssertEqual(state.relayAccountKey, "existing-key")
        XCTAssertEqual(state.expiresAt.timeIntervalSince1970, renewedExpiry.timeIntervalSince1970, accuracy: 0.001)
        let patch = try XCTUnwrap(harness.requests("PATCH", containing: "/subscriptions/sub-6").first)
        XCTAssertEqual(patch.jsonBody as? [String: String], ["expirationDateTime": GraphDate.string(from: renewedExpiry)])
        XCTAssertEqual(harness.requests.count, 1)
        XCTAssertEqual(harness.relay.calls, [], "renewal does not re-register")
        XCTAssertEqual(harness.secrets.all[MicrosoftKeychainKeys.subscriptionID(accountID)], "sub-6")
    }

    func testRenewFallsBackToRequestedExpiryWhenResponseHasNone() async throws {
        let accountID = UUID()
        let harness = MicrosoftHarness(accountID: accountID, secrets: seededSecrets(accountID: accountID))
        let current = PushSubscriptionState(id: "sub-7", expiresAt: now.addingTimeInterval(60), relayAccountKey: "k")
        harness.router.add("PATCH", contains: "/v1.0/subscriptions/sub-7", response: StubResponse(status: 200))

        let state = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: current)
        XCTAssertEqual(state.expiresAt, GraphSubscriptionManager.expiration(from: now))
    }

    func testRenew404CreatesNewSubscriptionAndReRegisters() async throws {
        let accountID = UUID()
        let harness = MicrosoftHarness(accountID: accountID, secrets: seededSecrets(accountID: accountID))
        let current = PushSubscriptionState(id: "sub-8", expiresAt: now.addingTimeInterval(3600), relayAccountKey: "existing-key")
        harness.router.add("PATCH", contains: "/v1.0/subscriptions/sub-8", response: .graphError(status: 404, code: "ResourceNotFound"))
        harness.router.add("POST", contains: "/v1.0/subscriptions", response: .json(GraphFixtures.subscription(id: "sub-9", expiration: GraphDate.string(from: now.addingTimeInterval(3600))), status: 201))

        let state = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: current)

        XCTAssertEqual(state.id, "sub-9")
        XCTAssertEqual(state.relayAccountKey, "existing-key", "the account key is kept")
        let clientState = try XCTUnwrap(harness.secrets.all[MicrosoftKeychainKeys.clientState(accountID)])
        XCTAssertEqual(harness.relay.calls, [
            .registerAccount(accountKey: "existing-key", provider: .microsoft),
            .registerGraphSubscription(subscriptionID: "sub-9", accountKey: "existing-key", clientState: clientState),
        ])
        XCTAssertEqual(harness.requests.map(\.method), ["PATCH", "POST"])
    }

    func testRenewOtherErrorsPropagate() async throws {
        let accountID = UUID()
        let harness = MicrosoftHarness(accountID: accountID, secrets: seededSecrets(accountID: accountID))
        let current = PushSubscriptionState(id: "sub-10", expiresAt: now.addingTimeInterval(3600), relayAccountKey: "k")
        harness.router.add("PATCH", contains: "/v1.0/subscriptions/sub-10", response: .graphError(status: 403, code: "Forbidden"))

        do {
            _ = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: current)
            XCTFail("expected an error")
        } catch let error as ProviderError {
            guard case .http(403, _) = error else { return XCTFail("unexpected \(error)") }
        }
        XCTAssertEqual(harness.requests("POST", containing: "/subscriptions").count, 0)
    }

    /// The coordinator only calls when expiring within 24 h OR when a renewal is forced (lifecycle event, cursor
    /// reset), so a subscription that still has days left must be PATCHed rather than returned untouched —
    /// otherwise a `subscriptionRemoved`/`reauthorizationRequired` event would be ignored for days.
    func testHealthySubscriptionIsStillRenewedWhenAsked() async throws {
        let accountID = UUID()
        let harness = MicrosoftHarness(accountID: accountID, secrets: seededSecrets(accountID: accountID))
        let current = PushSubscriptionState(id: "sub-11", expiresAt: now.addingTimeInterval(3 * 24 * 3600), relayAccountKey: "k")
        let renewedExpiry = now.addingTimeInterval(GraphSubscriptionManager.requestedLifetime)
        harness.router.add("PATCH", contains: "/v1.0/subscriptions/sub-11", response: .json(GraphFixtures.subscription(id: "sub-11", expiration: GraphDate.string(from: renewedExpiry))))

        let state = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: current)

        XCTAssertEqual(state.id, "sub-11")
        XCTAssertEqual(state.relayAccountKey, "k")
        XCTAssertEqual(state.expiresAt.timeIntervalSince1970, renewedExpiry.timeIntervalSince1970, accuracy: 0.001)
        XCTAssertEqual(harness.requests.map(\.method), ["PATCH"])
        XCTAssertEqual(harness.relay.calls, [])
    }

    func testForcedRenewalOfARemovedSubscriptionRecreatesIt() async throws {
        // Lifecycle `subscriptionRemoved` days before expiry: PATCH → 404 → new subscription, relay re-registered.
        let accountID = UUID()
        let harness = MicrosoftHarness(accountID: accountID, secrets: seededSecrets(accountID: accountID))
        let current = PushSubscriptionState(id: "sub-14", expiresAt: now.addingTimeInterval(5 * 24 * 3600), relayAccountKey: "existing-key")
        harness.router.add("PATCH", contains: "/v1.0/subscriptions/sub-14", response: .graphError(status: 404, code: "ResourceNotFound"))
        harness.router.add("POST", contains: "/v1.0/subscriptions", response: .json(GraphFixtures.subscription(id: "sub-15", expiration: GraphDate.string(from: now.addingTimeInterval(3600))), status: 201))

        let state = try await harness.provider.ensurePushSubscription(accountID: accountID, relay: harness.relayConfig, current: current)

        XCTAssertEqual(state.id, "sub-15")
        XCTAssertEqual(harness.requests.map(\.method), ["PATCH", "POST"])
        XCTAssertEqual(harness.relay.calls.count, 2)
    }

    // MARK: - Sign out

    func testSignOutDeletesSubscriptionUnregistersRelayAndClearsSecrets() async throws {
        let accountID = UUID()
        let secrets = seededSecrets(accountID: accountID)
        try secrets.setString("sub-12", for: MicrosoftKeychainKeys.subscriptionID(accountID))
        try secrets.setString("deadbeef", for: MicrosoftKeychainKeys.clientState(accountID))
        try secrets.setString("other", for: "unrelated.key")
        let harness = MicrosoftHarness(accountID: accountID, secrets: secrets)
        harness.router.add("DELETE", contains: "/v1.0/subscriptions/sub-12", response: StubResponse(status: 204))

        try await harness.provider.signOut(accountID: accountID)

        XCTAssertEqual(harness.requests.map { "\($0.method) \($0.path)" }, ["DELETE /v1.0/subscriptions/sub-12"])
        XCTAssertEqual(harness.relay.calls, [.unregisterAccount(accountKey: expectedAccountKey)])
        XCTAssertEqual(secrets.all, ["unrelated.key": "other"])
    }

    func testSignOutToleratesRemoteFailures() async throws {
        let accountID = UUID()
        let secrets = seededSecrets(accountID: accountID)
        try secrets.setString("sub-13", for: MicrosoftKeychainKeys.subscriptionID(accountID))
        let harness = MicrosoftHarness(accountID: accountID, secrets: secrets)
        harness.relay.failRegistrations(true)
        harness.router.add("DELETE", contains: "/v1.0/subscriptions/sub-13", response: .graphError(status: 500, code: "InternalServerError"))

        try await harness.provider.signOut(accountID: accountID)

        XCTAssertEqual(secrets.all, [:])
        XCTAssertEqual(harness.relay.calls, [.unregisterAccount(accountKey: expectedAccountKey)])
    }

    func testSignOutWithoutStateOnlyClearsSecrets() async throws {
        let accountID = UUID()
        let harness = MicrosoftHarness(accountID: accountID, secrets: InMemorySecretStore())

        try await harness.provider.signOut(accountID: accountID)

        XCTAssertEqual(harness.requests.count, 0)
        XCTAssertEqual(harness.relay.calls, [])
    }
}

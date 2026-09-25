import Foundation
import PhishCore
import SwiftData
import Synchronization
import UIKit
import XCTest
@testable import PhishGuard

/// `AccountLinker.linkIdentity`: the sign-in returned by a provider is bound to the (new or re-used) `LinkedAccount`
/// id synchronously, before the account is saved and before any scan can touch it.
final class AccountLinkerTests: XCTestCase {
    /// Records `linkAccount` calls; optionally fails them.
    private final class RecordingProvider: MailAccountProvider, Sendable {
        struct Bound: Equatable, Sendable {
            var accountID: UUID
            var identity: SignedInIdentity
        }

        let provider: MailProvider
        private let bound = Mutex<[Bound]>([])
        private let failure = Mutex<(any Error)?>(nil)

        init(provider: MailProvider) {
            self.provider = provider
        }

        var boundCalls: [Bound] { bound.withLock { $0 } }
        func fail(with error: any Error) { failure.withLock { $0 = error } }

        @MainActor
        func signIn(presenting: UIViewController) async throws -> SignedInIdentity {
            throw ProviderError.notImplemented("RecordingProvider.signIn")
        }

        func signOut(accountID: UUID) async throws {}

        func linkAccount(accountID: UUID, identity: SignedInIdentity) async throws {
            if let error = failure.withLock({ $0 }) { throw error }
            bound.withLock { $0.append(Bound(accountID: accountID, identity: identity)) }
        }

        func fetchNewMessages(accountID: UUID, cursor: SyncCursor?, lookback: TimeInterval) async throws -> FetchResult {
            FetchResult(messages: [], cursor: SyncCursor(opaque: "c"))
        }

        func ensurePushSubscription(accountID: UUID, relay: RelayConfig, current: PushSubscriptionState?) async throws -> PushSubscriptionState {
            PushSubscriptionState(id: "sub", expiresAt: .distantFuture, relayAccountKey: "k")
        }
    }

    private let config = AppConfig(relaySalt: "salt")

    /// The container must outlive the context (a `mainContext` whose container was released crashes on insert).
    private var container: ModelContainer!

    @MainActor
    private func makeContext() throws -> ModelContext {
        container = try Persistence.makeContainer(inMemory: true)
        return container.mainContext
    }

    override func tearDown() {
        container = nil
        super.tearDown()
    }

    @MainActor
    private func accounts(in context: ModelContext) throws -> [LinkedAccount] {
        try context.fetch(FetchDescriptor<LinkedAccount>())
    }

    @MainActor
    func testNewAccountIsBoundToItsFreshIdBeforeSaving() async throws {
        let context = try makeContext()
        let provider = RecordingProvider(provider: .gmail)
        let identity = SignedInIdentity(providerAccountID: "sub-1", email: "Sam@Example.com", displayName: "Sam")

        let account = try await AccountLinker.linkIdentity(identity, kind: .gmail, provider: provider, config: config, in: context)

        XCTAssertEqual(provider.boundCalls, [.init(accountID: account.id, identity: identity)], "bound exactly once, to the new id")
        XCTAssertFalse(context.hasChanges, "saved after binding")
        let stored = try accounts(in: context)
        XCTAssertEqual(stored.map(\.id), [account.id])
        XCTAssertEqual(stored.first?.email, "Sam@Example.com")
        XCTAssertEqual(stored.first?.relayAccountKey, config.accountKey(for: "sam@example.com"))
        XCTAssertFalse(stored.first?.needsReauthentication ?? true)
    }

    @MainActor
    func testReSignInReusesTheExistingAccountAndRebindsIt() async throws {
        let context = try makeContext()
        let provider = RecordingProvider(provider: .gmail)
        let existing = LinkedAccount(provider: .gmail, email: "sam@example.com", isEnabled: false, needsReauthentication: true)
        context.insert(existing)
        try context.save()

        let identity = SignedInIdentity(providerAccountID: "sub-1", email: "SAM@example.com")
        let account = try await AccountLinker.linkIdentity(identity, kind: .gmail, provider: provider, config: config, in: context)

        XCTAssertEqual(account.id, existing.id, "same address → same LinkedAccount (its alerts survive)")
        XCTAssertEqual(provider.boundCalls, [.init(accountID: existing.id, identity: identity)], "the fresh credentials replace the revoked ones under the SAME id")
        XCTAssertTrue(existing.isEnabled)
        XCTAssertFalse(existing.needsReauthentication, "a successful re-sign-in clears the flag")
        XCTAssertEqual(try accounts(in: context).count, 1)
    }

    @MainActor
    func testBindingFailureRollsBackANewAccount() async throws {
        let context = try makeContext()
        let provider = RecordingProvider(provider: .microsoft)
        provider.fail(with: ProviderError.notAuthenticated)

        do {
            _ = try await AccountLinker.linkIdentity(SignedInIdentity(providerAccountID: "id", email: "new@outlook.com"), kind: .microsoft, provider: provider, config: config, in: context)
            XCTFail("expected the binding error to propagate")
        } catch let error as ProviderError {
            guard case .notAuthenticated = error else { return XCTFail("unexpected \(error)") }
        }
        XCTAssertEqual(try accounts(in: context).count, 0, "no half-linked account is left behind")
        XCTAssertTrue(provider.boundCalls.isEmpty)
    }

    @MainActor
    func testBindingFailureLeavesAnExistingAccountUnchanged() async throws {
        let context = try makeContext()
        let provider = RecordingProvider(provider: .gmail)
        let existing = LinkedAccount(provider: .gmail, email: "sam@example.com", isEnabled: false, needsReauthentication: true)
        context.insert(existing)
        try context.save()
        provider.fail(with: ProviderError.notAuthenticated)

        do {
            _ = try await AccountLinker.linkIdentity(SignedInIdentity(providerAccountID: "sub-1", email: "sam@example.com"), kind: .gmail, provider: provider, config: config, in: context)
            XCTFail("expected the binding error to propagate")
        } catch is ProviderError {
            // expected
        }
        let stored = try XCTUnwrap(try accounts(in: context).first)
        XCTAssertEqual(stored.id, existing.id)
        XCTAssertTrue(stored.needsReauthentication, "still flagged: the new tokens were not bound")
        XCTAssertFalse(stored.isEnabled, "the rollback restores the pre-link state")
    }

    @MainActor
    func testLinkedAccountDefaultsToNotNeedingReauthentication() throws {
        let context = try makeContext()
        let account = LinkedAccount(provider: .microsoft, email: "x@outlook.com")
        XCTAssertFalse(account.needsReauthentication)
        context.insert(account)
        try context.save()
        account.needsReauthentication = true
        try context.save()
        XCTAssertEqual(try accounts(in: context).first?.needsReauthentication, true, "the flag persists")
    }
}

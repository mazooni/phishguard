import Foundation
import PhishCore
import SwiftData
import Synchronization
import UIKit
@testable import PhishGuard

/// Thread-safe counter for test doubles.
final class Counter: Sendable {
    private let storage = Mutex(0)
    func increment() { storage.withLock { $0 += 1 } }
    var value: Int { storage.withLock { $0 } }
}

/// Fake provider returning canned messages (`defaultMessages` unless overridden), with recorded calls and
/// injectable failures.
final class FakeMailProvider: MailAccountProvider, Sendable {
    /// One benign and two malicious fixtures. Kept explicit so the coordinator tests do not depend on how many
    /// fixtures `SampleEmails.all` grows to; `ScanCoordinatorTests.perMessage` must cover every id in this list.
    static let defaultMessages: [EmailMessage] = [
        SampleEmails.benignNewsletter,
        SampleEmails.paypalPhish,
        SampleEmails.giftCardScam,
    ]

    struct State: Sendable {
        var messages: [EmailMessage] = FakeMailProvider.defaultMessages
        var nextCursor = "cursor-1"
        var cursorWasReset = false
        var fetchError: (any Error)?
        var fetchDelay: Duration?
        var subscriptionError: (any Error)?
        var subscriptionDelay: Duration?
        var fetchCalls: [SyncCursor?] = []
        /// Account ids of every fetch, in call order.
        var fetchAccountIDs: [UUID] = []
        var subscriptionCalls: [PushSubscriptionState?] = []
        /// Message ids the coordinator's `isProcessed` predicate answered true for, in call order across fetches.
        var skippedIDs: [String] = []
        /// False simulates a provider that ignores the `isProcessed` hint (the protocol's default implementation).
        var honorsProcessedHint = true
    }

    let provider: MailProvider
    let state: Mutex<State>

    init(provider: MailProvider, state: State = State()) {
        self.provider = provider
        self.state = Mutex(state)
    }

    var fetchCalls: [SyncCursor?] { state.withLock { $0.fetchCalls } }
    var fetchAccountIDs: [UUID] { state.withLock { $0.fetchAccountIDs } }
    var subscriptionCalls: [PushSubscriptionState?] { state.withLock { $0.subscriptionCalls } }
    var skippedIDs: [String] { state.withLock { $0.skippedIDs } }

    @MainActor
    func signIn(presenting: UIViewController) async throws -> SignedInIdentity {
        throw ProviderError.notImplemented("FakeMailProvider.signIn")
    }

    func signOut(accountID: UUID) async throws {}

    func fetchNewMessages(accountID: UUID, cursor: SyncCursor?, lookback: TimeInterval) async throws -> FetchResult {
        let snapshot = state.withLock { state -> State in
            state.fetchCalls.append(cursor)
            state.fetchAccountIDs.append(accountID)
            return state
        }
        if let delay = snapshot.fetchDelay {
            try await Task.sleep(for: delay)
        }
        if let error = snapshot.fetchError {
            throw error
        }
        let messages = snapshot.messages.map { message in
            var copy = message
            copy.accountID = accountID.uuidString
            copy.provider = provider
            return copy
        }
        return FetchResult(messages: messages, cursor: SyncCursor(opaque: snapshot.nextCursor), cursorWasReset: snapshot.cursorWasReset)
    }

    /// Like the real providers: every listed id is checked against `isProcessed` and matches are dropped before
    /// the message would be "downloaded". With `honorsProcessedHint == false` the predicate is never consulted.
    func fetchNewMessages(
        accountID: UUID,
        cursor: SyncCursor?,
        lookback: TimeInterval,
        isProcessed: @escaping @Sendable (_ messageID: String) -> Bool
    ) async throws -> FetchResult {
        let full = try await fetchNewMessages(accountID: accountID, cursor: cursor, lookback: lookback)
        guard state.withLock({ $0.honorsProcessedHint }) else { return full }
        var kept: [EmailMessage] = []
        var skipped: [String] = []
        for message in full.messages {
            if isProcessed(message.messageID) {
                skipped.append(message.messageID)
            } else {
                kept.append(message)
            }
        }
        state.withLock { $0.skippedIDs.append(contentsOf: skipped) }
        return FetchResult(messages: kept, cursor: full.cursor, cursorWasReset: full.cursorWasReset)
    }

    func ensurePushSubscription(accountID: UUID, relay: RelayConfig, current: PushSubscriptionState?) async throws -> PushSubscriptionState {
        let (error, delay) = state.withLock { state -> ((any Error)?, Duration?) in
            state.subscriptionCalls.append(current)
            return (state.subscriptionError, state.subscriptionDelay)
        }
        if let delay {
            try await Task.sleep(for: delay)
        }
        if let error { throw error }
        return PushSubscriptionState(
            id: "sub-\(accountID.uuidString)",
            expiresAt: Date().addingTimeInterval(7 * 24 * 3600),
            relayAccountKey: "key-\(accountID.uuidString)"
        )
    }
}

/// Fake classifier with a fixed behaviour and a call counter.
final class FakeClassifier: EmailClassifier, Sendable {
    enum Behavior: Sendable {
        case fixed(ModelAssessment)
        /// Keyed by `messageID`; unknown ids throw.
        case perMessage([String: ModelAssessment])
        case fail(any Error)
        case unavailable(String)
    }

    /// riskScore 100 ⇒ confidence 1.0 (high) whatever the heuristic score — the model is an independent detector
    /// and `max(heuristic, risk/100)` takes it at its word — so alertability does not depend on the analyzer's
    /// rules, except where the authenticated-brand cap applies.
    static let suspicious = ModelAssessment(isSuspicious: true, category: .phishing, riskScore: 100, reasons: ["Credential lure"], summary: "Credential phishing.")
    static let benign = ModelAssessment(isSuspicious: false, category: .safe, riskScore: 2, reasons: [], summary: "Looks fine.")

    let identifier: String
    let displayName = "Fake classifier"
    private let behavior: Behavior
    /// Simulated inference time; honours task cancellation like a real model call.
    private let assessDelay: Duration?
    private let calls = Counter()
    /// Heuristic signal ids of the report each message was assessed with, keyed by `messageID`.
    private let reports = Mutex<[String: [String]]>([:])

    init(identifier: String = "fake.model", behavior: Behavior, assessDelay: Duration? = nil) {
        self.identifier = identifier
        self.behavior = behavior
        self.assessDelay = assessDelay
    }

    var callCount: Int { calls.value }

    /// Signal ids of the `HeuristicReport` the coordinator handed over for `messageID` (nil when never assessed).
    func reportedSignalIDs(for messageID: String) -> [String]? {
        reports.withLock { $0[messageID] }
    }

    func availability() async -> ClassifierAvailability {
        if case .unavailable(let reason) = behavior { return .unavailable(reason: reason) }
        return .available
    }

    func assess(_ input: ClassificationInput) async throws -> ModelAssessment {
        calls.increment()
        reports.withLock { $0[input.email.messageID] = input.report.signals.map(\.id) }
        if let assessDelay {
            try await Task.sleep(for: assessDelay)
        }
        switch behavior {
        case .fixed(let assessment):
            return assessment
        case .perMessage(let table):
            guard let assessment = table[input.email.messageID] else { throw ClassifierError.invalidOutput("no fixture for message") }
            return assessment
        case .fail(let error):
            throw error
        case .unavailable(let reason):
            throw ClassifierError.unavailable(reason)
        }
    }
}

/// A `FakeClassifier` that claims to run on the GPU (like `MLXClassifier`), so the coordinator's foreground gate
/// applies to it. Everything else is delegated, including the call counter.
final class FakeGPUClassifier: GPUBackedClassifier, Sendable {
    private let inner: FakeClassifier

    init(identifier: String = "fake.gpu.model", behavior: FakeClassifier.Behavior, assessDelay: Duration? = nil) {
        inner = FakeClassifier(identifier: identifier, behavior: behavior, assessDelay: assessDelay)
    }

    var identifier: String { inner.identifier }
    var displayName: String { inner.displayName }
    var callCount: Int { inner.callCount }

    func availability() async -> ClassifierAvailability { await inner.availability() }

    func assess(_ input: ClassificationInput) async throws -> ModelAssessment { try await inner.assess(input) }
}

/// Captures what `NotificationManager` would post.
final class AlertRecorder: Sendable {
    struct Posted: Sendable, Equatable {
        let identifier: String
        let content: NotificationManager.AlertContent
        /// nil for an immediate post; the trigger interval for a scheduled one (the demo simulate button).
        let delay: TimeInterval?

        init(identifier: String, content: NotificationManager.AlertContent, delay: TimeInterval? = nil) {
            self.identifier = identifier
            self.content = content
            self.delay = delay
        }
    }

    /// A Call Guard alert (`NotificationManager.postCallAlert`).
    struct PostedCall: Sendable, Equatable {
        let identifier: String
        let content: NotificationManager.CallAlertContent
        let delay: TimeInterval?
    }

    private let storage = Mutex<[Posted]>([])
    private let callStorage = Mutex<[PostedCall]>([])

    var posted: [Posted] { storage.withLock { $0 } }
    var postedCalls: [PostedCall] { callStorage.withLock { $0 } }

    func makeManager() -> NotificationManager {
        NotificationManager(
            poster: { identifier, content, delay in
                self.storage.withLock { $0.append(Posted(identifier: identifier, content: content, delay: delay)) }
            },
            callPoster: { identifier, content, delay in
                self.callStorage.withLock { $0.append(PostedCall(identifier: identifier, content: content, delay: delay)) }
            }
        )
    }
}

/// In-memory container + fakes wired into a `ScanCoordinator`.
@MainActor
final class ScanHarness {
    let container: ModelContainer
    let alerts = AlertRecorder()
    let releases = Counter()
    let coordinator: ScanCoordinator
    /// Open by default (tests run as if PhishGuard were frontmost); close it with `setForeground(false)` to make
    /// the coordinator behave as it does during a silent push or a BGTask.
    let foregroundGate: AppForegroundGate

    init(
        providers: [MailProvider: any MailAccountProvider],
        classifier: any EmailClassifier,
        settings: ScanSettingsSnapshot = ScanSettingsSnapshot(),
        foregroundGate: AppForegroundGate = AppForegroundGate(isForeground: true),
        maxMessagesPerScan: Int = ScanCoordinator.defaultMaxMessagesPerScan
    ) throws {
        container = try Persistence.makeContainer(inMemory: true)
        self.foregroundGate = foregroundGate
        let releases = self.releases
        coordinator = ScanCoordinator(
            container: container,
            providers: providers,
            notifications: alerts.makeManager(),
            classifierResolver: { classifier },
            settingsResolver: { settings },
            resourceReleaser: { releases.increment() },
            foregroundGate: foregroundGate,
            maxMessagesPerScan: maxMessagesPerScan
        )
    }

    @discardableResult
    func addAccount(
        provider: MailProvider,
        email: String = "user@example.com",
        isEnabled: Bool = true,
        pushSubscriptionExpiresAt: Date? = nil,
        isDemo: Bool = false
    ) throws -> UUID {
        let account = LinkedAccount(
            provider: provider,
            email: email,
            isEnabled: isEnabled,
            pushSubscriptionID: pushSubscriptionExpiresAt == nil ? nil : "existing-sub",
            pushSubscriptionExpiresAt: pushSubscriptionExpiresAt,
            relayAccountKey: pushSubscriptionExpiresAt == nil ? nil : "existing-key",
            isDemo: isDemo
        )
        container.mainContext.insert(account)
        try container.mainContext.save()
        return account.id
    }

    func account(_ id: UUID) throws -> LinkedAccount {
        let context = ModelContext(container)
        let accounts = try context.fetch(FetchDescriptor<LinkedAccount>(predicate: #Predicate { $0.id == id }))
        guard let account = accounts.first else { throw ProviderError.notImplemented("account \(id) missing") }
        return account
    }

    func flaggedRecords() throws -> [FlaggedEmailRecord] {
        try ModelContext(container).fetch(FetchDescriptor<FlaggedEmailRecord>(sortBy: [SortDescriptor(\.flaggedAt)]))
    }

    func processedKeys() throws -> [String] {
        try ModelContext(container).fetch(FetchDescriptor<ProcessedMessage>()).map(\.key).sorted()
    }

    func insertProcessed(key: String, processedAt: Date) throws {
        container.mainContext.insert(ProcessedMessage(key: key, processedAt: processedAt))
        try container.mainContext.save()
    }
}

extension EmailMessage {
    /// Copy of the message with a different id (for volume tests).
    func withMessageID(_ id: String) -> EmailMessage {
        var copy = self
        copy.messageID = id
        return copy
    }
}

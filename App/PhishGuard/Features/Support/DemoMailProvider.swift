#if DEBUG
import Foundation
import PhishCore
import Synchronization
import UIKit

/// The mailbox the screen-recording demo watches (`-PGDemoData 1`), in place of `GmailProvider`.
///
/// It exists because the demo account is fictional: the real provider would answer every scan with
/// `ProviderError.notAuthenticated`, which flips the account to "Needs sign-in", puts a red error in
/// Diagnostics and makes pull-to-refresh look broken on camera. Instead this replays bundled `SampleEmails`
/// fixtures as if they had just arrived, so a scan started from the UI — or from a silent push — runs the real
/// pipeline end to end: `HeuristicAnalyzer` → classifier → `VerdictEngine` → persist → notify.
///
/// It never touches the network and has no sign-in path. Nothing else about the scan is stubbed: the coordinator
/// does not know it is talking to this.
final class DemoMailProvider: MailAccountProvider {
    /// Benign fixtures handed over per fetch, so every "Scan now" genuinely checks new mail — and flags none of
    /// it, which is the everyday behaviour worth showing.
    static let benignBatchSize = 3

    /// Top-level key in a demo silent push naming the `SampleEmails` fixture to deliver
    /// (`scripts/demo-push-phish.apns`).
    static let pushFixtureKey = "demoFixture"

    let provider: MailProvider = .gmail

    private struct State {
        /// Benign fixture names not delivered yet, oldest arrival first.
        var deck: [String]
        /// Fixture names a demo silent push asked for; delivered on the next fetch.
        var queued: [String] = []
        /// The flagged email the "app closed" moment delivers, kept until a background wake takes it. The
        /// Simulator hands a `content-available` push to the background-fetch delegate, which is not given the
        /// payload, so the fixture cannot come from the push there (see `AppDelegate`).
        var armedBackgroundArrival: String? = DemoData.liveArrivalFixtureName
        var fetchCount = 0
    }

    private let state: Mutex<State>

    init() {
        state = Mutex(State(deck: SampleEmails.named.filter { !$0.malicious }.map(\.name)))
    }

    /// Takes the armed "app closed" arrival, leaving nothing behind: the moment happens once per install, and a
    /// background wake that finds it already spent behaves like any other scan with no new mail.
    func takeArmedBackgroundArrival() -> String? {
        state.withLock { state in
            defer { state.armedBackgroundArrival = nil }
            return state.armedBackgroundArrival
        }
    }

    /// Queues a fixture for the next fetch. Called by the silent-push path for
    /// `{"aps":{"content-available":1},"demoFixture":"<name>"}`, so the message arrives through the ordinary
    /// scan instead of a special code path.
    func enqueueFixture(named name: String) {
        state.withLock { $0.queued.append(name) }
    }

    /// Names that would be delivered next, for tests.
    var queuedFixtureNames: [String] { state.withLock { $0.queued } }

    // MARK: - MailAccountProvider

    @MainActor
    func signIn(presenting: UIViewController) async throws -> SignedInIdentity {
        throw ProviderError.notImplemented("the demo mailbox cannot be signed in to")
    }

    func signOut(accountID: UUID) async throws {}

    func fetchNewMessages(accountID: UUID, cursor: SyncCursor?, lookback: TimeInterval) async throws -> FetchResult {
        try await fetchNewMessages(accountID: accountID, cursor: cursor, lookback: lookback, isProcessed: { _ in false })
    }

    func fetchNewMessages(
        accountID: UUID,
        cursor: SyncCursor?,
        lookback: TimeInterval,
        isProcessed: @escaping @Sendable (_ messageID: String) -> Bool
    ) async throws -> FetchResult {
        let (names, fetchCount) = state.withLock { state -> ([String], Int) in
            state.fetchCount += 1
            var names = state.queued
            state.queued.removeAll()
            names += state.deck.prefix(Self.benignBatchSize)
            state.deck.removeFirst(min(Self.benignBatchSize, state.deck.count))
            return (names, state.fetchCount)
        }

        let fixtures = Dictionary(uniqueKeysWithValues: SampleEmails.named.map { ($0.name, $0.email) })
        let now = Date()
        var messages: [EmailMessage] = []
        for (index, name) in names.enumerated() {
            guard let fixture = fixtures[name] else { continue }
            // Staggered by a couple of minutes so the list and the trace panel do not show one identical timestamp.
            let receivedAt = now.addingTimeInterval(-Double(index) * 150)
            let email = DemoData.prepare(fixture, accountID: accountID, receivedAt: receivedAt)
            guard !isProcessed(email.messageID) else { continue }
            messages.append(email)
        }
        return FetchResult(messages: messages, cursor: SyncCursor(opaque: "demo-\(fetchCount)"))
    }

    func ensurePushSubscription(
        accountID: UUID,
        relay: RelayConfig,
        current: PushSubscriptionState?
    ) async throws -> PushSubscriptionState {
        PushSubscriptionState(
            id: current?.id ?? "demo-watch-8143",
            expiresAt: Date().addingTimeInterval(7 * 24 * 3600),
            relayAccountKey: current?.relayAccountKey ?? "demo-account-key"
        )
    }
}

/// The local model's part of a demo verdict: the answers the real `mlx-community/Qwen3-4B-Instruct-2507-4bit`
/// gave about these exact fixtures, recorded by `Tools/PromptLab` (see `MeasuredModelAssessments`).
///
/// MLX cannot run in the Simulator at all, so without this a recorded demo would show rules-only verdicts while
/// the seeded history showed model-backed ones. Replaying the measurement keeps every screen consistent and
/// keeps every number on it something the product really produced. A message with no measured answer is
/// reported as unavailable, exactly as a model that cannot answer would be, and the coordinator falls back to
/// the rules for it.
struct DemoClassifier: EmailClassifier {
    var identifier: String { DemoData.localModelIdentifier }

    var displayName: String {
        "Local model (\(ModelManager.entry(for: ModelManager.defaultModelID)?.displayName ?? ModelManager.defaultModelID))"
    }

    func availability() async -> ClassifierAvailability { .available }

    func assess(_ input: ClassificationInput) async throws -> ModelAssessment {
        guard let assessment = MeasuredModelAssessments.assessment(forMessageID: input.email.messageID) else {
            throw ClassifierError.unavailable("No recorded model answer for this message.")
        }
        // Replayed with the latency it was measured at: a 4B model answering in 0 ms would be the one plainly
        // untrue thing on screen, and the Diagnostics trace shows the number. Cancellable like a real generation.
        if let seconds = MeasuredModelAssessments.measuredSeconds(forMessageID: input.email.messageID) {
            try await Task.sleep(for: .seconds(seconds))
        }
        return assessment
    }
}
#endif

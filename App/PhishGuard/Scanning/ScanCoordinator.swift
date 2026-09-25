import Foundation
import OSLog
import PhishCore
import SwiftData
import Synchronization

enum ScanTrigger: String, Sendable, CaseIterable {
    case silentPush
    case backgroundRefresh
    case backgroundProcessing
    case manual
    case appLaunch
}

struct ScanSummary: Sendable, Equatable {
    var scanned: Int
    var flagged: Int
    var errors: [String]
    /// True when the scan stopped because of its deadline (or the per-scan message budget) while messages were
    /// still pending — the caller should schedule a `BGProcessingTask`.
    var deadlineReached: Bool
    /// True when the scan stopped early because its task was cancelled (BGTask expiration, app teardown).
    var cancelled: Bool

    init(scanned: Int = 0, flagged: Int = 0, errors: [String] = [], deadlineReached: Bool = false, cancelled: Bool = false) {
        self.scanned = scanned
        self.flagged = flagged
        self.errors = errors
        self.deadlineReached = deadlineReached
        self.cancelled = cancelled
    }

    /// Short human-readable outcome for Diagnostics. Never contains mail content.
    var outcomeText: String {
        var parts = ["\(scanned) checked", "\(flagged) flagged"]
        if !errors.isEmpty { parts.append("\(errors.count) error\(errors.count == 1 ? "" : "s")") }
        if deadlineReached { parts.append("hit deadline") }
        if cancelled { parts.append("cancelled") }
        return parts.joined(separator: ", ")
    }
}

/// Main-actor settings captured once per scan so the coordinator never touches `SettingsStore` directly.
struct ScanSettingsSnapshot: Sendable {
    var alertPolicy: AlertPolicy
    var lookback: TimeInterval
    var relayConfig: RelayConfig?

    init(alertPolicy: AlertPolicy = AlertPolicy(), lookback: TimeInterval = 24 * 3600, relayConfig: RelayConfig? = nil) {
        self.alertPolicy = alertPolicy
        self.lookback = lookback
        self.relayConfig = relayConfig
    }
}

/// One line of the Diagnostics scan log. Contains counts, identifiers, error descriptions and timings only —
/// never sender, subject, body or any other mail content.
struct ScanLogEntry: Sendable, Identifiable, Equatable {
    let id: UUID
    let date: Date
    let trigger: ScanTrigger
    /// nil for the per-scan summary line, set for per-account lines.
    let accountID: UUID?
    let provider: MailProvider?
    let scanned: Int
    let flagged: Int
    /// Messages skipped because they were already processed.
    let skipped: Int
    let errors: [String]
    let duration: TimeInterval
    let deadlineReached: Bool
    let cancelled: Bool
    let note: String?

    init(
        id: UUID = UUID(),
        date: Date = .now,
        trigger: ScanTrigger,
        accountID: UUID? = nil,
        provider: MailProvider? = nil,
        scanned: Int = 0,
        flagged: Int = 0,
        skipped: Int = 0,
        errors: [String] = [],
        duration: TimeInterval = 0,
        deadlineReached: Bool = false,
        cancelled: Bool = false,
        note: String? = nil
    ) {
        self.id = id
        self.date = date
        self.trigger = trigger
        self.accountID = accountID
        self.provider = provider
        self.scanned = scanned
        self.flagged = flagged
        self.skipped = skipped
        self.errors = errors
        self.duration = duration
        self.deadlineReached = deadlineReached
        self.cancelled = cancelled
        self.note = note
    }
}

#if DEBUG
/// One line of the Diagnostics "Recent evaluations" panel: why one message was, or was not, flagged.
///
/// Debug builds only, kept in memory only, never persisted and never logged. It holds identifiers, scores,
/// heuristic signal *ids* and severities, timings, the sender's address and the subject truncated to 80
/// characters — never body text, and never the signals' `detail` strings, which quote the email.
struct EvaluationTrace: Sendable, Identifiable, Equatable {
    /// A heuristic signal without its user-facing detail text.
    struct SignalTrace: Sendable, Equatable {
        let id: String
        let severity: Severity
        let weight: Double
    }

    static let maxSubjectLength = 80

    let id: UUID
    let date: Date
    let trigger: ScanTrigger
    /// The `From:` address, or "" when the message had none.
    let sender: String
    /// Truncated to `maxSubjectLength`.
    let subject: String
    let ruleScore: Double
    let signals: [SignalTrace]
    /// One entry per model consulted: identifier, risk score, category or the reason it did not answer.
    let modelRuns: [ModelRun]
    let confidence: Double
    let level: RiskLevel
    let category: ThreatCategory
    /// Whether the verdict cleared the alert policy of this run (in a real scan: saved and notified).
    let alerted: Bool
    let elapsedMilliseconds: Int

    init(
        id: UUID = UUID(),
        date: Date = .now,
        trigger: ScanTrigger,
        sender: String,
        subject: String,
        ruleScore: Double,
        signals: [SignalTrace],
        modelRuns: [ModelRun],
        confidence: Double,
        level: RiskLevel,
        category: ThreatCategory,
        alerted: Bool,
        elapsedMilliseconds: Int
    ) {
        self.id = id
        self.date = date
        self.trigger = trigger
        self.sender = sender
        self.subject = subject
        self.ruleScore = ruleScore
        self.signals = signals
        self.modelRuns = modelRuns
        self.confidence = confidence
        self.level = level
        self.category = category
        self.alerted = alerted
        self.elapsedMilliseconds = elapsedMilliseconds
    }
}
#endif

/// The pipeline: fetch → dedupe → analyze → classify → verdict → persist (flagged only) → notify.
///
/// Hardening rules:
/// - cooperative cancellation (`Task.checkCancellation` between messages), deadline checks with a safety margin,
///   and model inference time-boxed to the remaining budget;
/// - per-account error isolation: one account failing never stops the others;
/// - coalescing: a scan requested while one is running joins it; when the running scan cannot satisfy the request
///   (it already fetched, or does not cover the requested accounts) one shared follow-up pass runs afterwards over
///   the union of the joiners' accounts. A joiner with a deadline stops waiting at that deadline;
/// - classifier fallback: active model → heuristics-only (`modelIdentifier == nil`) on unavailability, error,
///   repeated failures or a memory warning; model resources are released after every scan;
/// - foreground gate: a `GPUBackedClassifier` (the local MLX model) is skipped for every message the app is not
///   frontmost for, because iOS kills the process rather than let it submit Metal work from the background
///   (`ForegroundGate`). That is the normal state of a silent-push or BGTask scan, so it is logged once per scan
///   at info level and never counted as a classifier failure;
/// - push subscriptions are renewed when they expire within 24 h and immediately after a cursor reset;
/// - `ProcessedMessage` rows older than 7 days are pruned;
/// - `FlaggedEmailRecord` is persisted and a notification posted only when `AlertPolicy.shouldAlert(verdict)`.
actor ScanCoordinator {
    /// Time reserved before `deadline` so the last save/notification completes.
    static let deadlineMargin: TimeInterval = 3
    /// Push subscriptions are renewed when they expire within this window.
    static let pushRenewalWindow: TimeInterval = 24 * 3600
    /// `ProcessedMessage` rows older than this are pruned at the end of a scan.
    static let processedMessageRetention: TimeInterval = 7 * 24 * 3600
    /// Upper bound of messages classified in one scan; hitting it reports `deadlineReached`.
    /// Equal to the providers' per-fetch caps (`GmailProvider.maxMessagesPerFetch`, `GraphMailSync.maxMessagesPerScan`)
    /// and never below them: a budget below the cap would split one fetch across scans and leave the cursor behind.
    /// Already-processed ids are skipped inside the providers (`fetchNewMessages(...isProcessed:)`) before their
    /// bodies are downloaded, so a backlog is neither re-downloaded nor counted against the cap.
    static let defaultMaxMessagesPerScan = 100
    /// Ring-buffer size of `scanLog`.
    static let scanLogCapacity = 50
    #if DEBUG
    /// Ring-buffer size of `evaluationTraces`.
    static let evaluationTraceCapacity = 30
    #endif
    /// After this many consecutive classifier errors the model is skipped for the rest of the scan.
    static let classifierFailureThreshold = 3
    /// Minimum time between push-subscription renewal attempts after a failure (unless forced).
    static let renewalRetryInterval: TimeInterval = 15 * 60
    /// Non-flagged progress (`ProcessedMessage` rows) is saved every N messages.
    static let saveBatchSize = 10

    private let container: ModelContainer
    private let providers: [MailProvider: any MailAccountProvider]
    private let notifications: NotificationManager
    private let classifierResolver: @Sendable () async -> any EmailClassifier
    private let settingsResolver: @Sendable () async -> ScanSettingsSnapshot
    private let resourceReleaser: (@Sendable () async -> Void)?
    /// "May we use the GPU right now?" — read (never awaited) before every model call, so a scan that starts in
    /// the foreground and continues after the app is backgrounded switches to the rules mid-run.
    private let foregroundGate: any ForegroundGate
    private let maxMessagesPerScan: Int
    private let verdictEngine = VerdictEngine()
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "scan")

    private struct InFlightScan {
        let generation: Int
        let trigger: ScanTrigger
        /// Accounts the scan was asked for (nil ⇒ every enabled account).
        let requestedAccountIDs: [UUID]?
        let task: Task<ScanSummary, Never>
    }

    /// Accounts a follow-up pass must cover: the union of the requests that joined a running scan without being
    /// satisfied by it.
    private enum FollowUpScope {
        case all
        case accounts(Set<UUID>)

        var accountIDs: [UUID]? {
            if case .accounts(let ids) = self { return Array(ids) }
            return nil
        }

        static func make(_ accountIDs: [UUID]?) -> FollowUpScope {
            accountIDs.map { .accounts(Set($0)) } ?? .all
        }

        func merging(_ accountIDs: [UUID]?) -> FollowUpScope {
            guard let accountIDs, case .accounts(let ids) = self else { return .all }
            return .accounts(ids.union(accountIDs))
        }
    }

    private var inFlight: InFlightScan?
    /// Accounts the in-flight scan loaded (nil until it has); an account added later is not part of that scan.
    private var inFlightLoadedAccountIDs: Set<UUID>?
    /// True once the in-flight scan issued its first fetch: a request arriving after that may concern newer mail.
    private var inFlightFetchStarted = false
    private var pendingFollowUp: FollowUpScope?
    private var generation = 0
    private var currentRun: ScanRun?
    private var forcedRenewals: Set<UUID> = []
    private var renewalFailedAt: [UUID: Date] = [:]

    private(set) var lastSummary: ScanSummary?
    private(set) var lastScanDate: Date?
    /// The last `scanLogCapacity` log entries, oldest first.
    private(set) var scanLog: [ScanLogEntry] = []
    #if DEBUG
    /// The last `evaluationTraceCapacity` evaluated messages, oldest first. Debug builds only, in memory only.
    private(set) var evaluationTraces: [EvaluationTrace] = []
    #endif

    init(
        container: ModelContainer,
        providers: [MailProvider: any MailAccountProvider],
        notifications: NotificationManager,
        classifierResolver: @escaping @Sendable () async -> any EmailClassifier,
        settingsResolver: @escaping @Sendable () async -> ScanSettingsSnapshot,
        resourceReleaser: (@Sendable () async -> Void)? = nil,
        foregroundGate: any ForegroundGate = AppForegroundGate.shared,
        maxMessagesPerScan: Int = ScanCoordinator.defaultMaxMessagesPerScan
    ) {
        self.container = container
        self.providers = providers
        self.notifications = notifications
        self.classifierResolver = classifierResolver
        self.settingsResolver = settingsResolver
        self.resourceReleaser = resourceReleaser
        self.foregroundGate = foregroundGate
        self.maxMessagesPerScan = max(1, maxMessagesPerScan)
    }

    // MARK: - Public API

    /// Scans the enabled accounts (or the given subset). `deadline` nil ⇒ unlimited.
    ///
    /// A call made while a scan is running joins it. Joining satisfies the request only when the running scan has
    /// not fetched yet and covers every requested account; otherwise the request earns one follow-up pass that is
    /// shared by every unsatisfied joiner of that scan and covers the union of their accounts — so a push for
    /// another account, or mail that arrived after the running fetch, is never dropped. A joiner with a deadline
    /// stops waiting at that deadline and reports `deadlineReached` (its caller then queues a processing task); it
    /// never cancels or shortens the shared scan.
    func scan(trigger: ScanTrigger, accountIDs: [UUID]? = nil, deadline: Date?) async -> ScanSummary {
        guard let running = inFlight else {
            return await start(trigger: trigger, accountIDs: accountIDs, deadline: deadline)
        }
        let satisfied = !inFlightFetchStarted && inFlightCovers(accountIDs)
        if !satisfied {
            pendingFollowUp = pendingFollowUp?.merging(accountIDs) ?? .make(accountIDs)
        }
        logger.info("Scan (\(trigger.rawValue, privacy: .public)) joined the in-flight \(running.trigger.rawValue, privacy: .public) scan\(satisfied ? "" : "; follow-up queued", privacy: .public)")
        guard let joined = await Self.awaitSummary(of: running.task, deadline: deadline) else {
            logger.notice("Scan (\(trigger.rawValue, privacy: .public)) stopped waiting for the in-flight scan at its deadline")
            return ScanSummary(deadlineReached: true)
        }
        if satisfied { return joined }
        if let newer = inFlight, newer.generation != running.generation {
            // Another joiner already started the shared follow-up; it covers this request too.
            logger.info("Scan (\(trigger.rawValue, privacy: .public)) joined the follow-up scan")
            return await Self.awaitSummary(of: newer.task, deadline: deadline) ?? ScanSummary(deadlineReached: true)
        }
        guard let scope = pendingFollowUp else {
            return lastSummary ?? joined // the follow-up already ran to completion
        }
        logger.info("Scan (\(trigger.rawValue, privacy: .public)) re-running once after the joined scan")
        return await start(trigger: trigger, accountIDs: scope.accountIDs, deadline: deadline)
    }

    /// Whether the in-flight scan will scan every account in `accountIDs` (nil ⇒ all enabled accounts).
    private func inFlightCovers(_ accountIDs: [UUID]?) -> Bool {
        guard let running = inFlight else { return false }
        if let loaded = inFlightLoadedAccountIDs {
            guard let accountIDs else { return running.requestedAccountIDs == nil }
            return Set(accountIDs).isSubset(of: loaded)
        }
        guard let requested = running.requestedAccountIDs else { return true }
        guard let accountIDs else { return false }
        return Set(accountIDs).isSubset(of: requested)
    }

    /// Awaits a shared scan's summary, giving up (nil) when `deadline` minus the margin passes first. The scan is
    /// never cancelled: a joiner only stops waiting.
    private static func awaitSummary(of task: Task<ScanSummary, Never>, deadline: Date?) async -> ScanSummary? {
        guard let deadline else { return await task.value }
        let wait = deadline.addingTimeInterval(-deadlineMargin).timeIntervalSinceNow
        guard wait > 0 else { return nil }
        let once = ResumeOnce<ScanSummary?>()
        return await withCheckedContinuation { continuation in
            once.install(continuation)
            Task { once.resume(await task.value) }
            Task {
                try? await Task.sleep(for: .seconds(wait))
                once.resume(nil)
            }
        }
    }

    /// Runs the analyze → classify → verdict part of the pipeline on one message without persisting anything.
    /// Model resources are NOT released afterwards: this is the primitive for tests and for callers that do their
    /// own release bookkeeping. UI callers (Diagnostics) use `evaluateBatch(_:)`, which releases like a scan does.
    func evaluate(_ email: EmailMessage) async -> Verdict {
        await evaluate(email, run: makeStandaloneRun())
    }

    /// `evaluate(_:)` over several messages sharing one classifier and analyzer, followed by the resource release
    /// `finish` performs after a scan: with MLX weights resident by default, a Diagnostics test scan would
    /// otherwise leave 1–3 GB loaded. The release is skipped while a scan is in flight (that scan releases when it
    /// finishes, and dropping its weights mid-run would only force a reload). Nothing is persisted or notified.
    func evaluateBatch(_ emails: [EmailMessage]) async -> [Verdict] {
        let run = await makeStandaloneRun()
        var verdicts: [Verdict] = []
        verdicts.reserveCapacity(emails.count)
        for email in emails {
            verdicts.append(await evaluate(email, run: run))
        }
        if inFlight == nil {
            await resourceReleaser?()
        }
        return verdicts
    }

    /// A deadline-free, budget-free run over the active classifier and the organization-aware analyzer.
    private func makeStandaloneRun() async -> ScanRun {
        let context = ModelContext(container)
        let organizationDomains = (try? Self.enabledAccounts(context: context)).map(Self.organizationDomains(of:)) ?? []
        return ScanRun(
            trigger: .manual, deadline: nil, maxMessages: .max, classifier: await classifierResolver(),
            analyzer: HeuristicAnalyzer(organizationDomains: organizationDomains),
            alertPolicy: await settingsResolver().alertPolicy
        )
    }

    /// Outcome of "Re-check recent email": what was forgotten, and what the re-scan found.
    struct RecheckSummary: Sendable, Equatable {
        /// `ProcessedMessage` rows deleted — messages the app is now willing to look at again.
        var clearedMessages: Int = 0
        /// Accounts whose sync cursor was reset, so the provider re-fetches the whole lookback window.
        var clearedAccounts: Int = 0
        var scanned: Int = 0
        var flagged: Int = 0
        var errors: [String] = []
        var deadlineReached: Bool = false
        var cancelled: Bool = false
    }

    /// Forgets what the enabled accounts (or the given subset) have already been checked, then scans them again.
    ///
    /// Scanned messages are recorded in `ProcessedMessage` and never looked at again, and the per-account sync
    /// cursor says "nothing newer". Together those leave earlier mail permanently unexamined after a detection
    /// improvement — or after a scan that was interrupted — which is exactly how a phishing test can end up
    /// never being flagged. This deletes both for the accounts concerned and runs a manual scan, so the
    /// provider re-fetches the whole lookback window (Settings → Scanning) and every message is classified
    /// afresh. Flagged rows the user already has are updated rather than duplicated (`upsertFlaggedRecord`);
    /// alerts may be posted again.
    func recheckRecentEmail(accountIDs: [UUID]? = nil, deadline: Date? = nil) async -> RecheckSummary {
        var summary = RecheckSummary()
        let context = ModelContext(container)
        context.autosaveEnabled = false
        do {
            let enabled = try Self.enabledAccounts(context: context)
            let accounts = enabled.filter { account in accountIDs.map { $0.contains(account.id) } ?? true }
            for account in accounts {
                guard let kind = account.provider else { continue }
                let prefix = "\(kind.rawValue):\(account.id.uuidString):"
                let rows = try context.fetch(FetchDescriptor<ProcessedMessage>(predicate: #Predicate { $0.key.starts(with: prefix) }))
                for row in rows { context.delete(row) }
                summary.clearedMessages += rows.count
                account.syncCursor = nil
                summary.clearedAccounts += 1
            }
            if context.hasChanges { try context.save() }
            logger.notice("Re-check requested: cleared \(summary.clearedMessages) processed rows across \(summary.clearedAccounts) account(s)")
        } catch {
            logger.error("Re-check could not clear the processed state: \(error.localizedDescription, privacy: .public)")
            summary.errors.append("Could not clear the checked-messages list: \(error.localizedDescription)")
        }

        let scan = await scan(trigger: .manual, accountIDs: accountIDs, deadline: deadline)
        summary.scanned = scan.scanned
        summary.flagged = scan.flagged
        summary.errors.append(contentsOf: scan.errors)
        summary.deadlineReached = scan.deadlineReached
        summary.cancelled = scan.cancelled
        return summary
    }

    /// Marks accounts whose push subscription must be renewed on the next scan regardless of its expiry
    /// (e.g. after a Graph lifecycle notification relayed through a silent push).
    func requestPushRenewal(for accountIDs: [UUID]) {
        forcedRenewals.formUnion(accountIDs)
    }

    /// Memory warning: the running scan (if any) continues with heuristics only and model resources are released.
    func handleMemoryWarning() async {
        logger.notice("Memory warning received; releasing model resources")
        currentRun?.disableModel(reason: "memory warning")
        await resourceReleaser?()
    }

    // MARK: - Scan lifecycle

    private func start(trigger: ScanTrigger, accountIDs: [UUID]?, deadline: Date?) async -> ScanSummary {
        // Requests that joined an earlier scan without being satisfied by it fold into this one.
        var accountIDs = accountIDs
        if let pending = pendingFollowUp {
            accountIDs = pending.merging(accountIDs).accountIDs
            pendingFollowUp = nil
        }
        generation += 1
        let thisGeneration = generation
        inFlightLoadedAccountIDs = nil
        inFlightFetchStarted = false
        logger.info("Scan started: \(trigger.rawValue, privacy: .public)")
        let task = Task { await self.performScan(trigger: trigger, accountIDs: accountIDs, deadline: deadline) }
        inFlight = InFlightScan(generation: thisGeneration, trigger: trigger, requestedAccountIDs: accountIDs, task: task)

        // Cancelling the caller (BGTask expiration) cancels the scan itself; joiners never cancel a shared scan.
        let summary = await withTaskCancellationHandler {
            await task.value
        } onCancel: {
            task.cancel()
        }

        if inFlight?.generation == thisGeneration { inFlight = nil }
        lastSummary = summary
        lastScanDate = .now
        logger.info("Scan finished (\(trigger.rawValue, privacy: .public)): scanned=\(summary.scanned) flagged=\(summary.flagged) errors=\(summary.errors.count) deadlineReached=\(summary.deadlineReached) cancelled=\(summary.cancelled)")
        return summary
    }

    private func performScan(trigger: ScanTrigger, accountIDs: [UUID]?, deadline: Date?) async -> ScanSummary {
        let startedAt = Date()
        var summary = ScanSummary()
        var skippedTotal = 0
        let settings = await settingsResolver()
        let context = ModelContext(container)
        context.autosaveEnabled = false

        let accounts: [LinkedAccount]
        let organizationDomains: Set<String>
        do {
            // Every enabled account contributes its domain, whatever subset this scan covers.
            let enabled = try Self.enabledAccounts(context: context)
            organizationDomains = Self.organizationDomains(of: enabled)
            accounts = enabled.filter { account in
                accountIDs.map { $0.contains(account.id) } ?? true
            }
        } catch {
            summary.errors.append("Could not load accounts: \(error.localizedDescription)")
            return await finish(summary, trigger: trigger, startedAt: startedAt, skipped: 0, note: "account load failed")
        }
        inFlightLoadedAccountIDs = Set(accounts.map(\.id))
        guard !accounts.isEmpty else {
            return await finish(summary, trigger: trigger, startedAt: startedAt, skipped: 0, note: "no enabled accounts")
        }

        let run = ScanRun(
            trigger: trigger, deadline: deadline, maxMessages: maxMessagesPerScan, classifier: await classifierResolver(),
            analyzer: HeuristicAnalyzer(organizationDomains: organizationDomains),
            alertPolicy: settings.alertPolicy
        )
        currentRun = run
        defer { currentRun = nil }

        for account in accounts {
            do {
                try run.checkpoint()
            } catch is CancellationError {
                summary.cancelled = true
                break
            } catch {
                summary.deadlineReached = true
                break
            }
            let result = await scanAccount(account, settings: settings, context: context, run: run)
            summary.scanned += result.scanned
            summary.flagged += result.flagged
            summary.errors.append(contentsOf: result.errors)
            summary.deadlineReached = summary.deadlineReached || result.deadlineReached
            summary.cancelled = summary.cancelled || result.cancelled
            skippedTotal += result.skipped
            appendLog(ScanLogEntry(
                trigger: trigger, accountID: result.accountID, provider: result.provider,
                scanned: result.scanned, flagged: result.flagged, skipped: result.skipped, errors: result.errors,
                duration: result.duration, deadlineReached: result.deadlineReached, cancelled: result.cancelled, note: result.note
            ))
            if result.cancelled || result.deadlineReached { break }
        }

        if !summary.cancelled, let error = pruneProcessedMessages(context: context, lookback: settings.lookback) {
            summary.errors.append(error)
        }
        return await finish(summary, trigger: trigger, startedAt: startedAt, skipped: skippedTotal, note: run.logNote)
    }

    /// Releases model resources and writes the per-scan log line. Runs after every scan, whatever the outcome.
    private func finish(_ summary: ScanSummary, trigger: ScanTrigger, startedAt: Date, skipped: Int, note: String?) async -> ScanSummary {
        await resourceReleaser?()
        appendLog(ScanLogEntry(
            date: startedAt, trigger: trigger, scanned: summary.scanned, flagged: summary.flagged, skipped: skipped,
            errors: summary.errors, duration: Date().timeIntervalSince(startedAt),
            deadlineReached: summary.deadlineReached, cancelled: summary.cancelled, note: note
        ))
        return summary
    }

    // MARK: - Per-account pipeline

    private struct AccountScanResult {
        let accountID: UUID
        let provider: MailProvider?
        var scanned = 0
        var flagged = 0
        var skipped = 0
        var errors: [String] = []
        var deadlineReached = false
        var cancelled = false
        var duration: TimeInterval = 0
        var note: String?
    }

    private func scanAccount(
        _ account: LinkedAccount,
        settings: ScanSettingsSnapshot,
        context: ModelContext,
        run: ScanRun
    ) async -> AccountScanResult {
        let startedAt = Date()
        var result = AccountScanResult(accountID: account.id, provider: account.provider)
        defer { result.duration = Date().timeIntervalSince(startedAt) }

        guard let kind = account.provider, let provider = providers[kind] else {
            result.errors.append("No provider registered for \(account.providerRaw)")
            return result
        }

        // 1. Push subscription (create / renew when missing, expiring within 24 h, or explicitly requested).
        if let relay = settings.relayConfig {
            let forced = forcedRenewals.remove(account.id) != nil
            if let error = await renewPushSubscriptionIfNeeded(account: account, provider: provider, relay: relay, force: forced) {
                result.errors.append(error)
            }
            if context.hasChanges {
                do { try context.save() } catch { result.errors.append("Could not save subscription state: \(error.localizedDescription)") }
            }
        }
        if Task.isCancelled {
            result.cancelled = true
            return result
        }

        // 2. Fetch new messages since the cursor. Ids this account already classified are handed to the provider,
        //    which drops them before downloading bodies (they do not count toward its per-fetch cap). The predicate
        //    runs inside the provider and only reads the precomputed set: it never touches the ModelContext.
        let alreadyProcessed: Set<String>
        do {
            alreadyProcessed = try processedMessageIDs(provider: kind, accountID: account.id, context: context)
        } catch {
            result.errors.append("Dedupe lookup failed: \(error.localizedDescription)")
            alreadyProcessed = []
        }
        let skippedByProvider = SkipRecorder()
        let fetch: FetchResult
        do {
            let cursor = account.syncCursor.map(SyncCursor.init(opaque:))
            inFlightFetchStarted = true
            fetch = try await provider.fetchNewMessages(
                accountID: account.id, cursor: cursor, lookback: settings.lookback,
                isProcessed: { messageID in
                    guard alreadyProcessed.contains(messageID) else { return false }
                    skippedByProvider.record(messageID)
                    return true
                }
            )
        } catch is CancellationError {
            result.cancelled = true
            return result
        } catch {
            if Task.isCancelled {
                result.cancelled = true
                return result
            }
            logger.error("Fetch failed for \(kind.rawValue, privacy: .public): \(error.localizedDescription, privacy: .private)")
            result.errors.append("\(kind.displayName): \(error.localizedDescription)")
            if case ProviderError.notAuthenticated = error {
                // The grant is gone (revoked / expired refresh token): flag the account so the UI can offer
                // "Sign in again" instead of failing silently on every scan.
                account.needsReauthentication = true
                do { try context.save() } catch { result.errors.append("Could not save account state: \(error.localizedDescription)") }
            }
            return result
        }
        account.lastScanAt = .now
        account.needsReauthentication = false
        result.skipped += skippedByProvider.count

        if fetch.cursorWasReset {
            logger.notice("Cursor was reset for \(kind.rawValue, privacy: .public); using lookback window")
            result.note = "cursor reset"
            // The provider-side watch/subscription may have lapsed together with the cursor: renew it right away.
            if let relay = settings.relayConfig,
               let error = await renewPushSubscriptionIfNeeded(account: account, provider: provider, relay: relay, force: true) {
                result.errors.append(error)
            }
        }

        // 3. Dedupe → analyze → classify → persist (flagged only) → notify.
        var processedAll = true
        var unsavedCount = 0
        for email in fetch.messages {
            do {
                try run.checkpoint()
            } catch is CancellationError {
                result.cancelled = true
                processedAll = false
                break
            } catch {
                result.deadlineReached = true
                processedAll = false
                break
            }

            do {
                // Second line of defence for providers that ignore the `isProcessed` hint or list an id twice.
                if try isAlreadyProcessed(email, context: context) {
                    result.skipped += 1
                    continue
                }
            } catch {
                result.errors.append("Dedupe lookup failed: \(error.localizedDescription)")
            }

            let verdict = await evaluate(email, run: run)
            run.processedCount += 1
            result.scanned += 1
            context.insert(ProcessedMessage(key: email.dedupeKey))

            if settings.alertPolicy.shouldAlert(verdict) {
                do {
                    let record = try upsertFlaggedRecord(email: email, verdict: verdict, accountID: account.id, context: context)
                    try context.save()
                    unsavedCount = 0
                    result.flagged += 1
                    notifications.postAlert(for: record, unreadCount: unreadFlaggedCount(context: context))
                } catch {
                    result.errors.append("Could not save flagged email: \(error.localizedDescription)")
                }
            } else {
                unsavedCount += 1
                if unsavedCount >= Self.saveBatchSize {
                    do {
                        try context.save()
                        unsavedCount = 0
                    } catch {
                        result.errors.append("Could not save scan state: \(error.localizedDescription)")
                    }
                }
            }
        }

        if processedAll {
            account.syncCursor = fetch.cursor.opaque
        } else {
            // Cursor intentionally not advanced: remaining messages are re-fetched by the next scan and
            // already-classified ones are skipped through ProcessedMessage.
            logger.info("Scan of \(kind.rawValue, privacy: .public) stopped early; cursor not advanced")
        }
        if context.hasChanges {
            do {
                try context.save()
            } catch {
                result.errors.append("Could not save scan state: \(error.localizedDescription)")
            }
        }
        return result
    }

    // MARK: - Classification

    /// What the model layer produced for one message: the assessment that reaches the `VerdictEngine`, the
    /// identifier recorded with the verdict, and one `ModelRun` per model that was considered (for the
    /// Diagnostics trace; a single-model run produces exactly one).
    private struct ModelOutcome {
        var assessment: ModelAssessment?
        var modelIdentifier: String?
        var runs: [ModelRun] = []
    }

    private func evaluate(_ email: EmailMessage, run: ScanRun) async -> Verdict {
        let startedAt = Date()
        let report = run.analyzer.analyze(email)
        var outcome = ModelOutcome()

        if run.modelEnabled, !skipModelForForeground(run) {
            let input = ClassificationInput(email: email, report: report)
            if let ensemble = run.classifier as? any MultiModelClassifier {
                outcome = await assessWithEnsemble(ensemble, input: input, run: run)
            } else {
                outcome = await assessWithSingleModel(run.classifier, input: input, run: run)
            }
        }

        let verdict = verdictEngine.makeVerdict(
            report: report, assessment: outcome.assessment, modelIdentifier: outcome.modelIdentifier
        )
        #if DEBUG
        appendTrace(EvaluationTrace(
            date: startedAt,
            trigger: run.trigger,
            sender: email.from?.address ?? "",
            subject: String(email.subject.prefix(EvaluationTrace.maxSubjectLength)),
            ruleScore: report.score,
            // Ids, severities and weights only: a signal's `detail` quotes the email.
            signals: report.signals.map { .init(id: $0.id, severity: $0.severity, weight: $0.weight) },
            modelRuns: outcome.runs,
            confidence: verdict.confidence,
            level: verdict.level,
            category: verdict.category,
            alerted: run.alertPolicy.shouldAlert(verdict),
            elapsedMilliseconds: Int((Date().timeIntervalSince(startedAt) * 1000).rounded())
        ))
        #endif
        return verdict
    }

    /// The classic path: one classifier, its availability resolved once per scan.
    private func assessWithSingleModel(
        _ classifier: any EmailClassifier,
        input: ClassificationInput,
        run: ScanRun
    ) async -> ModelOutcome {
        var outcome = ModelOutcome()
        if run.availability == nil {
            run.availability = await classifier.availability()
        }
        let startedAt = Date()
        func record(_ result: ModelRun.Outcome) {
            outcome.runs = [ModelRun(identifier: classifier.identifier, outcome: result, duration: Date().timeIntervalSince(startedAt))]
        }

        switch run.availability ?? .unavailable(reason: "unknown") {
        case .available:
            do {
                let assessment = try await Self.withRemainingBudget(deadline: run.deadline) {
                    try await classifier.assess(input)
                }
                outcome.assessment = assessment
                outcome.modelIdentifier = classifier.identifier
                record(.answered(assessment))
                run.consecutiveFailures = 0
            } catch ScanInterruption.deadline {
                // Budget exhausted mid-inference: heuristics only for this message (not a classifier failure);
                // the loop's next checkpoint reports the deadline.
                logger.notice("Classifier \(classifier.identifier, privacy: .public) exceeded the scan deadline; heuristics only")
                record(.interrupted)
            } catch ClassifierError.guardrailViolation {
                // Content-specific refusal: heuristics only for this message, the model stays enabled.
                logger.notice("Classifier \(classifier.identifier, privacy: .public) declined a message; heuristics only")
                record(.declined(ClassifierError.guardrailViolation.errorDescription ?? "The model declined this message."))
            } catch ClassifierError.requiresForeground(let reason) {
                // The app stopped being frontmost between the gate check above and the inference (or during
                // it), so the model refused rather than submit GPU work iOS would kill the app for. Expected,
                // not a failure: the rules decide this message and the model stays enabled for the next one.
                noteForegroundSkip(run, reason: reason)
                record(.notFrontmost(reason))
            } catch is CancellationError {
                // The loop notices the cancellation at its next checkpoint.
                record(.interrupted)
            } catch {
                run.consecutiveFailures += 1
                logger.notice("Classifier \(classifier.identifier, privacy: .public) failed (\(run.consecutiveFailures)), using heuristics only: \(error.localizedDescription, privacy: .private)")
                record(.failed(error.localizedDescription))
                if run.consecutiveFailures >= Self.classifierFailureThreshold {
                    run.disableModel(reason: "\(run.consecutiveFailures) consecutive classifier failures")
                }
            }
        case .unavailable(let reason):
            logger.notice("Classifier \(classifier.identifier, privacy: .public) unavailable (\(reason, privacy: .public)); heuristics only")
            run.disableModel(reason: reason)
            record(.unavailable(reason))
        }
        return outcome
    }

    /// Both models at once (`ClassifierChoice.both`): the members run concurrently, the **primary** decides, and
    /// a **corroborator**'s higher score is adopted only where something independent already pointed the same
    /// way (see `EnsembleClassifier` for the measurement behind that). A corroborator whose score is suppressed
    /// leaves `assessment` nil exactly as an unavailable model does, so the message falls back to the rules.
    ///
    /// Unlike the single-model path this does **not** cache availability for the scan. The members' answers to
    /// "can you run?" change mid-scan (the foreground gate opens and closes with the app), and one member being
    /// unavailable must never disable the other for the rest of the run.
    private func assessWithEnsemble(
        _ classifier: any MultiModelClassifier,
        input: ClassificationInput,
        run: ScanRun
    ) async -> ModelOutcome {
        var outcome = ModelOutcome()
        let result: MultiModelAssessment
        do {
            result = try await Self.withRemainingBudget(deadline: run.deadline) {
                await classifier.assessAll(input)
            }
        } catch {
            logger.notice("Classifier \(classifier.identifier, privacy: .public) exceeded the scan deadline; heuristics only")
            outcome.runs = [ModelRun(identifier: classifier.identifier, outcome: .interrupted, duration: 0)]
            return outcome
        }

        outcome.runs = result.runs
        if result.foregroundSkipped {
            let reason = result.runs.first { $0.wasSkippedForForeground }?.errorDescription
            noteForegroundSkip(run, reason: reason ?? MLXClassifier.foregroundOnlyReason)
        }
        if let assessment = result.assessment {
            outcome.assessment = assessment
            outcome.modelIdentifier = result.modelIdentifier
            // One model answering is enough to call the run healthy, whatever the other one did.
            run.consecutiveFailures = 0
        } else if result.hasFailure {
            run.consecutiveFailures += 1
            logger.notice("Every model failed (\(run.consecutiveFailures)), using heuristics only")
            if run.consecutiveFailures >= Self.classifierFailureThreshold {
                run.disableModel(reason: "\(run.consecutiveFailures) consecutive classifier failures")
            }
        }
        return outcome
    }

    /// Whether this run's classifier needs the GPU while the app is not frontmost. Reading the gate is a lock
    /// read, so it is re-checked for every message: a scan that began in the foreground degrades to the rules the
    /// moment the app is backgrounded, and a long background scan picks the model back up if the user opens the
    /// app while it runs.
    private func skipModelForForeground(_ run: ScanRun) -> Bool {
        guard run.classifierNeedsForeground, !foregroundGate.isForeground else { return false }
        noteForegroundSkip(run, reason: MLXClassifier.foregroundOnlyReason)
        return true
    }

    /// Records the rules-only fallback for the scan log and logs it once per scan (info, not an error: this is
    /// what every background scan with a local model selected is supposed to do).
    private func noteForegroundSkip(_ run: ScanRun, reason: String) {
        guard run.noteForegroundSkip() else { return }
        logger.info("PhishGuard is not in the foreground; \(run.classifier.identifier, privacy: .public) cannot run (\(reason, privacy: .public)). Classifying with the rules while it stays in the background.")
    }

    /// Runs `body` racing the remaining budget (`deadline` minus the margin): on timeout the body's task is cancelled
    /// and `ScanInterruption.deadline` is thrown, so an inference that started late cannot overrun the deadline.
    /// Without a deadline `body` runs unbounded. (A classifier that ignores cancellation still delays the return.)
    private static func withRemainingBudget<T: Sendable>(
        deadline: Date?,
        _ body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        guard let deadline else { return try await body() }
        let remaining = deadline.addingTimeInterval(-deadlineMargin).timeIntervalSinceNow
        guard remaining > 0 else { throw ScanInterruption.deadline }
        return try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await body() }
            group.addTask {
                try await Task.sleep(for: .seconds(remaining))
                throw ScanInterruption.deadline
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else { throw ScanInterruption.deadline }
            return first
        }
    }

    // MARK: - Accounts

    /// The mailboxes a scan may touch: enabled, and not the fictional Demo-mode account.
    ///
    /// This one predicate is what keeps demo data out of the pipeline. A demo account has no credentials and no
    /// mailbox behind it, so fetching it could only ever produce `ProviderError.notAuthenticated` — a red error in
    /// Diagnostics, a "Needs sign-in" badge and a push subscription the relay would be asked to create. Excluding
    /// it here covers every caller: `performScan` (fetch, classify, notify), `recheckRecentEmail` (cursor and
    /// `ProcessedMessage` clearing) and `organizationDomains` (so `example.com` is never treated as the user's own
    /// organization for real mail).
    private static func enabledAccounts(context: ModelContext) throws -> [LinkedAccount] {
        let descriptor = FetchDescriptor<LinkedAccount>(
            predicate: #Predicate { $0.isEnabled && !$0.isDemo },
            sortBy: [SortDescriptor(\.addedAt)]
        )
        return try context.fetch(descriptor)
    }

    /// Registrable domains of the enabled accounts' addresses: the user's own organization(s) for
    /// `HeuristicAnalyzer(organizationDomains:)`, which drops free-mail domains itself. Recomputed for every scan so
    /// that linking or pausing an account takes effect immediately.
    static func organizationDomains(of accounts: [LinkedAccount]) -> Set<String> {
        Set(accounts
            .map { DomainAnalysis.registrableDomain(of: EmailAddress(name: nil, address: $0.email).domain) }
            .filter { !$0.isEmpty })
    }

    // MARK: - Persistence helpers

    /// Provider message ids of the account that already have a `ProcessedMessage` row (keys are
    /// "<provider>:<account uuid>:<message id>"), for the provider-side skip.
    private func processedMessageIDs(provider kind: MailProvider, accountID: UUID, context: ModelContext) throws -> Set<String> {
        let prefix = "\(kind.rawValue):\(accountID.uuidString):"
        let descriptor = FetchDescriptor<ProcessedMessage>(predicate: #Predicate { $0.key.starts(with: prefix) })
        return Set(try context.fetch(descriptor).map { String($0.key.dropFirst(prefix.count)) })
    }

    /// Inserts the flagged row for this message, or refreshes the one the user already has.
    ///
    /// `FlaggedEmailRecord.id` is a fresh UUID per row, so nothing on its own stops the same email being listed
    /// twice once a message is classified a second time — which is exactly what "Re-check recent email" does.
    /// The identity of a *message* is (account, provider, message id): a newer verdict for it updates that row
    /// in place, keeping its `id` (so a delivered notification and any deep link still resolve) and its read
    /// state (the user has already seen this email).
    private func upsertFlaggedRecord(
        email: EmailMessage,
        verdict: Verdict,
        accountID: UUID,
        context: ModelContext
    ) throws -> FlaggedEmailRecord {
        let providerRaw = email.provider.rawValue
        let messageID = email.messageID
        var descriptor = FetchDescriptor<FlaggedEmailRecord>(
            predicate: #Predicate { record in
                record.accountID == accountID && record.providerRaw == providerRaw && record.messageID == messageID
            }
        )
        descriptor.fetchLimit = 1
        if let existing = try context.fetch(descriptor).first {
            existing.update(email: email, verdict: verdict)
            return existing
        }
        let record = FlaggedEmailRecord(email: email, verdict: verdict, accountID: accountID)
        context.insert(record)
        return record
    }

    private func isAlreadyProcessed(_ email: EmailMessage, context: ModelContext) throws -> Bool {
        let key = email.dedupeKey
        var descriptor = FetchDescriptor<ProcessedMessage>(predicate: #Predicate { $0.key == key })
        descriptor.fetchLimit = 1
        return try context.fetchCount(descriptor) > 0
    }

    private func unreadFlaggedCount(context: ModelContext) -> Int {
        let descriptor = FetchDescriptor<FlaggedEmailRecord>(predicate: #Predicate { $0.isRead == false })
        return (try? context.fetchCount(descriptor)) ?? 0
    }

    /// Deletes `ProcessedMessage` rows older than the retention window (never shorter than the lookback window, so a
    /// cursor reset cannot re-notify an email that was already classified). Returns an error string on failure.
    private func pruneProcessedMessages(context: ModelContext, lookback: TimeInterval) -> String? {
        let retention = max(Self.processedMessageRetention, lookback + 3600)
        let cutoff = Date().addingTimeInterval(-retention)
        do {
            try context.delete(model: ProcessedMessage.self, where: #Predicate { $0.processedAt < cutoff })
            if context.hasChanges { try context.save() }
            return nil
        } catch {
            logger.error("Pruning processed messages failed: \(error.localizedDescription, privacy: .public)")
            return "Could not prune processed messages: \(error.localizedDescription)"
        }
    }

    /// Returns an error string on failure, nil when nothing was needed or renewal succeeded.
    private func renewPushSubscriptionIfNeeded(
        account: LinkedAccount,
        provider: any MailAccountProvider,
        relay: RelayConfig,
        force: Bool
    ) async -> String? {
        // IMAP and anything else without a webhook is scanned in the foreground and by background refresh;
        // there is nothing to renew and a missing subscription is not an error.
        guard provider.provider.supportsPushSubscriptions else { return nil }
        let expiresSoon = account.pushSubscriptionExpiresAt.map { $0.timeIntervalSinceNow < Self.pushRenewalWindow } ?? true
        guard force || expiresSoon else { return nil }
        if !force, let failedAt = renewalFailedAt[account.id], Date().timeIntervalSince(failedAt) < Self.renewalRetryInterval {
            return nil // backing off after a recent failure; it was already reported
        }
        do {
            let state = try await provider.ensurePushSubscription(accountID: account.id, relay: relay, current: account.pushSubscriptionState)
            account.pushSubscriptionID = state.id
            account.pushSubscriptionExpiresAt = state.expiresAt
            account.relayAccountKey = state.relayAccountKey
            renewalFailedAt[account.id] = nil
            logger.info("Push subscription for \(provider.provider.rawValue, privacy: .public) valid until \(state.expiresAt, privacy: .public)")
            return nil
        } catch is CancellationError {
            return nil
        } catch ProviderError.pushNotSupported {
            // Expected for providers without a webhook; never surfaced as a scan error, never retried.
            logger.debug("Push subscriptions are not available for \(provider.provider.rawValue, privacy: .public)")
            return nil
        } catch {
            renewalFailedAt[account.id] = Date()
            if case ProviderError.notAuthenticated = error { account.needsReauthentication = true }
            logger.error("Push subscription renewal failed for \(provider.provider.rawValue, privacy: .public): \(error.localizedDescription, privacy: .private)")
            return "Push subscription (\(provider.provider.displayName)): \(error.localizedDescription)"
        }
    }

    // MARK: - Log

    private func appendLog(_ entry: ScanLogEntry) {
        scanLog.append(entry)
        if scanLog.count > Self.scanLogCapacity {
            scanLog.removeFirst(scanLog.count - Self.scanLogCapacity)
        }
    }

    #if DEBUG
    private func appendTrace(_ trace: EvaluationTrace) {
        evaluationTraces.append(trace)
        if evaluationTraces.count > Self.evaluationTraceCapacity {
            evaluationTraces.removeFirst(evaluationTraces.count - Self.evaluationTraceCapacity)
        }
    }

    /// Empties the Diagnostics "Recent evaluations" panel.
    func clearEvaluationTraces() {
        evaluationTraces.removeAll()
    }
    #endif
}

/// Reasons a scan loop stops before the message list is exhausted (besides task cancellation).
private enum ScanInterruption: Error {
    case deadline
    case messageBudget
}

/// Counts the distinct message ids a provider skipped through the `isProcessed` predicate. The predicate runs in the
/// provider's isolation domain, hence the lock.
private final class SkipRecorder: Sendable {
    private let ids = Mutex<Set<String>>([])

    func record(_ id: String) {
        ids.withLock { _ = $0.insert(id) }
    }

    var count: Int { ids.withLock { $0.count } }
}

/// Resumes a continuation exactly once, whichever of two racing tasks finishes first.
private final class ResumeOnce<T: Sendable>: Sendable {
    private let continuation = Mutex<CheckedContinuation<T, Never>?>(nil)

    func install(_ continuation: CheckedContinuation<T, Never>) {
        self.continuation.withLock { $0 = continuation }
    }

    func resume(_ value: T) {
        let pending = continuation.withLock { slot -> CheckedContinuation<T, Never>? in
            defer { slot = nil }
            return slot
        }
        pending?.resume(returning: value)
    }
}

/// Mutable per-scan state (classifier health, message budget). Confined to the coordinator actor.
private final class ScanRun {
    let trigger: ScanTrigger
    let deadline: Date?
    let maxMessages: Int
    let classifier: any EmailClassifier
    /// Organization-aware analyzer built for this scan (see `ScanCoordinator.organizationDomains(of:)`).
    let analyzer: HeuristicAnalyzer
    /// The policy in force for this run. Only used to record "did this alert?" in the debug evaluation trace;
    /// the scan loop applies the policy itself, and a standalone `evaluate` never persists or notifies.
    let alertPolicy: AlertPolicy
    /// True when the classifier runs on the GPU (`GPUBackedClassifier`), i.e. only while the app is frontmost.
    /// An `EnsembleClassifier` is never GPU-backed as a whole: it skips its GPU-backed *member* itself, so the
    /// other member keeps answering in the background.
    let classifierNeedsForeground: Bool
    var availability: ClassifierAvailability?
    var consecutiveFailures = 0
    var processedCount = 0
    private(set) var modelDisabledReason: String?
    /// Set once the first message fell back to the rules because the app was not frontmost. Not a failure and not
    /// permanent: every later message asks the gate again.
    private(set) var foregroundSkipped = false

    init(
        trigger: ScanTrigger,
        deadline: Date?,
        maxMessages: Int,
        classifier: any EmailClassifier,
        analyzer: HeuristicAnalyzer,
        alertPolicy: AlertPolicy = AlertPolicy()
    ) {
        self.trigger = trigger
        self.deadline = deadline
        self.maxMessages = maxMessages
        self.classifier = classifier
        self.analyzer = analyzer
        self.alertPolicy = alertPolicy
        self.classifierNeedsForeground = classifier is any GPUBackedClassifier
    }

    var modelEnabled: Bool {
        modelDisabledReason == nil && classifier.identifier != HeuristicsOnlyClassifier.classifierIdentifier
    }

    func disableModel(reason: String) {
        if modelDisabledReason == nil { modelDisabledReason = reason }
    }

    /// Records the "app was not frontmost" fallback. Returns true the first time, so the coordinator logs once
    /// per scan instead of once per message.
    func noteForegroundSkip() -> Bool {
        guard !foregroundSkipped else { return false }
        foregroundSkipped = true
        return true
    }

    /// Why the model did not answer, for the per-scan log line (counts and reasons only, never mail content).
    var logNote: String? {
        var parts: [String] = []
        if let modelDisabledReason { parts.append("model disabled: \(modelDisabledReason)") }
        if foregroundSkipped { parts.append("rules only: app not in the foreground") }
        return parts.isEmpty ? nil : parts.joined(separator: "; ")
    }

    /// Throws `CancellationError` when the task was cancelled, `ScanInterruption` when the deadline (minus margin)
    /// or the message budget was reached.
    func checkpoint() throws {
        try Task.checkCancellation()
        if let deadline, Date() >= deadline.addingTimeInterval(-ScanCoordinator.deadlineMargin) {
            throw ScanInterruption.deadline
        }
        if processedCount >= maxMessages {
            throw ScanInterruption.messageBudget
        }
    }
}

import BackgroundTasks
import Foundation
import OSLog
import UIKit

/// BGTaskScheduler wrapper. Identifiers are derived from the bundle id and must match
/// `BGTaskSchedulerPermittedIdentifiers` in Info.plist (project.yml).
///
/// - `registerTasks()` must complete inside `application(_:didFinishLaunchingWithOptions:)`.
/// - Launch handlers run the scan in a `Task` with a deadline (25 s refresh / 120 s processing); the task's
///   `expirationHandler` cancels that `Task`; `setTaskCompleted` is called exactly once.
/// - The refresh task is re-armed (earliest in 15 min) after every run and whenever the app enters the background;
///   a processing task is queued when a scan hit its deadline with work left.
@MainActor
final class BackgroundTaskManager {
    static let refreshBudget: TimeInterval = 25
    static let processingBudget: TimeInterval = 120
    static let refreshInterval: TimeInterval = 15 * 60
    /// After expiration, the task is force-completed if the cancelled scan has not unwound within this time.
    static let expirationGrace: TimeInterval = 2

    let refreshIdentifier: String
    let processingIdentifier: String
    /// Last-run timestamps/outcomes for Diagnostics (persisted in UserDefaults).
    let status: BackgroundStatus

    private let scan: @Sendable (ScanTrigger, Date?) async -> ScanSummary
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "background")
    private var didRegister = false
    private var lifecycleObserver: (any NSObjectProtocol)?

    init(config: AppConfig, defaults: UserDefaults = .standard, scan: @escaping @Sendable (ScanTrigger, Date?) async -> ScanSummary) {
        self.refreshIdentifier = config.backgroundRefreshTaskIdentifier
        self.processingIdentifier = config.backgroundProcessingTaskIdentifier
        self.status = BackgroundStatus(defaults: defaults)
        self.scan = scan
    }

    // MARK: - Registration

    /// Registers both launch handlers. Must be called before `application(_:didFinishLaunchingWithOptions:)` returns
    /// and only once per process (a second registration of the same identifier kills the app).
    func registerTasks() {
        guard !didRegister else { return }
        didRegister = true
        let scan = self.scan

        let refreshRegistered = BGTaskScheduler.shared.register(forTaskWithIdentifier: refreshIdentifier, using: nil) { task in
            Self.run(task, trigger: .backgroundRefresh, budget: Self.refreshBudget, scan: scan, manager: self)
        }
        let processingRegistered = BGTaskScheduler.shared.register(forTaskWithIdentifier: processingIdentifier, using: nil) { task in
            Self.run(task, trigger: .backgroundProcessing, budget: Self.processingBudget, scan: scan, manager: self)
        }
        logger.info("Registered background tasks refresh=\(refreshRegistered) processing=\(processingRegistered)")
        observeLifecycle()
    }

    /// Re-arms the refresh task whenever the app goes to the background.
    private func observeLifecycle() {
        guard lifecycleObserver == nil else { return }
        lifecycleObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil,
            queue: .main
        ) { _ in
            Task { @MainActor in
                self.scheduleAppRefresh()
            }
        }
    }

    // MARK: - Scheduling

    /// Reschedules the periodic refresh (earliest in 15 minutes). Safe to call often; the latest request wins.
    func scheduleAppRefresh() {
        let request = BGAppRefreshTaskRequest(identifier: refreshIdentifier)
        request.earliestBeginDate = Date().addingTimeInterval(Self.refreshInterval)
        submit(request)
    }

    /// Schedules a longer processing task for work a deadline-limited scan could not finish.
    func scheduleProcessing() {
        let request = BGProcessingTaskRequest(identifier: processingIdentifier)
        request.requiresNetworkConnectivity = true
        request.requiresExternalPower = false
        submit(request)
    }

    func cancelAll() {
        BGTaskScheduler.shared.cancelAllTaskRequests()
        status.pendingTaskIdentifiers = []
    }

    /// Identifiers of the requests currently queued with the scheduler (also stored in `status`).
    @discardableResult
    func refreshPendingRequests() async -> [String] {
        let identifiers = await Self.pendingTaskIdentifiers()
        status.pendingTaskIdentifiers = identifiers
        return identifiers
    }

    nonisolated static func pendingTaskIdentifiers() async -> [String] {
        await withCheckedContinuation { continuation in
            BGTaskScheduler.shared.getPendingTaskRequests { requests in
                continuation.resume(returning: requests.map(\.identifier))
            }
        }
    }

    /// Called by the AppDelegate after a silent-push scan: records it and keeps the fallbacks armed.
    func didHandleSilentPush(summary: ScanSummary) {
        status.record(trigger: .silentPush, summary: summary)
        scheduleAppRefresh()
        if summary.deadlineReached { scheduleProcessing() }
    }

    private func submit(_ request: BGTaskRequest) {
        do {
            try BGTaskScheduler.shared.submit(request)
            logger.debug("Submitted \(request.identifier, privacy: .public)")
        } catch {
            // Expected on the simulator (BGTaskSchedulerErrorDomain code 1: unavailable).
            logger.notice("Could not submit \(request.identifier, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - Launch handling

    /// Before the scan: re-arm the refresh so a kill mid-scan still leaves a request queued.
    private func willStart(trigger: ScanTrigger) {
        logger.info("Background task launched: \(trigger.rawValue, privacy: .public)")
        if trigger == .backgroundRefresh { scheduleAppRefresh() }
    }

    /// After the scan: record the outcome, re-arm the refresh, queue processing when work is left.
    private func didFinish(trigger: ScanTrigger, summary: ScanSummary) {
        status.record(trigger: trigger, summary: summary)
        scheduleAppRefresh()
        if summary.deadlineReached {
            // For the processing task only re-queue when progress was made, so a stuck account cannot loop forever.
            if trigger != .backgroundProcessing || summary.scanned > 0 {
                scheduleProcessing()
            }
        }
        logger.info("Background task finished: \(trigger.rawValue, privacy: .public) \(summary.outcomeText, privacy: .public)")
    }

    /// Runs on the scheduler's thread: sets the expiration handler immediately, then hands off to the scan task.
    private nonisolated static func run(
        _ task: BGTask,
        trigger: ScanTrigger,
        budget: TimeInterval,
        scan: @escaping @Sendable (ScanTrigger, Date?) async -> ScanSummary,
        manager: BackgroundTaskManager
    ) {
        let box = BGTaskBox(task)
        let deadline = Date().addingTimeInterval(budget)

        Task { @MainActor in manager.willStart(trigger: trigger) }

        let work = Task {
            await scan(trigger, deadline)
        }

        box.task.expirationHandler = {
            // Cooperative: the coordinator checks Task.isCancelled / the deadline between messages and unwinds.
            work.cancel()
            Task {
                try? await Task.sleep(for: .seconds(Self.expirationGrace))
                box.complete(success: false) // no-op when the scan already unwound and completed the task
            }
        }

        Task {
            let summary = await work.value
            await manager.didFinish(trigger: trigger, summary: summary)
            box.complete(success: BackgroundOutcome.taskSucceeded(summary) && !work.isCancelled)
        }
    }
}

/// `BGTask` is not `Sendable` in the SDK, but its completion/expiration API is thread-safe; the box lets the launch
/// handler share the task between the scan `Task` and the expiration handler and guarantees `setTaskCompleted` is
/// called exactly once.
private final class BGTaskBox: @unchecked Sendable {
    let task: BGTask
    private let lock = NSLock()
    private var completed = false

    init(_ task: BGTask) { self.task = task }

    func complete(success: Bool) {
        lock.lock()
        let first = !completed
        completed = true
        lock.unlock()
        guard first else { return }
        task.setTaskCompleted(success: success)
    }
}

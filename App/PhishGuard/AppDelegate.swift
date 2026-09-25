import BackgroundTasks
import OSLog
import UIKit
import UserNotifications

/// APNs registration, silent-push entry point, BGTask registration and notification delegate.
///
/// Launch ordering (both before `didFinishLaunching` returns, as BGTaskScheduler requires):
/// 1. `willFinishLaunching`: the foreground gate (`ForegroundGate`: no MLX GPU work unless the app is frontmost),
///    the notification delegate + categories (so a cold launch from an alert tap is delivered);
/// 2. `didFinishLaunching`: `BackgroundTaskManager.registerTasks()`, then `registerForRemoteNotifications()`.
///
/// The `UNUserNotificationCenterDelegate` conformance is `@preconcurrency` so its two `async` witnesses keep the
/// class's main-actor isolation although the protocol is nonisolated. That is load-bearing: for an `async` witness the
/// compiler generates the ObjC completion-handler entry point as a task that runs *with the witness's isolation* and
/// then calls UIKit's completion handler, which asserts the main thread ("Call must be made on main thread" in
/// `-[UIApplication _performBlockAfterCATransactionCommitSynchronizes:]`). Declared `nonisolated`, both witnesses
/// completed on the cooperative pool and every banner tap crashed the app (device, 2026-09-24).
/// `BackgroundTests.testNotificationDelegateCompletionsRunOnTheMainThread` drives those entry points.
final class AppDelegate: NSObject, UIApplicationDelegate, @preconcurrency UNUserNotificationCenterDelegate {
    /// Wall-clock budget for a silent push scan; the system allows 30 s including the completion handler.
    static let silentPushBudget: TimeInterval = 25
    /// The completion handler is forced this long after the budget if the scan has not returned by then
    /// (e.g. it joined an unbounded foreground scan), so it always runs inside the system's 30 s window.
    static let silentPushGrace: TimeInterval = 2

    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "app")

    func application(
        _ application: UIApplication,
        willFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        // Before anything can ask for a classification: the gate starts closed, reads the real application state
        // and then follows didBecomeActive / willResignActive / didEnterBackground. A background launch (silent
        // push, BGTask) therefore never believes it may use the GPU.
        AppEnvironment.shared.foregroundGate.start()
        AppEnvironment.shared.notificationManager.registerCategories()
        return true
    }

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        let environment = AppEnvironment.shared
        // BGTaskScheduler requires registration of every permitted identifier before launch finishes.
        environment.backgroundTasks.registerTasks()
        environment.backgroundTasks.scheduleAppRefresh()
        // Silent pushes need no user permission. The token is requested on every launch (and on every activation,
        // see `AppEnvironment.scanOnActivate`); `RelayClient` re-sends it only when it changed or the relay no
        // longer knows the device.
        application.registerForRemoteNotifications()
        return true
    }

    func applicationDidReceiveMemoryWarning(_ application: UIApplication) {
        logger.notice("Memory warning")
        let coordinator = AppEnvironment.shared.scanCoordinator
        Task { await coordinator.handleMemoryWarning() }
    }

    // MARK: - APNs

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let environment = AppEnvironment.shared
        let apnsEnvironment = environment.config.apnsEnvironment
        logger.info("APNs token received (environment=\(apnsEnvironment, privacy: .public))")
        guard environment.relayClient.isConfigured else {
            logger.info("Relay not configured; skipping device registration")
            return
        }
        let relay = environment.relayClient
        let logger = self.logger
        Task {
            do {
                let sent = try await relay.registerDevice(apnsToken: deviceToken, environment: apnsEnvironment)
                logger.info("Device registration \(sent ? "sent" : "unchanged", privacy: .public)")
            } catch {
                logger.error("Device registration failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: any Error) {
        // Typical on the simulator without a paired account, on devices without connectivity, and on any build
        // without the push entitlement (a free Apple team). BGAppRefresh remains the mail fallback and a later
        // launch retries automatically. The device is still registered with the relay — without a token — so
        // Call Guard's device-scoped routes (line, history, demo, live feed) work; only pushes cannot.
        logger.notice("APNs registration failed: \(error.localizedDescription, privacy: .public)")
        let environment = AppEnvironment.shared
        guard environment.relayClient.isConfigured else { return }
        let relay = environment.relayClient
        let apnsEnvironment = environment.config.apnsEnvironment
        let logger = self.logger
        Task {
            do {
                let sent = try await relay.registerDevice(apnsToken: nil, environment: apnsEnvironment)
                logger.info("Tokenless device registration \(sent ? "sent" : "unchanged", privacy: .public)")
            } catch {
                logger.error("Tokenless device registration failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// Silent push from the relay: `{ aps: { content-available: 1 }, provider, accountKey }` → scan within ~25 s.
    /// Overlapping pushes join the running scan (coordinator coalescing). A watchdog calls the completion handler
    /// at budget + grace whatever the scan is doing, so the 30 s system limit always holds; leftover work is then
    /// handed to a `BGProcessingTask`.
    ///
    /// The app is not frontmost here, so with the local MLX model selected the scan classifies with the rule engine
    /// only (`ForegroundGate`); Apple Intelligence, which the system allows in the background, still answers.
    func application(
        _ application: UIApplication,
        didReceiveRemoteNotification userInfo: [AnyHashable: Any],
        fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        let payload: SilentPushPayload
        switch RemoteNotificationRoute.classify(userInfo) {
        case .callAlert:
            // Call Guard alert (docs/CALLS.md §5.4): iOS has shown the banner; fetch and persist the call so the
            // tap has a record to open. Never a mail scan. Same 25 s budget and exactly-once completion as below.
            handleCallAlertPush(userInfo, completionHandler: completionHandler)
            return
        case .ignored:
            logger.notice("Remote notification without content-available; ignoring")
            completionHandler(.noData)
            return
        case .mailSilentPush(let mailPayload):
            payload = mailPayload
        }
        let environment = AppEnvironment.shared
        environment.backgroundTasks.status.recordSilentPushArrival()

        #if DEBUG
        // Screen-recording demo: `{"aps":{"content-available":1},"demoFixture":"<SampleEmails name>"}` queues
        // that fixture on `DemoMailProvider`, so the scan below finds it the way it finds any new mail — same
        // analyzer, same classifier, same verdict engine, same notification. See docs/DEMO.md.
        if let fixture = userInfo[DemoMailProvider.pushFixtureKey] as? String,
           let demo = environment.demoMailProvider {
            demo.enqueueFixture(named: fixture)
            logger.info("Demo push queued fixture \(fixture, privacy: .public)")
        }
        #endif

        let matched = payload.accountKey.map { environment.accountIDs(forRelayAccountKey: $0) } ?? []
        let accountIDs = matched.isEmpty ? nil : matched
        logger.info("Silent push (provider=\(payload.provider?.rawValue ?? "?", privacy: .public), matched accounts=\(matched.count), lifecycle=\(payload.lifecycleEvent ?? "none", privacy: .public))")

        let deadline = Date().addingTimeInterval(Self.silentPushBudget)
        let completion = SilentPushCompletion(completionHandler)
        let logger = self.logger
        let work = Task {
            if payload.lifecycleEvent != nil, let accountIDs {
                await environment.scanCoordinator.requestPushRenewal(for: accountIDs)
            }
            let summary = await environment.runScan(trigger: .silentPush, accountIDs: accountIDs, deadline: deadline)
            if completion.complete(BackgroundOutcome.fetchResult(for: summary)) {
                environment.backgroundTasks.didHandleSilentPush(summary: summary)
            }
        }
        Task {
            try? await Task.sleep(for: .seconds(Self.silentPushBudget + Self.silentPushGrace))
            // Nothing is known about the scan at this point beyond "still running": answer noData, stop waiting
            // (the shared scan itself is never cancelled by a joiner) and queue the processing task for the rest.
            guard completion.complete(.noData) else { return }
            work.cancel()
            logger.notice("Silent push scan exceeded its budget; completed with noData and queued processing")
            environment.backgroundTasks.didHandleSilentPush(summary: ScanSummary(deadlineReached: true))
        }
    }

    /// `kind: call-alert` → `CallGuardCoordinator.handleAlertPush` under the silent-push budget; the watchdog
    /// answers `.noData` if the fetch has not returned in time.
    private func handleCallAlertPush(_ userInfo: [AnyHashable: Any], completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        guard let payload = CallAlertPushPayload.parse(userInfo) else {
            logger.notice("Call alert push without a callID; ignoring")
            completionHandler(.noData)
            return
        }
        let environment = AppEnvironment.shared
        let completion = SilentPushCompletion(completionHandler)
        let logger = self.logger
        logger.info("Call alert push received (level=\(payload.level.rawValue, privacy: .public))")
        let work = Task {
            let result = await environment.callGuard.handleAlertPush(payload)
            completion.complete(result)
        }
        Task {
            try? await Task.sleep(for: .seconds(Self.silentPushBudget + Self.silentPushGrace))
            guard completion.complete(.noData) else { return }
            work.cancel()
            logger.notice("Call alert fetch exceeded its budget; completed with noData")
        }
    }

    #if DEBUG
    /// Background-fetch route, kept **only** for the screen-recording demo.
    ///
    /// Apple documents this method as disabled once `BGTaskSchedulerPermittedIdentifiers` is in the Info.plist,
    /// and on a device it is: a `content-available` push arrives at `didReceiveRemoteNotification` above. The
    /// Simulator does the opposite — measured on Xcode 26.6, `xcrun simctl push` with `content-available` decodes
    /// to a `UIFetchContentInBackgroundAction` that never reaches the remote-notification delegate, which is the
    /// misrouting docs/research/background.md warns about. So the demo's "an email arrives while the app is
    /// closed" moment would silently do nothing in the Simulator without this hook.
    ///
    /// It changes nothing outside the demo: with no `-PGDemoData 1` there is no `demoMailProvider` and it
    /// answers `.noData` immediately. Inside the demo it runs the same scan the silent-push handler runs, over
    /// the same provider and classifier, so the record and the alert are produced by the shipping pipeline.
    /// `userInfo` is not passed to this method, so the fixture delivered is the one the demo armed at launch
    /// rather than the one named in the payload — the only thing the Simulator costs us here.
    func application(
        _ application: UIApplication,
        performFetchWithCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        let environment = AppEnvironment.shared
        guard let demo = environment.demoMailProvider else {
            completionHandler(.noData)
            return
        }
        if let fixture = demo.takeArmedBackgroundArrival() {
            demo.enqueueFixture(named: fixture)
            logger.notice("Demo background wake: delivering \(fixture, privacy: .public)")
        }
        environment.backgroundTasks.status.recordSilentPushArrival()
        let deadline = Date().addingTimeInterval(Self.silentPushBudget)
        let completion = SilentPushCompletion(completionHandler)
        Task {
            let summary = await environment.runScan(trigger: .silentPush, accountIDs: nil, deadline: deadline)
            if completion.complete(BackgroundOutcome.fetchResult(for: summary)) {
                environment.backgroundTasks.didHandleSilentPush(summary: summary)
            }
        }
    }
    #endif

    // MARK: - UNUserNotificationCenterDelegate

    /// Alerts are shown even while the app is in the foreground. Main-actor isolated on purpose (see the class comment).
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }

    /// Tap or "View" action → navigate to the record; "Dismiss" does nothing. The call alert category (a relay
    /// push or the in-app demo's local notification) deep-links to the call through `pendingCallID`; the mail
    /// category keeps deep-linking to the email through `pendingRecordID`. Main-actor isolated on purpose (see the
    /// class comment).
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        let content = response.notification.request.content
        if content.categoryIdentifier == NotificationManager.callAlertCategoryIdentifier {
            guard response.actionIdentifier != NotificationManager.callDismissActionIdentifier,
                  response.actionIdentifier != UNNotificationDismissActionIdentifier else { return }
            let callID = (content.userInfo[NotificationManager.callIDUserInfoKey] as? String).flatMap(UUID.init(uuidString:))
            guard let callID else { return }
            AppEnvironment.shared.callGuard.pendingCallID = callID
            return
        }
        guard response.actionIdentifier != NotificationManager.dismissActionIdentifier,
              response.actionIdentifier != UNNotificationDismissActionIdentifier else { return }
        let recordID = (content.userInfo[NotificationManager.recordIDUserInfoKey] as? String)
            .flatMap(UUID.init(uuidString:))
        guard let recordID else { return }
        AppEnvironment.shared.pendingRecordID = recordID
    }
}

/// Delivers a silent push's fetch result exactly once (scan completion vs. watchdog race). Both callers run on the
/// main actor, which serialises `complete`.
@MainActor
final class SilentPushCompletion {
    private var handler: ((UIBackgroundFetchResult) -> Void)?

    init(_ handler: @escaping (UIBackgroundFetchResult) -> Void) {
        self.handler = handler
    }

    /// Returns true when this call delivered the result (false when it was already delivered).
    @discardableResult
    func complete(_ result: UIBackgroundFetchResult) -> Bool {
        guard let handler else { return false }
        self.handler = nil
        handler(result)
        return true
    }
}

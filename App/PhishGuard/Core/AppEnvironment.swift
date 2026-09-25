import Foundation
import Observation
import PhishCore
import SwiftData
import UIKit

/// Dependency container. One instance (`AppEnvironment.shared`) is created on the main actor at launch and
/// injected into SwiftUI via `.environment(_:)`; `AppDelegate` uses the same instance.
@MainActor
@Observable
final class AppEnvironment {
    static let shared = AppEnvironment()

    let config: AppConfig
    let container: ModelContainer
    let settings: SettingsStore
    let keychain: Keychain
    let notificationManager: NotificationManager
    let relayClient: RelayClient
    let modelManager: ModelManager
    let classifierRegistry: ClassifierRegistry
    let providers: [MailProvider: any MailAccountProvider]
    let scanCoordinator: ScanCoordinator
    let backgroundTasks: BackgroundTaskManager
    /// Call Guard (docs/CALLS.md): the registered line, the live call and the flagged-call history.
    let callGuard: CallGuardCoordinator
    /// The app's answer to "may we use the GPU right now?", shared by the classifier registry and the scan
    /// coordinator. Fed by `AppDelegate` (UIKit lifecycle notifications) and by `PhishGuardApp` (`scenePhase`).
    let foregroundGate: AppForegroundGate
    #if DEBUG
    /// Non-nil only while the screen-recording demo is running (`-PGDemoData 1`); it stands in for
    /// `GmailProvider` and is what the demo silent push queues a fixture on. See `DemoMailProvider`.
    let demoMailProvider: DemoMailProvider?
    #endif

    /// Result of the most recent scan started through `runScan`.
    private(set) var lastScanSummary: ScanSummary?
    private(set) var lastScanDate: Date?
    /// Number of `runScan` calls in progress. Overlapping calls are normal (a call joins the in-flight scan and may
    /// wait for a follow-up pass), so the UI must not report "idle" until the last one returns.
    private var activeScanCount = 0
    /// True while any `runScan` call is in progress.
    var isScanning: Bool { activeScanCount > 0 }
    /// Set when the user taps an alert notification; the UI navigates to that record and clears it.
    var pendingRecordID: UUID?

    init(
        config: AppConfig = .current,
        container: ModelContainer? = nil,
        defaults: UserDefaults = .standard,
        foregroundGate: AppForegroundGate = .shared
    ) {
        self.config = config
        self.foregroundGate = foregroundGate
        let container = container ?? Persistence.makeDefaultContainer()
        self.container = container

        let settings = SettingsStore(defaults: defaults)
        self.settings = settings

        let keychain = Keychain(service: config.bundleIdentifier)
        self.keychain = keychain

        let notifications = NotificationManager()
        self.notificationManager = notifications
        let relayClient = RelayClient(config: config.relayConfig, keychain: keychain, bundleIdentifier: config.bundleIdentifier)
        self.relayClient = relayClient

        let modelManager = ModelManager()
        self.modelManager = modelManager
        let registry = ClassifierRegistry(settings: settings, modelManager: modelManager, foregroundGate: foregroundGate)
        self.classifierRegistry = registry

        var providers: [MailProvider: any MailAccountProvider] = [
            .gmail: GmailProvider(config: config, keychain: keychain),
            .microsoft: MicrosoftProvider(config: config, keychain: keychain),
            // No client id and no relay registration: IMAP accounts sign in with a password and are scanned
            // in the foreground and by background refresh.
            .imap: IMAPProvider(keychain: keychain),
        ]
        #if DEBUG
        // Screen-recording demo (`-PGDemoData 1`): the demo mailbox is fictional, so the real provider would
        // answer every scan with `notAuthenticated`. `DemoMailProvider` replays bundled fixtures instead and
        // `DemoClassifier` replays the recorded answers of the real local model, which cannot run in the
        // Simulator — everything else, including the whole scan pipeline, is untouched. See docs/DEMO.md.
        let demoProvider = DemoData.isRequested ? DemoMailProvider() : nil
        if let demoProvider { providers[.gmail] = demoProvider }
        self.demoMailProvider = demoProvider
        #endif
        self.providers = providers

        let relayConfig = config.relayConfig
        let coordinator = ScanCoordinator(
            container: container,
            providers: providers,
            notifications: notifications,
            classifierResolver: {
                #if DEBUG
                if demoProvider != nil { return DemoClassifier() }
                #endif
                return await MainActor.run { registry.activeClassifier() }
            },
            settingsResolver: {
                await MainActor.run {
                    ScanSettingsSnapshot(alertPolicy: settings.alertPolicy, lookback: settings.lookback, relayConfig: relayConfig)
                }
            },
            resourceReleaser: { await registry.releaseResources() },
            foregroundGate: foregroundGate
        )
        self.scanCoordinator = coordinator
        self.backgroundTasks = BackgroundTaskManager(config: config) { trigger, deadline in
            await coordinator.scan(trigger: trigger, accountIDs: nil, deadline: deadline)
        }
        self.callGuard = CallGuardCoordinator(
            client: CallGuardClient(relay: relayClient),
            container: container,
            settings: settings
        )
    }

    /// In-memory environment for SwiftUI previews and tests.
    static func preview() -> AppEnvironment {
        let container: ModelContainer
        do {
            container = try Persistence.makeContainer(inMemory: true)
        } catch {
            fatalError("Unable to create in-memory ModelContainer: \(error)")
        }
        let defaults = UserDefaults(suiteName: "com.mazooni.PhishGuard.preview") ?? .standard
        return AppEnvironment(config: AppConfig(), container: container, defaults: defaults)
    }

    // MARK: - Scanning entry points

    /// Runs a scan and records its summary for the UI. A foreground scan that stopped on the deadline or the
    /// per-scan message budget leaves work pending, so the processing task is queued for it (silent-push scans are
    /// handled by `BackgroundTaskManager.didHandleSilentPush`, BGTask launches by `didFinish`).
    @discardableResult
    func runScan(trigger: ScanTrigger, accountIDs: [UUID]? = nil, deadline: Date? = nil) async -> ScanSummary {
        activeScanCount += 1
        defer { activeScanCount -= 1 }
        let summary = await scanCoordinator.scan(trigger: trigger, accountIDs: accountIDs, deadline: deadline)
        lastScanSummary = summary
        lastScanDate = .now
        if summary.deadlineReached, trigger != .silentPush {
            backgroundTasks.scheduleProcessing()
        }
        return summary
    }

    /// "Re-check recent email" (Diagnostics and Settings → Scanning): forget which messages have already been
    /// checked, reset the accounts' sync cursors and scan again, so a detection improvement — or an
    /// interrupted scan — does not leave earlier mail unexamined forever. Counts as a scan for the UI, so the
    /// "Scan now" buttons stay disabled while it runs.
    @discardableResult
    func recheckRecentEmail(accountIDs: [UUID]? = nil) async -> ScanCoordinator.RecheckSummary {
        activeScanCount += 1
        defer { activeScanCount -= 1 }
        let result = await scanCoordinator.recheckRecentEmail(accountIDs: accountIDs, deadline: nil)
        lastScanSummary = ScanSummary(
            scanned: result.scanned, flagged: result.flagged, errors: result.errors,
            deadlineReached: result.deadlineReached, cancelled: result.cancelled
        )
        lastScanDate = .now
        if result.deadlineReached {
            backgroundTasks.scheduleProcessing()
        }
        return result
    }

    /// Fresh-install default for the detection model, applied once this device's Apple Intelligence
    /// availability is known: "Both models" where Apple Intelligence works, the downloaded local model
    /// otherwise. A no-op as soon as any choice has been stored, so it can never override the user (or
    /// onboarding). Called from `RootView`.
    func applyDefaultClassifierChoiceIfNeeded() async {
        guard !settings.hasStoredClassifierChoice else { return }
        let availability = await classifierRegistry.classifier(for: .appleFoundation).availability()
        settings.applyDefaultClassifierChoice(appleIntelligenceAvailable: availability.isAvailable)
    }

    /// `scenePhase == .active` hook: open the GPU gate, foreground scan, keep the refresh task scheduled, and ask
    /// iOS for the APNs token again so a device registration that failed at launch (or was forgotten after a relay
    /// 401) is re-sent through `AppDelegate.didRegisterForRemoteNotificationsWithDeviceToken` (a no-op when
    /// unchanged).
    func scanOnActivate() {
        // Redundant with `didBecomeActiveNotification`, and deliberately so: the scan started below must never run
        // with a stale, closed gate and silently skip the model in the foreground.
        foregroundGate.setForeground(true)
        backgroundTasks.scheduleAppRefresh()
        if relayClient.isConfigured {
            UIApplication.shared.registerForRemoteNotifications()
        }
        Task { await runScan(trigger: .appLaunch) }
    }

    /// `scenePhase == .inactive` hook: the app is no longer frontmost (Control Centre, the app switcher, an
    /// incoming call, the screen locking). iOS already refuses GPU work here, so the gate closes *now* — which
    /// cancels any MLX generation in flight — even though the app may never reach `.background`.
    func willResignActive() {
        foregroundGate.setForeground(false)
    }

    /// `scenePhase == .background` hook (the app-level phase, i.e. every scene is in the background): closes the
    /// GPU gate and drops resident MLX weights so the suspended app is not jettisoned for memory
    /// (docs/research/mlx.md §6). A scan still running continues with the rules only. The refresh task is re-armed
    /// on the same transition by `BackgroundTaskManager`'s `didEnterBackgroundNotification` observer.
    ///
    /// Order matters: closing the gate cancels an in-flight generation synchronously, so the weights are only
    /// unloaded once nothing is generating with them.
    func didEnterBackground() {
        foregroundGate.setForeground(false)
        let registry = classifierRegistry
        Task { await registry.releaseResources() }
    }

    /// Routes OAuth redirect URLs (from `onOpenURL`) to the provider that owns them.
    @discardableResult
    func handleOpenURL(_ url: URL) -> Bool {
        for provider in providers.values where provider.handleRedirectURL(url) {
            return true
        }
        return false
    }

    /// Resolves the accounts a silent push refers to (`accountKey` in the payload). Demo accounts are excluded:
    /// the relay never knows one, and a scan would skip it anyway.
    func accountIDs(forRelayAccountKey key: String) -> [UUID] {
        let descriptor = FetchDescriptor<LinkedAccount>(predicate: #Predicate { $0.relayAccountKey == key && !$0.isDemo })
        return ((try? container.mainContext.fetch(descriptor)) ?? []).map(\.id)
    }
}

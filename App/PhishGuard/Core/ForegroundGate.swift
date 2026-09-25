import Foundation
import OSLog
import PhishCore
import Synchronization
import UIKit

/// The app's single source of truth for "PhishGuard may submit GPU work right now".
///
/// iOS refuses Metal command-buffer submission from an app that is not frontmost, and the refusal arrives as an
/// uncaught C++ exception — `std::runtime_error: [METAL] Command buffer execution failed: Insufficient Permission
/// (to submit GPU work from background) (00000006:kIOGPUCommandBufferCallbackErrorBackgroundExecutionNotPermitted)`
/// — which terminates the process and **cannot be caught in Swift**. It has to be prevented instead: nothing may
/// start GPU work while this gate is closed.
///
/// `MLXClassifier` is the only classifier this applies to: it runs every forward pass on the GPU and submits new
/// command buffers for each generated token. Apple's `FoundationModels` is a system service Apple documents as
/// usable in the background (docs/research/foundationModels.md §3), and `HeuristicAnalyzer` is pure CPU Swift.
///
/// Only `UIApplication.State.active` counts as open. `.inactive` (Control Centre, Notification Centre, the app
/// switcher, an incoming call, the screen locking) is treated as closed because the GPU restriction bites before
/// the app reaches full background — that is exactly the transition the field crash happened on.
protocol ForegroundGate: Sendable {
    /// True only while the app is frontmost and interactive. Readable from any actor or thread without hopping to
    /// the main actor: implementations must not block or suspend.
    var isForeground: Bool { get }

    /// Registers `handler` for every state change; it is called synchronously on the thread that changed the
    /// state (the main thread, for UIKit lifecycle notifications) so an in-flight inference can be cancelled
    /// before the app has finished resigning active. Handlers must be cheap and must not block.
    ///
    /// The returned subscription removes the handler when it is cancelled or deallocated; callers keep it alive
    /// for as long as they want the callbacks.
    func onForegroundChange(_ handler: @escaping @Sendable (Bool) -> Void) -> ForegroundGateSubscription
}

/// Handle that removes a `ForegroundGate` observer on `cancel()` or deallocation.
final class ForegroundGateSubscription: Sendable {
    private let remove: Mutex<(@Sendable () -> Void)?>

    init(remove: @escaping @Sendable () -> Void) {
        self.remove = Mutex(remove)
    }

    func cancel() {
        let remove = remove.withLock { slot -> (@Sendable () -> Void)? in
            defer { slot = nil }
            return slot
        }
        remove?()
    }

    deinit {
        cancel()
    }
}

/// `ForegroundGate` fed by the UIKit/SwiftUI lifecycle.
///
/// State lives behind a `Mutex`, so the `ScanCoordinator` actor and the `MLXClassifier` actor can read it mid-scan
/// (and mid-inference) without hopping to the main actor. `AppEnvironment` owns `shared`; tests create their own
/// instance and drive it with `setForeground(_:)`.
final class AppForegroundGate: ForegroundGate {
    static let shared = AppForegroundGate()

    private struct State {
        var isForeground: Bool
        var didStart = false
        var nextObserverID = 0
        var observers: [Int: @Sendable (Bool) -> Void] = [:]
    }

    private let state: Mutex<State>
    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "foreground")

    /// Starts closed: a process launched into the background (silent push, BGTask) must never assume it may use
    /// the GPU, and `start()` opens the gate immediately when the app is in fact active.
    init(isForeground: Bool = false) {
        state = Mutex(State(isForeground: isForeground))
    }

    var isForeground: Bool {
        state.withLock { $0.isForeground }
    }

    /// Reads the current application state and observes the lifecycle notifications. Called once from
    /// `AppDelegate.application(_:willFinishLaunchingWithOptions:)`; `PhishGuardApp` keeps it honest from
    /// `scenePhase` as well. Idempotent.
    @MainActor
    func start() {
        let alreadyStarted = state.withLock { state -> Bool in
            defer { state.didStart = true }
            return state.didStart
        }
        guard !alreadyStarted else { return }

        setForeground(UIApplication.shared.applicationState == .active)
        let center = NotificationCenter.default
        let transitions: [(Notification.Name, Bool)] = [
            (UIApplication.didBecomeActiveNotification, true),
            (UIApplication.willResignActiveNotification, false),
            (UIApplication.didEnterBackgroundNotification, false),
        ]
        for (name, isForeground) in transitions {
            // `queue: nil` delivers on the posting thread (the main thread) *synchronously*, which is the point:
            // a queued block would leave a window in which MLX could still submit a command buffer.
            _ = center.addObserver(forName: name, object: nil, queue: nil) { [weak self] _ in
                self?.setForeground(isForeground)
            }
        }
        // Observers are never removed: the gate lives as long as the process.
    }

    /// The single writer. Observers are notified synchronously, outside the lock, on the caller's thread.
    func setForeground(_ isForeground: Bool) {
        let observers = state.withLock { state -> [@Sendable (Bool) -> Void]? in
            guard state.isForeground != isForeground else { return nil }
            state.isForeground = isForeground
            return Array(state.observers.values)
        }
        guard let observers else { return }
        logger.info("Foreground gate \(isForeground ? "open" : "closed", privacy: .public)")
        for observer in observers {
            observer(isForeground)
        }
    }

    func onForegroundChange(_ handler: @escaping @Sendable (Bool) -> Void) -> ForegroundGateSubscription {
        let id = state.withLock { state -> Int in
            state.nextObserverID += 1
            state.observers[state.nextObserverID] = handler
            return state.nextObserverID
        }
        return ForegroundGateSubscription { [weak self] in
            self?.state.withLock { $0.observers[id] = nil }
        }
    }
}

/// Marks a classifier whose inference runs on the GPU and that therefore may only be called while
/// `ForegroundGate.isForeground` is true.
///
/// The classifier refuses on its own too (`MLXClassifier.availability()` / `assess(_:)`), but `ScanCoordinator`
/// checks this cheaply before every message so a background scan never even reaches the model — and so the
/// fallback is recorded as "expected", not as a classifier failure.
protocol GPUBackedClassifier: EmailClassifier {}

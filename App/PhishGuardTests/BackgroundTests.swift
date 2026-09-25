import PhishCore
import UIKit
import UserNotifications
import XCTest
@testable import PhishGuard

final class BackgroundTests: XCTestCase {
    private let key = "88c9b9630189acc1265c686fca97d64a720348160cdae5cdfa11fa5d3974bc58"

    // MARK: - Silent push payload

    func testSilentPushPayloadParsing() {
        let payload = SilentPushPayload.parse([
            "aps": ["content-available": 1],
            "provider": "gmail",
            "accountKey": key.uppercased(),
        ])
        XCTAssertTrue(payload.isContentAvailable)
        XCTAssertEqual(payload.provider, .gmail)
        XCTAssertEqual(payload.accountKey, key, "keys are normalised to lowercase hex")
        XCTAssertNil(payload.lifecycleEvent)
    }

    func testSilentPushPayloadToleratesVariants() {
        XCTAssertTrue(SilentPushPayload.parse(["aps": ["content-available": "1"]]).isContentAvailable)
        XCTAssertTrue(SilentPushPayload.parse(["aps": ["content-available": true]]).isContentAvailable)
        XCTAssertFalse(SilentPushPayload.parse(["aps": ["content-available": 0]]).isContentAvailable)
        XCTAssertFalse(SilentPushPayload.parse(["aps": ["alert": "hi"]]).isContentAvailable)
        XCTAssertFalse(SilentPushPayload.parse(["provider": "gmail"]).isContentAvailable)
        XCTAssertFalse(SilentPushPayload.parse([:]).isContentAvailable)

        let microsoft = SilentPushPayload.parse([
            "aps": ["content-available": 1],
            "provider": "Microsoft",
            "accountKey": key,
            "lifecycleEvent": " subscriptionRemoved ",
        ])
        XCTAssertEqual(microsoft.provider, .microsoft)
        XCTAssertEqual(microsoft.lifecycleEvent, "subscriptionRemoved")

        let garbage = SilentPushPayload.parse([
            "aps": ["content-available": 1],
            "provider": "yahoo",
            "accountKey": "not-a-hash",
            "lifecycleEvent": "",
        ])
        XCTAssertTrue(garbage.isContentAvailable)
        XCTAssertNil(garbage.provider)
        XCTAssertNil(garbage.accountKey, "malformed account keys are ignored so every enabled account is scanned")
        XCTAssertNil(garbage.lifecycleEvent)
        XCTAssertNil(SilentPushPayload.parse(["aps": ["content-available": 1], "accountKey": 42]).accountKey)
    }

    // MARK: - Remote notification routing (docs/CALLS.md §5.4, §8)

    func testCallAlertIsRoutedBeforeTheMailDoorbell() {
        let callAlert = CallFixtures.pushUserInfo()
        XCTAssertEqual(RemoteNotificationRoute.classify(callAlert), .callAlert, "kind wins even though content-available is set")
        XCTAssertTrue(SilentPushPayload.parse(callAlert).isContentAvailable, "which is exactly why the mail path must not see it")
        XCTAssertEqual(RemoteNotificationRoute.classify(["kind": "call-alert", "callID": "x"]), .callAlert, "with or without aps")
        XCTAssertEqual(RemoteNotificationRoute.classify(["kind": " call-alert ", "callID": "x", "aps": ["content-available": 1]]), .callAlert)
    }

    func testMailDoorbellAndUnknownPushesRouteAsBefore() {
        let mail: [AnyHashable: Any] = ["aps": ["content-available": 1], "provider": "gmail", "accountKey": key]
        guard case .mailSilentPush(let payload) = RemoteNotificationRoute.classify(mail) else {
            return XCTFail("expected the mail route")
        }
        XCTAssertEqual(payload.provider, .gmail)
        XCTAssertEqual(payload.accountKey, key)

        XCTAssertEqual(RemoteNotificationRoute.classify(["aps": ["alert": "hi"]]), .ignored)
        XCTAssertEqual(RemoteNotificationRoute.classify(["kind": "something-else", "aps": ["alert": "hi"]]), .ignored)
        XCTAssertEqual(RemoteNotificationRoute.classify([:]), .ignored)
        guard case .mailSilentPush = RemoteNotificationRoute.classify(["aps": ["content-available": 1], "kind": "newsletter"]) else {
            return XCTFail("an unknown kind with content-available is still the mail doorbell")
        }
    }

    // MARK: - Outcome mapping

    func testFetchResultMapping() {
        XCTAssertEqual(BackgroundOutcome.fetchResult(for: ScanSummary(scanned: 2, flagged: 1)), .newData)
        XCTAssertEqual(BackgroundOutcome.fetchResult(for: ScanSummary(scanned: 1, errors: ["x"])), .newData)
        XCTAssertEqual(BackgroundOutcome.fetchResult(for: ScanSummary()), .noData)
        XCTAssertEqual(BackgroundOutcome.fetchResult(for: ScanSummary(deadlineReached: true)), .noData)
        XCTAssertEqual(BackgroundOutcome.fetchResult(for: ScanSummary(errors: ["boom"])), .failed)
        XCTAssertEqual(BackgroundOutcome.fetchResult(for: ScanSummary(cancelled: true)), .failed)
    }

    func testTaskSuccessMapping() {
        XCTAssertTrue(BackgroundOutcome.taskSucceeded(ScanSummary()))
        XCTAssertTrue(BackgroundOutcome.taskSucceeded(ScanSummary(scanned: 3, errors: ["one account failed"])))
        XCTAssertFalse(BackgroundOutcome.taskSucceeded(ScanSummary(errors: ["boom"])))
        XCTAssertFalse(BackgroundOutcome.taskSucceeded(ScanSummary(scanned: 3, cancelled: true)))
    }

    func testSummaryOutcomeText() {
        XCTAssertEqual(ScanSummary(scanned: 4, flagged: 1).outcomeText, "4 checked, 1 flagged")
        XCTAssertEqual(ScanSummary(scanned: 0, flagged: 0, errors: ["a", "b"], deadlineReached: true, cancelled: true).outcomeText, "0 checked, 0 flagged, 2 errors, hit deadline, cancelled")
        XCTAssertEqual(ScanSummary(errors: ["a"]).outcomeText, "0 checked, 0 flagged, 1 error")
    }

    // MARK: - Silent push completion

    @MainActor
    func testSilentPushCompletionDeliversExactlyOnce() {
        final class Results { var values: [UIBackgroundFetchResult] = [] }
        let results = Results()
        let completion = SilentPushCompletion { results.values.append($0) }

        XCTAssertTrue(completion.complete(.newData), "the first caller (scan or watchdog) delivers the result")
        XCTAssertFalse(completion.complete(.noData), "the loser must not call the system handler again")
        XCTAssertFalse(completion.complete(.failed))
        XCTAssertEqual(results.values, [.newData])
        XCTAssertLessThan(AppDelegate.silentPushBudget + AppDelegate.silentPushGrace, 30, "the watchdog fires inside the system's 30 s window")
    }

    // MARK: - Notification delegate completions (device crash, 2026-09-24)

    /// UIKit wraps the notification delegate's completion handlers and asserts they are called on the main thread. For
    /// an `async` witness the compiler-generated ObjC entry point runs a task *with the witness's isolation* and then
    /// calls that handler, so the witnesses must be main-actor isolated: declared `nonisolated` they completed on the
    /// cooperative pool and every banner tap crashed the app ("Call must be made on main thread" in
    /// `-[UIApplication _performBlockAfterCATransactionCommitSynchronizes:]`). Drives the same ObjC entry points UIKit
    /// does, with real `UNNotificationResponse` / `UNNotification` values.
    @MainActor
    func testNotificationDelegateCompletionsRunOnTheMainThread() async throws {
        let delegate = AppDelegate()
        let objcDelegate = delegate as any UNUserNotificationCenterDelegate
        let center = UNUserNotificationCenter.current()
        let callID = UUID()
        let response = try NotificationFixtures.response(
            categoryIdentifier: NotificationManager.callAlertCategoryIdentifier,
            userInfo: [NotificationManager.callIDUserInfoKey: callID.uuidString]
        )

        // The optional-chained calls dispatch through objc_msgSend into the same generated thunks UIKit uses. If a
        // requirement were ever dropped the chain would yield nil and never resume, so guard against a hang.
        XCTAssertTrue(delegate.responds(to: #selector(UNUserNotificationCenterDelegate.userNotificationCenter(_:didReceive:withCompletionHandler:))))
        XCTAssertTrue(delegate.responds(to: #selector(UNUserNotificationCenterDelegate.userNotificationCenter(_:willPresent:withCompletionHandler:))))
        defer { AppEnvironment.shared.callGuard.pendingCallID = nil }

        // `pendingCallID` is read inside the handler, before SwiftUI's observers get a chance to consume it.
        let (tapCompletedOnMainThread, pendingCallID): (Bool, UUID?) = await withCheckedContinuation { continuation in
            let dispatched: Void? = objcDelegate.userNotificationCenter?(center, didReceive: response) {
                let pending = Thread.isMainThread ? MainActor.assumeIsolated { AppEnvironment.shared.callGuard.pendingCallID } : nil
                continuation.resume(returning: (Thread.isMainThread, pending))
            }
            if dispatched == nil { continuation.resume(returning: (false, nil)) }
        }
        XCTAssertTrue(tapCompletedOnMainThread, "UIKit asserts the tap completion handler is called on the main thread")
        XCTAssertEqual(pendingCallID, callID, "the tap still deep-links to the call")

        let (presentCompletedOnMainThread, options): (Bool, UNNotificationPresentationOptions?) = await withCheckedContinuation { continuation in
            let dispatched: Void? = objcDelegate.userNotificationCenter?(center, willPresent: response.notification) { options in
                continuation.resume(returning: (Thread.isMainThread, options))
            }
            if dispatched == nil { continuation.resume(returning: (false, nil)) }
        }
        XCTAssertTrue(presentCompletedOnMainThread, "same wrapper for the foreground-presentation completion handler")
        XCTAssertEqual(options, [.banner, .list, .sound])
    }

    // MARK: - Status persistence

    @MainActor
    func testBackgroundStatusPersistsRuns() throws {
        let suite = "PhishGuardTests.background.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        let status = BackgroundStatus(defaults: defaults)
        XCTAssertNil(status.lastRefreshRun)
        XCTAssertNil(status.lastProcessingRun)
        XCTAssertNil(status.lastSilentPushAt)

        let refreshAt = Date(timeIntervalSince1970: 1_800_000_000)
        status.record(trigger: .backgroundRefresh, summary: ScanSummary(scanned: 2, flagged: 1), at: refreshAt)
        status.record(trigger: .backgroundProcessing, summary: ScanSummary(scanned: 9, deadlineReached: true), at: refreshAt.addingTimeInterval(60))
        status.recordSilentPushArrival(at: refreshAt.addingTimeInterval(120))
        status.record(trigger: .manual, summary: ScanSummary(scanned: 100), at: refreshAt.addingTimeInterval(500))

        let reloaded = BackgroundStatus(defaults: defaults)
        XCTAssertEqual(reloaded.lastRefreshRun, refreshAt)
        XCTAssertEqual(reloaded.lastRefreshOutcome, "2 checked, 1 flagged")
        XCTAssertEqual(reloaded.lastProcessingRun, refreshAt.addingTimeInterval(60))
        XCTAssertEqual(reloaded.lastProcessingOutcome, "9 checked, 0 flagged, hit deadline")
        XCTAssertEqual(reloaded.lastSilentPushAt, refreshAt.addingTimeInterval(120))
        XCTAssertEqual(reloaded.lastSilentPushOutcome, "received, scanning…")

        reloaded.record(trigger: .silentPush, summary: ScanSummary(scanned: 1, flagged: 1), at: refreshAt.addingTimeInterval(130))
        XCTAssertEqual(BackgroundStatus(defaults: defaults).lastSilentPushOutcome, "1 checked, 1 flagged")
        XCTAssertEqual(BackgroundStatus(defaults: defaults).lastRefreshRun, refreshAt, "manual scans never touch the background timestamps")
    }

    @MainActor
    func testBackgroundTaskManagerIdentifiersAndStatus() throws {
        let suite = "PhishGuardTests.background.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        let manager = BackgroundTaskManager(config: AppConfig(bundleIdentifier: "com.example.pg"), defaults: defaults) { _, _ in ScanSummary() }
        XCTAssertEqual(manager.refreshIdentifier, "com.example.pg.refresh")
        XCTAssertEqual(manager.processingIdentifier, "com.example.pg.process")
        XCTAssertEqual(BackgroundTaskManager.refreshBudget, 25)
        XCTAssertEqual(BackgroundTaskManager.processingBudget, 120)
        XCTAssertEqual(BackgroundTaskManager.refreshInterval, 15 * 60)

        manager.didHandleSilentPush(summary: ScanSummary(scanned: 1, deadlineReached: true))
        XCTAssertNotNil(manager.status.lastSilentPushAt)
        XCTAssertEqual(manager.status.lastSilentPushOutcome, "1 checked, 0 flagged, hit deadline")
        XCTAssertEqual(BackgroundStatus(defaults: defaults).lastSilentPushOutcome, "1 checked, 0 flagged, hit deadline")
    }
}

/// Real `UNNotification` / `UNNotificationResponse` values for delegate tests. Neither has a public initialiser, but both
/// are `NSSecureCoding`: the keyed values are archived under a stand-in class name that the unarchiver maps to the
/// framework class, whose `init(coder:)` then reads them (`request` / `date` and `notification` / `actionIdentifier`,
/// the ivar names, unchanged since iOS 10). Public API only.
enum NotificationFixtures {
    static func notification(
        categoryIdentifier: String,
        userInfo: [AnyHashable: Any],
        identifier: String = "PhishGuardTests.notification"
    ) throws -> UNNotification {
        let content = UNMutableNotificationContent()
        content.categoryIdentifier = categoryIdentifier
        content.userInfo = userInfo
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        return try unarchive(UNNotification.self, ["request": request, "date": Date()])
    }

    static func response(
        categoryIdentifier: String,
        userInfo: [AnyHashable: Any],
        actionIdentifier: String = UNNotificationDefaultActionIdentifier
    ) throws -> UNNotificationResponse {
        let notification = try notification(categoryIdentifier: categoryIdentifier, userInfo: userInfo)
        return try unarchive(UNNotificationResponse.self, ["notification": notification, "actionIdentifier": actionIdentifier])
    }

    /// The stand-in's archived class name (its `@objc` name, stable across modules and builds).
    private static let standInClassName = "PhishGuardTestsNotificationFixtureValues"

    private static func unarchive<Decoded: NSObject & NSSecureCoding>(_ type: Decoded.Type, _ values: [String: Any]) throws -> Decoded {
        let archiver = NSKeyedArchiver(requiringSecureCoding: true)
        archiver.encode(KeyedValues(values), forKey: NSKeyedArchiveRootObjectKey)
        archiver.finishEncoding()
        let unarchiver = try NSKeyedUnarchiver(forReadingFrom: archiver.encodedData)
        unarchiver.requiresSecureCoding = true
        unarchiver.setClass(type, forClassName: standInClassName)
        defer { unarchiver.finishDecoding() }
        let decoded = unarchiver.decodeObject(of: type, forKey: NSKeyedArchiveRootObjectKey)
        return try XCTUnwrap(decoded, "\(type) did not decode: \(unarchiver.error?.localizedDescription ?? "no error")")
    }

    @objc(PhishGuardTestsNotificationFixtureValues)
    private final class KeyedValues: NSObject, NSSecureCoding {
        static let supportsSecureCoding = true
        let values: [String: Any]

        init(_ values: [String: Any]) { self.values = values }
        required init?(coder: NSCoder) { nil }

        func encode(with coder: NSCoder) {
            for (key, value) in values { coder.encode(value, forKey: key) }
        }
    }
}

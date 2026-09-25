import Foundation
import OSLog
import PhishCore
import UserNotifications

/// UNUserNotificationCenter wrapper. Posts one local notification per flagged email (rule 5: notify only when
/// flagged). A notification carries sender, subject and the top reason — never the body.
final class NotificationManager: Sendable {
    static let categoryIdentifier = "PHISHGUARD_ALERT"
    static let viewActionIdentifier = "PHISHGUARD_VIEW"
    static let dismissActionIdentifier = "PHISHGUARD_DISMISS"
    /// Thread used when no account is known (test alerts). Real alerts are threaded per account.
    static let threadIdentifier = "com.mazooni.PhishGuard.alerts"
    static let recordIDUserInfoKey = "recordID"
    static let accountIDUserInfoKey = "accountID"
    static let alertTitle = "Suspicious email flagged"
    static let testAlertIdentifier = "phishguard-test-alert"

    // Call Guard (docs/CALLS.md §5.4, §8). The category and thread are what the relay's push carries; the local
    // notification the in-app demo posts uses the same ones so a tap lands in the same place.
    static let callAlertCategoryIdentifier = "PHISHGUARD_CALL_ALERT"
    static let callViewActionIdentifier = "PHISHGUARD_CALL_VIEW"
    static let callDismissActionIdentifier = "PHISHGUARD_CALL_DISMISS"
    static let callThreadIdentifier = "com.mazooni.PhishGuard.calls"
    static let callIDUserInfoKey = "callID"

    /// Test seam: receives what would be posted instead of `UNUserNotificationCenter`. `delay` is nil for an
    /// immediate post and the trigger's interval otherwise.
    typealias Poster = @Sendable (_ identifier: String, _ content: AlertContent, _ delay: TimeInterval?) -> Void
    /// Same seam for call alerts.
    typealias CallPoster = @Sendable (_ identifier: String, _ content: CallAlertContent, _ delay: TimeInterval?) -> Void

    /// Everything that goes into a call alert notification — the same title/subtitle/body rules as the relay's
    /// push (`CallAlertText`), time-sensitive so it breaks through Focus while the person is on the call.
    struct CallAlertContent: Sendable, Equatable {
        var title: String
        var subtitle: String
        var body: String
        var callID: UUID
        var level: RiskLevel

        static func make(callID: UUID, level: RiskLevel, callerNumber: String, reasonTitles: [String], summary: String = "") -> CallAlertContent {
            let text = CallAlertText.make(level: level, callerNumber: callerNumber, reasonTitles: reasonTitles, summary: summary)
            return CallAlertContent(title: text.title, subtitle: text.subtitle, body: text.body, callID: callID, level: level)
        }

        func makeNotificationContent() -> UNMutableNotificationContent {
            let content = UNMutableNotificationContent()
            content.title = title
            content.subtitle = subtitle
            content.body = body
            content.sound = .default
            content.interruptionLevel = .timeSensitive
            content.relevanceScore = 1
            content.threadIdentifier = NotificationManager.callThreadIdentifier
            content.categoryIdentifier = NotificationManager.callAlertCategoryIdentifier
            content.userInfo = [NotificationManager.callIDUserInfoKey: callID.uuidString]
            return content
        }
    }

    /// Everything that goes into a flagged-email notification, as a plain value so it can be unit-tested.
    struct AlertContent: Sendable, Equatable {
        static let maxSubjectLength = 120
        static let maxReasonLength = 160
        static let maxSubtitleLength = 100

        var title: String
        var subtitle: String
        var body: String
        var threadIdentifier: String
        var recordID: UUID?
        var accountID: UUID?
        /// App badge to set with this notification (unread flagged count); nil leaves the badge untouched.
        var badge: Int?

        static func make(
            senderName: String?,
            senderAddress: String,
            subject: String,
            topReason: String?,
            summary: String,
            recordID: UUID?,
            accountID: UUID?,
            unreadCount: Int?
        ) -> AlertContent {
            let trimmedSubject = subject.trimmingCharacters(in: .whitespacesAndNewlines)
            var body = String((trimmedSubject.isEmpty ? "(no subject)" : trimmedSubject).prefix(maxSubjectLength))
            let reason = (topReason ?? summary).trimmingCharacters(in: .whitespacesAndNewlines)
            if !reason.isEmpty {
                body += " — " + String(reason.prefix(maxReasonLength))
            }

            let sender: String
            if let senderName, !senderName.isEmpty {
                sender = senderAddress.isEmpty ? senderName : "\(senderName) <\(senderAddress)>"
            } else {
                sender = senderAddress
            }

            return AlertContent(
                title: NotificationManager.alertTitle,
                subtitle: String(sender.prefix(maxSubtitleLength)),
                body: body,
                threadIdentifier: NotificationManager.threadIdentifier(forAccount: accountID),
                recordID: recordID,
                accountID: accountID,
                badge: unreadCount
            )
        }

        func makeNotificationContent() -> UNMutableNotificationContent {
            let content = UNMutableNotificationContent()
            content.title = title
            content.subtitle = subtitle
            content.body = body
            content.sound = .default
            content.interruptionLevel = .active
            content.threadIdentifier = threadIdentifier
            content.categoryIdentifier = NotificationManager.categoryIdentifier
            var userInfo: [String: String] = [:]
            if let recordID { userInfo[NotificationManager.recordIDUserInfoKey] = recordID.uuidString }
            if let accountID { userInfo[NotificationManager.accountIDUserInfoKey] = accountID.uuidString }
            content.userInfo = userInfo
            if let badge { content.badge = NSNumber(value: max(0, badge)) }
            return content
        }
    }

    private let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "notifications")
    private let poster: Poster?
    private let callPoster: CallPoster?

    init(poster: Poster? = nil, callPoster: CallPoster? = nil) {
        self.poster = poster
        self.callPoster = callPoster
    }

    // MARK: - Identifiers

    static func requestIdentifier(recordID: UUID) -> String { "flagged-\(recordID.uuidString)" }

    /// `call-<callID>`, mirroring the push's `apns-collapse-id`.
    static func callRequestIdentifier(callID: UUID) -> String { "call-\(callID.uuidString)" }

    /// Every request identifier a delivered alert for `callID` can carry: the local notification's
    /// (`callRequestIdentifier`, upper-case as `UUID.uuidString` prints it) and the relay push's — iOS uses the
    /// `apns-collapse-id` (`call-<callID>`, docs/CALLS.md §5.4) as the delivered request's identifier, and the
    /// relay spells its uuids lower-case (Node's `randomUUID()`). Withdrawing only one spelling would leave the
    /// real push standing after the person has read the call.
    static func callAlertIdentifiers(callID: UUID) -> [String] {
        let local = callRequestIdentifier(callID: callID)
        let push = "call-\(callID.uuidString.lowercased())"
        return local == push ? [local] : [local, push]
    }

    static func threadIdentifier(forAccount accountID: UUID?) -> String {
        accountID.map { "com.mazooni.PhishGuard.account.\($0.uuidString)" } ?? threadIdentifier
    }

    /// Builds the notification content for a flagged record. `unreadCount` becomes the app badge.
    static func alertContent(for record: FlaggedEmailRecord, unreadCount: Int?) -> AlertContent {
        AlertContent.make(
            senderName: record.senderName,
            senderAddress: record.senderAddress,
            subject: record.subject,
            topReason: record.reasons.first?.title,
            summary: record.summary,
            recordID: record.id,
            accountID: record.accountID,
            unreadCount: unreadCount
        )
    }

    /// Builds the call alert content for a flagged call record.
    static func callAlertContent(for record: FlaggedCallRecord) -> CallAlertContent {
        CallAlertContent.make(
            callID: record.id,
            level: record.level,
            callerNumber: record.callerNumber,
            reasonTitles: record.reasons.map(\.title),
            summary: record.summary
        )
    }

    // MARK: - Setup / permission

    /// The mail alert category ("View" opens the record, "Dismiss" does nothing) and the call alert category
    /// (same two actions under their own identifiers — action identifiers must be unique across categories).
    /// `setNotificationCategories` replaces the whole set, so both are always registered in one call.
    static func makeCategories() -> [UNNotificationCategory] {
        let view = UNNotificationAction(identifier: Self.viewActionIdentifier, title: "View", options: [.foreground])
        let dismiss = UNNotificationAction(identifier: Self.dismissActionIdentifier, title: "Dismiss", options: [])
        let mail = UNNotificationCategory(
            identifier: Self.categoryIdentifier,
            actions: [view, dismiss],
            intentIdentifiers: [],
            hiddenPreviewsBodyPlaceholder: "Suspicious email",
            options: []
        )
        let callView = UNNotificationAction(identifier: Self.callViewActionIdentifier, title: "View", options: [.foreground])
        let callDismiss = UNNotificationAction(identifier: Self.callDismissActionIdentifier, title: "Dismiss", options: [])
        let call = UNNotificationCategory(
            identifier: Self.callAlertCategoryIdentifier,
            actions: [callView, callDismiss],
            intentIdentifiers: [],
            hiddenPreviewsBodyPlaceholder: "Possible scam call",
            options: []
        )
        return [mail, call]
    }

    /// Registers every notification category. Call at launch.
    func registerCategories() {
        UNUserNotificationCenter.current().setNotificationCategories(Set(Self.makeCategories()))
    }

    /// Asks for alert/sound/badge permission. Returns whether it was granted.
    func requestAuthorization() async -> Bool {
        do {
            return try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
        } catch {
            logger.error("Notification authorization failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    func authorizationStatus() async -> UNAuthorizationStatus {
        await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
    }

    // MARK: - Posting

    /// Posts the alert for a flagged email. `unreadCount` (unread flagged records) becomes the app badge.
    ///
    /// `delay` nil delivers immediately, which is what every real detection does — the scan has already happened
    /// by the time it posts. A delay schedules the same notification through a `UNTimeIntervalNotificationTrigger`
    /// and exists for the debug-only "simulate an incoming flagged email" button, so the presenter can lock the
    /// phone before the banner arrives. Nothing else about the notification differs.
    func postAlert(for record: FlaggedEmailRecord, unreadCount: Int? = nil, after delay: TimeInterval? = nil) {
        post(
            identifier: Self.requestIdentifier(recordID: record.id),
            content: Self.alertContent(for: record, unreadCount: unreadCount),
            delay: delay
        )
    }

    /// Diagnostics: posts a sample alert built from the bundled PayPal phishing fixture. Nothing is persisted and
    /// the notification carries no record id, so tapping it just opens the app; repeats replace the previous one.
    /// Pass `verdict` to reuse one already computed by the full pipeline; otherwise a heuristics-only verdict is used.
    func postTestAlert(verdict: Verdict? = nil) {
        let email = SampleEmails.paypalPhish
        let verdict = verdict ?? VerdictEngine().makeVerdict(report: HeuristicAnalyzer().analyze(email), assessment: nil, modelIdentifier: nil)
        let content = AlertContent.make(
            senderName: email.from?.name,
            senderAddress: email.from?.address ?? "",
            subject: email.subject,
            topReason: verdict.reasons.first?.title,
            summary: verdict.summary,
            recordID: nil,
            accountID: nil,
            unreadCount: nil
        )
        post(identifier: Self.testAlertIdentifier, content: content)
    }

    /// Removes a delivered alert (e.g. after the user opened the record in-app) and optionally updates the badge.
    /// A not-yet-delivered one is withdrawn too, so a record deleted before its scheduled alert fires — which
    /// only the debug simulate button can produce — cannot deep-link to a row that no longer exists.
    func clearAlert(recordID: UUID, unreadCount: Int? = nil) {
        let identifier = Self.requestIdentifier(recordID: recordID)
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [identifier])
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [identifier])
        if let unreadCount { setBadge(unreadCount: unreadCount) }
    }

    // MARK: - Call alerts (docs/CALLS.md §8)

    /// Posts the local call alert for a flagged call — the in-app demo's stand-in for the relay's push, with the
    /// same text rules, category, thread and `callID` payload, delivered time-sensitive. `delay` works as in
    /// `postAlert(for:unreadCount:after:)`.
    func postCallAlert(for record: FlaggedCallRecord, after delay: TimeInterval? = nil) {
        postCall(
            identifier: Self.callRequestIdentifier(callID: record.id),
            content: Self.callAlertContent(for: record),
            delay: delay
        )
    }

    /// Withdraws a call alert, delivered or still scheduled (a demo record deleted before its alert fires), under
    /// both spellings of its identifier (`callAlertIdentifiers`) so the relay's push goes too.
    func clearCallAlert(callID: UUID) {
        let identifiers = Self.callAlertIdentifiers(callID: callID)
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: identifiers)
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: identifiers)
    }

    private func postCall(identifier: String, content: CallAlertContent, delay: TimeInterval?) {
        if let callPoster {
            callPoster(identifier, content, delay)
            return
        }
        let trigger = delay.flatMap { seconds -> UNNotificationTrigger? in
            seconds >= 1 ? UNTimeIntervalNotificationTrigger(timeInterval: seconds, repeats: false) : nil
        }
        let request = UNNotificationRequest(identifier: identifier, content: content.makeNotificationContent(), trigger: trigger)
        let logger = self.logger
        UNUserNotificationCenter.current().add(request) { error in
            if let error {
                logger.error("Failed to post call alert: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// Sets the app badge to the number of unread flagged emails (0 clears it).
    func setBadge(unreadCount: Int) {
        let logger = self.logger
        UNUserNotificationCenter.current().setBadgeCount(max(0, unreadCount)) { error in
            if let error {
                logger.error("Failed to set badge: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    private func post(identifier: String, content: AlertContent, delay: TimeInterval? = nil) {
        if let poster {
            poster(identifier, content, delay)
            return
        }
        // UNTimeIntervalNotificationTrigger rejects a non-positive interval, so anything that small posts now.
        let trigger = delay.flatMap { seconds -> UNNotificationTrigger? in
            seconds >= 1 ? UNTimeIntervalNotificationTrigger(timeInterval: seconds, repeats: false) : nil
        }
        let request = UNNotificationRequest(identifier: identifier, content: content.makeNotificationContent(), trigger: trigger)
        let logger = self.logger
        UNUserNotificationCenter.current().add(request) { error in
            if let error {
                logger.error("Failed to post alert: \(error.localizedDescription, privacy: .public)")
            }
        }
    }
}

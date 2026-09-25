import Foundation
import PhishCore
import SwiftData
import UserNotifications
import XCTest
@testable import PhishGuard

/// The call alert notification: registered next to the mail category, time-sensitive, same text rules as the
/// relay's push, and the `callID` payload the tap deep-links on. Email alerts are unchanged.
final class CallNotificationTests: XCTestCase {
    @MainActor
    private func makeRecord(_ scenario: DemoCalls.Scenario = DemoCalls.grandparent) throws -> FlaggedCallRecord {
        _ = try Persistence.makeContainer(inMemory: true)
        return DemoCalls.makeRecord(scenario, startedAt: Date(timeIntervalSince1970: 1_758_600_000), isDemo: true)
    }

    func testCallCategoryIsRegisteredAlongsideTheMailCategory() throws {
        let categories = NotificationManager.makeCategories()

        XCTAssertEqual(categories.map(\.identifier), [NotificationManager.categoryIdentifier, NotificationManager.callAlertCategoryIdentifier])
        XCTAssertEqual(NotificationManager.callAlertCategoryIdentifier, "PHISHGUARD_CALL_ALERT")
        XCTAssertEqual(NotificationManager.categoryIdentifier, "PHISHGUARD_ALERT", "the mail category is unchanged")

        let call = try XCTUnwrap(categories.first { $0.identifier == NotificationManager.callAlertCategoryIdentifier })
        XCTAssertEqual(call.actions.map(\.identifier), [NotificationManager.callViewActionIdentifier, NotificationManager.callDismissActionIdentifier])
        XCTAssertEqual(call.actions.map(\.title), ["View", "Dismiss"])
        XCTAssertTrue(call.actions[0].options.contains(.foreground), "View opens the app")
        XCTAssertFalse(call.actions[1].options.contains(.foreground), "Dismiss does not")
        XCTAssertEqual(call.hiddenPreviewsBodyPlaceholder, "Possible scam call")

        let mail = try XCTUnwrap(categories.first { $0.identifier == NotificationManager.categoryIdentifier })
        XCTAssertEqual(mail.actions.map(\.identifier), [NotificationManager.viewActionIdentifier, NotificationManager.dismissActionIdentifier])
        let allActionIDs = categories.flatMap { $0.actions.map(\.identifier) }
        XCTAssertEqual(Set(allActionIDs).count, allActionIDs.count, "action identifiers must be unique across categories")
    }

    /// The relay spells `callID` lower-case (Node `randomUUID()`), and iOS keys a delivered push by its
    /// `apns-collapse-id` (`call-<callID>`), while `UUID.uuidString` is upper-case: clearing must cover both.
    func testCallAlertIdentifiersCoverTheLocalAndTheRelayPushSpelling() throws {
        let id = try XCTUnwrap(UUID(uuidString: CallFixtures.callID))

        let identifiers = NotificationManager.callAlertIdentifiers(callID: id)

        XCTAssertEqual(identifiers, ["call-\(id.uuidString)", "call-\(CallFixtures.callID)"])
        XCTAssertEqual(identifiers.first, NotificationManager.callRequestIdentifier(callID: id), "the local notification's identifier")
        XCTAssertEqual(identifiers.last, "call-8f1c2f3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f", "the push's apns-collapse-id (docs/CALLS.md §5.4)")
        XCTAssertNotEqual(identifiers.first, identifiers.last, "UUID.uuidString is upper-case, so the two differ")
        XCTAssertEqual(Set(identifiers).count, identifiers.count)
    }

    @MainActor
    func testCallAlertContentFollowsThePushRulesAndIsTimeSensitive() throws {
        let record = try makeRecord()

        let content = NotificationManager.callAlertContent(for: record)

        XCTAssertEqual(content.title, "Likely scam call")
        XCTAssertEqual(content.subtitle, "Call from +1 (415) 555-0134")
        // The recorded verdict's five titles: the fifth ("Creates urgency") would take the body past 160 characters, so it is dropped.
        XCTAssertEqual(content.body, "Asks for gift cards · Threatens arrest or government action · Claims a family member is in trouble · Says not to tell anyone or to stay on the line")
        XCTAssertLessThanOrEqual(content.body.count, CallAlertText.maxBodyLength)
        XCTAssertEqual(record.reasons.count, 5)
        XCTAssertGreaterThan((content.body + CallAlertText.separator + "Creates urgency").count, CallAlertText.maxBodyLength, "why the fifth title is cut")
        XCTAssertEqual(content.callID, record.id)
        XCTAssertEqual(content.level, .high)
        XCTAssertEqual(content, .make(callID: record.id, level: .high, callerNumber: record.callerNumber, reasonTitles: record.reasons.map(\.title)))

        let notification = content.makeNotificationContent()
        XCTAssertEqual(notification.title, content.title)
        XCTAssertEqual(notification.subtitle, content.subtitle)
        XCTAssertEqual(notification.body, content.body)
        XCTAssertEqual(notification.interruptionLevel, .timeSensitive)
        XCTAssertEqual(notification.relevanceScore, 1)
        XCTAssertEqual(notification.threadIdentifier, "com.mazooni.PhishGuard.calls")
        XCTAssertEqual(notification.threadIdentifier, NotificationManager.callThreadIdentifier)
        XCTAssertEqual(notification.categoryIdentifier, "PHISHGUARD_CALL_ALERT")
        XCTAssertEqual(notification.userInfo[NotificationManager.callIDUserInfoKey] as? String, record.id.uuidString)
        XCTAssertEqual(NotificationManager.callIDUserInfoKey, "callID", "the same key the relay's push uses")
        XCTAssertNil(notification.userInfo[NotificationManager.recordIDUserInfoKey], "a call alert never deep-links to an email")
        XCTAssertNotNil(notification.sound)
        XCTAssertNil(notification.badge, "the icon badge stays the unread email count")
    }

    @MainActor
    func testTitlesFollowTheRecordLevel() throws {
        let high = NotificationManager.callAlertContent(for: try makeRecord(DemoCalls.techSupport))
        XCTAssertEqual(high.title, "Likely scam call")
        XCTAssertEqual(high.subtitle, "Call from +1 (800) 555-0162")
        XCTAssertTrue(high.body.hasPrefix("Asks for gift cards · Asks for remote access to a device"), "the recorded verdict's top reasons")

        let record = try makeRecord(DemoCalls.irs)
        record.levelRaw = RiskLevel.medium.rawValue
        XCTAssertEqual(NotificationManager.callAlertContent(for: record).title, "Possible scam call")
        record.levelRaw = RiskLevel.low.rawValue
        record.reasonsJSON = FlaggedCallRecord.encodeReasons([])
        let low = NotificationManager.callAlertContent(for: record)
        XCTAssertEqual(low.title, "Suspicious call")
        // No reason titles: the summary is the body, cut to 160 characters, as the relay's `alertBody` does.
        XCTAssertEqual(low.body, CallAlertText.truncate(record.summary, to: CallAlertText.maxBodyLength))
        XCTAssertLessThanOrEqual(low.body.count, CallAlertText.maxBodyLength)
        // The recorded (rules-only) verdict's summary is generated from its top signals, so it is never empty.
        XCTAssertFalse(low.body.isEmpty)

        record.summary = ""
        XCTAssertEqual(NotificationManager.callAlertContent(for: record).body, CallAlertText.fallbackBody, "neither reasons nor a summary")
    }

    @MainActor
    func testPostCallAlertGoesThroughTheCallPosterWithIdentifierAndDelay() throws {
        let record = try makeRecord()
        let recorder = AlertRecorder()
        let manager = recorder.makeManager()

        manager.postCallAlert(for: record, after: 6)
        manager.postCallAlert(for: record)

        let posted = recorder.postedCalls
        XCTAssertEqual(posted.count, 2)
        XCTAssertEqual(posted[0].identifier, "call-\(record.id.uuidString)")
        XCTAssertEqual(posted[0].identifier, NotificationManager.callRequestIdentifier(callID: record.id))
        XCTAssertEqual(posted[0].delay, 6)
        XCTAssertNil(posted[1].delay)
        XCTAssertEqual(posted[0].content, NotificationManager.callAlertContent(for: record))
        XCTAssertTrue(recorder.posted.isEmpty, "a call alert is not an email alert")
    }

    @MainActor
    func testEmailAlertsAreUnchanged() throws {
        _ = try Persistence.makeContainer(inMemory: true)
        let verdict = Verdict(category: .phishing, confidence: 0.9, level: .high, reasons: [], summary: "Credential phishing.", heuristicScore: 0.9, modelRiskScore: nil, modelIdentifier: nil)
        let record = FlaggedEmailRecord(email: SampleEmails.paypalPhish, verdict: verdict, accountID: UUID())
        let recorder = AlertRecorder()
        let manager = recorder.makeManager()

        manager.postAlert(for: record, unreadCount: 2)

        XCTAssertEqual(recorder.posted.count, 1)
        XCTAssertTrue(recorder.postedCalls.isEmpty)
        let notification = recorder.posted[0].content.makeNotificationContent()
        XCTAssertEqual(notification.interruptionLevel, .active)
        XCTAssertEqual(notification.categoryIdentifier, NotificationManager.categoryIdentifier)
        XCTAssertEqual(recorder.posted[0].identifier, "flagged-\(record.id.uuidString)")
    }
}

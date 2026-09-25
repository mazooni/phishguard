import PhishCore
import SwiftData
import UserNotifications
import XCTest
@testable import PhishGuard

final class ScanNotificationTests: XCTestCase {
    private func makeVerdict(reasons: [Reason], summary: String = "Credential phishing attempt.") -> Verdict {
        Verdict(category: .phishing, confidence: 0.9, level: .high, reasons: reasons, summary: summary, heuristicScore: 0.9, modelRiskScore: 96, modelIdentifier: "fake.model")
    }

    @MainActor
    func testAlertContentFromFlaggedRecord() throws {
        _ = try Persistence.makeContainer(inMemory: true)
        let reasons = [
            Reason(id: "link.lookalike_domain", title: "Lookalike link", detail: "paypal.com.account-verify-login.com", severity: .high, source: .heuristic),
            Reason(id: "auth.dkim_fail", title: "DKIM failed", detail: "dkim=fail", severity: .medium, source: .heuristic),
        ]
        let accountID = UUID()
        let record = FlaggedEmailRecord(email: SampleEmails.paypalPhish, verdict: makeVerdict(reasons: reasons), accountID: accountID)

        let content = NotificationManager.alertContent(for: record, unreadCount: 3)

        XCTAssertEqual(content.title, "Suspicious email flagged")
        XCTAssertEqual(content.subtitle, "PayPal <service@paypal.com>")
        XCTAssertEqual(content.body, "Action required: Your account has been limited [Case ID PP-018-442-919] — Lookalike link")
        XCTAssertEqual(content.threadIdentifier, "com.mazooni.PhishGuard.account.\(accountID.uuidString)")
        XCTAssertEqual(content.recordID, record.id)
        XCTAssertEqual(content.accountID, accountID)
        XCTAssertEqual(content.badge, 3)

        let notification = content.makeNotificationContent()
        XCTAssertEqual(notification.title, content.title)
        XCTAssertEqual(notification.subtitle, content.subtitle)
        XCTAssertEqual(notification.body, content.body)
        XCTAssertEqual(notification.threadIdentifier, content.threadIdentifier)
        XCTAssertEqual(notification.categoryIdentifier, NotificationManager.categoryIdentifier)
        XCTAssertEqual(notification.interruptionLevel, .active)
        XCTAssertEqual(notification.userInfo[NotificationManager.recordIDUserInfoKey] as? String, record.id.uuidString)
        XCTAssertEqual(notification.userInfo[NotificationManager.accountIDUserInfoKey] as? String, accountID.uuidString)
        XCTAssertEqual(notification.badge, 3)
        XCTAssertNotNil(notification.sound)
        XCTAssertEqual(NotificationManager.requestIdentifier(recordID: record.id), "flagged-\(record.id.uuidString)")
    }

    @MainActor
    func testAlertContentFallsBackToSummaryAndHandlesMissingFields() throws {
        _ = try Persistence.makeContainer(inMemory: true)
        var email = SampleEmails.giftCardScam
        email.subject = "   "
        email.from = EmailAddress(name: nil, address: "mchen.exec.desk@outlook.com")
        let record = FlaggedEmailRecord(email: email, verdict: makeVerdict(reasons: [], summary: "Urgent gift-card request from a lookalike executive."), accountID: UUID())

        let content = NotificationManager.alertContent(for: record, unreadCount: nil)

        XCTAssertEqual(content.subtitle, "mchen.exec.desk@outlook.com")
        XCTAssertEqual(content.body, "(no subject) — Urgent gift-card request from a lookalike executive.")
        XCTAssertNil(content.badge)
        let notification = content.makeNotificationContent()
        XCTAssertNil(notification.badge)
    }

    func testAlertContentTruncatesLongFields() {
        let longSubject = String(repeating: "S", count: 400)
        let longReason = String(repeating: "R", count: 400)
        let content = NotificationManager.AlertContent.make(
            senderName: String(repeating: "N", count: 300),
            senderAddress: "a@b.example",
            subject: longSubject,
            topReason: longReason,
            summary: "unused",
            recordID: nil,
            accountID: nil,
            unreadCount: -4
        )
        XCTAssertEqual(content.body.count, NotificationManager.AlertContent.maxSubjectLength + 3 + NotificationManager.AlertContent.maxReasonLength)
        XCTAssertEqual(content.subtitle.count, NotificationManager.AlertContent.maxSubtitleLength)
        XCTAssertEqual(content.threadIdentifier, NotificationManager.threadIdentifier)
        XCTAssertEqual(content.makeNotificationContent().badge, 0, "negative badges are clamped")
    }

    func testPostAlertAndTestAlertGoThroughPoster() async throws {
        let recorder = AlertRecorder()
        let manager = recorder.makeManager()

        manager.postTestAlert()

        let posted = recorder.posted
        XCTAssertEqual(posted.count, 1)
        XCTAssertEqual(posted[0].identifier, NotificationManager.testAlertIdentifier)
        XCTAssertNil(posted[0].content.recordID, "the test alert must not deep-link anywhere")
        XCTAssertEqual(posted[0].content.title, NotificationManager.alertTitle)
        XCTAssertEqual(posted[0].content.subtitle, "PayPal <service@paypal.com>")
        XCTAssertTrue(posted[0].content.body.hasPrefix("Action required"))
        XCTAssertEqual(posted[0].content.threadIdentifier, NotificationManager.threadIdentifier)
    }

    func testTestAlertUsesTheProvidedVerdictAndNeverDeepLinks() {
        let recorder = AlertRecorder()
        let manager = recorder.makeManager()
        let modelVerdict = makeVerdict(reasons: [
            Reason(id: "model.credential_lure", title: "Model: credential lure", detail: "Asks for a password.", severity: .high, source: .model),
        ])

        manager.postTestAlert(verdict: modelVerdict)
        manager.postTestAlert(verdict: modelVerdict)

        let posted = recorder.posted
        XCTAssertEqual(posted.count, 2)
        for alert in posted {
            XCTAssertEqual(alert.identifier, NotificationManager.testAlertIdentifier, "repeats replace the previous test alert")
            XCTAssertNil(alert.content.recordID, "no record exists for the sample, so the alert must not deep-link")
            XCTAssertNil(alert.content.accountID)
            XCTAssertNil(alert.content.badge)
            XCTAssertTrue(alert.content.body.hasSuffix("— Model: credential lure"), alert.content.body)
        }
    }
}

import Foundation
import PhishCore
import UIKit

/// The relay's silent push: `{ "aps": { "content-available": 1 }, "provider": "gmail"|"microsoft", "accountKey": "<sha256 hex>" }`,
/// optionally with `lifecycleEvent` (Graph subscription lifecycle forwarded by the relay). Values are treated as
/// untrusted input; nothing here is logged with mail-derived content.
struct SilentPushPayload: Sendable, Equatable {
    static let providerKey = "provider"
    static let accountKeyKey = "accountKey"
    static let lifecycleEventKey = "lifecycleEvent"

    var isContentAvailable: Bool
    var provider: MailProvider?
    var accountKey: String?
    var lifecycleEvent: String?

    init(isContentAvailable: Bool, provider: MailProvider? = nil, accountKey: String? = nil, lifecycleEvent: String? = nil) {
        self.isContentAvailable = isContentAvailable
        self.provider = provider
        self.accountKey = accountKey
        self.lifecycleEvent = lifecycleEvent
    }

    /// Parses `userInfo` from `application(_:didReceiveRemoteNotification:fetchCompletionHandler:)`.
    static func parse(_ userInfo: [AnyHashable: Any]) -> SilentPushPayload {
        var contentAvailable = false
        if let aps = userInfo["aps"] as? [AnyHashable: Any], let flag = aps["content-available"] {
            switch flag {
            case let number as NSNumber: contentAvailable = number.intValue == 1
            case let text as String: contentAvailable = text == "1" || text.lowercased() == "true"
            default: contentAvailable = false
            }
        }
        let provider = (userInfo[providerKey] as? String).flatMap { MailProvider(rawValue: $0.lowercased()) }
        let accountKey = (userInfo[accountKeyKey] as? String).flatMap(Self.normalizedAccountKey)
        let lifecycleEvent = (userInfo[lifecycleEventKey] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        return SilentPushPayload(
            isContentAvailable: contentAvailable,
            provider: provider,
            accountKey: accountKey,
            lifecycleEvent: lifecycleEvent.flatMap { $0.isEmpty ? nil : $0 }
        )
    }

    /// Account keys are SHA-256 hex digests; anything else is ignored.
    static func normalizedAccountKey(_ raw: String) -> String? {
        let key = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard key.count == 64, key.allSatisfy({ $0.isHexDigit }) else { return nil }
        return key
    }
}

/// Where a remote notification goes. The call alert is decided **first**, on the top-level `kind` key: it carries
/// `content-available: 1` too (so the app can fetch the call), and must never be mistaken for the mail doorbell
/// and start a mail scan.
enum RemoteNotificationRoute: Equatable {
    case callAlert
    case mailSilentPush(SilentPushPayload)
    case ignored

    static func classify(_ userInfo: [AnyHashable: Any]) -> RemoteNotificationRoute {
        if CallAlertPushPayload.isCallAlert(userInfo) { return .callAlert }
        let payload = SilentPushPayload.parse(userInfo)
        return payload.isContentAvailable ? .mailSilentPush(payload) : .ignored
    }
}

/// Maps a scan outcome to what the system wants back from a background fetch / silent push.
enum BackgroundOutcome {
    static func fetchResult(for summary: ScanSummary) -> UIBackgroundFetchResult {
        if summary.scanned > 0 { return .newData }
        if summary.errors.isEmpty && !summary.cancelled { return .noData }
        return .failed
    }

    /// Success flag for `BGTask.setTaskCompleted(success:)`: not cancelled and either error-free or productive.
    static func taskSucceeded(_ summary: ScanSummary) -> Bool {
        !summary.cancelled && (summary.errors.isEmpty || summary.scanned > 0)
    }
}

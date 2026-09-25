#if DEBUG
import Foundation
import OSLog
import PhishCore
import SwiftData

/// Settings → Demo (debug builds only): put the demo inbox on a phone that is watching a **real** mailbox, and
/// make a real alert arrive on cue.
///
/// `-PGDemoData 1` cannot be passed when the app is launched from the Home Screen, so the populated experience
/// that exists in the Simulator was unreachable on a device. This is that experience as a switch, with one extra
/// requirement: it runs alongside real flagged emails and real linked accounts and must not be able to damage
/// them.
///
/// **How the separation is enforced.** Everything this file inserts carries `isDemo == true` —
/// `FlaggedEmailRecord.isDemo` and `LinkedAccount.isDemo`. That one flag is:
/// - the *only* thing `disable` deletes (both fetches are `#Predicate { $0.isDemo }`, so a record or account
///   with `isDemo == false` is never even loaded, let alone deleted);
/// - what `ScanCoordinator.enabledAccounts` excludes, so the credential-less demo account is never fetched,
///   never produces a scan error, never gets a push subscription and never contributes an organization domain;
/// - what the "accounts" figures on Home and in Settings exclude, and what the Accounts row labels "Demo".
///
/// Real scanning, re-check, dedupe and notifications are untouched: nothing here runs inside the scan pipeline,
/// and the pipeline's only change is the `!$0.isDemo` clause on the account fetch.
@MainActor
enum DemoMode {
    private static let logger = Logger(subsystem: "com.mazooni.PhishGuard", category: "demo")

    /// What `enable`/`disable` did, for the confirmation line in Settings.
    struct Change: Equatable {
        var records: Int
        var accounts: Int
        /// Demo call records (Call Guard) seeded or removed.
        var calls: Int = 0
    }

    // MARK: - On / off

    /// Turns demo mode on or off and stores the choice. Returns what changed.
    @discardableResult
    static func setEnabled(_ enabled: Bool, in environment: AppEnvironment, now: Date = .now) -> Change {
        environment.settings.isDemoModeEnabled = enabled
        // Either way the demo data is being replaced, so the simulate button starts its cycle again.
        environment.settings.demoSimulatedArrivalCount = 0
        return enabled
            ? enable(in: environment.container.mainContext, now: now)
            : disable(in: environment.container.mainContext, notifications: environment.notificationManager)
    }

    /// Seeds the demo corpus next to whatever is already in the store. Re-enabling re-seeds with fresh
    /// timestamps (so "Today" is always today) after removing the previous demo rows, which is also what keeps
    /// this idempotent.
    @discardableResult
    static func enable(in context: ModelContext, now: Date = .now) -> Change {
        // Demo data is disposable by definition; clearing it first means a second "on" never doubles the list.
        removeDemoData(in: context)
        DemoData.insertCorpus(into: context, isDemo: true, now: now, calendar: .current)
        save(context, what: "demo seeding")
        let change = Change(
            records: (try? context.fetchCount(demoRecordDescriptor())) ?? 0,
            accounts: 1,
            calls: (try? context.fetchCount(demoCallDescriptor())) ?? 0
        )
        logger.notice("Demo mode on: seeded \(change.records) demo records and \(change.calls) demo calls")
        return change
    }

    /// Removes every demo record, every demo call and every demo account — and nothing else. Delivered and
    /// scheduled alerts for those records are withdrawn, and the badge is set to the real unread count.
    @discardableResult
    static func disable(in context: ModelContext, notifications: NotificationManager?) -> Change {
        let removedIDs = removeDemoData(in: context)
        save(context, what: "demo removal")
        if let notifications {
            for id in removedIDs.recordIDs {
                notifications.clearAlert(recordID: id)
            }
            for id in removedIDs.callIDs {
                notifications.clearCallAlert(callID: id)
            }
            notifications.setBadge(unreadCount: unreadCount(in: context))
        }
        logger.notice("Demo mode off: removed \(removedIDs.recordIDs.count) demo records, \(removedIDs.callIDs.count) demo calls and \(removedIDs.accountIDs.count) demo account(s)")
        return Change(records: removedIDs.recordIDs.count, accounts: removedIDs.accountIDs.count, calls: removedIDs.callIDs.count)
    }

    /// Deletes the demo rows without saving. Every fetch filters on `isDemo`, so a real record, a real call, a
    /// real account or a real account's `ProcessedMessage` row can never be reached from here — that is the whole
    /// safety argument, and it is one predicate per fetch rather than a rule to remember.
    @discardableResult
    private static func removeDemoData(in context: ModelContext) -> (recordIDs: [UUID], accountIDs: [UUID], callIDs: [UUID]) {
        let records = (try? context.fetch(demoRecordDescriptor())) ?? []
        let recordIDs = records.map(\.id)
        for record in records {
            assert(record.isDemo, "demo removal must never touch a real flagged email")
            context.delete(record)
        }

        let calls = (try? context.fetch(demoCallDescriptor())) ?? []
        let callIDs = calls.map(\.id)
        for call in calls {
            assert(call.isDemo, "demo removal must never touch a real flagged call")
            context.delete(call)
        }

        let accounts = (try? context.fetch(FetchDescriptor<LinkedAccount>(predicate: #Predicate { $0.isDemo }))) ?? []
        let accountIDs = accounts.map(\.id)
        for account in accounts {
            assert(account.isDemo, "demo removal must never touch a real account")
            // The demo account is never scanned, so it normally has no dedupe rows; clear any the seeding or a
            // future change might leave behind, scoped to this account id alone.
            let marker = ":\(account.id.uuidString):"
            let processed = (try? context.fetch(FetchDescriptor<ProcessedMessage>(predicate: #Predicate { $0.key.contains(marker) }))) ?? []
            for entry in processed { context.delete(entry) }
            context.delete(account)
        }
        return (recordIDs, accountIDs, callIDs)
    }

    static func demoRecordDescriptor() -> FetchDescriptor<FlaggedEmailRecord> {
        FetchDescriptor<FlaggedEmailRecord>(predicate: #Predicate { $0.isDemo })
    }

    static func demoCallDescriptor() -> FetchDescriptor<FlaggedCallRecord> {
        FetchDescriptor<FlaggedCallRecord>(predicate: #Predicate { $0.isDemo })
    }

    /// The demo account, creating it if demo mode has not seeded one yet. Never returns a real account.
    static func demoAccount(in context: ModelContext, now: Date = .now) -> LinkedAccount {
        var descriptor = FetchDescriptor<LinkedAccount>(predicate: #Predicate { $0.isDemo })
        descriptor.fetchLimit = 1
        if let existing = try? context.fetch(descriptor).first { return existing }
        let account = DemoData.makeAccount(now: now, isDemo: true)
        context.insert(account)
        return account
    }

    // MARK: - "Simulate an incoming flagged email"

    /// What one press produced, so Settings can say it out loud and tests can check it.
    struct SimulatedArrival {
        /// The `SampleEmails` fixture that was delivered.
        let fixtureName: String
        let record: FlaggedEmailRecord
        /// Exactly what `NotificationManager` was asked to post — including the record id it deep-links to.
        let alert: NotificationManager.AlertContent
        let delay: TimeInterval?
    }

    /// Inserts a brand-new flagged record dated now and schedules the real alert for it.
    ///
    /// Everything about it is the shipping pipeline: the fixture goes through `HeuristicAnalyzer` and
    /// `VerdictEngine` with its measured `MeasuredModelAssessments` answer (exactly as `DemoData` seeds), the row
    /// is built by `FlaggedEmailRecord(email:verdict:accountID:)`, and the notification is built and posted by
    /// `NotificationManager.postAlert(for:)` — the same title, subtitle and body a real detection produces, and
    /// the same `recordID` payload, so tapping it deep-links through `pendingRecordID` to this record's detail
    /// screen. (Diagnostics' "Send test notification" deliberately passes `recordID: nil` and therefore does not.)
    ///
    /// `delay` nil posts immediately; a value schedules the alert that many seconds out, which is what gives the
    /// presenter time to lock the phone. `arrivalNumber` is how many presses came before this one — it is what
    /// keeps a repeated press showing a *different* email once the list already holds every fixture.
    @discardableResult
    static func simulateIncomingAlert(
        in context: ModelContext,
        notifications: NotificationManager,
        delay: TimeInterval?,
        arrivalNumber: Int = 0,
        now: Date = .now
    ) -> SimulatedArrival {
        let account = demoAccount(in: context, now: now)
        let present = existingMessageIDs(in: context)
        let draw = DemoArrivalPool.next(presentMessageIDs: present, arrivalNumber: arrivalNumber)

        var email = DemoData.prepare(draw.email, accountID: account.id, receivedAt: now)
        // A press must always add a row, never refresh one: once the pool has cycled back to a fixture the list
        // already shows, the arrival gets its own message id so it is a genuinely new email.
        email.messageID = DemoArrivalPool.uniqueMessageID(base: draw.email.messageID, taken: present)

        let verdict = DemoData.verdict(for: email, account: account, modelAnswered: true)
        let record = FlaggedEmailRecord(email: email, verdict: verdict, accountID: account.id, flaggedAt: now, isDemo: true)
        context.insert(record)
        save(context, what: "simulated arrival")

        let content = NotificationManager.alertContent(for: record, unreadCount: unreadCount(in: context))
        notifications.postAlert(for: record, unreadCount: content.badge, after: delay)
        logger.notice("Simulated arrival: \(draw.name, privacy: .public) in \(delay ?? 0, privacy: .public)s")
        return SimulatedArrival(fixtureName: draw.name, record: record, alert: content, delay: delay)
    }

    // MARK: - "Simulate a scam call" (docs/CALLS.md §7.4)

    /// What one press produced.
    struct SimulatedCall {
        let scenario: DemoCalls.Scenario
        let record: FlaggedCallRecord
        /// Exactly what `NotificationManager` was asked to post — including the call id it deep-links to.
        let alert: NotificationManager.CallAlertContent
        let delay: TimeInterval?
    }

    /// Inserts a `FlaggedCallRecord` for a bundled scenario, dated now and marked `isDemo`, and posts the same
    /// local, time-sensitive notification the relay's push produces — same title/subtitle/body rules
    /// (`CallAlertText`), same category and thread, same `callID` payload, so a tap deep-links through
    /// `pendingCallID` to this record. Nothing leaves the phone. `delay` works as for the email button.
    @discardableResult
    static func simulateIncomingCall(
        _ scenario: DemoCalls.Scenario,
        in context: ModelContext,
        notifications: NotificationManager,
        delay: TimeInterval?,
        now: Date = .now
    ) -> SimulatedCall {
        let record = DemoCalls.makeRecord(scenario, startedAt: now, isDemo: true)
        context.insert(record)
        save(context, what: "simulated call")
        let content = NotificationManager.callAlertContent(for: record)
        notifications.postCallAlert(for: record, after: delay)
        logger.notice("Simulated call: \(scenario.id.rawValue, privacy: .public) in \(delay ?? 0, privacy: .public)s")
        return SimulatedCall(scenario: scenario, record: record, alert: content, delay: delay)
    }

    // MARK: - Helpers

    private static func existingMessageIDs(in context: ModelContext) -> Set<String> {
        Set(((try? context.fetch(FetchDescriptor<FlaggedEmailRecord>())) ?? []).map(\.messageID))
    }

    private static func unreadCount(in context: ModelContext) -> Int {
        (try? context.fetchCount(FetchDescriptor<FlaggedEmailRecord>(predicate: #Predicate { $0.isRead == false }))) ?? 0
    }

    private static func save(_ context: ModelContext, what: String) {
        guard context.hasChanges else { return }
        do {
            try context.save()
        } catch {
            logger.error("Could not save \(what, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }
}

/// Which bundled fixture the next "simulate an incoming flagged email" press delivers.
///
/// Pure and order-defined so it can be tested without a store. Two rules, in this order:
/// 1. **Something the list does not already show.** The malicious fixtures the seeded corpus does not contain
///    come first in `entries`, and any entry already in the store is skipped — so the first press on a freshly
///    seeded demo is an email the audience has not seen scrolling past.
/// 2. **Then cycle.** With the corpus seeded, every entry is already present after one press, so "not present"
///    alone would repeat that one email forever. From there the draw is `entries[arrivalNumber % count]`, which
///    walks the whole pool in order, and `uniqueMessageID` gives the repeat its own row rather than refreshing
///    the one that is there.
enum DemoArrivalPool {
    /// Excluded for the same reason `DemoData` leaves it out of the seeded week: its measured summary contains a
    /// stray non-English token the model emitted, and model output is never edited here.
    static let excludedFixtureNames: Set<String> = ["techSupportScam"]

    /// Draw order.
    static let entries: [(name: String, email: EmailMessage)] = {
        let malicious = SampleEmails.named.filter { $0.malicious && !excludedFixtureNames.contains($0.name) }
        let seeded = Set(DemoData.seededFixtureNames)
        let unseeded = malicious.filter { !seeded.contains($0.name) }
        let seededOnes = malicious.filter { seeded.contains($0.name) }
        return (unseeded + seededOnes).map { (name: $0.name, email: $0.email) }
    }()

    /// The next fixture to deliver: the first entry the store does not already hold, else the `arrivalNumber`-th
    /// entry of the cycle.
    static func next(presentMessageIDs: Set<String>, arrivalNumber: Int = 0) -> (name: String, email: EmailMessage) {
        if let unused = entries.first(where: { entry in
            !presentMessageIDs.contains { $0.hasPrefix(entry.email.messageID) }
        }) {
            return unused
        }
        // `entries` is built from a non-empty constant corpus, so the modulo is always in range.
        return entries[((arrivalNumber % entries.count) + entries.count) % entries.count]
    }

    /// `base`, or the first numbered variant of it that is free, so a press always inserts a new row.
    static func uniqueMessageID(base: String, taken: Set<String>) -> String {
        guard taken.contains(base) else { return base }
        var suffix = 2
        while taken.contains("\(base)-sim\(suffix)") { suffix += 1 }
        return "\(base)-sim\(suffix)"
    }
}

/// How long after the press the simulated alert arrives. A delay is the point of the feature: it is what lets
/// the presenter put the phone down or lock it before the banner appears on the Lock Screen.
enum DemoAlertDelay: Int, CaseIterable, Identifiable, Sendable {
    case immediate = 0
    case sixSeconds = 6
    case fifteenSeconds = 15

    static let `default` = DemoAlertDelay.sixSeconds

    var id: Int { rawValue }

    /// nil posts the alert immediately (no `UNNotificationTrigger`).
    var seconds: TimeInterval? { self == .immediate ? nil : TimeInterval(rawValue) }

    var label: String {
        switch self {
        case .immediate: return "Now"
        case .sixSeconds: return "6s"
        case .fifteenSeconds: return "15s"
        }
    }

    /// What Settings says after the press.
    var confirmation: String {
        switch self {
        case .immediate:
            return "Alert posted. It is on screen now, and the email is at the top of Alerts."
        case .sixSeconds, .fifteenSeconds:
            return "Alert scheduled for \(rawValue) seconds from now — lock the phone to see it on the Lock Screen."
        }
    }

    /// The same, for "Simulate a scam call".
    var callConfirmation: String {
        switch self {
        case .immediate:
            return "Alert posted. It is on screen now, and the call is at the top of Calls."
        case .sixSeconds, .fifteenSeconds:
            return "Alert scheduled for \(rawValue) seconds from now — lock the phone to see it break through on the Lock Screen."
        }
    }
}
#endif

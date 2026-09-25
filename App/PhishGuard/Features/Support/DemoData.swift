import Foundation
import PhishCore
import SwiftData

/// Seeds the app with a believable inbox history for screen recordings, SwiftUI previews and screenshots.
///
/// **Nothing on screen is written by hand.** Every record is one bundled `SampleEmails` fixture put through the
/// shipping detector — `HeuristicAnalyzer` → `VerdictEngine` → `FlaggedEmailRecord(email:verdict:accountID:)` —
/// in exactly the order and with exactly the inputs `ScanCoordinator` uses, including the organization domains it
/// derives from the linked account. The model's side of each verdict is the *measured* answer the real
/// `mlx-community/Qwen3-4B-Instruct-2507-4bit` gave for that same fixture on an Apple-silicon Mac
/// (`MeasuredModelAssessments`, recorded by `Tools/PromptLab`), so the confidences, levels, categories, reasons
/// and summaries the demo shows are the ones the product actually produces. A fixture whose real verdict would
/// not clear `AlertPolicy` is skipped rather than faked.
///
/// Launch-argument seeding is compiled into debug builds only. Launch with `-PGDemoData 1`; see docs/DEMO.md.
enum DemoData {
    static let launchArgumentKey = "PGDemoData"

    /// The demo mailbox. Fictional on purpose — `example.com` can never be a real address.
    static let accountEmail = "sam.rivera@example.com"
    static let accountDisplayName = "Sam Rivera"

    /// The identifier `MLXClassifier` reports for the default catalog model, so the detail screen's footnote and
    /// the Diagnostics rows name the model that really produced the measured assessments.
    static var localModelIdentifier: String {
        "mlx:\(ModelManager.entry(for: ModelManager.defaultModelID)?.hfRepo ?? ModelManager.defaultModelID)"
    }

    /// Held back from the seeding so the "a new email arrives while the app is closed" moment has something to
    /// deliver: `scripts/demo-push-phish.apns` names it, and the silent-push path feeds it to the real scan.
    static let liveArrivalFixtureName = "microsoft365PasswordPhish"

    /// The alert level the demo runs at, so the list shows everything the engine flagged rather than only what
    /// clears the shipped default. The lowest-scoring record here is a real retailer's prize-draw mail the rules
    /// put at 0.31 — genuinely low risk, and worth seeing next to the 100% ones, because a detector that only
    /// ever says "high" tells you nothing. Settings shows this choice honestly ("Low risk and above"); the
    /// shipped default is `.medium`.
    static let alertMinimumLevel: RiskLevel = .low

    /// True when this launch asked for the demo (debug builds only): the launch argument, or a web-demo build.
    static var isRequested: Bool {
        #if DEBUG
        return UserDefaults.standard.bool(forKey: launchArgumentKey) || isWebDemoBuild
        #else
        return false
        #endif
    }

    /// `PG_WEB_DEMO=YES` on the xcodebuild command line (`PGWebDemo` in Info.plist, see project.yml) makes the build
    /// seed the demo by itself on first launch. It exists for the browser-hosted demo (a cloud Simulator streamed
    /// into a web page), where nothing can pass a launch argument reliably. Debug builds only, like the argument.
    static var isWebDemoBuild: Bool {
        (Bundle.main.object(forInfoDictionaryKey: "PGWebDemo") as? String)?.uppercased() == "YES"
    }

    @MainActor
    static func seedIfRequested(into environment: AppEnvironment) {
        #if DEBUG
        guard isRequested else { return }
        // A recording starts on the Alerts list, not on the welcome flow; the flow itself is still reachable
        // from Diagnostics › Reset onboarding.
        environment.settings.hasCompletedOnboarding = true
        environment.settings.alertMinimumLevel = alertMinimumLevel
        seed(into: environment.container)
        // Without this the header card reads "Notifications off" and no alert banner can appear. The system
        // prompt is shown once per install; see docs/DEMO.md.
        let notifications = environment.notificationManager
        Task {
            if await notifications.authorizationStatus() == .notDetermined {
                _ = await notifications.requestAuthorization()
            }
        }
        #endif
    }

    static let onboardingPageKey = "PGOnboardingPage"

    /// `-PGOnboardingPage 2` opens onboarding directly on that page (used to capture the model-download page
    /// without swiping through the flow). Out-of-range values and release builds start at the first page.
    static func initialOnboardingPage(pageCount: Int) -> Int {
        #if DEBUG
        guard UserDefaults.standard.object(forKey: onboardingPageKey) != nil else { return 0 }
        let index = UserDefaults.standard.integer(forKey: onboardingPageKey)
        return (0..<pageCount).contains(index) ? index : 0
        #else
        return 0
        #endif
    }

    static let openNewestRecordKey = "PGOpenNewestRecord"

    /// `-PGOpenNewestRecord 1` simulates tapping an alert notification for the newest record (exercises the
    /// `pendingRecordID` deep link; used for Detail screenshots).
    @MainActor
    static func openNewestRecordIfRequested(in environment: AppEnvironment) {
        #if DEBUG
        guard UserDefaults.standard.bool(forKey: openNewestRecordKey) else { return }
        var descriptor = FetchDescriptor<FlaggedEmailRecord>(sortBy: [SortDescriptor(\.receivedAt, order: .reverse)])
        descriptor.fetchLimit = 1
        if let record = try? environment.container.mainContext.fetch(descriptor).first {
            environment.pendingRecordID = record.id
        }
        #endif
    }

    static let openNewestCallKey = "PGOpenNewestCall"

    /// `-PGOpenNewestCall 1` simulates tapping a call alert notification for the newest flagged call (exercises the
    /// `pendingCallID` deep link; used for call-detail screenshots).
    @MainActor
    static func openNewestCallIfRequested(in environment: AppEnvironment) {
        #if DEBUG
        guard UserDefaults.standard.bool(forKey: openNewestCallKey) else { return }
        var descriptor = FetchDescriptor<FlaggedCallRecord>(sortBy: [SortDescriptor(\.startedAt, order: .reverse)])
        descriptor.fetchLimit = 1
        if let record = try? environment.container.mainContext.fetch(descriptor).first {
            environment.callGuard.pendingCallID = record.id
        }
        #endif
    }

    static let demoCallKey = "PGDemoCall"

    /// `-PGDemoCall grandparent` (any `DemoScenario` raw value) starts that scripted call on the relay at launch, the
    /// same request the Calls tab's "Run a scripted call on the relay" menu sends; needs a configured relay with demo
    /// calls enabled. Used for live-call screenshots.
    @MainActor
    static func startDemoCallIfRequested(in environment: AppEnvironment) {
        #if DEBUG
        guard let raw = UserDefaults.standard.string(forKey: demoCallKey), let scenario = DemoScenario(rawValue: raw),
              environment.callGuard.isConfigured else { return }
        let coordinator = environment.callGuard
        Task { _ = try? await coordinator.startDemoCall(scenario: scenario) }
        #endif
    }

    // MARK: - The seeded inbox

    /// When one fixture arrived and whether the user has opened it yet. Times are written as "this many days
    /// back, at this hour" so the Home list always shows Today / Yesterday / several named days, whatever time
    /// of day the demo is recorded.
    private struct Arrival {
        let fixtureName: String
        /// Calendar days before today. 0 places the mail earlier today (see `date(for:now:calendar:)`).
        let daysAgo: Int
        /// Minutes before now, for `daysAgo == 0`.
        let minutesAgo: Int
        /// Time of day for `daysAgo > 0`.
        let hour: Int
        let minute: Int
        let isRead: Bool

        static func today(_ fixtureName: String, minutesAgo: Int, isRead: Bool) -> Arrival {
            Arrival(fixtureName: fixtureName, daysAgo: 0, minutesAgo: minutesAgo, hour: 0, minute: 0, isRead: isRead)
        }

        static func day(_ daysAgo: Int, _ fixtureName: String, at hour: Int, _ minute: Int, isRead: Bool = true) -> Arrival {
            Arrival(fixtureName: fixtureName, daysAgo: daysAgo, minutesAgo: 0, hour: hour, minute: minute, isRead: isRead)
        }
    }

    /// The week the demo shows, and the one thing about it that is a *story* rather than a measurement: **today's
    /// mail was checked with the app open, everything older was checked with it closed.**
    ///
    /// That is not decoration, it is how the product behaves. A downloaded model needs the GPU and iOS only
    /// allows that while the app is frontmost (see `ForegroundGate`), so mail that arrives while PhishGuard is
    /// closed is classified by the rules alone and keeps that verdict until the user re-checks. So today's three
    /// carry the model's recorded answer and older ones carry `assessment: nil` — which is why their confidences
    /// are the raw rule scores, their categories are the engine's derived ones, and their detail screens say
    /// "heuristics only". Every number is still the engine's; none of them is chosen.
    ///
    /// Three malicious fixtures are deliberately absent: `microsoft365PasswordPhish`, which the silent-push demo
    /// delivers live; `techSupportScam`, whose measured summary contains a stray non-English token the model
    /// emitted ("…impersonating Norton LifeLock billing to诱导 users to call…") and model output is never edited
    /// here; and nothing else.
    private static let arrivals: [Arrival] = [
        .today("paypalPhish", minutesAgo: 35, isRead: false),
        .today("webmailPayPalPretext", minutesAgo: 125, isRead: false),
        .today("fakeInvoiceHTMLAttachment", minutesAgo: 310, isRead: false),
        .day(1, "giftCardScam", at: 16, 42),
        .day(1, "mailboxQuotaUpsell", at: 11, 28),
        .day(1, "cryptoGiveawayScam", at: 9, 14),
        .day(2, "sextortionScam", at: 20, 7),
        .day(2, "benignSurveyPrizeDraw", at: 13, 5),
        .day(3, "webmailPayrollMeetingLure", at: 14, 55),
        .day(3, "subscriptionDunningNotice", at: 7, 40),
        .day(4, "bankAccountCompromisedPretext", at: 8, 21),
        .day(5, "packageDeliveryFeeScam", at: 19, 2),
        .day(6, "advanceFeeScam", at: 13, 47),
    ]

    /// The fixtures the seeded week contains, in arrival order. `DemoArrivalPool` uses it to draw the
    /// "simulate an incoming flagged email" fixtures the list does not already show first.
    static var seededFixtureNames: [String] { arrivals.map(\.fixtureName) }

    /// Inserts the demo account and one flagged record per arrival. No-op when any record already exists, so a
    /// relaunch keeps what the recording has already produced.
    ///
    /// This is the `-PGDemoData 1` path and it deliberately marks nothing `isDemo`: the Simulator demo *scans*
    /// its mailbox (`DemoMailProvider` stands in for Gmail, pull-to-refresh and the background arrival both run
    /// the real pipeline over it), and a demo account is by definition one the coordinator never fetches. Demo
    /// mode in Settings — which runs on a real phone next to a real mailbox — uses `insertCorpus` with
    /// `isDemo: true` instead. Both build their records the same way, from the same arrivals.
    @MainActor
    static func seed(into container: ModelContainer, now: Date = .now, calendar: Calendar = .current) {
        let context = container.mainContext
        let existing = (try? context.fetchCount(FetchDescriptor<FlaggedEmailRecord>())) ?? 0
        guard existing == 0 else { return }
        insertCorpus(into: context, isDemo: false, now: now, calendar: calendar)
        try? context.save()
    }

    /// The demo mailbox as a `LinkedAccount`. Fictional, credential-less and — with `isDemo: true` — never
    /// fetched, never counted as a real mailbox and removed again when demo mode is turned off.
    static func makeAccount(now: Date = .now, isDemo: Bool) -> LinkedAccount {
        LinkedAccount(
            provider: .gmail,
            email: accountEmail,
            displayName: accountDisplayName,
            addedAt: now.addingTimeInterval(-12 * 24 * 3600),
            lastScanAt: now.addingTimeInterval(-6 * 60),
            pushSubscriptionID: "demo-watch-8143",
            pushSubscriptionExpiresAt: now.addingTimeInterval(6 * 24 * 3600 + 5 * 3600),
            relayAccountKey: "demo-account-key",
            isDemo: isDemo
        )
    }

    /// Inserts the demo account and one flagged record per arrival into `context`, without saving and without
    /// looking at what is already there. The single source of the demo inbox: the launch argument seeds it with
    /// `isDemo: false`, Settings → Demo mode with `isDemo: true`. Returns the account the records belong to.
    ///
    /// Timestamps are computed from `now` on every call, so re-enabling demo mode always puts three alerts under
    /// "Today".
    @MainActor
    @discardableResult
    static func insertCorpus(
        into context: ModelContext,
        isDemo: Bool,
        now: Date = .now,
        calendar: Calendar = .current
    ) -> LinkedAccount {
        let account = makeAccount(now: now, isDemo: isDemo)
        context.insert(account)

        let fixtures = Dictionary(uniqueKeysWithValues: SampleEmails.named.map { ($0.name, $0.email) })
        let policy = AlertPolicy(minimumLevel: alertMinimumLevel)
        for arrival in arrivals {
            guard let fixture = fixtures[arrival.fixtureName] else { continue }
            let receivedAt = date(for: arrival, now: now, calendar: calendar)
            let email = prepare(fixture, accountID: account.id, receivedAt: receivedAt)
            let verdict = verdict(for: email, account: account, modelAnswered: arrival.daysAgo == 0)
            // Never seed something the product would not have alerted on.
            guard policy.shouldAlert(verdict) else { continue }
            let record = FlaggedEmailRecord(
                email: email,
                verdict: verdict,
                accountID: account.id,
                flaggedAt: receivedAt.addingTimeInterval(38),
                isDemo: isDemo
            )
            record.isRead = arrival.isRead
            context.insert(record)
        }
        // Call Guard: three flagged calls across the same week (docs/CALLS.md §7.4).
        DemoCalls.insertHistory(into: context, isDemo: isDemo, now: now, calendar: calendar)
        return account
    }

    /// The fixture as the account would have received it: addressed to this account (so the dedupe key and the
    /// "sent from your own address" rule see the demo mailbox) and stamped with the arrival time.
    static func prepare(_ fixture: EmailMessage, accountID: UUID, receivedAt: Date) -> EmailMessage {
        var email = fixture
        email.accountID = accountID.uuidString
        email.receivedAt = receivedAt
        return email
    }

    /// The verdict `ScanCoordinator` would reach for this email: the same analyzer (organization domains
    /// included) and the same `VerdictEngine`.
    ///
    /// `modelAnswered` is the one input the demo chooses, and it chooses it for a reason that is true of the
    /// product: with `false` the verdict is the rules alone, which is what every background scan produces while
    /// a downloaded model cannot run. With `true` the measured answer for this fixture is fused in as well. A
    /// fixture with no measured answer falls back to the rules either way rather than inventing one.
    static func verdict(for email: EmailMessage, account: LinkedAccount, modelAnswered: Bool) -> Verdict {
        let analyzer = HeuristicAnalyzer(organizationDomains: ScanCoordinator.organizationDomains(of: [account]))
        let report = analyzer.analyze(email)
        let assessment = modelAnswered ? MeasuredModelAssessments.assessment(forMessageID: email.messageID) : nil
        return VerdictEngine().makeVerdict(
            report: report,
            assessment: assessment,
            modelIdentifier: assessment == nil ? nil : localModelIdentifier
        )
    }

    /// Places an arrival on the calendar.
    ///
    /// Today's arrivals are "n minutes ago" — except when the demo is seeded early in the day and "5 hours ago"
    /// would fall before midnight. Rather than lose the "Today" section (or, worse, date mail into the future),
    /// the spread is compressed into the part of today that has actually happened, in the same order.
    private static func date(for arrival: Arrival, now: Date, calendar: Calendar) -> Date {
        let startOfToday = calendar.startOfDay(for: now)
        guard arrival.daysAgo > 0 else {
            let wanted = Double(arrival.minutesAgo) * 60
            let elapsedToday = max(now.timeIntervalSince(startOfToday), 60)
            let longest = Double(arrivals.filter { $0.daysAgo == 0 }.map(\.minutesAgo).max() ?? arrival.minutesAgo) * 60
            // All of today's arrivals scale together or none of them do. Compressing only the ones that fall
            // before midnight would reorder the list: the 5-hour-old mail would be pulled to just now while the
            // 35-minute-old one stayed put, and the oldest would sort newest.
            guard longest >= elapsedToday, longest > 0 else { return now.addingTimeInterval(-wanted) }
            return now.addingTimeInterval(-elapsedToday * 0.95 * (wanted / longest))
        }
        let day = calendar.date(byAdding: .day, value: -arrival.daysAgo, to: startOfToday) ?? startOfToday
        return day.addingTimeInterval(Double(arrival.hour) * 3600 + Double(arrival.minute) * 60)
    }
}

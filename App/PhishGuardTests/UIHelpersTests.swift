import PhishCore
import SwiftData
import SwiftUI
import XCTest
@testable import PhishGuard

/// Tests for the view-layer helpers in Features/ (no UI rendering).
final class UIHelpersTests: XCTestCase {
    private struct Item {
        let level: RiskLevel
        let date: Date
    }

    private var utc: Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        calendar.locale = Locale(identifier: "en_US")
        return calendar
    }

    private func date(_ year: Int, _ month: Int, _ day: Int, _ hour: Int = 12, _ minute: Int = 0) -> Date {
        utc.date(from: DateComponents(year: year, month: month, day: day, hour: hour, minute: minute))!
    }

    private func isFromToday(_ date: Date, now: Date) -> Bool {
        utc.isDate(date, inSameDayAs: now)
    }

    // MARK: - Level → color / name

    func testRiskLevelColorsAndNames() {
        XCTAssertEqual(RiskLevel.high.color, .red)
        XCTAssertEqual(RiskLevel.medium.color, .orange)
        XCTAssertEqual(RiskLevel.low.color, .yellow)
        XCTAssertEqual(RiskLevel.safe.color, .green)

        XCTAssertEqual(RiskLevel.high.shortName, "High")
        XCTAssertEqual(RiskLevel.medium.shortName, "Medium")
        XCTAssertEqual(RiskLevel.low.shortName, "Low")
        XCTAssertEqual(RiskLevel.high.displayName, "High risk")

        for level in RiskLevel.allCases {
            XCTAssertFalse(level.symbolName.isEmpty, "\(level) needs a symbol")
            XCTAssertFalse(level.alertDescription.isEmpty, "\(level) needs a picker description")
        }
    }

    func testSeverityAndCategoryPresentation() {
        XCTAssertEqual(Severity.high.color, .red)
        XCTAssertEqual(Severity.medium.color, .orange)
        XCTAssertEqual(Severity.low.color, .yellow)
        XCTAssertEqual(Severity.info.displayName, "Info")
        XCTAssertEqual(Set([Severity.info, .low, .medium, .high].map(\.symbolName)).count, 4, "each severity has a distinct icon")

        XCTAssertEqual(ThreatCategory.phishing.color, .red)
        XCTAssertEqual(ThreatCategory.scam.color, .orange)
        XCTAssertEqual(ReasonSource.model.tagName, "AI")
        XCTAssertEqual(ReasonSource.heuristic.tagName, "Heuristic")
        XCTAssertEqual(MailProvider.gmail.monogram, "G")
        XCTAssertEqual(MailProvider.microsoft.monogram, "M")
    }

    // MARK: - Minimum-level filtering

    func testMinimumLevelFiltering() {
        let now = Date()
        let items = [Item(level: .high, date: now), Item(level: .medium, date: now), Item(level: .low, date: now), Item(level: .safe, date: now)]

        XCTAssertEqual(AlertFilter.filter(items, minimum: .medium, level: \.level).map(\.level), [.high, .medium])
        XCTAssertEqual(AlertFilter.filter(items, minimum: .low, level: \.level).map(\.level), [.high, .medium, .low])
        XCTAssertEqual(AlertFilter.filter(items, minimum: .high, level: \.level).map(\.level), [.high])
        XCTAssertEqual(AlertFilter.filter(items, minimum: .safe, level: \.level).count, 3, "safe verdicts are never listed, like AlertPolicy")

        XCTAssertTrue(AlertFilter.includes(level: .medium, minimum: .medium))
        XCTAssertFalse(AlertFilter.includes(level: .low, minimum: .medium))
        XCTAssertTrue(AlertFilter.includes(level: .high, minimum: .low))
    }

    func testFilteringMatchesAlertPolicy() {
        let verdict = { (level: RiskLevel) in
            Verdict(category: .phishing, confidence: 0.9, level: level, reasons: [], summary: "", heuristicScore: 0.9)
        }
        for minimum in RiskLevel.allCases {
            let policy = AlertPolicy(minimumLevel: minimum)
            for level in RiskLevel.allCases {
                XCTAssertEqual(AlertFilter.includes(level: level, minimum: minimum), policy.shouldAlert(verdict(level)), "minimum=\(minimum) level=\(level)")
            }
        }
    }

    // MARK: - Day grouping

    func testDayGroupingNewestFirstWithTitles() {
        let now = date(2026, 9, 21, 15)
        let items = [
            Item(level: .high, date: date(2026, 9, 21, 14)),
            Item(level: .medium, date: date(2026, 9, 21, 9)),
            Item(level: .medium, date: date(2026, 9, 20, 23, 30)),
            Item(level: .low, date: date(2026, 9, 15, 8)),
            Item(level: .low, date: date(2025, 12, 31, 10)),
        ]

        let sections = DayGrouping.sections(items, date: \.date, now: now, calendar: utc)

        XCTAssertEqual(sections.count, 4)
        XCTAssertEqual(sections[0].title, "Today")
        XCTAssertEqual(sections[0].items.map(\.date), [date(2026, 9, 21, 14), date(2026, 9, 21, 9)], "input order is preserved inside a section")
        XCTAssertEqual(sections[1].title, "Yesterday")
        XCTAssertEqual(sections[1].items.count, 1)
        XCTAssertEqual(sections[2].day, utc.startOfDay(for: date(2026, 9, 15)))
        XCTAssertTrue(sections[2].title.contains("15"), "same-year title shows the day: \(sections[2].title)")
        XCTAssertFalse(sections[2].title.contains("2026"), "same-year title omits the year: \(sections[2].title)")
        XCTAssertTrue(sections[3].title.contains("2025"), "other-year title shows the year: \(sections[3].title)")
        XCTAssertEqual(sections.map(\.day), sections.map(\.day).sorted(by: >), "sections are newest first")
        XCTAssertEqual(sections.map(\.id), sections.map(\.day))
    }

    func testDayGroupingUnorderedInputStillSortsSections() {
        let now = date(2026, 9, 21, 15)
        let items = [
            Item(level: .low, date: date(2026, 9, 1)),
            Item(level: .high, date: date(2026, 9, 21)),
            Item(level: .medium, date: date(2026, 9, 10)),
        ]
        let sections = DayGrouping.sections(items, date: \.date, now: now, calendar: utc)
        XCTAssertEqual(sections.map(\.day), [date(2026, 9, 21), date(2026, 9, 10), date(2026, 9, 1)].map { utc.startOfDay(for: $0) })
    }

    func testDayGroupingEmpty() {
        let sections = DayGrouping.sections([Item](), date: \.date, now: Date(), calendar: utc)
        XCTAssertTrue(sections.isEmpty)
    }

    func testDayTitleBoundaries() {
        let now = date(2026, 1, 1, 0, 5)
        XCTAssertEqual(DayGrouping.title(for: date(2026, 1, 1, 0, 0), now: now, calendar: utc), "Today")
        XCTAssertEqual(DayGrouping.title(for: date(2025, 12, 31, 23, 59), now: now, calendar: utc), "Yesterday")
        XCTAssertTrue(DayGrouping.title(for: date(2025, 12, 30), now: now, calendar: utc).contains("2025"))
    }

    // MARK: - Shield status

    func testShieldStatus() {
        XCTAssertEqual(ShieldStatus.make(enabledAccountCount: 0, notificationsAuthorized: true), .noAccounts)
        XCTAssertEqual(ShieldStatus.make(enabledAccountCount: 0, notificationsAuthorized: false), .noAccounts, "missing accounts outranks notifications")
        XCTAssertEqual(ShieldStatus.make(enabledAccountCount: 1, notificationsAuthorized: false), .notificationsOff)
        XCTAssertEqual(ShieldStatus.make(enabledAccountCount: 2, notificationsAuthorized: true), .protected)
        XCTAssertEqual(ShieldStatus.make(enabledAccountCount: 1, notificationsAuthorized: nil), .protected, "unknown permission does not flash a warning")
        XCTAssertEqual(ShieldStatus.protected.title, "Protected")
        XCTAssertEqual(ShieldStatus.noAccounts.title, "No accounts linked")
        XCTAssertEqual(ShieldStatus.notificationsOff.title, "Notifications off")
        XCTAssertEqual(ShieldStatus.protected.color, .green)
    }

    // MARK: - Push subscription status

    func testPushSubscriptionStatus() {
        let now = date(2026, 9, 21, 12)
        XCTAssertEqual(PushSubscriptionStatus.make(expiresAt: nil, now: now), .none)
        let inFiveDays = now.addingTimeInterval(5 * 24 * 3600)
        XCTAssertEqual(PushSubscriptionStatus.make(expiresAt: inFiveDays, now: now), .active(until: inFiveDays))
        let inTwoHours = now.addingTimeInterval(2 * 3600)
        XCTAssertEqual(PushSubscriptionStatus.make(expiresAt: inTwoHours, now: now), .expiring(at: inTwoHours))
        let anHourAgo = now.addingTimeInterval(-3600)
        XCTAssertEqual(PushSubscriptionStatus.make(expiresAt: anHourAgo, now: now), .expired(at: anHourAgo))
        XCTAssertEqual(PushSubscriptionStatus.none.label, "No push subscription")
        XCTAssertTrue(PushSubscriptionStatus.make(expiresAt: inFiveDays, now: now).label.hasPrefix("Push active until"))
    }

    // MARK: - Classifier names

    func testClassifierDisplayNames() {
        XCTAssertEqual(ClassifierDisplay.name(forIdentifier: nil), "Heuristics only")
        XCTAssertEqual(ClassifierDisplay.name(forIdentifier: ""), "Heuristics only")
        XCTAssertEqual(ClassifierDisplay.name(forIdentifier: HeuristicsOnlyClassifier.classifierIdentifier), "Heuristics only")
        XCTAssertEqual(ClassifierDisplay.name(forIdentifier: AppleFoundationClassifier.classifierIdentifier), "Apple Intelligence (on-device)")
        XCTAssertEqual(ClassifierDisplay.name(forIdentifier: "mlx:mlx-community/some-model-4bit"), "Local model (mlx-community/some-model-4bit)")
        if let entry = ModelManager.catalog.first {
            XCTAssertEqual(ClassifierDisplay.name(forIdentifier: "mlx:\(entry.hfRepo)"), "Local model (\(entry.displayName))")
        }
        XCTAssertEqual(ClassifierDisplay.name(forIdentifier: "custom.thing"), "custom.thing")
        XCTAssertTrue(ClassifierDisplay.footnote(forIdentifier: nil).contains("heuristics only"))
        XCTAssertTrue(ClassifierDisplay.footnote(forIdentifier: AppleFoundationClassifier.classifierIdentifier).contains("Apple Intelligence"))
    }

    // MARK: - Device recommendation

    func testDeviceModelRecommendation() {
        let big = ModelManager.CatalogEntry(id: "big", displayName: "Big", hfRepo: "x/big", approxSizeBytes: 2_700_000_000, notes: "", minimumRecommendedRAMBytes: 0, extraEOSTokens: [], isThinkingModel: false)
        let mid = ModelManager.CatalogEntry(id: "mid", displayName: "Mid", hfRepo: "x/mid", approxSizeBytes: 1_900_000_000, notes: "", minimumRecommendedRAMBytes: 0, extraEOSTokens: [], isThinkingModel: false)
        let small = ModelManager.CatalogEntry(id: "small", displayName: "Small", hfRepo: "x/small", approxSizeBytes: 1_000_000_000, notes: "", minimumRecommendedRAMBytes: 0, extraEOSTokens: [], isThinkingModel: false)
        let catalog = [big, mid, small]

        let large = DeviceModelRecommendation(physicalMemory: 7_900_000_000)
        XCTAssertEqual(large.memoryClass, .large)
        XCTAssertTrue(large.fits(big))
        XCTAssertEqual(large.recommendedEntry(in: catalog)?.id, "big", "first fitting entry in catalog order")
        XCTAssertNil(large.warning(for: big))

        let medium = DeviceModelRecommendation(physicalMemory: 5_900_000_000)
        XCTAssertEqual(medium.memoryClass, .medium)
        XCTAssertFalse(medium.fits(big))
        XCTAssertFalse(medium.fits(mid))
        XCTAssertTrue(medium.fits(small))
        XCTAssertEqual(medium.recommendedEntry(in: catalog)?.id, "small")
        XCTAssertNotNil(medium.warning(for: big))

        let tiny = DeviceModelRecommendation(physicalMemory: 3_900_000_000)
        XCTAssertEqual(tiny.memoryClass, .small)
        XCTAssertNil(tiny.maxRecommendedBytes)
        XCTAssertNil(tiny.recommendedEntry(in: catalog))
        XCTAssertNotNil(tiny.warning(for: small))
        XCTAssertFalse(tiny.memoryDescription.isEmpty)
    }

    // MARK: - Model row accessibility

    /// #46: VoiceOver exposes each row button separately, so "Download, button" repeated per catalog entry gives
    /// no clue which multi-GB model (or which deletion) is being triggered.
    @MainActor
    func testModelRowActionButtonsNameTheirModel() throws {
        let entry = try XCTUnwrap(ModelManager.entry(for: ModelManager.defaultModelID))
        let download = ModelRow.downloadAccessibilityLabel(for: entry)
        XCTAssertTrue(download.hasPrefix("Download "), download)
        XCTAssertTrue(download.contains(entry.displayName), download)
        XCTAssertTrue(download.contains(ByteFormat.string(entry.approxSizeBytes)), download)
        XCTAssertEqual(ModelRow.deleteAccessibilityLabel(for: entry), "Delete \(entry.displayName)")
        XCTAssertEqual(ModelRow.cancelAccessibilityLabel(for: entry), "Cancel download of \(entry.displayName)")

        // Every row gets a distinct label for each action, which is the whole point.
        for label in [ModelRow.downloadAccessibilityLabel, ModelRow.deleteAccessibilityLabel, ModelRow.cancelAccessibilityLabel] {
            let labels = ModelManager.catalog.map(label)
            XCTAssertEqual(Set(labels).count, ModelManager.catalog.count, "\(labels)")
        }
    }

    // MARK: - Storage size

    func testDirectorySizeSumsRegularFiles() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "UIHelpersTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root.appending(path: "nested"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data(repeating: 1, count: 1000).write(to: root.appending(path: "a.safetensors"))
        try Data(repeating: 2, count: 234).write(to: root.appending(path: "nested/config.json"))

        XCTAssertEqual(ModelDownloadController.directorySize(at: root), 1234)
        XCTAssertEqual(ModelDownloadController.directorySize(at: root.appending(path: "missing")), 0)
    }

    // MARK: - Account linking persistence

    @MainActor
    func testDeleteRecordsRemovesOnlyThatAccountsData() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        let keep = LinkedAccount(provider: .gmail, email: "keep@example.com")
        let drop = LinkedAccount(provider: .microsoft, email: "drop@example.com")
        context.insert(keep)
        context.insert(drop)

        let report = HeuristicReport(signals: [], score: 0.9, bodyText: "")
        let verdict = VerdictEngine().makeVerdict(report: report, assessment: nil, modelIdentifier: nil)
        context.insert(FlaggedEmailRecord(email: SampleEmails.paypalPhish, verdict: verdict, accountID: keep.id))
        context.insert(FlaggedEmailRecord(email: SampleEmails.giftCardScam, verdict: verdict, accountID: drop.id))
        context.insert(ProcessedMessage(key: "gmail:\(keep.id.uuidString):m1"))
        context.insert(ProcessedMessage(key: "microsoft:\(drop.id.uuidString):m2"))
        try context.save()

        let deleted = try AccountLinker.deleteRecords(for: drop.id, in: context)

        XCTAssertEqual(deleted.count, 1)
        let remaining = try context.fetch(FetchDescriptor<FlaggedEmailRecord>())
        XCTAssertEqual(remaining.map(\.accountID), [keep.id])
        let processed = try context.fetch(FetchDescriptor<ProcessedMessage>())
        XCTAssertEqual(processed.map(\.key), ["gmail:\(keep.id.uuidString):m1"])
    }

    @MainActor
    func testUpsertAccountReusesExistingAddressCaseInsensitively() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext
        let config = AppConfig(relaySalt: "salt")

        let first = try AccountLinker.upsertAccount(for: .gmail, identity: SignedInIdentity(providerAccountID: "1", email: "Sam@Example.com", displayName: "Sam"), config: config, in: context)
        first.isEnabled = false
        try context.save()

        let second = try AccountLinker.upsertAccount(for: .gmail, identity: SignedInIdentity(providerAccountID: "1", email: "sam@example.com", displayName: "Sam R."), config: config, in: context)
        try context.save()

        XCTAssertEqual(first.id, second.id)
        XCTAssertTrue(second.isEnabled, "re-linking re-enables the account")
        XCTAssertEqual(second.displayName, "Sam R.")
        XCTAssertEqual(second.relayAccountKey, config.accountKey(for: "sam@example.com"))
        XCTAssertEqual(try context.fetchCount(FetchDescriptor<LinkedAccount>()), 1)

        let other = try AccountLinker.upsertAccount(for: .microsoft, identity: SignedInIdentity(providerAccountID: "2", email: "sam@example.com"), config: config, in: context)
        XCTAssertNotEqual(other.id, first.id, "same address on another provider is a separate account")
    }

    /// Both providers are offered unconditionally; the missing piece is named when the option is used, and it
    /// has to name the key and where to put it, or the message is not actionable.
    @MainActor
    func testUnconfiguredProviderMessageNamesTheMissingKeyAndSetupStep() {
        let gmail = AccountLinker.unconfiguredMessage(for: .gmail)
        XCTAssertTrue(gmail.contains("GOOGLE_CLIENT_ID"), gmail)
        XCTAssertTrue(gmail.contains("Secrets.xcconfig"), gmail)
        XCTAssertTrue(gmail.contains("docs/SETUP.md"), gmail)

        let microsoft = AccountLinker.unconfiguredMessage(for: .microsoft)
        XCTAssertTrue(microsoft.contains("MS_CLIENT_ID"), microsoft)
        XCTAssertTrue(microsoft.contains("Secrets.xcconfig"), microsoft)
        XCTAssertTrue(microsoft.contains("docs/SETUP.md"), microsoft)
    }

    /// The check itself must stay: the message above is only reachable because `link` still refuses to start a
    /// sign-in this build cannot finish.
    @MainActor
    func testIsConfiguredStillReflectsTheBuildConfiguration() {
        let empty = AppConfig()
        XCTAssertFalse(AccountLinker.isConfigured(.gmail, config: empty))
        XCTAssertFalse(AccountLinker.isConfigured(.microsoft, config: empty))

        let filled = AppConfig(
            googleClientID: "id.apps.googleusercontent.com",
            googleReversedClientID: "com.googleusercontent.apps.id",
            microsoftClientID: "00000000-0000-0000-0000-000000000001"
        )
        XCTAssertTrue(AccountLinker.isConfigured(.gmail, config: filled))
        XCTAssertTrue(AccountLinker.isConfigured(.microsoft, config: filled))
    }

    @MainActor
    func testDemoDataSeedsOnceAndGroupsAcrossDays() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let now = date(2026, 9, 21, 15)
        DemoData.seed(into: container, now: now, calendar: utc)
        DemoData.seed(into: container, now: now, calendar: utc)

        let records = try container.mainContext.fetch(FetchDescriptor<FlaggedEmailRecord>(sortBy: [SortDescriptor(\.receivedAt, order: .reverse)]))
        XCTAssertEqual(records.count, 13, "one record per seeded fixture, and seeding is idempotent")
        XCTAssertEqual(try container.mainContext.fetchCount(FetchDescriptor<LinkedAccount>()), 1)
        XCTAssertTrue(records.allSatisfy { $0.level != .safe })

        let sections = DayGrouping.sections(records, date: \.receivedAt, now: now, calendar: utc)
        XCTAssertGreaterThanOrEqual(sections.count, 6)
        XCTAssertEqual(sections.first?.title, "Today")
        XCTAssertEqual(sections.dropFirst().first?.title, "Yesterday")
        XCTAssertEqual(records.prefix(3).filter { !$0.isRead }.count, 3, "the newest three drive the tab badge")
        XCTAssertTrue(records.dropFirst(3).allSatisfy(\.isRead))
    }

    /// Seeded just after midnight, "5 hours ago" would land yesterday — or, with a naive clamp, in the future.
    /// Today's arrivals must stay inside today, in order, and in the past whatever time the demo is started.
    /// Seeded early in the day, "5 hours ago" would land yesterday — or, with a naive clamp, in the future. And
    /// compressing only the arrivals that fall before midnight reorders the list, which is the second bug this
    /// pins: at 01:02 the five-hour-old mail was pulled to "24 minutes ago" while the 35-minute-old one stayed
    /// put, so the oldest sorted newest. Today's arrivals must stay inside today, in the past, and in order, at
    /// every hour of the day.
    @MainActor
    func testDemoDataKeepsTodayOrderedInsideTodayAtAnyHour() throws {
        for (hour, minute) in [(0, 3), (1, 2), (3, 0), (5, 30), (12, 0), (23, 45)] {
            let container = try Persistence.makeContainer(inMemory: true)
            let now = date(2026, 9, 21, hour, minute)
            DemoData.seed(into: container, now: now, calendar: utc)
            let at = "at \(hour):\(minute)"

            let records = try container.mainContext.fetch(FetchDescriptor<FlaggedEmailRecord>(sortBy: [SortDescriptor(\.receivedAt, order: .reverse)]))
            let sections = DayGrouping.sections(records, date: \.receivedAt, now: now, calendar: utc)
            XCTAssertEqual(sections.first?.title, "Today", at)
            XCTAssertEqual(sections.first?.items.count, 3, at)
            for record in records {
                XCTAssertLessThanOrEqual(record.receivedAt, now, "\(record.subject) is dated in the future \(at)")
            }
            let today = try XCTUnwrap(sections.first).items
            XCTAssertEqual(today.map(\.subject), ["Action required: Your account has been limited [Case ID PP-018-442-919]",
                                                  "PayPal account in question",
                                                  "Invoice INV-30917 - Payment Overdue"],
                           "newest first, whatever the hour \(at)")
            XCTAssertGreaterThanOrEqual(try XCTUnwrap(today.last).receivedAt, utc.startOfDay(for: now), at)
        }
    }

    /// Nothing in the demo is hand-written: every record must be reproducible by running its fixture through the
    /// shipping analyzer, the recorded model answer and the verdict engine.
    @MainActor
    func testDemoRecordsComeFromTheRealEngine() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let now = date(2026, 9, 21, 15)
        DemoData.seed(into: container, now: now, calendar: utc)
        let context = container.mainContext
        let account = try XCTUnwrap(try context.fetch(FetchDescriptor<LinkedAccount>()).first)
        let fixtures = Dictionary(uniqueKeysWithValues: SampleEmails.named.map { ($0.email.messageID, $0.email) })

        let records = try context.fetch(FetchDescriptor<FlaggedEmailRecord>())
        XCTAssertFalse(records.isEmpty)
        for record in records {
            let fixture = try XCTUnwrap(fixtures[record.messageID], "\(record.messageID) is not a bundled fixture")
            let email = DemoData.prepare(fixture, accountID: account.id, receivedAt: record.receivedAt)
            let expected = DemoData.verdict(for: email, account: account, modelAnswered: isFromToday(record.receivedAt, now: now))
            XCTAssertEqual(record.confidence, expected.confidence, accuracy: 0.0001, record.subject)
            XCTAssertEqual(record.level, expected.level, record.subject)
            XCTAssertEqual(record.category, expected.category, record.subject)
            XCTAssertEqual(record.summary, expected.summary, record.subject)
            XCTAssertEqual(record.reasons, expected.reasons, record.subject)
            XCTAssertTrue(AlertPolicy(minimumLevel: DemoData.alertMinimumLevel).shouldAlert(expected), record.subject)
        }
    }

    /// Today's mail was checked with the app open, so it carries the model's recorded answer; everything older
    /// was checked with the app closed, so it is the rules alone. Both halves have to be on screen, because both
    /// halves are how the product behaves.
    @MainActor
    func testTodaysRecordsCarryTheModelAnswerAndOlderOnesAreRulesOnly() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let now = date(2026, 9, 21, 15)
        DemoData.seed(into: container, now: now, calendar: utc)
        let records = try container.mainContext.fetch(FetchDescriptor<FlaggedEmailRecord>())

        let today = records.filter { isFromToday($0.receivedAt, now: now) }
        let older = records.filter { !isFromToday($0.receivedAt, now: now) }
        XCTAssertEqual(today.count, 3)
        XCTAssertFalse(older.isEmpty)
        for record in today {
            XCTAssertEqual(record.modelIdentifier, DemoData.localModelIdentifier, record.subject)
            XCTAssertTrue(record.reasons.contains { $0.source == .model }, "\(record.subject) shows model findings")
        }
        for record in older {
            XCTAssertNil(record.modelIdentifier, "\(record.subject) was checked while the app was closed")
            XCTAssertTrue(record.reasons.allSatisfy { $0.source == .heuristic }, record.subject)
        }
    }

    /// A list of thirteen identical "High, 100%" rows would say the detector has one output. It has a range, and
    /// the demo has to show it — with whatever the engine really returns.
    @MainActor
    func testDemoListSpansTheRiskBands() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        DemoData.seed(into: container, now: date(2026, 9, 21, 15), calendar: utc)
        let records = try container.mainContext.fetch(FetchDescriptor<FlaggedEmailRecord>())
        let levels = Set(records.map(\.level))
        XCTAssertTrue(levels.contains(.high), "levels: \(levels)")
        XCTAssertTrue(levels.contains(.medium), "levels: \(levels)")
        XCTAssertTrue(levels.contains(.low), "levels: \(levels)")
        XCTAssertEqual(Set(records.map(\.category)), [.phishing, .scam], "both categories are represented")
        XCTAssertGreaterThanOrEqual(Set(records.map { Int(($0.confidence * 100).rounded()) }).count, 7,
                                    "distinct confidence readings")
        // Every one of them is still something the demo's own alert level would have raised.
        for record in records {
            XCTAssertTrue(AlertFilter.includes(level: record.level, minimum: DemoData.alertMinimumLevel), record.subject)
        }
    }
}

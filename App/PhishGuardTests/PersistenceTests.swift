import PhishCore
import SwiftData
import XCTest
@testable import PhishGuard

final class PersistenceTests: XCTestCase {
    @MainActor
    func testInMemoryContainerStoresFlaggedRecord() throws {
        let container = try Persistence.makeContainer(inMemory: true)
        let context = container.mainContext

        let signal = Signal(id: "link.lookalike_domain", title: "Lookalike link", detail: "paypal.com.account-verify-login.com", severity: .high, weight: 0.9)
        let report = HeuristicReport(signals: [signal], score: 0.9, bodyText: "body")
        let verdict = VerdictEngine().makeVerdict(report: report, assessment: nil, modelIdentifier: nil)
        let accountID = UUID()

        let record = FlaggedEmailRecord(email: SampleEmails.paypalPhish, verdict: verdict, accountID: accountID)
        context.insert(record)
        context.insert(ProcessedMessage(key: SampleEmails.paypalPhish.dedupeKey))
        try context.save()

        let records = try context.fetch(FetchDescriptor<FlaggedEmailRecord>())
        XCTAssertEqual(records.count, 1)
        let stored = try XCTUnwrap(records.first)
        XCTAssertEqual(stored.accountID, accountID)
        XCTAssertEqual(stored.level, .high)
        XCTAssertEqual(stored.category, .phishing)
        XCTAssertEqual(stored.senderAddress, "service@paypal.com")
        XCTAssertEqual(stored.reasons.map(\.id), ["link.lookalike_domain"])
        XCTAssertNil(stored.modelIdentifier)
        XCTAssertFalse(stored.isRead)

        let key = SampleEmails.paypalPhish.dedupeKey
        let processed = try context.fetchCount(FetchDescriptor<ProcessedMessage>(predicate: #Predicate { $0.key == key }))
        XCTAssertEqual(processed, 1)
    }

    @MainActor
    func testSettingsStorePersistsToUserDefaults() throws {
        let suite = "PhishGuardTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        let store = SettingsStore(defaults: defaults)
        XCTAssertEqual(store.alertMinimumLevel, .medium)
        XCTAssertEqual(store.lookbackHours, SettingsStore.defaultLookbackHours)
        XCTAssertFalse(store.hasCompletedOnboarding)
        // The downloaded local model is the default classifier; Apple Intelligence is opt-in.
        XCTAssertEqual(store.classifierChoice, .mlx)
        XCTAssertEqual(store.selectedMLXModelID, ModelManager.defaultModelID)
        XCTAssertEqual(store.selectedMLXModelID, "qwen3-4b-instruct-2507-4bit")

        store.alertMinimumLevel = .high
        store.lookbackHours = 500
        store.hasCompletedOnboarding = true
        store.classifierChoice = .appleFoundation
        store.selectedMLXModelID = "gemma-3-4b-it-4bit"

        let reloaded = SettingsStore(defaults: defaults)
        XCTAssertEqual(reloaded.alertMinimumLevel, .high)
        XCTAssertEqual(reloaded.lookbackHours, SettingsStore.lookbackRange.upperBound, "clamped")
        XCTAssertTrue(reloaded.hasCompletedOnboarding)
        XCTAssertEqual(reloaded.classifierChoice, .appleFoundation)
        XCTAssertEqual(reloaded.selectedMLXModelID, "gemma-3-4b-it-4bit")

        // Clearing the pick falls back to the default model rather than to "nothing chosen".
        reloaded.selectedMLXModelID = nil
        XCTAssertEqual(SettingsStore(defaults: defaults).selectedMLXModelID, ModelManager.defaultModelID)
    }

    func testAccountKeyIsSHA256OfLowercasedEmailAndSalt() {
        let config = AppConfig(relaySalt: "salt")
        XCTAssertEqual(config.accountKey(for: " Foo@Example.COM "), "88c9b9630189acc1265c686fca97d64a720348160cdae5cdfa11fa5d3974bc58")
        XCTAssertEqual(config.accountKey(for: "foo@example.com"), config.accountKey(for: "FOO@EXAMPLE.COM"))
    }

    func testPlaceholderDetection() {
        XCTAssertTrue(AppConfig.isPlaceholder("replace-me"))
        XCTAssertTrue(AppConfig.isPlaceholder("https://relay.example.com"))
        XCTAssertTrue(AppConfig.isPlaceholder("$(RELAY_SALT)"))
        XCTAssertFalse(AppConfig.isPlaceholder("https://phishguard-relay.fly.dev"))
    }

    // MARK: - Schema migration

    /// A store written by the schema as it stood **before** `LinkedAccount.isDemo` and
    /// `FlaggedEmailRecord.isDemo` existed must open with the shipping schema and keep its rows — this is the
    /// upgrade an already-installed phone performs, and the alternative is `makeDefaultContainer` silently
    /// falling back to an in-memory store and the user's alerts appearing to vanish.
    ///
    /// Both attributes are additive and non-optional **with a default**, which is the case Core Data can infer a
    /// mapping for, so no `VersionedSchema`/`SchemaMigrationPlan` is needed. `PreIsDemoSchema` below is that
    /// earlier model, entity for entity; SwiftData names an entity after its type's simple name, so the nested
    /// copies are the same entities to the store.
    @MainActor
    func testStoreFromBeforeIsDemoMigratesAndDefaultsToFalse() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PhishGuardMigration-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("PhishGuard.store")

        let accountID = UUID()
        let recordID = UUID()
        let processedKey = "gmail:\(accountID.uuidString):message-1"
        try writeStoreWithoutIsDemo(at: url, accountID: accountID, recordID: recordID, processedKey: processedKey)
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))

        let container = try ModelContainer(
            for: Persistence.schema,
            configurations: [ModelConfiguration(schema: Persistence.schema, url: url)]
        )
        let context = ModelContext(container)

        let accounts = try context.fetch(FetchDescriptor<LinkedAccount>())
        XCTAssertEqual(accounts.map(\.id), [accountID], "the account written by the older schema is still there")
        let account = try XCTUnwrap(accounts.first)
        XCTAssertEqual(account.email, "owner@gmail.com")
        XCTAssertEqual(account.relayAccountKey, "real-key")
        XCTAssertTrue(account.isEnabled)
        XCTAssertFalse(account.isDemo, "a pre-existing account is a real one")

        let records = try context.fetch(FetchDescriptor<FlaggedEmailRecord>())
        XCTAssertEqual(records.map(\.id), [recordID])
        let record = try XCTUnwrap(records.first)
        XCTAssertEqual(record.subject, "Action required: Your account has been limited")
        XCTAssertEqual(record.level, .high)
        XCTAssertEqual(record.reasons.map(\.id), ["link.lookalike_domain"])
        XCTAssertFalse(record.isDemo, "a pre-existing flagged email is a real one")
        XCTAssertEqual(try context.fetch(FetchDescriptor<ProcessedMessage>()).map(\.key), [processedKey])

        // And because both default to false, nothing in a migrated store is demo data for Demo mode to remove.
        XCTAssertEqual(try context.fetchCount(FetchDescriptor<FlaggedEmailRecord>(predicate: #Predicate { $0.isDemo })), 0)
        XCTAssertEqual(try context.fetchCount(FetchDescriptor<LinkedAccount>(predicate: #Predicate { $0.isDemo })), 0)
    }

    /// A store written **before** `FlaggedCallRecord` existed (the three mail entities, as they ship today) must
    /// open with the schema that adds the call entity and keep its rows: adding an entity is additive, so no
    /// migration plan is needed — but an installed phone performs exactly this upgrade, and the alternative is
    /// `makeDefaultContainer` silently falling back to an in-memory store.
    @MainActor
    func testStoreFromBeforeCallGuardOpensWithTheCallEntityAdded() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PhishGuardCallMigration-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("PhishGuard.store")

        let accountID = UUID()
        let recordID = UUID()
        do {
            let mailOnly = Schema([LinkedAccount.self, FlaggedEmailRecord.self, ProcessedMessage.self])
            XCTAssertEqual(mailOnly.entities.count + 1, Persistence.schema.entities.count, "the shipping schema adds exactly the call entity")
            let container = try ModelContainer(for: mailOnly, configurations: [ModelConfiguration(schema: mailOnly, url: url)])
            let context = ModelContext(container)
            context.insert(LinkedAccount(id: accountID, provider: .gmail, email: "owner@gmail.com", relayAccountKey: "real-key"))
            let verdict = VerdictEngine().makeVerdict(report: HeuristicAnalyzer().analyze(SampleEmails.paypalPhish), assessment: nil, modelIdentifier: nil)
            let record = FlaggedEmailRecord(email: SampleEmails.paypalPhish, verdict: verdict, accountID: accountID)
            record.id = recordID
            context.insert(record)
            try context.save()
        }

        let container = try ModelContainer(
            for: Persistence.schema,
            configurations: [ModelConfiguration(schema: Persistence.schema, url: url)]
        )
        let context = ModelContext(container)

        XCTAssertEqual(try context.fetch(FetchDescriptor<LinkedAccount>()).map(\.id), [accountID])
        XCTAssertEqual(try context.fetch(FetchDescriptor<FlaggedEmailRecord>()).map(\.id), [recordID])
        XCTAssertEqual(try context.fetchCount(FetchDescriptor<FlaggedCallRecord>()), 0, "no call has been flagged on this phone yet")

        let summary = try JSONDecoder().decode(CallSummary.self, from: CallFixtures.data(CallFixtures.summaryJSON()))
        context.insert(try XCTUnwrap(FlaggedCallRecord(summary: summary)))
        try context.save()
        let calls = try context.fetch(FetchDescriptor<FlaggedCallRecord>())
        XCTAssertEqual(calls.map(\.id), [UUID(uuidString: CallFixtures.callID)])
        XCTAssertEqual(calls.first?.level, .high)
        XCTAssertEqual(calls.first?.reasons.count, 3)
        XCTAssertFalse(calls.first?.isDemo ?? true)
    }

    /// Writes the store with `PreIsDemoSchema` and lets the container go out of scope before the caller reopens
    /// the same file with the shipping schema.
    @MainActor
    private func writeStoreWithoutIsDemo(at url: URL, accountID: UUID, recordID: UUID, processedKey: String) throws {
        let schema = Schema([
            PreIsDemoSchema.LinkedAccount.self,
            PreIsDemoSchema.FlaggedEmailRecord.self,
            PreIsDemoSchema.ProcessedMessage.self,
        ])
        // The legacy copies must be the same entities as the shipping mail models, or this would test nothing.
        // `FlaggedCallRecord` (Call Guard) was added later and is not part of the pre-isDemo store.
        XCTAssertEqual(Set(schema.entities.map(\.name)), ["LinkedAccount", "FlaggedEmailRecord", "ProcessedMessage"])
        XCTAssertTrue(
            Set(schema.entities.map(\.name)).isSubset(of: Set(Persistence.schema.entities.map(\.name))),
            "the legacy copies must be entities the shipping schema still has"
        )
        let container = try ModelContainer(for: schema, configurations: [ModelConfiguration(schema: schema, url: url)])
        let context = ModelContext(container)
        context.insert(PreIsDemoSchema.LinkedAccount(
            id: accountID, providerRaw: "gmail", email: "owner@gmail.com", displayName: "Owner",
            addedAt: Date(timeIntervalSince1970: 1_700_000_000), isEnabled: true, relayAccountKey: "real-key"
        ))
        let reasons = [Reason(id: "link.lookalike_domain", title: "Lookalike link",
                              detail: "paypal.com.account-verify-login.com", severity: .high, source: .heuristic)]
        context.insert(PreIsDemoSchema.FlaggedEmailRecord(
            id: recordID, accountID: accountID, providerRaw: "gmail", messageID: "message-1",
            senderName: "PayPal", senderAddress: "service@paypal.com",
            subject: "Action required: Your account has been limited",
            receivedAt: Date(timeIntervalSince1970: 1_700_000_100), flaggedAt: Date(timeIntervalSince1970: 1_700_000_130),
            categoryRaw: "phishing", confidence: 0.92, levelRaw: "high",
            reasonsJSON: (try? JSONEncoder().encode(reasons)) ?? Data("[]".utf8),
            summary: "Credential phishing.", modelIdentifier: nil, webLinkString: nil, isRead: false
        ))
        context.insert(PreIsDemoSchema.ProcessedMessage(key: processedKey, processedAt: Date(timeIntervalSince1970: 1_700_000_130)))
        try context.save()
    }
}

/// The persisted models exactly as they were before `isDemo` was added, used only to write a store that predates
/// it. Nested so the names cannot shadow the shipping models anywhere else in the test target; SwiftData still
/// registers them under the entity names `LinkedAccount`, `FlaggedEmailRecord` and `ProcessedMessage`, which the
/// assertion in `writeStoreWithoutIsDemo` pins.
enum PreIsDemoSchema {
    @Model
    final class LinkedAccount {
        @Attribute(.unique) var id: UUID
        var providerRaw: String
        var email: String
        var displayName: String?
        var addedAt: Date
        var isEnabled: Bool
        var syncCursor: String?
        var lastScanAt: Date?
        var pushSubscriptionID: String?
        var pushSubscriptionExpiresAt: Date?
        var relayAccountKey: String?
        var needsReauthentication: Bool = false

        init(
            id: UUID, providerRaw: String, email: String, displayName: String?, addedAt: Date, isEnabled: Bool,
            syncCursor: String? = nil, lastScanAt: Date? = nil, pushSubscriptionID: String? = nil,
            pushSubscriptionExpiresAt: Date? = nil, relayAccountKey: String? = nil, needsReauthentication: Bool = false
        ) {
            self.id = id
            self.providerRaw = providerRaw
            self.email = email
            self.displayName = displayName
            self.addedAt = addedAt
            self.isEnabled = isEnabled
            self.syncCursor = syncCursor
            self.lastScanAt = lastScanAt
            self.pushSubscriptionID = pushSubscriptionID
            self.pushSubscriptionExpiresAt = pushSubscriptionExpiresAt
            self.relayAccountKey = relayAccountKey
            self.needsReauthentication = needsReauthentication
        }
    }

    @Model
    final class FlaggedEmailRecord {
        @Attribute(.unique) var id: UUID
        var accountID: UUID
        var providerRaw: String
        var messageID: String
        var senderName: String?
        var senderAddress: String
        var subject: String
        var receivedAt: Date
        var flaggedAt: Date
        var categoryRaw: String
        var confidence: Double
        var levelRaw: String
        var reasonsJSON: Data
        var summary: String
        var modelIdentifier: String?
        var webLinkString: String?
        var isRead: Bool

        init(
            id: UUID, accountID: UUID, providerRaw: String, messageID: String, senderName: String?,
            senderAddress: String, subject: String, receivedAt: Date, flaggedAt: Date, categoryRaw: String,
            confidence: Double, levelRaw: String, reasonsJSON: Data, summary: String, modelIdentifier: String?,
            webLinkString: String?, isRead: Bool
        ) {
            self.id = id
            self.accountID = accountID
            self.providerRaw = providerRaw
            self.messageID = messageID
            self.senderName = senderName
            self.senderAddress = senderAddress
            self.subject = subject
            self.receivedAt = receivedAt
            self.flaggedAt = flaggedAt
            self.categoryRaw = categoryRaw
            self.confidence = confidence
            self.levelRaw = levelRaw
            self.reasonsJSON = reasonsJSON
            self.summary = summary
            self.modelIdentifier = modelIdentifier
            self.webLinkString = webLinkString
            self.isRead = isRead
        }
    }

    @Model
    final class ProcessedMessage {
        @Attribute(.unique) var key: String
        var processedAt: Date

        init(key: String, processedAt: Date) {
            self.key = key
            self.processedAt = processedAt
        }
    }
}

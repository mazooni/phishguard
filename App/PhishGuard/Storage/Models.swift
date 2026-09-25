import Foundation
import PhishCore
import SwiftData

/// A watched mailbox. Tokens are NOT stored here (Keychain only); this holds sync state and push-subscription metadata.
@Model
final class LinkedAccount {
    @Attribute(.unique) var id: UUID
    var providerRaw: String
    var email: String
    var displayName: String?
    var addedAt: Date
    var isEnabled: Bool
    /// Opaque provider cursor: Gmail `historyId`, Graph `deltaLink`.
    var syncCursor: String?
    var lastScanAt: Date?
    var pushSubscriptionID: String?
    var pushSubscriptionExpiresAt: Date?
    /// `AppConfig.accountKey(for:)` — what the relay knows this account as.
    var relayAccountKey: String?
    /// Set by the scan coordinator when the provider reported `ProviderError.notAuthenticated` (revoked or expired
    /// grant, or Keychain state missing after a restore); cleared by a successful re-sign-in or fetch. The Accounts
    /// screen offers "Sign in again" while it is set.
    var needsReauthentication: Bool = false
    /// True for the fictional mailbox Demo mode seeds (`DemoData`), never for an account the user signed in to.
    ///
    /// It has no credentials and no real mailbox behind it, so it is excluded everywhere an account is treated as
    /// a mailbox: `ScanCoordinator.enabledAccounts` never fetches it (no scan error, no push-subscription work),
    /// the "accounts" figures count real mailboxes only, and the Accounts row labels it "Demo". It is also the
    /// only thing turning Demo mode off deletes — a `false` here is never touched. Additive with a default, so an
    /// existing store migrates lightly (`PersistenceTests.testStoreFromBeforeIsDemoMigrates`).
    var isDemo: Bool = false

    init(
        id: UUID = UUID(),
        provider: MailProvider,
        email: String,
        displayName: String? = nil,
        addedAt: Date = .now,
        isEnabled: Bool = true,
        syncCursor: String? = nil,
        lastScanAt: Date? = nil,
        pushSubscriptionID: String? = nil,
        pushSubscriptionExpiresAt: Date? = nil,
        relayAccountKey: String? = nil,
        needsReauthentication: Bool = false,
        isDemo: Bool = false
    ) {
        self.id = id
        self.providerRaw = provider.rawValue
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
        self.isDemo = isDemo
    }

    var provider: MailProvider? { MailProvider(rawValue: providerRaw) }

    var pushSubscriptionState: PushSubscriptionState? {
        guard let pushSubscriptionID, let pushSubscriptionExpiresAt, let relayAccountKey else { return nil }
        return PushSubscriptionState(id: pushSubscriptionID, expiresAt: pushSubscriptionExpiresAt, relayAccountKey: relayAccountKey)
    }
}

/// The only thing persisted about an email, and only when it was flagged: sender, subject, date, verdict and
/// reasons (short evidence snippets). Never the body or raw message.
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
    /// JSON-encoded `[Reason]`.
    var reasonsJSON: Data
    var summary: String
    var modelIdentifier: String?
    var webLinkString: String?
    var isRead: Bool
    /// True for a record Demo mode seeded or the "simulate an incoming flagged email" button produced. It is the
    /// only thing turning Demo mode off deletes, and no real flagged email ever carries it. Additive with a
    /// default, so an existing store migrates lightly.
    var isDemo: Bool = false

    init(
        id: UUID = UUID(),
        accountID: UUID,
        providerRaw: String,
        messageID: String,
        senderName: String?,
        senderAddress: String,
        subject: String,
        receivedAt: Date,
        flaggedAt: Date = .now,
        categoryRaw: String,
        confidence: Double,
        levelRaw: String,
        reasonsJSON: Data,
        summary: String,
        modelIdentifier: String? = nil,
        webLinkString: String? = nil,
        isRead: Bool = false,
        isDemo: Bool = false
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
        self.isDemo = isDemo
    }

    /// Builds the record from an in-memory email and its verdict. Only metadata and the verdict are copied.
    convenience init(email: EmailMessage, verdict: Verdict, accountID: UUID, flaggedAt: Date = .now, isDemo: Bool = false) {
        self.init(
            accountID: accountID,
            providerRaw: email.provider.rawValue,
            messageID: email.messageID,
            senderName: email.from?.name.map { String($0.prefix(120)) },
            senderAddress: email.from?.address ?? "",
            subject: String(email.subject.prefix(200)),
            receivedAt: email.receivedAt,
            flaggedAt: flaggedAt,
            categoryRaw: verdict.category.rawValue,
            confidence: verdict.confidence,
            levelRaw: verdict.level.rawValue,
            reasonsJSON: Self.encodeReasons(verdict.reasons),
            summary: String(verdict.summary.prefix(500)),
            modelIdentifier: verdict.modelIdentifier,
            webLinkString: email.webLink?.absoluteString,
            isDemo: isDemo
        )
    }

    /// Refreshes this row from a newer verdict for the same message (a re-check, or a second scan that reached
    /// the same email). `id`, `accountID`, `messageID` and `isRead` are deliberately kept: it is the same
    /// email, so a delivered notification, an open deep link and the fact the user has already read it all
    /// stay valid. Everything the verdict decided is replaced.
    func update(email: EmailMessage, verdict: Verdict, flaggedAt: Date = .now) {
        senderName = email.from?.name.map { String($0.prefix(120)) }
        senderAddress = email.from?.address ?? ""
        subject = String(email.subject.prefix(200))
        receivedAt = email.receivedAt
        self.flaggedAt = flaggedAt
        categoryRaw = verdict.category.rawValue
        confidence = verdict.confidence
        levelRaw = verdict.level.rawValue
        reasonsJSON = Self.encodeReasons(verdict.reasons)
        summary = String(verdict.summary.prefix(500))
        modelIdentifier = verdict.modelIdentifier
        webLinkString = email.webLink?.absoluteString
    }

    var provider: MailProvider? { MailProvider(rawValue: providerRaw) }
    var category: ThreatCategory { ThreatCategory(rawValue: categoryRaw) ?? .safe }
    var level: RiskLevel { RiskLevel(rawValue: levelRaw) ?? .safe }
    var reasons: [Reason] { (try? JSONDecoder().decode([Reason].self, from: reasonsJSON)) ?? [] }
    var webLink: URL? { webLinkString.flatMap { URL(string: $0) } }
    var senderDisplay: String {
        if let senderName, !senderName.isEmpty { return "\(senderName) <\(senderAddress)>" }
        return senderAddress
    }

    static func encodeReasons(_ reasons: [Reason]) -> Data {
        (try? JSONEncoder().encode(reasons)) ?? Data("[]".utf8)
    }
}

/// Dedupe table so a message is classified at most once. Key: "\(provider):\(accountID):\(messageID)".
@Model
final class ProcessedMessage {
    @Attribute(.unique) var key: String
    var processedAt: Date

    init(key: String, processedAt: Date = .now) {
        self.key = key
        self.processedAt = processedAt
    }
}

/// What the phone keeps about a call Call Guard flagged (docs/CALLS.md §8, §10): the numbers, the times, the
/// verdict, the reasons and the summary the relay produced. **Never a transcript** — the relay only keeps one in
/// memory for the call, and nothing here can hold one. `id` is the relay's `callID`.
@Model
final class FlaggedCallRecord {
    @Attribute(.unique) var id: UUID
    /// E.164.
    var callerNumber: String
    /// The guard number that was called (the relay's Twilio number), E.164.
    var guardNumber: String
    var startedAt: Date
    var endedAt: Date?
    var durationSeconds: Int?
    /// `CallStatus` raw value.
    var statusRaw: String
    /// `CallSource` raw value.
    var sourceRaw: String
    /// `ThreatCategory` raw value.
    var categoryRaw: String
    var confidence: Double
    /// `RiskLevel` raw value.
    var levelRaw: String
    /// JSON-encoded `[Reason]` — the same shape as `FlaggedEmailRecord.reasonsJSON`.
    var reasonsJSON: Data
    var summary: String
    var recommendedAction: String
    /// `"openai:<model id>"` from the relay, nil when the verdict came from the call rules alone.
    var modelIdentifier: String?
    /// True when the relay alerted (push and/or spoken warning) during the call.
    var alerted: Bool
    var isRead: Bool
    /// True for a record the in-app demo produced (Settings › Demo › "Simulate a scam call", or the Demo-mode
    /// seed). It is the only thing turning Demo mode off deletes; a call the relay reported never carries it.
    var isDemo: Bool = false

    init(
        id: UUID,
        callerNumber: String,
        guardNumber: String,
        startedAt: Date,
        endedAt: Date? = nil,
        durationSeconds: Int? = nil,
        statusRaw: String,
        sourceRaw: String,
        categoryRaw: String,
        confidence: Double,
        levelRaw: String,
        reasonsJSON: Data,
        summary: String,
        recommendedAction: String,
        modelIdentifier: String? = nil,
        alerted: Bool,
        isRead: Bool = false,
        isDemo: Bool = false
    ) {
        self.id = id
        self.callerNumber = callerNumber
        self.guardNumber = guardNumber
        self.startedAt = startedAt
        self.endedAt = endedAt
        self.durationSeconds = durationSeconds
        self.statusRaw = statusRaw
        self.sourceRaw = sourceRaw
        self.categoryRaw = categoryRaw
        self.confidence = confidence
        self.levelRaw = levelRaw
        self.reasonsJSON = reasonsJSON
        self.summary = summary
        self.recommendedAction = recommendedAction
        self.modelIdentifier = modelIdentifier
        self.alerted = alerted
        self.isRead = isRead
        self.isDemo = isDemo
    }

    /// Builds the record from what the relay reported. Nil when `callID` is not a UUID (the contract says it is;
    /// a call the app cannot key on is skipped rather than stored under a made-up id).
    convenience init?(summary: CallSummary, isDemo: Bool = false) {
        guard let id = UUID(uuidString: summary.callID) else { return nil }
        let verdict = summary.verdict
        self.init(
            id: id,
            callerNumber: summary.callerNumber,
            guardNumber: summary.calledNumber,
            startedAt: summary.startedDate,
            endedAt: summary.endedDate,
            durationSeconds: summary.durationSeconds,
            statusRaw: summary.status.rawValue,
            sourceRaw: summary.source.rawValue,
            categoryRaw: (verdict?.category ?? .safe).rawValue,
            confidence: verdict?.confidence ?? 0,
            levelRaw: (verdict?.level ?? .safe).rawValue,
            reasonsJSON: Self.encodeReasons(verdict?.reasons ?? []),
            summary: String((verdict?.summary ?? "").prefix(500)),
            recommendedAction: String((verdict?.recommendedAction ?? "").prefix(200)),
            modelIdentifier: verdict?.modelIdentifier,
            alerted: summary.alerted,
            isDemo: isDemo
        )
    }

    /// Refreshes this row from a newer report of the same call (a later verdict, the call ending). `id`, `isRead`
    /// and `isDemo` are deliberately kept: it is the same call, so an open deep link and the fact the user has
    /// already looked at it stay valid.
    func update(from summary: CallSummary) {
        callerNumber = summary.callerNumber
        guardNumber = summary.calledNumber
        startedAt = summary.startedDate
        endedAt = summary.endedDate
        durationSeconds = summary.durationSeconds
        statusRaw = summary.status.rawValue
        sourceRaw = summary.source.rawValue
        if let verdict = summary.verdict {
            apply(verdict)
        }
        alerted = alerted || summary.alerted
    }

    /// Takes a newer verdict for this call on its own — the relay's `verdict.updated` that lands after the call
    /// ended, when the detector's final model pass completes. Nothing else about the call changes.
    func apply(_ verdict: CallVerdict) {
        categoryRaw = verdict.category.rawValue
        confidence = verdict.confidence
        levelRaw = verdict.level.rawValue
        reasonsJSON = Self.encodeReasons(verdict.reasons)
        summary = String(verdict.summary.prefix(500))
        recommendedAction = String(verdict.recommendedAction.prefix(200))
        modelIdentifier = verdict.modelIdentifier
    }

    var status: CallStatus? { CallStatus(rawValue: statusRaw) }
    var source: CallSource? { CallSource(rawValue: sourceRaw) }
    var category: ThreatCategory { ThreatCategory(rawValue: categoryRaw) ?? .safe }
    var level: RiskLevel { RiskLevel(rawValue: levelRaw) ?? .safe }
    var reasons: [Reason] { (try? JSONDecoder().decode([Reason].self, from: reasonsJSON)) ?? [] }

    static func encodeReasons(_ reasons: [CallReason]) -> Data {
        (try? JSONEncoder().encode(reasons.map(\.reason))) ?? Data("[]".utf8)
    }
}

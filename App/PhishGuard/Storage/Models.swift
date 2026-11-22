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
/// verdict, the reasons and the summary the relay produced — and, when the relay checked the caller's voice for
/// AI-generated speech, what that check concluded. **Never a transcript** — the relay only keeps one in memory
/// for the call, and nothing here can hold one. `id` is the relay's `callID`.
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
    /// True when the relay alerted (push and/or spoken warning) during the call — a scam alert, or the AI-voice
    /// warning.
    var alerted: Bool
    var isRead: Bool
    /// True for a record the in-app demo produced (Settings › Demo › "Simulate a scam call", or the Demo-mode
    /// seed). It is the only thing turning Demo mode off deletes; a call the relay reported never carries it.
    var isDemo: Bool = false
    /// `VoiceStatus` raw value of the relay's AI-voice assessment of the caller; nil when no detector ran on the
    /// call (and on every record from before the check existed). It sits next to the verdict and never changes
    /// it: a synthetic voice is not by itself a scam. The four voice attributes are additive optionals with a nil
    /// default, so an existing store migrates lightly (`PersistenceTests.testStoreFromBeforeTheVoiceCheckMigrates`).
    var voiceStatusRaw: String? = nil
    /// 0…1: the share of the caller's analysed speech that was judged synthetic.
    var voiceSyntheticShare: Double? = nil
    /// 0…1: the detector's confidence in the judgement behind `voiceStatusRaw`.
    var voiceConfidence: Double? = nil
    /// `"<vendor>:<model>"` of the detector, e.g. `"modulate:…"`.
    var voiceProvider: String? = nil

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
        isDemo: Bool = false,
        voiceStatusRaw: String? = nil,
        voiceSyntheticShare: Double? = nil,
        voiceConfidence: Double? = nil,
        voiceProvider: String? = nil
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
        self.voiceStatusRaw = voiceStatusRaw
        self.voiceSyntheticShare = voiceSyntheticShare
        self.voiceConfidence = voiceConfidence
        self.voiceProvider = voiceProvider
    }

    /// Builds the record from what the relay reported. Nil when `callID` is not a UUID (the contract says it is;
    /// a call the app cannot key on is skipped rather than stored under a made-up id). A call without a verdict —
    /// one kept only because the caller's voice was judged AI-generated — is stored with neutral verdict fields
    /// (safe, no reasons, no summary): the voice assessment is never turned into a scam verdict.
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
            alerted: summary.alerted || summary.voice?.alert != nil,
            isDemo: isDemo,
            voiceStatusRaw: summary.voice?.status.rawValue,
            voiceSyntheticShare: summary.voice?.syntheticShare,
            voiceConfidence: summary.voice?.confidence,
            voiceProvider: summary.voice?.provider
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
        if let voice = summary.voice {
            apply(voice)
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

    /// Takes a newer AI-voice assessment for this call — from a summary, or on its own from the relay's
    /// `voice.updated`. One that carries the AI-voice warning marks the call alerted. Nothing the verdict decided
    /// (level, category, confidence, reasons, summary) is touched.
    func apply(_ voice: CallVoiceAssessment) {
        voiceStatusRaw = voice.status.rawValue
        voiceSyntheticShare = voice.syntheticShare
        voiceConfidence = voice.confidence
        voiceProvider = voice.provider
        if voice.alert != nil {
            alerted = true
        }
    }

    /// Records that the caller's voice was judged AI-generated when all the app has is the warning push — the
    /// push is proof of the judgement, but carries no share or confidence, so figures that belonged to an earlier
    /// status are dropped rather than shown next to it. A record that already says so is left as it is.
    func markVoiceSynthetic() {
        guard voiceStatus != .synthetic else { return }
        voiceStatusRaw = VoiceStatus.synthetic.rawValue
        voiceSyntheticShare = nil
        voiceConfidence = nil
    }

    var status: CallStatus? { CallStatus(rawValue: statusRaw) }
    var source: CallSource? { CallSource(rawValue: sourceRaw) }
    /// nil when no AI-voice detector ran on the call; `.unknown` for a value this app does not know.
    var voiceStatus: VoiceStatus? { voiceStatusRaw.map { VoiceStatus(rawValue: $0) ?? .unknown } }
    var category: ThreatCategory { ThreatCategory(rawValue: categoryRaw) ?? .safe }
    var level: RiskLevel { RiskLevel(rawValue: levelRaw) ?? .safe }
    var reasons: [Reason] { (try? JSONDecoder().decode([Reason].self, from: reasonsJSON)) ?? [] }

    /// A call listed only because of the caller's voice: judged AI-generated, while the scam check found nothing
    /// or never ran. Its screens show the voice finding where the verdict would be — not a green "Safe" next to
    /// a warning.
    var isVoiceOnly: Bool { voiceStatus == .synthetic && level == .safe }
    /// A voice-only call for which no scam verdict was ever recorded: the AI-voice warning's placeholder, or a
    /// call that ended before anything was scored. (A scored safe verdict always has a summary.)
    var hasNoScamVerdict: Bool { isVoiceOnly && summary.isEmpty && confidence == 0 && reasons.isEmpty }

    static func encodeReasons(_ reasons: [CallReason]) -> Data {
        (try? JSONEncoder().encode(reasons.map(\.reason))) ?? Data("[]".utf8)
    }
}

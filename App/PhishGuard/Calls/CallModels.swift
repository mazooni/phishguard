import Foundation
import PhishCore

// Codable mirrors of `Relay/src/calls/types.ts` (docs/CALLS.md §4, §5). Field names match the relay's JSON
// projections exactly. Decoding is lenient: an unknown enumeration value falls back to the harmless case (an
// unknown level is `.safe`, an unknown category `.safe`), optionals the relay left out decode as nil, and
// numbers are accepted as integers or doubles — the relay is the only producer, and a newer relay must never make
// an older app drop a call. `RiskLevel`, `ThreatCategory`, `Severity` and `ReasonSource` are PhishCore's own
// types: the relay uses the same raw names on purpose.

// MARK: - Enumerations

/// `CallSource`: how a session came to exist.
enum CallSource: String, Codable, Sendable, CaseIterable {
    /// An inbound call to the guard number, forwarded to the protected phone.
    case twilio
    /// An outbound call the relay placed to the protected phone with a scripted, spoken "scammer" (§7.2).
    case testCall = "test-call"
    /// A scripted transcript fed straight into the detector (no audio, no Twilio).
    case demo
    /// A WAV file replayed through the Media Streams handler.
    case replay

    static let fallback = CallSource.twilio

    init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = CallSource(rawValue: raw) ?? .fallback
    }

    var displayName: String {
        switch self {
        case .twilio: return "Incoming call"
        case .testCall: return "Test call"
        case .demo: return "Scripted demo"
        case .replay: return "Recording replay"
        }
    }
}

/// `CallStatus`: the Twilio-derived lifecycle of a session.
enum CallStatus: String, Codable, Sendable, CaseIterable {
    case ringing
    case connecting
    case inProgress = "in_progress"
    case completed
    case failed
    case noAnswer = "no_answer"
    case busy
    case canceled

    /// An unknown status keeps a live card up until the authoritative `call.ended` event arrives.
    static let fallback = CallStatus.inProgress

    init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = CallStatus(rawValue: raw) ?? .fallback
    }

    var isEnded: Bool {
        switch self {
        case .completed, .failed, .noAnswer, .busy, .canceled: return true
        case .ringing, .connecting, .inProgress: return false
        }
    }

    var displayName: String {
        switch self {
        case .ringing: return "Ringing"
        case .connecting: return "Connecting"
        case .inProgress: return "In progress"
        case .completed: return "Completed"
        case .failed: return "Failed"
        case .noAnswer: return "No answer"
        case .busy: return "Busy"
        case .canceled: return "Canceled"
        }
    }
}

/// `Speaker`: which side of the call a transcript line belongs to.
enum Speaker: String, Codable, Sendable, CaseIterable {
    case caller
    case user

    init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = Speaker(rawValue: raw) ?? .caller
    }

    /// The label next to a transcript line.
    var label: String {
        switch self {
        case .caller: return "Caller"
        case .user: return "You"
        }
    }
}

/// `DemoScenarioId`: the scripted calls the relay can run (§5.1 `POST /v1/devices/calls/demo`, `test-call`).
enum DemoScenario: String, Codable, Sendable, CaseIterable, Identifiable {
    case grandparent
    case irs
    case techSupport
    case bankFraud
    case prize
    case benign

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .grandparent: return "Grandchild in trouble"
        case .irs: return "IRS arrest threat"
        case .techSupport: return "Tech support"
        case .bankFraud: return "Bank fraud department"
        case .prize: return "Prize winner"
        case .benign: return "Benign call"
        }
    }
}

// MARK: - Lenient decoding helpers

extension KeyedDecodingContainer {
    func lenientString(_ key: Key) -> String? {
        try? decodeIfPresent(String.self, forKey: key)
    }

    func lenientDouble(_ key: Key) -> Double? {
        if let value = try? decodeIfPresent(Double.self, forKey: key), value.isFinite { return value }
        if let value = try? decodeIfPresent(Int.self, forKey: key) { return Double(value) }
        return nil
    }

    func lenientInt(_ key: Key) -> Int? {
        if let value = try? decodeIfPresent(Int.self, forKey: key) { return value }
        if let value = try? decodeIfPresent(Double.self, forKey: key), value.isFinite, abs(value) < 9e15 { return Int(value) }
        return nil
    }

    func lenientBool(_ key: Key) -> Bool? {
        if let value = try? decodeIfPresent(Bool.self, forKey: key) { return value }
        if let value = try? decodeIfPresent(Int.self, forKey: key) { return value != 0 }
        return nil
    }

    func lenientEnum<E: RawRepresentable>(_ key: Key, default fallback: E) -> E where E.RawValue == String {
        lenientString(key).flatMap(E.init(rawValue:)) ?? fallback
    }

    func lenientOptionalEnum<E: RawRepresentable>(_ key: Key) -> E? where E.RawValue == String {
        lenientString(key).flatMap(E.init(rawValue:))
    }
}

// MARK: - Transcript, reasons, verdict, alert

/// `TranscriptSegment`: one utterance. A partial and its final share the `id`; partials are display-only.
struct TranscriptSegment: Codable, Sendable, Equatable, Identifiable {
    var id: String
    var speaker: Speaker
    var text: String
    /// Offset from the call's `startedAt`, in ms.
    var atMs: Int
    /// `final` in the JSON (a Swift keyword).
    var isFinal: Bool

    enum CodingKeys: String, CodingKey {
        case id, speaker, text, atMs
        case isFinal = "final"
    }

    init(id: String, speaker: Speaker, text: String, atMs: Int, isFinal: Bool) {
        self.id = id
        self.speaker = speaker
        self.text = text
        self.atMs = atMs
        self.isFinal = isFinal
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        speaker = container.lenientEnum(.speaker, default: .caller)
        text = container.lenientString(.text) ?? ""
        atMs = container.lenientInt(.atMs) ?? 0
        isFinal = container.lenientBool(.isFinal) ?? true
    }
}

/// `CallReason`: the same five fields as PhishCore's `Reason`, so a call's reasons render and persist exactly
/// like an email's (`reason`).
struct CallReason: Codable, Sendable, Equatable, Identifiable {
    var id: String
    var title: String
    /// ≤ 300 characters, like `Reason.detail`.
    var detail: String
    var severity: Severity
    var source: ReasonSource

    enum CodingKeys: String, CodingKey { case id, title, detail, severity, source }

    init(id: String, title: String, detail: String, severity: Severity, source: ReasonSource) {
        self.id = id
        self.title = title
        self.detail = String(detail.prefix(300))
        self.severity = severity
        self.source = source
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: container.lenientString(.id) ?? "call.unknown",
            title: container.lenientString(.title) ?? "",
            detail: container.lenientString(.detail) ?? "",
            severity: container.lenientEnum(.severity, default: .info),
            source: container.lenientEnum(.source, default: .heuristic)
        )
    }

    var reason: Reason {
        Reason(id: id, title: title, detail: detail, severity: severity, source: source)
    }
}

/// `CallVerdict`: the fused rules + model verdict for a session, updated as the call goes on.
struct CallVerdict: Codable, Sendable, Equatable {
    /// Monotonically increasing per session; the app ignores stale ones.
    var sequence: Int
    var category: ThreatCategory
    /// 0…1, fused.
    var confidence: Double
    var level: RiskLevel
    /// Ordered by severity desc, ≤ 8.
    var reasons: [CallReason]
    /// ≤ 500 chars, user-facing.
    var summary: String
    /// ≤ 200 chars, imperative, user-facing.
    var recommendedAction: String
    /// 0…1 from the rules.
    var heuristicScore: Double
    /// 0…100 from the model; nil when the model did not answer.
    var modelRiskScore: Double?
    /// `"openai:<model id>"`; nil ⇒ rules only.
    var modelIdentifier: String?
    /// ms since epoch.
    var updatedAt: Int

    enum CodingKeys: String, CodingKey {
        case sequence, category, confidence, level, reasons, summary, recommendedAction, heuristicScore, modelRiskScore, modelIdentifier, updatedAt
    }

    init(
        sequence: Int,
        category: ThreatCategory,
        confidence: Double,
        level: RiskLevel,
        reasons: [CallReason],
        summary: String,
        recommendedAction: String,
        heuristicScore: Double,
        modelRiskScore: Double? = nil,
        modelIdentifier: String? = nil,
        updatedAt: Int
    ) {
        self.sequence = sequence
        self.category = category
        self.confidence = confidence
        self.level = level
        self.reasons = reasons
        self.summary = summary
        self.recommendedAction = recommendedAction
        self.heuristicScore = heuristicScore
        self.modelRiskScore = modelRiskScore
        self.modelIdentifier = modelIdentifier
        self.updatedAt = updatedAt
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sequence = container.lenientInt(.sequence) ?? 0
        category = container.lenientEnum(.category, default: .safe)
        confidence = min(max(container.lenientDouble(.confidence) ?? 0, 0), 1)
        level = container.lenientEnum(.level, default: .safe)
        reasons = (try? container.decodeIfPresent([CallReason].self, forKey: .reasons)) ?? []
        summary = container.lenientString(.summary) ?? ""
        recommendedAction = container.lenientString(.recommendedAction) ?? ""
        heuristicScore = min(max(container.lenientDouble(.heuristicScore) ?? 0, 0), 1)
        modelRiskScore = container.lenientDouble(.modelRiskScore)
        modelIdentifier = container.lenientString(.modelIdentifier)
        updatedAt = container.lenientInt(.updatedAt) ?? 0
    }

    var updatedDate: Date { Date(timeIntervalSince1970: Double(updatedAt) / 1000) }
}

/// `CallAlert`: one warning the relay delivered (push and/or spoken) during a session.
struct CallAlert: Codable, Sendable, Equatable {
    var sequence: Int
    var level: RiskLevel
    var title: String
    var subtitle: String
    var body: String
    /// ms since epoch.
    var sentAt: Int
    var pushed: Bool
    var spoken: Bool

    enum CodingKeys: String, CodingKey { case sequence, level, title, subtitle, body, sentAt, pushed, spoken }

    init(sequence: Int, level: RiskLevel, title: String, subtitle: String, body: String, sentAt: Int, pushed: Bool, spoken: Bool) {
        self.sequence = sequence
        self.level = level
        self.title = title
        self.subtitle = subtitle
        self.body = body
        self.sentAt = sentAt
        self.pushed = pushed
        self.spoken = spoken
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sequence = container.lenientInt(.sequence) ?? 0
        level = container.lenientEnum(.level, default: .safe)
        title = container.lenientString(.title) ?? ""
        subtitle = container.lenientString(.subtitle) ?? ""
        body = container.lenientString(.body) ?? ""
        sentAt = container.lenientInt(.sentAt) ?? 0
        pushed = container.lenientBool(.pushed) ?? false
        spoken = container.lenientBool(.spoken) ?? false
    }

    var sentDate: Date { Date(timeIntervalSince1970: Double(sentAt) / 1000) }
}

// MARK: - Summary, line

/// `CallSummaryJSON`: what the relay tells the app about one call — never a transcript.
struct CallSummary: Codable, Sendable, Equatable, Identifiable {
    var callID: String
    var source: CallSource
    var callerNumber: String
    var calledNumber: String
    /// ms since epoch.
    var startedAt: Int
    var endedAt: Int?
    var durationSeconds: Int?
    var status: CallStatus
    var verdict: CallVerdict?
    var alerted: Bool
    var alertLevel: RiskLevel?

    enum CodingKeys: String, CodingKey {
        case callID, source, callerNumber, calledNumber, startedAt, endedAt, durationSeconds, status, verdict, alerted, alertLevel
    }

    init(
        callID: String,
        source: CallSource,
        callerNumber: String,
        calledNumber: String,
        startedAt: Int,
        endedAt: Int? = nil,
        durationSeconds: Int? = nil,
        status: CallStatus,
        verdict: CallVerdict? = nil,
        alerted: Bool,
        alertLevel: RiskLevel? = nil
    ) {
        self.callID = callID
        self.source = source
        self.callerNumber = callerNumber
        self.calledNumber = calledNumber
        self.startedAt = startedAt
        self.endedAt = endedAt
        self.durationSeconds = durationSeconds
        self.status = status
        self.verdict = verdict
        self.alerted = alerted
        self.alertLevel = alertLevel
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        callID = try container.decode(String.self, forKey: .callID)
        source = container.lenientEnum(.source, default: CallSource.fallback)
        callerNumber = container.lenientString(.callerNumber) ?? ""
        calledNumber = container.lenientString(.calledNumber) ?? ""
        startedAt = container.lenientInt(.startedAt) ?? 0
        endedAt = container.lenientInt(.endedAt)
        durationSeconds = container.lenientInt(.durationSeconds)
        status = container.lenientEnum(.status, default: CallStatus.fallback)
        verdict = try container.decodeIfPresent(CallVerdict.self, forKey: .verdict)
        alerted = container.lenientBool(.alerted) ?? false
        alertLevel = container.lenientOptionalEnum(.alertLevel)
    }

    var id: String { callID }
    var startedDate: Date { Date(timeIntervalSince1970: Double(startedAt) / 1000) }
    var endedDate: Date? { endedAt.map { Date(timeIntervalSince1970: Double($0) / 1000) } }
}

/// `GET /v1/devices/calls/:callID`: the summary plus, while the relay still holds the session in memory, its
/// transcript. The transcript is shown live and then forgotten; nothing in the app persists it.
struct CallDetail: Decodable, Sendable, Equatable {
    var summary: CallSummary
    var transcript: [TranscriptSegment]?

    enum CodingKeys: String, CodingKey { case transcript }

    init(summary: CallSummary, transcript: [TranscriptSegment]? = nil) {
        self.summary = summary
        self.transcript = transcript
    }

    init(from decoder: any Decoder) throws {
        summary = try CallSummary(from: decoder)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        transcript = try container.decodeIfPresent([TranscriptSegment].self, forKey: .transcript)
    }
}

/// `CallLineJSON`: this device's registration — the protected number and the guard number to hand out.
struct CallLine: Codable, Sendable, Equatable {
    var lineID: String
    /// The relay's Twilio number, E.164.
    var guardNumber: String
    /// The protected person's real number, E.164.
    var phoneNumber: String
    var minimumLevel: RiskLevel
    var spokenWarning: Bool
    /// ms since epoch.
    var createdAt: Int

    enum CodingKeys: String, CodingKey { case lineID, guardNumber, phoneNumber, minimumLevel, spokenWarning, createdAt }

    init(lineID: String, guardNumber: String, phoneNumber: String, minimumLevel: RiskLevel, spokenWarning: Bool, createdAt: Int) {
        self.lineID = lineID
        self.guardNumber = guardNumber
        self.phoneNumber = phoneNumber
        self.minimumLevel = minimumLevel
        self.spokenWarning = spokenWarning
        self.createdAt = createdAt
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        lineID = try container.decode(String.self, forKey: .lineID)
        guardNumber = container.lenientString(.guardNumber) ?? ""
        phoneNumber = container.lenientString(.phoneNumber) ?? ""
        minimumLevel = max(container.lenientEnum(.minimumLevel, default: RiskLevel.medium), .low)
        spokenWarning = container.lenientBool(.spokenWarning) ?? true
        createdAt = container.lenientInt(.createdAt) ?? 0
    }
}

// MARK: - Live feed

/// `LiveEvent`: one frame of `GET /v1/devices/calls/live`, decoded on `type`.
enum LiveEvent: Sendable, Equatable {
    case hello(activeCalls: [CallSummary], serverTime: Int)
    case callStarted(CallSummary)
    case callStatus(callID: String, status: CallStatus)
    case transcriptSegment(callID: String, segment: TranscriptSegment)
    case verdictUpdated(callID: String, verdict: CallVerdict)
    case callAlert(callID: String, alert: CallAlert)
    case callEnded(CallSummary)
    case pong

    /// Decodes one text frame. Returns nil for a `type` this app does not know (a newer relay), so the feed keeps
    /// going; throws for malformed JSON or a known type without its payload.
    static func decode(_ data: Data) throws -> LiveEvent? {
        let envelope = try JSONDecoder().decode(Envelope.self, from: data)
        switch envelope.type {
        case "hello":
            return .hello(activeCalls: envelope.activeCalls ?? [], serverTime: envelope.serverTime ?? 0)
        case "call.started":
            guard let call = envelope.call else { throw FrameError.missingPayload("call") }
            return .callStarted(call)
        case "call.status":
            guard let callID = envelope.callID, let status = envelope.status else { throw FrameError.missingPayload("status") }
            return .callStatus(callID: callID, status: status)
        case "transcript.segment":
            guard let callID = envelope.callID, let segment = envelope.segment else { throw FrameError.missingPayload("segment") }
            return .transcriptSegment(callID: callID, segment: segment)
        case "verdict.updated":
            guard let callID = envelope.callID, let verdict = envelope.verdict else { throw FrameError.missingPayload("verdict") }
            return .verdictUpdated(callID: callID, verdict: verdict)
        case "call.alert":
            guard let callID = envelope.callID, let alert = envelope.alert else { throw FrameError.missingPayload("alert") }
            return .callAlert(callID: callID, alert: alert)
        case "call.ended":
            guard let call = envelope.call else { throw FrameError.missingPayload("call") }
            return .callEnded(call)
        case "pong":
            return .pong
        default:
            return nil
        }
    }

    static func decode(_ text: String) throws -> LiveEvent? {
        try decode(Data(text.utf8))
    }

    /// The call an event is about, when it is about one.
    var callID: String? {
        switch self {
        case .hello, .pong: return nil
        case .callStarted(let call), .callEnded(let call): return call.callID
        case .callStatus(let callID, _), .transcriptSegment(let callID, _), .verdictUpdated(let callID, _), .callAlert(let callID, _): return callID
        }
    }

    private struct Envelope: Decodable {
        var type: String
        var activeCalls: [CallSummary]?
        var serverTime: Int?
        var call: CallSummary?
        var callID: String?
        var status: CallStatus?
        var segment: TranscriptSegment?
        var verdict: CallVerdict?
        var alert: CallAlert?

        enum CodingKeys: String, CodingKey { case type, activeCalls, serverTime, call, callID, status, segment, verdict, alert }

        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            type = try container.decode(String.self, forKey: .type)
            activeCalls = try container.decodeIfPresent([CallSummary].self, forKey: .activeCalls)
            serverTime = container.lenientInt(.serverTime)
            call = try container.decodeIfPresent(CallSummary.self, forKey: .call)
            callID = container.lenientString(.callID)
            status = container.lenientOptionalEnum(.status)
            segment = try container.decodeIfPresent(TranscriptSegment.self, forKey: .segment)
            verdict = try container.decodeIfPresent(CallVerdict.self, forKey: .verdict)
            alert = try container.decodeIfPresent(CallAlert.self, forKey: .alert)
        }
    }

    /// A known event type whose payload is missing.
    enum FrameError: Error, Equatable {
        case missingPayload(String)
    }
}

// MARK: - APNs alert push (§5.4)

/// The custom keys of the relay's call alert push, next to `aps`: `kind == "call-alert"` plus the call's identity
/// and the level that triggered the alert. Values are untrusted input; nothing here is logged with call content.
struct CallAlertPushPayload: Sendable, Equatable {
    static let kindKey = "kind"
    static let kind = "call-alert"
    static let callIDKey = "callID"

    var callID: String
    var level: RiskLevel
    var confidence: Double?
    var category: ThreatCategory?
    var callerNumber: String?
    var startedAt: Date?
    var sequence: Int?
    /// `aps.alert.body` — the banner's text, kept for a placeholder record when the relay cannot be reached.
    var alertBody: String?

    /// True when this remote notification is a call alert, whatever else it carries. `AppDelegate` branches on
    /// this **before** the mail silent-push path: a call alert (which also has `content-available`) must never
    /// start a mail scan.
    static func isCallAlert(_ userInfo: [AnyHashable: Any]) -> Bool {
        (userInfo[kindKey] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) == kind
    }

    /// Parses `userInfo`; nil unless `kind == "call-alert"` and a non-empty `callID` is present.
    static func parse(_ userInfo: [AnyHashable: Any]) -> CallAlertPushPayload? {
        guard isCallAlert(userInfo) else { return nil }
        guard let callID = (userInfo[callIDKey] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !callID.isEmpty else {
            return nil
        }
        // A push means the relay alerted, so an unreadable level is read as the default alert level, never as safe.
        let level = (userInfo["level"] as? String).flatMap(RiskLevel.init(rawValue:)).map { max($0, .low) } ?? .medium
        let confidence = (userInfo["confidence"] as? NSNumber)?.doubleValue
        let category = (userInfo["category"] as? String).flatMap(ThreatCategory.init(rawValue:))
        let callerNumber = (userInfo["callerNumber"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let startedAt = (userInfo["startedAt"] as? NSNumber).map { Date(timeIntervalSince1970: $0.doubleValue / 1000) }
        let sequence = (userInfo["sequence"] as? NSNumber)?.intValue
        var alertBody: String?
        if let aps = userInfo["aps"] as? [AnyHashable: Any] {
            if let alert = aps["alert"] as? [AnyHashable: Any] {
                alertBody = alert["body"] as? String
            } else if let text = aps["alert"] as? String {
                alertBody = text
            }
        }
        return CallAlertPushPayload(
            callID: callID,
            level: level,
            confidence: confidence.map { min(max($0, 0), 1) },
            category: category,
            callerNumber: callerNumber.flatMap { $0.isEmpty ? nil : $0 },
            startedAt: startedAt,
            sequence: sequence,
            alertBody: alertBody
        )
    }
}

// MARK: - Alert text (§5.4) and phone numbers

/// The title / subtitle / body rules of the call alert, shared by the relay's push and the app's local
/// notification so a simulated alert reads exactly like a real one.
struct CallAlertText: Sendable, Equatable {
    static let maxBodyLength = 160
    static let separator = " · "
    static let fallbackBody = "This call shows signs of a scam."

    var title: String
    var subtitle: String
    var body: String

    /// *Suspicious call* for low, *Possible scam call* for medium, *Likely scam call* for high.
    static func title(for level: RiskLevel) -> String {
        switch level {
        case .high: return "Likely scam call"
        case .medium: return "Possible scam call"
        case .low, .safe: return "Suspicious call"
        }
    }

    static func make(level: RiskLevel, callerNumber: String, reasons: [CallReason], summary: String = "") -> CallAlertText {
        make(level: level, callerNumber: callerNumber, reasonTitles: reasons.map(\.title), summary: summary)
    }

    static func make(level: RiskLevel, callerNumber: String, reasonTitles: [String], summary: String = "") -> CallAlertText {
        let number = callerNumber.trimmingCharacters(in: .whitespacesAndNewlines)
        let subtitle = number.isEmpty ? "Call from an unknown number" : "Call from \(PhoneNumberFormat.display(number))"
        return CallAlertText(title: title(for: level), subtitle: subtitle, body: body(reasonTitles: reasonTitles, summary: summary))
    }

    /// The top reasons' titles joined by ` · `, as many as fit in 160 characters. When not even the first title fits:
    /// the verdict's summary, else that first title, else a fixed sentence — each cut to 160 characters with an
    /// ellipsis. This is the relay's `alertBody` (`Relay/src/calls/alerts/text.ts`) step for step.
    static func body(reasonTitles: [String], summary: String = "") -> String {
        let titles = reasonTitles.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        var body = ""
        for title in titles {
            let candidate = body.isEmpty ? title : body + separator + title
            guard candidate.count <= maxBodyLength else { break }
            body = candidate
        }
        if !body.isEmpty { return body }
        let trimmedSummary = summary.trimmingCharacters(in: .whitespacesAndNewlines)
        let fallback = trimmedSummary.isEmpty ? (titles.first ?? fallbackBody) : trimmedSummary
        return truncate(fallback, to: maxBodyLength)
    }

    /// The relay's `truncate`: at most `max` characters, the last one an ellipsis when something was cut.
    static func truncate(_ text: String, to max: Int) -> String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count > max else { return trimmed }
        return String(trimmed.prefix(max - 1)).trimmingCharacters(in: .whitespaces) + "…"
    }
}

/// E.164 handling for the setup form and for display.
enum PhoneNumberFormat {
    /// `+` then 8–15 digits, first digit 1–9 (the relay's `E164_PATTERN`).
    static func isE164(_ value: String) -> Bool {
        guard value.hasPrefix("+") else { return false }
        let digits = value.dropFirst()
        guard (8...15).contains(digits.count), digits.allSatisfy(\.isNumber), let first = digits.first, first != "0" else { return false }
        return digits.allSatisfy { $0.isASCII }
    }

    /// Turns what someone typed into E.164, or nil. Spaces, dashes, dots and parentheses are ignored; `00…`
    /// becomes `+…`; a bare 10-digit number is read as North American (`+1…`), an 11-digit one starting with 1 too.
    static func normalize(_ input: String) -> String? {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let hasPlus = trimmed.hasPrefix("+")
        var digits = trimmed.filter(\.isNumber).filter(\.isASCII)
        guard !digits.isEmpty else { return nil }
        if !hasPlus {
            if digits.hasPrefix("00") {
                digits = String(digits.dropFirst(2))
            } else if digits.count == 10 {
                digits = "1" + digits
            } else if digits.count == 11, digits.hasPrefix("1") {
                // already "1" + 10 digits
            } else {
                return nil
            }
        }
        let candidate = "+" + digits
        return isE164(candidate) ? candidate : nil
    }

    /// `+14155550134` → `+1 (415) 555-0134`; anything that is not a North American number is shown as given.
    static func display(_ e164: String) -> String {
        let trimmed = e164.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("+1") else { return trimmed }
        let digits = trimmed.dropFirst(2)
        guard digits.count == 10, digits.allSatisfy(\.isNumber) else { return trimmed }
        let area = digits.prefix(3)
        let exchange = digits.dropFirst(3).prefix(3)
        let line = digits.suffix(4)
        return "+1 (\(area)) \(exchange)-\(line)"
    }
}

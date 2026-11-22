import Foundation
import PhishCore
import XCTest
@testable import PhishGuard

/// JSON exactly as `Relay/src/calls/types.ts` projects it (docs/CALLS.md §4, §5.4), shared by the Call Guard tests.
enum CallFixtures {
    static let callID = "8f1c2f3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f"
    static let secondCallID = "0a1b2c3d-1111-4222-8333-444455556666"

    static let verdictJSON = """
    {
      "sequence": 3,
      "category": "scam",
      "confidence": 0.92,
      "level": "high",
      "reasons": [
        {"id": "call.gift_cards", "title": "Asks for gift cards", "detail": "Caller: \\"go buy four $500 cards\\"", "severity": "high", "source": "heuristic"},
        {"id": "call.family_emergency", "title": "Claims to be a grandchild in trouble", "detail": "Caller: \\"Grandma, it's me\\"", "severity": "high", "source": "heuristic"},
        {"id": "model.secrecy", "title": "Says not to tell anyone", "detail": "The caller asked the person to keep the call secret.", "severity": "medium", "source": "model"}
      ],
      "summary": "The caller claims to be a grandchild in trouble and asks for gift cards.",
      "recommendedAction": "Hang up and call your grandchild on a number you already have.",
      "heuristicScore": 0.81,
      "modelRiskScore": 92,
      "modelIdentifier": "openai:gpt-4.1-mini",
      "updatedAt": 1758600120000
    }
    """

    /// `voice` is a `CallVoiceAssessment` object as JSON text; nil leaves the key out, as the relay does on every
    /// call no AI-voice detector ran on.
    static func summaryJSON(callID: String = CallFixtures.callID, status: String = "completed", alerted: Bool = true, withVerdict: Bool = true, voice: String? = nil) -> String {
        """
        {
          "callID": "\(callID)",
          "source": "twilio",
          "callerNumber": "+14155550134",
          "calledNumber": "+16285550199",
          "startedAt": 1758600000000,
          "endedAt": 1758600254000,
          "durationSeconds": 254,
          "status": "\(status)",
          \(withVerdict ? "\"verdict\": \(verdictJSON)," : "")
          \(voice.map { "\"voice\": \($0)," } ?? "")
          "alerted": \(alerted),
          "alertLevel": "high"
        }
        """
    }

    static let lineJSON = """
    {"lineID": "line-42", "guardNumber": "+16285550199", "phoneNumber": "+14155550100", "minimumLevel": "medium", "spokenWarning": true, "createdAt": 1758500000000}
    """

    static let segmentJSON = """
    {"id": "seg-7", "speaker": "caller", "text": "go buy four gift cards", "atMs": 42000, "final": false}
    """

    static let alertJSON = """
    {"sequence": 3, "level": "high", "title": "Likely scam call", "subtitle": "Call from +1 (415) 555-0134", "body": "Asks for gift cards · Claims to be a grandchild in trouble", "sentAt": 1758600121000, "pushed": true, "spoken": false}
    """

    /// `CallVoiceAssessment` once the caller's voice was judged AI-generated and the warning went out.
    static let voiceJSON = """
    {
      "status": "synthetic",
      "syntheticShare": 0.87,
      "confidence": 0.93,
      "speechMs": 6200,
      "provider": "modulate:velma-2-synthetic-voice-detection-streaming",
      "detectedAt": 1758600030000,
      "alert": {"title": "AI voice detected", "subtitle": "Call from +1 (415) 555-0134", "body": "The caller's voice appears to be AI-generated. If they say they are someone you know, hang up and call them back on a number you trust.", "sentAt": 1758600031000, "pushed": true, "spoken": true},
      "updatedAt": 1758600031000
    }
    """

    /// The relay's fixed body for the AI-voice warning (`VOICE_ALERT_BODY` in Relay/src/calls/alerts/text.ts).
    static let voiceAlertBody = "The caller's voice appears to be AI-generated. If they say they are someone you know, hang up and call them back on a number you trust."

    /// The AI-voice warning push as the relay builds it (Relay/src/calls/alerts/voiceDispatcher.ts): its own
    /// `kind`, `voice: "synthetic"`, and next to them the usual keys. `level` mirrors the scam verdict at that
    /// moment ("low" without one, never "safe") and `confidence` is the voice detector's; the app never reads a
    /// scam level or confidence out of this push.
    static func voicePushUserInfo(callID: String = CallFixtures.callID, level: String = "low") -> [AnyHashable: Any] {
        [
            "aps": [
                "alert": ["title": "AI voice detected", "subtitle": "Call from +1 (415) 555-0134", "body": voiceAlertBody],
                "sound": "default", "interruption-level": "time-sensitive", "relevance-score": 1,
                "thread-id": "com.mazooni.PhishGuard.calls", "category": "PHISHGUARD_CALL_ALERT", "content-available": 1,
            ],
            "kind": "call-voice-alert", "callID": callID, "level": level, "confidence": 0.93, "category": "safe",
            "callerNumber": "+14155550134", "startedAt": 1758600000000, "sequence": 0, "voice": "synthetic",
        ]
    }

    /// The §5.4 push, as `userInfo` hands it to the app.
    static func pushUserInfo(callID: String = CallFixtures.callID, level: String = "high") -> [AnyHashable: Any] {
        [
            "aps": [
                "alert": ["title": "Likely scam call", "subtitle": "Call from +1 (415) 555-0134", "body": "Asks for gift cards · Says not to tell anyone"],
                "sound": "default", "interruption-level": "time-sensitive", "relevance-score": 1,
                "thread-id": "com.mazooni.PhishGuard.calls", "category": "PHISHGUARD_CALL_ALERT", "content-available": 1,
            ],
            "kind": "call-alert", "callID": callID, "level": level, "confidence": 0.92, "category": "scam",
            "callerNumber": "+14155550134", "startedAt": 1758600000000, "sequence": 3,
        ]
    }

    static func data(_ json: String) -> Data { Data(json.utf8) }
}

final class CallModelsTests: XCTestCase {
    private let decoder = JSONDecoder()

    // MARK: - Summary / verdict / line

    func testCallSummaryFixtureDecodesEveryField() throws {
        let summary = try decoder.decode(CallSummary.self, from: CallFixtures.data(CallFixtures.summaryJSON()))

        XCTAssertEqual(summary.callID, CallFixtures.callID)
        XCTAssertEqual(summary.id, CallFixtures.callID)
        XCTAssertEqual(summary.source, .twilio)
        XCTAssertEqual(summary.callerNumber, "+14155550134")
        XCTAssertEqual(summary.calledNumber, "+16285550199")
        XCTAssertEqual(summary.startedAt, 1_758_600_000_000)
        XCTAssertEqual(summary.startedDate, Date(timeIntervalSince1970: 1_758_600_000))
        XCTAssertEqual(summary.endedDate, Date(timeIntervalSince1970: 1_758_600_254))
        XCTAssertEqual(summary.durationSeconds, 254)
        XCTAssertEqual(summary.status, .completed)
        XCTAssertTrue(summary.alerted)
        XCTAssertEqual(summary.alertLevel, .high)

        let verdict = try XCTUnwrap(summary.verdict)
        XCTAssertEqual(verdict.sequence, 3)
        XCTAssertEqual(verdict.category, .scam)
        XCTAssertEqual(verdict.confidence, 0.92, accuracy: 0.0001)
        XCTAssertEqual(verdict.level, .high)
        XCTAssertEqual(verdict.reasons.map(\.id), ["call.gift_cards", "call.family_emergency", "model.secrecy"])
        XCTAssertEqual(verdict.reasons.map(\.severity), [.high, .high, .medium])
        XCTAssertEqual(verdict.reasons.map(\.source), [.heuristic, .heuristic, .model])
        XCTAssertEqual(verdict.reasons[0].detail, "Caller: \"go buy four $500 cards\"")
        XCTAssertEqual(verdict.summary, "The caller claims to be a grandchild in trouble and asks for gift cards.")
        XCTAssertEqual(verdict.recommendedAction, "Hang up and call your grandchild on a number you already have.")
        XCTAssertEqual(verdict.heuristicScore, 0.81, accuracy: 0.0001)
        XCTAssertEqual(verdict.modelRiskScore, 92)
        XCTAssertEqual(verdict.modelIdentifier, "openai:gpt-4.1-mini")
        XCTAssertEqual(verdict.updatedDate, Date(timeIntervalSince1970: 1_758_600_120))
    }

    func testCallSummaryDecodesLenientlyWithUnknownValuesAndMissingOptionals() throws {
        let json = """
        {"callID": "\(CallFixtures.callID)", "source": "voip", "callerNumber": "+14155550134", "calledNumber": "+16285550199",
         "startedAt": 1758600000000.0, "status": "on_hold",
         "verdict": {"sequence": 1, "category": "fraud", "confidence": 2, "level": "extreme", "summary": "x", "recommendedAction": "y", "heuristicScore": -1, "updatedAt": 1}}
        """
        let summary = try decoder.decode(CallSummary.self, from: CallFixtures.data(json))

        XCTAssertEqual(summary.source, .twilio, "an unknown source is read as a real call")
        XCTAssertEqual(summary.status, .inProgress, "an unknown status keeps the live card up until call.ended")
        XCTAssertEqual(summary.startedAt, 1_758_600_000_000, "a float timestamp is accepted")
        XCTAssertNil(summary.endedAt)
        XCTAssertNil(summary.durationSeconds)
        XCTAssertFalse(summary.alerted, "a missing alerted flag is false")
        XCTAssertNil(summary.alertLevel)
        let verdict = try XCTUnwrap(summary.verdict)
        XCTAssertEqual(verdict.level, .safe, "an unknown level is safe")
        XCTAssertEqual(verdict.category, .safe, "an unknown category is safe")
        XCTAssertEqual(verdict.confidence, 1, "clamped to 0…1")
        XCTAssertEqual(verdict.heuristicScore, 0, "clamped to 0…1")
        XCTAssertEqual(verdict.reasons, [], "missing reasons are an empty list")
        XCTAssertNil(verdict.modelRiskScore)
        XCTAssertNil(verdict.modelIdentifier)

        let noVerdict = try decoder.decode(CallSummary.self, from: CallFixtures.data(CallFixtures.summaryJSON(withVerdict: false)))
        XCTAssertNil(noVerdict.verdict)
    }

    func testCallSummaryWithoutACallIDFailsToDecode() {
        XCTAssertThrowsError(try decoder.decode(CallSummary.self, from: CallFixtures.data(#"{"source": "twilio", "status": "ringing"}"#)))
    }

    func testCallReasonDecodesLenientlyAndConvertsToAReason() throws {
        let json = #"{"id": "call.urgency", "title": "Demands action now", "detail": "\#(String(repeating: "x", count: 400))", "severity": "critical", "source": "oracle"}"#
        let reason = try decoder.decode(CallReason.self, from: CallFixtures.data(json))
        XCTAssertEqual(reason.severity, .info, "an unknown severity is info")
        XCTAssertEqual(reason.source, .heuristic, "an unknown source is heuristic")
        XCTAssertEqual(reason.detail.count, 300, "details are capped like PhishCore.Reason")
        let converted = reason.reason
        XCTAssertEqual(converted.id, "call.urgency")
        XCTAssertEqual(converted.title, "Demands action now")
        XCTAssertEqual(converted.severity, .info)
        XCTAssertEqual(converted.source, .heuristic)
    }

    func testTranscriptSegmentUsesTheFinalKey() throws {
        let segment = try decoder.decode(TranscriptSegment.self, from: CallFixtures.data(CallFixtures.segmentJSON))
        XCTAssertEqual(segment.id, "seg-7")
        XCTAssertEqual(segment.speaker, .caller)
        XCTAssertEqual(segment.text, "go buy four gift cards")
        XCTAssertEqual(segment.atMs, 42_000)
        XCTAssertFalse(segment.isFinal)

        let encoded = try JSONEncoder().encode(segment)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        XCTAssertEqual(object["final"] as? Bool, false, "encodes back to the relay's key")
        XCTAssertNil(object["isFinal"])

        let user = try decoder.decode(TranscriptSegment.self, from: CallFixtures.data(#"{"id": "s", "speaker": "user", "text": "hello"}"#))
        XCTAssertEqual(user.speaker, .user)
        XCTAssertTrue(user.isFinal, "a segment without the flag is treated as final")
        XCTAssertEqual(user.atMs, 0)
        XCTAssertEqual(Speaker.caller.label, "Caller")
        XCTAssertEqual(Speaker.user.label, "You")
    }

    func testCallLineDecodesAndNeverReportsSafe() throws {
        let line = try decoder.decode(CallLine.self, from: CallFixtures.data(CallFixtures.lineJSON))
        XCTAssertEqual(line.lineID, "line-42")
        XCTAssertEqual(line.guardNumber, "+16285550199")
        XCTAssertEqual(line.phoneNumber, "+14155550100")
        XCTAssertEqual(line.minimumLevel, .medium)
        XCTAssertTrue(line.spokenWarning)
        XCTAssertEqual(line.createdAt, 1_758_500_000_000)

        let odd = try decoder.decode(CallLine.self, from: CallFixtures.data(#"{"lineID": "l", "minimumLevel": "safe", "spokenWarning": false}"#))
        XCTAssertEqual(odd.minimumLevel, .low)
        XCTAssertFalse(odd.spokenWarning)
        XCTAssertThrowsError(try decoder.decode(CallLine.self, from: CallFixtures.data(#"{"guardNumber": "+1"}"#)))
    }

    func testCallDetailCarriesTheTranscriptNextToTheSummary() throws {
        let json = """
        {"callID": "\(CallFixtures.callID)", "source": "demo", "callerNumber": "+14155550134", "calledNumber": "+16285550199",
         "startedAt": 1, "status": "in_progress", "alerted": false,
         "transcript": [\(CallFixtures.segmentJSON), {"id": "seg-8", "speaker": "user", "text": "who is this?", "atMs": 45000, "final": true}]}
        """
        let detail = try decoder.decode(CallDetail.self, from: CallFixtures.data(json))
        XCTAssertEqual(detail.summary.callID, CallFixtures.callID)
        XCTAssertEqual(detail.summary.source, .demo)
        XCTAssertEqual(detail.transcript?.map(\.id), ["seg-7", "seg-8"])

        let bare = try decoder.decode(CallDetail.self, from: CallFixtures.data(CallFixtures.summaryJSON()))
        XCTAssertNil(bare.transcript, "an ended call the relay no longer holds has no transcript")
    }

    func testStatusAndSourceHelpers() {
        XCTAssertTrue(CallStatus.completed.isEnded)
        XCTAssertTrue(CallStatus.noAnswer.isEnded)
        XCTAssertTrue(CallStatus.canceled.isEnded)
        XCTAssertFalse(CallStatus.ringing.isEnded)
        XCTAssertFalse(CallStatus.inProgress.isEnded)
        XCTAssertEqual(CallStatus.inProgress.rawValue, "in_progress")
        XCTAssertEqual(CallStatus.noAnswer.rawValue, "no_answer")
        XCTAssertEqual(CallSource.testCall.rawValue, "test-call")
        XCTAssertEqual(CallSource.allCases.map(\.rawValue), ["twilio", "test-call", "demo", "replay"])
        XCTAssertEqual(DemoScenario.allCases.map(\.rawValue), ["grandparent", "irs", "techSupport", "bankFraud", "prize", "benign"], "the relay's DemoScenarioId list")
        for scenario in DemoScenario.allCases {
            XCTAssertFalse(scenario.displayName.isEmpty)
        }
    }

    // MARK: - Live events

    func testLiveEventDecodesEveryVariant() throws {
        let hello = try XCTUnwrap(LiveEvent.decode(#"{"type": "hello", "activeCalls": [\#(CallFixtures.summaryJSON(status: "in_progress"))], "serverTime": 1758600001000}"#))
        guard case .hello(let activeCalls, let serverTime) = hello else { return XCTFail("expected hello, got \(hello)") }
        XCTAssertEqual(activeCalls.map(\.callID), [CallFixtures.callID])
        XCTAssertEqual(activeCalls.first?.status, .inProgress)
        XCTAssertEqual(serverTime, 1_758_600_001_000)

        let started = try XCTUnwrap(LiveEvent.decode(#"{"type": "call.started", "call": \#(CallFixtures.summaryJSON(status: "ringing", alerted: false, withVerdict: false))}"#))
        guard case .callStarted(let call) = started else { return XCTFail("expected call.started") }
        XCTAssertEqual(call.status, .ringing)
        XCTAssertNil(call.verdict)
        XCTAssertEqual(started.callID, CallFixtures.callID)

        let status = try XCTUnwrap(LiveEvent.decode(#"{"type": "call.status", "callID": "\#(CallFixtures.callID)", "status": "in_progress"}"#))
        XCTAssertEqual(status, .callStatus(callID: CallFixtures.callID, status: .inProgress))

        let segment = try XCTUnwrap(LiveEvent.decode(#"{"type": "transcript.segment", "callID": "\#(CallFixtures.callID)", "segment": \#(CallFixtures.segmentJSON)}"#))
        guard case .transcriptSegment(let segmentCallID, let decodedSegment) = segment else { return XCTFail("expected transcript.segment") }
        XCTAssertEqual(segmentCallID, CallFixtures.callID)
        XCTAssertEqual(decodedSegment.id, "seg-7")

        let verdict = try XCTUnwrap(LiveEvent.decode(#"{"type": "verdict.updated", "callID": "\#(CallFixtures.callID)", "verdict": \#(CallFixtures.verdictJSON)}"#))
        guard case .verdictUpdated(_, let decodedVerdict) = verdict else { return XCTFail("expected verdict.updated") }
        XCTAssertEqual(decodedVerdict.sequence, 3)
        XCTAssertEqual(decodedVerdict.level, .high)

        let alert = try XCTUnwrap(LiveEvent.decode(#"{"type": "call.alert", "callID": "\#(CallFixtures.callID)", "alert": \#(CallFixtures.alertJSON)}"#))
        guard case .callAlert(_, let decodedAlert) = alert else { return XCTFail("expected call.alert") }
        XCTAssertEqual(decodedAlert.level, .high)
        XCTAssertEqual(decodedAlert.title, "Likely scam call")
        XCTAssertTrue(decodedAlert.pushed)
        XCTAssertFalse(decodedAlert.spoken)
        XCTAssertEqual(decodedAlert.sentDate, Date(timeIntervalSince1970: 1_758_600_121))

        let ended = try XCTUnwrap(LiveEvent.decode(#"{"type": "call.ended", "call": \#(CallFixtures.summaryJSON())}"#))
        guard case .callEnded(let endedCall) = ended else { return XCTFail("expected call.ended") }
        XCTAssertEqual(endedCall.status, .completed)
        XCTAssertEqual(endedCall.durationSeconds, 254)

        XCTAssertEqual(try LiveEvent.decode(#"{"type": "pong"}"#), .pong)
        XCTAssertNil(LiveEvent.pong.callID)
    }

    func testLiveEventIgnoresUnknownTypesAndRejectsBrokenFrames() throws {
        XCTAssertNil(try LiveEvent.decode(#"{"type": "call.recording", "callID": "x"}"#), "a newer relay's event is skipped, not fatal")
        XCTAssertThrowsError(try LiveEvent.decode("not json"))
        XCTAssertThrowsError(try LiveEvent.decode(#"{"callID": "x"}"#), "no type")
        XCTAssertThrowsError(try LiveEvent.decode(#"{"type": "call.started"}"#), "a known type without its payload")
        XCTAssertThrowsError(try LiveEvent.decode(#"{"type": "verdict.updated", "callID": "x"}"#))
        XCTAssertThrowsError(try LiveEvent.decode(#"{"type": "transcript.segment", "segment": \#(CallFixtures.segmentJSON)}"#), "no callID")
    }

    // MARK: - Alert text (§5.4)

    func testAlertTitlesFollowTheLevel() {
        XCTAssertEqual(CallAlertText.title(for: .high), "Likely scam call")
        XCTAssertEqual(CallAlertText.title(for: .medium), "Possible scam call")
        XCTAssertEqual(CallAlertText.title(for: .low), "Suspicious call")
        XCTAssertEqual(CallAlertText.title(for: .safe), "Suspicious call")
    }

    func testAlertTextSubtitleAndBody() {
        let text = CallAlertText.make(level: .high, callerNumber: "+14155550134", reasonTitles: ["Asks for gift cards", "Claims to be a grandchild in trouble", "Says not to tell anyone"])
        XCTAssertEqual(text.title, "Likely scam call")
        XCTAssertEqual(text.subtitle, "Call from +1 (415) 555-0134")
        XCTAssertEqual(text.body, "Asks for gift cards · Claims to be a grandchild in trouble · Says not to tell anyone")

        let reasons = [CallReason(id: "a", title: "One", detail: "", severity: .high, source: .heuristic), CallReason(id: "b", title: " Two ", detail: "", severity: .low, source: .model)]
        XCTAssertEqual(CallAlertText.make(level: .medium, callerNumber: "+442071234567", reasons: reasons).body, "One · Two")
        XCTAssertEqual(CallAlertText.make(level: .medium, callerNumber: "+442071234567", reasons: reasons).subtitle, "Call from +442071234567")
        XCTAssertEqual(CallAlertText.make(level: .low, callerNumber: "  ", reasonTitles: []).subtitle, "Call from an unknown number")
        XCTAssertEqual(CallAlertText.make(level: .low, callerNumber: "+1", reasonTitles: []).body, CallAlertText.fallbackBody)
    }

    func testAlertBodyStaysUnder160Characters() {
        let titles = (1...12).map { "Reason number \($0) with some padding text" }
        let body = CallAlertText.body(reasonTitles: titles)
        XCTAssertLessThanOrEqual(body.count, CallAlertText.maxBodyLength)
        XCTAssertTrue(body.hasPrefix("Reason number 1 with some padding text · Reason number 2"))
        XCTAssertFalse(body.hasSuffix(CallAlertText.separator), "no dangling separator")

        let huge = CallAlertText.body(reasonTitles: [String(repeating: "a", count: 300)])
        XCTAssertEqual(huge.count, CallAlertText.maxBodyLength)
        XCTAssertTrue(huge.hasSuffix("…"))
        XCTAssertEqual(CallAlertText.body(reasonTitles: ["", "   "]), CallAlertText.fallbackBody)
    }

    /// The relay's `alertBody` (`Relay/src/calls/alerts/text.ts`): titles that fit, else the summary, else the first
    /// title, else the fixed sentence — so the in-app demo's local notification reads like the push would.
    func testAlertBodyFallsBackToTheSummaryLikeTheRelay() {
        let oversized = String(repeating: "X", count: 200)
        XCTAssertEqual(CallAlertText.body(reasonTitles: [oversized], summary: "The caller pretends to be a grandchild."), "The caller pretends to be a grandchild.")
        XCTAssertEqual(CallAlertText.body(reasonTitles: [], summary: "  Short summary. "), "Short summary.")
        XCTAssertEqual(CallAlertText.body(reasonTitles: ["Asks for gift cards"], summary: "Ignored while a title fits"), "Asks for gift cards")
        XCTAssertEqual(CallAlertText.body(reasonTitles: [], summary: "   "), CallAlertText.fallbackBody)

        let cut = CallAlertText.body(reasonTitles: [oversized], summary: String(repeating: "Y", count: 300))
        XCTAssertEqual(cut.count, CallAlertText.maxBodyLength)
        XCTAssertTrue(cut.hasPrefix("Y") && cut.hasSuffix("…"))

        let titleCut = CallAlertText.body(reasonTitles: [oversized], summary: "")
        XCTAssertEqual(titleCut, String(repeating: "X", count: CallAlertText.maxBodyLength - 1) + "…")
        XCTAssertEqual(CallAlertText.make(level: .high, callerNumber: "+14155550134", reasonTitles: [oversized], summary: "Summary wins.").body, "Summary wins.")
    }

    // MARK: - Phone numbers

    func testPhoneNumberDisplay() {
        XCTAssertEqual(PhoneNumberFormat.display("+14155550134"), "+1 (415) 555-0134")
        XCTAssertEqual(PhoneNumberFormat.display(" +12025550188 "), "+1 (202) 555-0188")
        XCTAssertEqual(PhoneNumberFormat.display("+442071234567"), "+442071234567", "non-NANP numbers are shown raw")
        XCTAssertEqual(PhoneNumberFormat.display("+1415555"), "+1415555", "a short +1 number is not NANP")
        XCTAssertEqual(PhoneNumberFormat.display("anonymous"), "anonymous")
    }

    func testPhoneNumberValidationAndNormalisation() {
        XCTAssertTrue(PhoneNumberFormat.isE164("+14155550134"))
        XCTAssertTrue(PhoneNumberFormat.isE164("+442071234567"))
        XCTAssertFalse(PhoneNumberFormat.isE164("14155550134"), "no plus")
        XCTAssertFalse(PhoneNumberFormat.isE164("+0415555"), "leading zero")
        XCTAssertFalse(PhoneNumberFormat.isE164("+1234567"), "too short")
        XCTAssertFalse(PhoneNumberFormat.isE164("+1234567890123456"), "too long")
        XCTAssertFalse(PhoneNumberFormat.isE164("+1 415 555 0134"), "spaces are not E.164")

        XCTAssertEqual(PhoneNumberFormat.normalize("+1 (415) 555-0134"), "+14155550134")
        XCTAssertEqual(PhoneNumberFormat.normalize("415.555.0134"), "+14155550134", "a bare 10-digit number is North American")
        XCTAssertEqual(PhoneNumberFormat.normalize("1 415 555 0134"), "+14155550134")
        XCTAssertEqual(PhoneNumberFormat.normalize("00 44 20 7123 4567"), "+442071234567")
        XCTAssertEqual(PhoneNumberFormat.normalize("+44 20 7123 4567"), "+442071234567")
        XCTAssertNil(PhoneNumberFormat.normalize(""))
        XCTAssertNil(PhoneNumberFormat.normalize("555-0134"), "too short to guess a country")
        XCTAssertNil(PhoneNumberFormat.normalize("+0 415 555 0134"))
        XCTAssertNil(PhoneNumberFormat.normalize("call me"))
    }

    // MARK: - Push payload (§5.4)

    func testCallAlertPushPayloadParses() throws {
        let payload = try XCTUnwrap(CallAlertPushPayload.parse(CallFixtures.pushUserInfo()))
        XCTAssertEqual(payload.callID, CallFixtures.callID)
        XCTAssertEqual(payload.level, .high)
        XCTAssertEqual(try XCTUnwrap(payload.confidence), 0.92, accuracy: 0.0001)
        XCTAssertEqual(payload.category, .scam)
        XCTAssertEqual(payload.callerNumber, "+14155550134")
        XCTAssertEqual(payload.startedAt, Date(timeIntervalSince1970: 1_758_600_000))
        XCTAssertEqual(payload.sequence, 3)
        XCTAssertEqual(payload.alertBody, "Asks for gift cards · Says not to tell anyone")
        XCTAssertTrue(CallAlertPushPayload.isCallAlert(CallFixtures.pushUserInfo()))
    }

    func testCallAlertPushPayloadIsLenientAboutEverythingButTheCallID() throws {
        let minimal = try XCTUnwrap(CallAlertPushPayload.parse(["kind": "call-alert", "callID": " \(CallFixtures.callID) ", "level": "bogus"]))
        XCTAssertEqual(minimal.callID, CallFixtures.callID, "trimmed")
        XCTAssertEqual(minimal.level, .medium, "an unreadable level on an alert is the default alert level, never safe")
        XCTAssertNil(minimal.confidence)
        XCTAssertNil(minimal.category)
        XCTAssertNil(minimal.callerNumber)
        XCTAssertNil(minimal.startedAt)
        XCTAssertNil(minimal.sequence)
        XCTAssertNil(minimal.alertBody)

        let safeLevel = try XCTUnwrap(CallAlertPushPayload.parse(["kind": "call-alert", "callID": "x", "level": "safe", "aps": ["alert": "plain body"]]))
        XCTAssertEqual(safeLevel.level, .low)
        XCTAssertEqual(safeLevel.alertBody, "plain body")
    }

    func testCallAlertPushPayloadRejectsNonCallPayloads() {
        XCTAssertNil(CallAlertPushPayload.parse(["aps": ["content-available": 1], "provider": "gmail", "accountKey": "abc"]), "the mail doorbell")
        XCTAssertNil(CallAlertPushPayload.parse(["kind": "call-alert"]), "no callID")
        XCTAssertNil(CallAlertPushPayload.parse(["kind": "call-alert", "callID": "   "]), "blank callID")
        XCTAssertNil(CallAlertPushPayload.parse(["kind": "callAlert", "callID": "x"]), "the kind must match exactly")
        XCTAssertNil(CallAlertPushPayload.parse(["kind": 7, "callID": "x"]))
        XCTAssertNil(CallAlertPushPayload.parse([:]))
        XCTAssertFalse(CallAlertPushPayload.isCallAlert(["aps": ["content-available": 1]]))
    }

    // MARK: - AI-voice assessment

    func testVoiceAssessmentFixtureDecodesEveryField() throws {
        let voice = try decoder.decode(CallVoiceAssessment.self, from: CallFixtures.data(CallFixtures.voiceJSON))

        XCTAssertEqual(voice.status, .synthetic)
        XCTAssertEqual(voice.syntheticShare, 0.87, accuracy: 0.0001)
        XCTAssertEqual(voice.confidence, 0.93, accuracy: 0.0001)
        XCTAssertEqual(voice.speechMs, 6200)
        XCTAssertEqual(voice.provider, "modulate:velma-2-synthetic-voice-detection-streaming")
        XCTAssertEqual(voice.detectedAt, 1_758_600_030_000)
        XCTAssertEqual(voice.detectedDate, Date(timeIntervalSince1970: 1_758_600_030))
        XCTAssertEqual(voice.updatedAt, 1_758_600_031_000)
        XCTAssertEqual(voice.updatedDate, Date(timeIntervalSince1970: 1_758_600_031))
        let alert = try XCTUnwrap(voice.alert)
        XCTAssertEqual(alert.title, "AI voice detected")
        XCTAssertEqual(alert.subtitle, "Call from +1 (415) 555-0134")
        XCTAssertEqual(alert.body, CallFixtures.voiceAlertBody)
        XCTAssertEqual(alert.sentDate, Date(timeIntervalSince1970: 1_758_600_031))
        XCTAssertTrue(alert.pushed)
        XCTAssertTrue(alert.spoken)

        // Every status the relay sends has its own case; `unknown` is the app's, for a newer relay's.
        XCTAssertEqual(VoiceStatus.allCases.map(\.rawValue), ["analyzing", "human", "synthetic", "inconclusive", "unavailable", "unknown"])
        for status in VoiceStatus.allCases {
            let decoded = try decoder.decode(CallVoiceAssessment.self, from: CallFixtures.data(#"{"status": "\#(status.rawValue)"}"#))
            XCTAssertEqual(decoded.status, status)
        }

        let roundTripped = try decoder.decode(CallVoiceAssessment.self, from: try JSONEncoder().encode(voice))
        XCTAssertEqual(roundTripped, voice)
    }

    func testVoiceAssessmentDecodesLenientlyWithMissingOptionalsUnknownStatusAndWrongTypes() throws {
        let minimal = try decoder.decode(CallVoiceAssessment.self, from: CallFixtures.data(#"{"status": "analyzing"}"#))
        XCTAssertEqual(minimal.status, .analyzing)
        XCTAssertEqual(minimal.syntheticShare, 0)
        XCTAssertEqual(minimal.confidence, 0)
        XCTAssertEqual(minimal.speechMs, 0)
        XCTAssertEqual(minimal.provider, "")
        XCTAssertNil(minimal.detectedAt)
        XCTAssertNil(minimal.detectedDate)
        XCTAssertNil(minimal.alert)
        XCTAssertEqual(minimal.updatedAt, 0)

        let newer = try decoder.decode(CallVoiceAssessment.self, from: CallFixtures.data(#"{"status": "robotic", "syntheticShare": 0.4, "futureField": {"x": 1}}"#))
        XCTAssertEqual(newer.status, .unknown, "a status this app does not know never fails the decode")
        XCTAssertEqual(newer.syntheticShare, 0.4, accuracy: 0.0001)

        let empty = try decoder.decode(CallVoiceAssessment.self, from: CallFixtures.data("{}"))
        XCTAssertEqual(empty.status, .unknown, "no status at all is unknown too")

        let odd = try decoder.decode(CallVoiceAssessment.self, from: CallFixtures.data(
            #"{"status": 7, "syntheticShare": "high", "confidence": 3, "speechMs": -40, "provider": 12, "detectedAt": "soon", "alert": "sent", "updatedAt": 1758600031000.0}"#
        ))
        XCTAssertEqual(odd.status, .unknown)
        XCTAssertEqual(odd.syntheticShare, 0, "not a number")
        XCTAssertEqual(odd.confidence, 1, "clamped to 0…1")
        XCTAssertEqual(odd.speechMs, 0, "never negative")
        XCTAssertEqual(odd.provider, "")
        XCTAssertNil(odd.detectedAt)
        XCTAssertNil(odd.alert, "an alert that is not an object is no alert")
        XCTAssertEqual(odd.updatedAt, 1_758_600_031_000, "a float timestamp is accepted")

        let bareAlert = try decoder.decode(CallVoiceAssessment.self, from: CallFixtures.data(#"{"status": "synthetic", "syntheticShare": -2, "alert": {}}"#))
        XCTAssertEqual(bareAlert.syntheticShare, 0, "clamped to 0…1")
        XCTAssertEqual(bareAlert.alert, CallVoiceAlert(title: "", subtitle: "", body: "", sentAt: 0, pushed: false, spoken: false), "an empty alert object is still an alert")
        let nullAlert = try decoder.decode(CallVoiceAssessment.self, from: CallFixtures.data(#"{"status": "synthetic", "alert": null, "detectedAt": null}"#))
        XCTAssertNil(nullAlert.alert)

        XCTAssertThrowsError(try decoder.decode(CallVoiceAssessment.self, from: CallFixtures.data(#"["synthetic"]"#)), "an assessment is an object")
    }

    func testCallSummaryCarriesTheVoiceAssessmentNextToTheVerdict() throws {
        let summary = try decoder.decode(CallSummary.self, from: CallFixtures.data(CallFixtures.summaryJSON(voice: CallFixtures.voiceJSON)))
        XCTAssertEqual(summary.voice?.status, .synthetic)
        XCTAssertNotNil(summary.voice?.alert)
        XCTAssertEqual(summary.verdict?.level, .high, "the verdict is untouched")
        XCTAssertTrue(summary.alerted)

        // No detector ran: the relay leaves the key out.
        let without = try decoder.decode(CallSummary.self, from: CallFixtures.data(CallFixtures.summaryJSON()))
        XCTAssertNil(without.voice)

        // The caller's voice is flagged before any transcript exists: a voice assessment and no verdict at all.
        let voiceOnly = try decoder.decode(CallSummary.self, from: CallFixtures.data(CallFixtures.summaryJSON(status: "in_progress", withVerdict: false, voice: CallFixtures.voiceJSON)))
        XCTAssertNil(voiceOnly.verdict)
        XCTAssertEqual(voiceOnly.voice?.status, .synthetic)

        // A voice value this app cannot read costs only itself, never the call or its verdict.
        for unreadable in [#""yes""#, "[1, 2]", "7", "null"] {
            let decoded = try decoder.decode(CallSummary.self, from: CallFixtures.data(CallFixtures.summaryJSON(voice: unreadable)))
            XCTAssertNil(decoded.voice, unreadable)
            XCTAssertEqual(decoded.callID, CallFixtures.callID)
            XCTAssertEqual(decoded.verdict?.sequence, 3, unreadable)
        }

        let unknownStatus = try decoder.decode(CallSummary.self, from: CallFixtures.data(CallFixtures.summaryJSON(voice: #"{"status": "robotic"}"#)))
        XCTAssertEqual(unknownStatus.voice?.status, .unknown)

        // The detail route is the summary plus a transcript, so it carries the assessment the same way.
        let detail = try decoder.decode(CallDetail.self, from: CallFixtures.data(CallFixtures.summaryJSON(voice: CallFixtures.voiceJSON)))
        XCTAssertEqual(detail.summary.voice?.status, .synthetic)

        let roundTripped = try decoder.decode(CallSummary.self, from: try JSONEncoder().encode(summary))
        XCTAssertEqual(roundTripped, summary)
    }

    func testLiveEventDecodesVoiceUpdatedAndRejectsOneWithoutItsPayload() throws {
        let event = try XCTUnwrap(LiveEvent.decode(#"{"type": "voice.updated", "callID": "\#(CallFixtures.callID)", "voice": \#(CallFixtures.voiceJSON)}"#))
        guard case .voiceUpdated(let callID, let voice) = event else { return XCTFail("expected voice.updated, got \(event)") }
        XCTAssertEqual(callID, CallFixtures.callID)
        XCTAssertEqual(event.callID, CallFixtures.callID)
        XCTAssertEqual(voice.status, .synthetic)
        XCTAssertEqual(voice.alert?.title, "AI voice detected")

        // A status from a newer relay is still an event; the views show nothing for it.
        let newer = try LiveEvent.decode(#"{"type": "voice.updated", "callID": "x", "voice": {"status": "robotic"}}"#)
        XCTAssertEqual(newer, .voiceUpdated(callID: "x", voice: CallVoiceAssessment(status: .unknown, syntheticShare: 0, confidence: 0, speechMs: 0, provider: "", updatedAt: 0)))

        XCTAssertThrowsError(try LiveEvent.decode(#"{"type": "voice.updated", "callID": "x"}"#), "a known type without its payload") { error in
            XCTAssertEqual(error as? LiveEvent.FrameError, .missingPayload("voice"))
        }
        XCTAssertThrowsError(try LiveEvent.decode(#"{"type": "voice.updated", "callID": "x", "voice": "synthetic"}"#), "a voice that is not an object is no payload") { error in
            XCTAssertEqual(error as? LiveEvent.FrameError, .missingPayload("voice"))
        }
        XCTAssertThrowsError(try LiveEvent.decode(#"{"type": "voice.updated", "voice": \#(CallFixtures.voiceJSON)}"#), "no callID")

        // A stray or unreadable `voice` key never costs another frame.
        XCTAssertEqual(try LiveEvent.decode(#"{"type": "pong", "voice": 7}"#), .pong)
        XCTAssertEqual(try LiveEvent.decode(#"{"type": "call.status", "callID": "x", "status": "ringing", "voice": "?"}"#), .callStatus(callID: "x", status: .ringing))

        // The summaries inside hello / call.started / call.ended carry the assessment too.
        let analyzing = #"{"status": "analyzing", "provider": "modulate:m", "updatedAt": 5}"#
        let startedCall = CallFixtures.summaryJSON(status: "in_progress", alerted: false, withVerdict: false, voice: analyzing)
        let started = try XCTUnwrap(LiveEvent.decode(#"{"type": "call.started", "call": \#(startedCall)}"#))
        guard case .callStarted(let call) = started else { return XCTFail("expected call.started") }
        XCTAssertEqual(call.voice?.status, .analyzing)
        XCTAssertNil(call.verdict)
    }

    func testCallAlertPushPayloadReadsTheVoiceKey() throws {
        let voicePush = CallFixtures.voicePushUserInfo()
        let payload = try XCTUnwrap(CallAlertPushPayload.parse(voicePush))
        XCTAssertEqual(payload.voice, .synthetic)
        XCTAssertTrue(payload.isVoiceWarning)
        XCTAssertEqual(payload.callID, CallFixtures.callID)
        XCTAssertEqual(payload.callerNumber, "+14155550134")
        XCTAssertEqual(payload.startedAt, Date(timeIntervalSince1970: 1_758_600_000))
        XCTAssertEqual(payload.alertBody, CallFixtures.voiceAlertBody)
        XCTAssertTrue(CallAlertPushPayload.isCallAlert(voicePush), "its own kind, the same route: never a mail scan")
        XCTAssertEqual(RemoteNotificationRoute.classify(voicePush), .callAlert)

        // The kind alone says what it is: a relay that left the `voice` key out, or sent one this app cannot
        // read, is still delivering the AI-voice warning — never a scam alert.
        var bare = voicePush
        bare["voice"] = nil
        XCTAssertTrue(try XCTUnwrap(CallAlertPushPayload.parse(bare)).isVoiceWarning)
        bare["voice"] = "robotic"
        XCTAssertTrue(try XCTUnwrap(CallAlertPushPayload.parse(bare)).isVoiceWarning)
        bare["kind"] = " call-voice-alert "
        XCTAssertEqual(RemoteNotificationRoute.classify(bare), .callAlert)
        XCTAssertNil(CallAlertPushPayload.parse(["kind": "call-voice-alert"]), "no callID")

        // The spelling this app also accepts: the scam alert's kind with `voice: "synthetic"` on it.
        var legacy = voicePush
        legacy["kind"] = "call-alert"
        XCTAssertTrue(try XCTUnwrap(CallAlertPushPayload.parse(legacy)).isVoiceWarning)

        // The scam alert has no such key and is read exactly as before.
        let scam = try XCTUnwrap(CallAlertPushPayload.parse(CallFixtures.pushUserInfo()))
        XCTAssertNil(scam.voice)
        XCTAssertFalse(scam.isVoiceWarning)
        XCTAssertEqual(scam.level, .high)

        var odd = CallFixtures.pushUserInfo()
        odd["voice"] = "robotic"
        XCTAssertNil(try XCTUnwrap(CallAlertPushPayload.parse(odd)).voice, "an unknown value is no voice key")
        odd["voice"] = "unknown"
        XCTAssertNil(try XCTUnwrap(CallAlertPushPayload.parse(odd)).voice)
        odd["voice"] = 1
        XCTAssertNil(try XCTUnwrap(CallAlertPushPayload.parse(odd)).voice, "not a string")
        odd["voice"] = " synthetic "
        XCTAssertTrue(try XCTUnwrap(CallAlertPushPayload.parse(odd)).isVoiceWarning, "trimmed")
        odd["voice"] = "human"
        XCTAssertFalse(try XCTUnwrap(CallAlertPushPayload.parse(odd)).isVoiceWarning, "only synthetic is a warning")
    }

    func testVoicePresentationHelpers() {
        XCTAssertEqual(VoiceStatus.analyzing.displayTitle, "Checking the caller's voice…")
        XCTAssertEqual(VoiceStatus.human.displayTitle, "Voice sounds human")
        XCTAssertEqual(VoiceStatus.synthetic.displayTitle, "AI voice detected")
        for silent in [VoiceStatus.inconclusive, .unavailable, .unknown] {
            XCTAssertNil(silent.displayTitle, "\(silent) shows nothing")
        }
        XCTAssertTrue(VoiceStatus.allCases.allSatisfy { !$0.symbolName.isEmpty })

        XCTAssertEqual(CallVoiceDisplay.percent(0.874), 87)
        XCTAssertEqual(CallVoiceDisplay.percent(1.7), 100)
        XCTAssertEqual(CallVoiceDisplay.percent(-1), 0)
        XCTAssertEqual(CallVoiceDisplay.percent(.nan), 0)
        XCTAssertEqual(CallVoiceDisplay.shareText(0.87), "About 87% of the caller's speech sounded AI-generated.")
        XCTAssertNil(CallVoiceDisplay.shareText(nil))
        XCTAssertNil(CallVoiceDisplay.shareText(0.001), "a share that rounds to nothing is not shown")
        XCTAssertEqual(CallVoiceDisplay.confidenceText(0.93), "Detector confidence: 93%.")
        XCTAssertNil(CallVoiceDisplay.confidenceText(nil))
        XCTAssertEqual(CallVoiceDisplay.measurement(share: 0.87, confidence: 0.93), "About 87% of the caller's speech sounded AI-generated. Detector confidence: 93%.")
        XCTAssertEqual(CallVoiceDisplay.measurement(share: nil, confidence: 0.93), "Detector confidence: 93%.")
        XCTAssertNil(CallVoiceDisplay.measurement(share: nil, confidence: nil), "a placeholder from the push alone has neither")
        XCTAssertEqual(CallVoiceDisplay.liveMessage(share: 0), CallVoiceDisplay.liveDetail)
        XCTAssertEqual(CallVoiceDisplay.liveMessage(share: 0.87), "This caller's voice appears to be AI-generated. About 87% of the caller's speech sounded AI-generated.")

        XCTAssertEqual(CallVoiceDisplay.providerName(forIdentifier: "modulate:velma-2-synthetic-voice-detection-streaming"), "Modulate")
        XCTAssertEqual(CallVoiceDisplay.providerName(forIdentifier: "other:model"), "other:model")
        XCTAssertNil(CallVoiceDisplay.providerName(forIdentifier: nil))
        XCTAssertNil(CallVoiceDisplay.providerName(forIdentifier: ""))
        XCTAssertEqual(CallVoiceDisplay.footnote(status: .synthetic, provider: "modulate:m"), "The caller's voice was checked for AI-generated speech by Modulate.")
        XCTAssertEqual(CallVoiceDisplay.footnote(status: .human, provider: nil), "The caller's voice was checked for AI-generated speech.")
        XCTAssertTrue(CallVoiceDisplay.footnote(status: .synthetic, provider: "demo:scripted")?.contains("scripted demo") ?? false)
        XCTAssertNil(CallVoiceDisplay.footnote(status: .unavailable, provider: "modulate:m"), "nothing was judged")
        XCTAssertNil(CallVoiceDisplay.footnote(status: .inconclusive, provider: "modulate:m"))
        XCTAssertNil(CallVoiceDisplay.footnote(status: nil, provider: nil), "no detector ran")

        // A synthetic voice is not a scam: its wording never says so, and never replaces a scam call's own.
        XCTAssertEqual(CallVoiceDisplay.rowSummary(summary: "The caller asks for gift cards.", level: .high, voiceStatus: .synthetic), "The caller asks for gift cards.")
        // Listed only for the voice: the safe verdict's own summary would sit right under a warning.
        XCTAssertEqual(CallVoiceDisplay.rowSummary(summary: "No signs of a scam so far.", level: .safe, voiceStatus: .synthetic), CallVoiceDisplay.listSummary)
        XCTAssertEqual(CallVoiceDisplay.rowSummary(summary: "No signs of a scam so far.", level: .safe, voiceStatus: .human), "No signs of a scam so far.")
        XCTAssertFalse(CallVoiceDisplay.noScamSigns.isEmpty)
        XCTAssertFalse(CallVoiceDisplay.noScamVerdict.isEmpty)
        XCTAssertEqual(CallVoiceDisplay.rowSummary(summary: "", level: .safe, voiceStatus: .synthetic), CallVoiceDisplay.listSummary)
        XCTAssertEqual(CallVoiceDisplay.rowSummary(summary: "", level: .high, voiceStatus: .synthetic), CallAlertText.fallbackBody)
        XCTAssertEqual(CallVoiceDisplay.rowSummary(summary: "", level: .safe, voiceStatus: .human), CallAlertText.fallbackBody)
        XCTAssertEqual(CallVoiceDisplay.rowSummary(summary: "", level: .medium, voiceStatus: nil), CallAlertText.fallbackBody, "as before the voice check existed")
        XCTAssertFalse(CallVoiceDisplay.listSummary.lowercased().contains("scam"))
        XCTAssertFalse(CallVoiceDisplay.liveDetail.lowercased().contains("scam"))
        XCTAssertTrue(CallVoiceDisplay.explanation.contains("does not prove the call was a scam"))

        XCTAssertNil(CallVoiceDisplay.diagnostics(statusRaw: nil, share: nil, confidence: nil, provider: nil))
        XCTAssertEqual(CallVoiceDisplay.diagnostics(statusRaw: "unavailable", share: nil, confidence: nil, provider: ""), "AI voice check: unavailable")
        XCTAssertEqual(
            CallVoiceDisplay.diagnostics(statusRaw: "synthetic", share: 0.87, confidence: 0.93, provider: "modulate:m"),
            "AI voice check: synthetic (synthetic share 87%, confidence 93%, modulate:m)"
        )
    }

    // MARK: - Presentation helpers

    func testCallPresentationHelpers() {
        XCTAssertEqual(CallModelDisplay.name(forIdentifier: nil), "Call rules only")
        XCTAssertEqual(CallModelDisplay.name(forIdentifier: "openai:gpt-4.1-mini"), "OpenAI gpt-4.1-mini")
        XCTAssertEqual(CallModelDisplay.name(forIdentifier: "other"), "other")
        XCTAssertTrue(CallModelDisplay.footnote(forIdentifier: nil).contains("rules only"))
        XCTAssertTrue(CallModelDisplay.footnote(forIdentifier: "openai:gpt-4.1-mini").contains("OpenAI gpt-4.1-mini"))
        XCTAssertEqual(CallDurationFormat.string(seconds: 42), "0:42")
        XCTAssertEqual(CallDurationFormat.string(seconds: 254), "4:14")
        XCTAssertEqual(CallDurationFormat.string(seconds: 3723), "1:02:03")
        XCTAssertEqual(CallDurationFormat.string(seconds: -5), "0:00")
        let start = Date(timeIntervalSince1970: 1_000)
        XCTAssertEqual(CallDurationFormat.elapsed(since: start, now: start.addingTimeInterval(95.9)), "1:35")
        XCTAssertEqual(CallGuardStatus.make(relayConfigured: false, line: nil), .relayNotConfigured)
        XCTAssertEqual(CallGuardStatus.make(relayConfigured: true, line: nil), .notSetUp)
        let line = CallLine(lineID: "l", guardNumber: "+16285550199", phoneNumber: "+14155550100", minimumLevel: .medium, spokenWarning: true, createdAt: 0)
        XCTAssertEqual(CallGuardStatus.make(relayConfigured: true, line: line), .protected(guardNumber: "+16285550199", phoneNumber: "+14155550100"))
        XCTAssertTrue(CallGuardStatus.make(relayConfigured: true, line: line).isProtected)
        XCTAssertTrue(CallGuardStatus.make(relayConfigured: true, line: line).detail.contains("+1 (628) 555-0199"))
    }
}

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

    static func summaryJSON(callID: String = CallFixtures.callID, status: String = "completed", alerted: Bool = true, withVerdict: Bool = true) -> String {
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

import { describe, expect, it } from "vitest";

import { CallSession } from "../../src/calls/session.js";
import {
  COULD_NOT_REACH_MESSAGE,
  DEFAULT_TEST_CALL_SCRIPT,
  LOOP_GUARD_MESSAGE,
  NOT_SET_UP_MESSAGE,
  TEST_CALL_GOODBYE,
  announceTwiml,
  callbackUrl,
  conferenceNameFor,
  couldNotReachTwiml,
  inboundCallTwiml,
  loopGuardTwiml,
  mediaStreamUrl,
  notSetUpTwiml,
  speakerForTrack,
  testCallTwiml,
  trackSpeakers,
} from "../../src/calls/twilio/twiml.js";
import type { CallSource } from "../../src/calls/types.js";
import { CALLER_NUMBER, GUARD_NUMBER, PROTECTED_NUMBER } from "./fakes.js";

const BASE = "https://relay.test";
const CALL_ID = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";

function session(source: CallSource = "twilio"): CallSession {
  return new CallSession({
    callId: CALL_ID,
    deviceId: "device-1",
    line: null,
    source,
    callerNumber: CALLER_NUMBER,
    calledNumber: GUARD_NUMBER,
    startedAt: 1_760_000_000_000,
    transcriptionSource: "openai",
  });
}

function tag(xml: string, name: string): string {
  const match = new RegExp(`<${name}\\b[^>]*>`).exec(xml);
  if (!match) throw new Error(`no <${name}> in ${xml}`);
  return match[0];
}

function query(s: CallSession, extra = ""): string {
  return `callID=${s.callId}&amp;token=${s.mediaToken}${extra}`;
}

describe("inbound call TwiML", () => {
  it("forks to Media Streams for source openai with the exact stream attributes and a callID parameter", () => {
    const s = session();
    const xml = inboundCallTwiml({ session: s, source: "openai", publicBaseUrl: BASE, transcribeTracks: "both" });
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?><Response><Start>')).toBe(true);
    expect(tag(xml, "Stream")).toBe(
      `<Stream url="wss://relay.test/v1/calls/twilio/media/${s.mediaToken}" track="both_tracks" ` +
        `statusCallback="https://relay.test/v1/calls/twilio/stream?${query(s)}" statusCallbackMethod="POST">`,
    );
    expect(xml).toContain(`<Parameter name="callID" value="${CALL_ID}"/></Stream></Start>`);
    expect(xml).not.toContain("<Transcription");
  });

  it("uses Twilio's <Transcription> for source twilio with partial results and speaker labels", () => {
    const s = session();
    const xml = inboundCallTwiml({ session: s, source: "twilio", publicBaseUrl: BASE, transcribeTracks: "both" });
    expect(tag(xml, "Transcription")).toBe(
      `<Transcription name="cg-${CALL_ID}" statusCallbackUrl="https://relay.test/v1/calls/twilio/transcription?${query(s)}" ` +
        `statusCallbackMethod="POST" track="both_tracks" partialResults="true" inboundTrackLabel="caller" outboundTrackLabel="user"/>`,
    );
    expect(xml).not.toContain("<Stream");
  });

  it("parks the caller in the session's conference with ringback, callbacks and no beep, then hangs up", () => {
    const s = session();
    const xml = inboundCallTwiml({ session: s, source: "openai", publicBaseUrl: BASE, transcribeTracks: "both" });
    expect(tag(xml, "Conference")).toBe(
      '<Conference startConferenceOnEnter="false" endConferenceOnExit="true" beep="false" ' +
        'waitUrl="https://relay.test/v1/calls/twilio/ringback.wav" waitMethod="GET" ' +
        `statusCallback="https://relay.test/v1/calls/twilio/conference?${query(s)}" statusCallbackMethod="POST" ` +
        'statusCallbackEvent="start end join leave" participantLabel="caller">',
    );
    expect(xml).toContain(`participantLabel="caller">cg-${CALL_ID}</Conference></Dial><Hangup/></Response>`);
    expect(conferenceNameFor(CALL_ID)).toBe(`cg-${CALL_ID}`);
  });

  it("streams only the caller's track when CALLS_TRANSCRIBE_TRACKS=caller", () => {
    const s = session();
    const stream = inboundCallTwiml({ session: s, source: "openai", publicBaseUrl: BASE, transcribeTracks: "caller" });
    expect(tag(stream, "Stream")).toContain('track="inbound_track"');
    const transcription = inboundCallTwiml({ session: s, source: "twilio", publicBaseUrl: BASE, transcribeTracks: "caller" });
    expect(tag(transcription, "Transcription")).toContain('track="inbound_track"');
  });
});

describe("test call TwiML", () => {
  it("forks, speaks each scripted line with a pause, says goodbye and hangs up", () => {
    const s = session("test-call");
    const script = {
      lines: [
        { text: "Hi Grandma, it's me & I need help <now>.", pauseSeconds: 3 },
        { text: "Buy gift cards.", pauseSeconds: 0.2 },
      ],
    };
    const xml = testCallTwiml({ session: s, source: "openai", publicBaseUrl: BASE, transcribeTracks: "both", script });
    expect(xml).toContain('<Start><Stream url="wss://relay.test/v1/calls/twilio/media/');
    expect(xml).toContain(
      '<Say voice="Polly.Matthew-Neural">Hi Grandma, it\'s me &amp; I need help &lt;now&gt;.</Say><Pause length="3"/>' +
        '<Say voice="Polly.Matthew-Neural">Buy gift cards.</Say><Pause length="1"/>',
    );
    expect(xml.endsWith(`<Say voice="Polly.Joanna-Neural">${TEST_CALL_GOODBYE}</Say><Hangup/></Response>`)).toBe(true);
  });

  it("swaps the speaker labels on a test call because the person is the inbound track", () => {
    const s = session("test-call");
    const xml = testCallTwiml({ session: s, source: "twilio", publicBaseUrl: BASE, transcribeTracks: "both", script: DEFAULT_TEST_CALL_SCRIPT });
    expect(tag(xml, "Transcription")).toContain('inboundTrackLabel="user" outboundTrackLabel="caller"');
    const callerOnly = testCallTwiml({ session: s, source: "openai", publicBaseUrl: BASE, transcribeTracks: "caller", script: DEFAULT_TEST_CALL_SCRIPT });
    expect(tag(callerOnly, "Stream")).toContain('track="outbound_track"');
    expect(DEFAULT_TEST_CALL_SCRIPT.lines.length).toBeGreaterThanOrEqual(3);
  });
});

describe("short responses", () => {
  it("says the message in the warning voice and hangs up", () => {
    expect(notSetUpTwiml()).toBe(
      `<?xml version="1.0" encoding="UTF-8"?><Response><Say voice="Polly.Joanna-Neural">${NOT_SET_UP_MESSAGE}</Say><Hangup/></Response>`,
    );
    expect(loopGuardTwiml()).toContain(`<Say voice="Polly.Joanna-Neural">${LOOP_GUARD_MESSAGE}</Say><Hangup/>`);
    expect(couldNotReachTwiml()).toContain(`<Say voice="Polly.Joanna-Neural">${COULD_NOT_REACH_MESSAGE}</Say><Hangup/>`);
  });

  it("builds the announcement as a single <Say> (AnnounceUrl documents may not hang up) with XML escaping", () => {
    expect(announceTwiml("Do not buy gift cards & hang up <now>.")).toBe(
      '<?xml version="1.0" encoding="UTF-8"?><Response><Say voice="Polly.Joanna-Neural">Do not buy gift cards &amp; hang up &lt;now&gt;.</Say></Response>',
    );
  });
});

describe("urls and track semantics", () => {
  it("builds callback URLs with the session token and extra parameters, and a wss media URL", () => {
    const s = session();
    expect(callbackUrl(`${BASE}/`, "status", s, { leg: "user" })).toBe(
      `https://relay.test/v1/calls/twilio/status?callID=${CALL_ID}&token=${s.mediaToken}&leg=user`,
    );
    expect(mediaStreamUrl(BASE, s)).toBe(`wss://relay.test/v1/calls/twilio/media/${s.mediaToken}`);
    expect(mediaStreamUrl("http://localhost:8080", s)).toBe(`ws://localhost:8080/v1/calls/twilio/media/${s.mediaToken}`);
  });

  it("maps tracks to speakers per call direction and accepts our labels", () => {
    expect(trackSpeakers("twilio")).toEqual({ inbound: "caller", outbound: "user" });
    expect(trackSpeakers("test-call")).toEqual({ inbound: "user", outbound: "caller" });
    expect(speakerForTrack("twilio", "inbound")).toBe("caller");
    expect(speakerForTrack("twilio", "outbound_track")).toBe("user");
    expect(speakerForTrack("test-call", "inbound_track")).toBe("user");
    expect(speakerForTrack("test-call", "outbound")).toBe("caller");
    expect(speakerForTrack("twilio", "USER")).toBe("user");
    expect(speakerForTrack("twilio", "caller")).toBe("caller");
    expect(speakerForTrack("twilio", "sideways")).toBeUndefined();
    expect(speakerForTrack("twilio", undefined)).toBeUndefined();
    expect(PROTECTED_NUMBER).not.toBe(GUARD_NUMBER);
  });
});

import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";

import { CallSession } from "../../src/calls/session.js";
import { DEFAULT_TEST_CALL_SCRIPT, inboundCallTwiml, testCallTwiml } from "../../src/calls/twilio/twiml.js";
import type { CallSource } from "../../src/calls/types.js";
import type { CallsConfig } from "../../src/calls/config.js";
import { RelayDb } from "../../src/db.js";
import { buildApp } from "../../src/server.js";
import { DEVICE_ID, FakeSender, FakeVerifier, closeTestApp, createCallsTestApp, testConfig, type CallsTestContext } from "../helpers.js";
import { CALLER_NUMBER, FakeScorer, FakeTranscriber, FakeTwilioClient, FakeVoiceDetector, GUARD_NUMBER, PROTECTED_NUMBER, testCallsConfig } from "./fakes.js";
import { TEST_SID, inboundCall, postForm, registerLine, settle, statusForm, tokenQuery } from "./twilio-helpers.js";

/**
 * The extra caller-only `<Stream>` a Twilio-transcribed call gets for AI-voice detection: the TwiML itself, and
 * the routes' per-call decision (a detector exists, the source resolved to `twilio`, the account is Full).
 * Without `voiceStream` — and so without `MODULATE_API_KEY` — the TwiML is byte-for-byte what it was.
 */

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
  });
}

/** The whole inbound document for source `twilio`, both tracks, as it was before voice detection existed. */
function inboundTwilioDocument(s: CallSession, forks: string): string {
  const query = `callID=${s.callId}&amp;token=${s.mediaToken}`;
  return (
    '<?xml version="1.0" encoding="UTF-8"?><Response>' +
    forks +
    '<Dial><Conference startConferenceOnEnter="false" endConferenceOnExit="true" beep="false" ' +
    'waitUrl="https://relay.test/v1/calls/twilio/ringback.wav" waitMethod="GET" ' +
    `statusCallback="https://relay.test/v1/calls/twilio/conference?${query}" statusCallbackMethod="POST" ` +
    `statusCallbackEvent="start end join leave" participantLabel="caller">cg-${s.callId}</Conference></Dial><Hangup/></Response>`
  );
}

function transcriptionStart(s: CallSession, track: string, inbound: string, outbound: string): string {
  return (
    `<Start><Transcription name="cg-${s.callId}" statusCallbackUrl="https://relay.test/v1/calls/twilio/transcription?callID=${s.callId}&amp;token=${s.mediaToken}" ` +
    `statusCallbackMethod="POST" track="${track}" partialResults="true" inboundTrackLabel="${inbound}" outboundTrackLabel="${outbound}"/></Start>`
  );
}

function voiceStart(s: CallSession, track: string): string {
  return (
    `<Start><Stream url="wss://relay.test/v1/calls/twilio/media/${s.mediaToken}" track="${track}" ` +
    `statusCallback="https://relay.test/v1/calls/twilio/stream?callID=${s.callId}&amp;token=${s.mediaToken}" statusCallbackMethod="POST">` +
    `<Parameter name="callID" value="${s.callId}"/></Stream></Start>`
  );
}

describe("TwiML: voiceStream", () => {
  it("without voiceStream the Twilio-transcribed document is byte-identical to the one before voice detection", () => {
    const s = session();
    const today = inboundTwilioDocument(s, transcriptionStart(s, "both_tracks", "caller", "user"));
    const input = { session: s, source: "twilio" as const, publicBaseUrl: BASE, transcribeTracks: "both" as const };
    expect(inboundCallTwiml(input)).toBe(today);
    expect(inboundCallTwiml({ ...input, voiceStream: false })).toBe(today);
    expect(inboundCallTwiml({ ...input, voiceStream: undefined })).toBe(today);
  });

  it("with voiceStream a SECOND <Start> carries a <Stream> of the caller's track only, same URL, callback and parameter", () => {
    const s = session();
    const xml = inboundCallTwiml({ session: s, source: "twilio", publicBaseUrl: BASE, transcribeTracks: "both", voiceStream: true });
    expect(xml).toBe(inboundTwilioDocument(s, transcriptionStart(s, "both_tracks", "caller", "user") + voiceStart(s, "inbound_track")));
    // Twilio's shared limit is four forks per call: <Transcription> on both tracks is two, this stream is one.
    expect(xml.match(/<Start>/g)).toHaveLength(2);
    expect(xml.match(/<Stream /g)).toHaveLength(1);
  });

  it("the stream is caller-only whatever CALLS_TRANSCRIBE_TRACKS says", () => {
    const s = session();
    const xml = inboundCallTwiml({ session: s, source: "twilio", publicBaseUrl: BASE, transcribeTracks: "caller", voiceStream: true });
    expect(xml).toBe(inboundTwilioDocument(s, transcriptionStart(s, "inbound_track", "caller", "user") + voiceStart(s, "inbound_track")));
  });

  it("on a test call the caller is the OUTBOUND track", () => {
    const s = session("test-call");
    const input = { session: s, source: "twilio" as const, publicBaseUrl: BASE, transcribeTracks: "both" as const, script: DEFAULT_TEST_CALL_SCRIPT };
    const without = testCallTwiml(input);
    const withVoice = testCallTwiml({ ...input, voiceStream: true });
    expect(without).not.toContain("<Stream");
    expect(testCallTwiml({ ...input, voiceStream: false })).toBe(without);
    const forks = transcriptionStart(s, "both_tracks", "user", "caller");
    expect(without.startsWith(`<?xml version="1.0" encoding="UTF-8"?><Response>${forks}<Say voice="Polly.Matthew-Neural">`)).toBe(true);
    // The only difference is the inserted second <Start>.
    expect(withVoice).toBe(without.replace(forks, forks + voiceStart(s, "outbound_track")));
  });

  it("adds nothing for source openai: its own stream already carries the caller's track in both modes", () => {
    for (const source of ["twilio", "test-call"] as const) {
      for (const transcribeTracks of ["both", "caller"] as const) {
        const s = session(source);
        const input = { session: s, source: "openai" as const, publicBaseUrl: BASE, transcribeTracks, script: DEFAULT_TEST_CALL_SCRIPT };
        const build = source === "twilio" ? inboundCallTwiml : testCallTwiml;
        const without = build(input);
        expect(build({ ...input, voiceStream: true })).toBe(without);
        expect(without.match(/<Stream /g)).toHaveLength(1);
        const callerTrack = source === "twilio" ? "inbound_track" : "outbound_track";
        expect(without).toContain(transcribeTracks === "both" ? 'track="both_tracks"' : `track="${callerTrack}"`);
      }
    }
  });
});

describe("routes: which calls get the voice stream", () => {
  let ctx: CallsTestContext | undefined;
  afterEach(async () => {
    if (ctx) await closeTestApp(ctx);
    ctx = undefined;
  });

  async function app(calls: Partial<CallsConfig>, accountType: "Full" | "Trial" | "unknown", voice = true): Promise<CallsTestContext> {
    ctx = await createCallsTestApp(calls, {}, { voiceDetector: voice });
    ctx.twilio.accountType = accountType;
    await registerLine(ctx);
    return ctx;
  }

  it("Twilio transcription on a Full account: <Transcription> plus the caller-only <Stream>", async () => {
    const context = await app({ transcriptionSource: "twilio" }, "Full");
    const { response, session: s } = await inboundCall(context);
    expect(s.transcriptionSource).toBe("twilio");
    expect(response.body).toBe(inboundTwilioDocument(s, transcriptionStart(s, "both_tracks", "caller", "user") + voiceStart(s, "inbound_track")));
  });

  it("Twilio transcription on a Trial account (Media Streams are blocked): no <Stream>", async () => {
    const context = await app({ transcriptionSource: "twilio" }, "Trial");
    const { response, session: s } = await inboundCall(context);
    expect(response.body).toBe(inboundTwilioDocument(s, transcriptionStart(s, "both_tracks", "caller", "user")));
  });

  it("an account whose type cannot be fetched is treated like a Trial", async () => {
    const context = await app({ transcriptionSource: "twilio" }, "unknown");
    const { response } = await inboundCall(context);
    expect(response.body).not.toContain("<Stream");
    expect(response.body).toContain("<Transcription");
  });

  it("source openai: the one existing stream, nothing added", async () => {
    const context = await app({ transcriptionSource: "openai" }, "Full");
    const { response, session: s } = await inboundCall(context);
    expect(s.transcriptionSource).toBe("openai");
    expect(response.body.match(/<Start>/g)).toHaveLength(1);
    expect(response.body.match(/<Stream /g)).toHaveLength(1);
    expect(response.body).toContain('track="both_tracks"');
    expect(response.body).not.toContain("<Transcription");
  });

  it("auto: OpenAI on a Full account keeps its single stream; a Trial account gets Twilio transcription and no stream", async () => {
    const full = await app({ transcriptionSource: "auto" }, "Full");
    const first = await inboundCall(full);
    expect(first.session.transcriptionSource).toBe("openai");
    expect(first.response.body.match(/<Stream /g)).toHaveLength(1);
    expect(first.response.body).not.toContain("<Transcription");
    await closeTestApp(full);

    const trial = await app({ transcriptionSource: "auto" }, "Trial");
    const second = await inboundCall(trial);
    expect(second.session.transcriptionSource).toBe("twilio");
    expect(second.response.body).not.toContain("<Stream");
  });

  it("auto without an OpenAI key on a Full account: Twilio transcribes, and the voice stream is added", async () => {
    const context = await app({ transcriptionSource: "auto", openai: undefined }, "Full");
    const { response, session: s } = await inboundCall(context);
    expect(s.transcriptionSource).toBe("twilio");
    expect(response.body).toBe(inboundTwilioDocument(s, transcriptionStart(s, "both_tracks", "caller", "user") + voiceStart(s, "inbound_track")));
  });

  it("without a detector nothing changes: the same bytes as before, and no account lookup for a configured source", async () => {
    const context = await app({ transcriptionSource: "twilio" }, "Full", false);
    expect(context.voiceDetector).toBeUndefined();
    const { response, session: s } = await inboundCall(context);
    expect(response.body).toBe(inboundTwilioDocument(s, transcriptionStart(s, "both_tracks", "caller", "user")));
    expect(context.twilio.accountTypeFetches).toBe(0);
  });

  it("prefetches the account type at start-up when a detector is configured, so the webhook does not wait for it", async () => {
    const context = await app({ transcriptionSource: "twilio" }, "Full");
    await settle();
    expect(context.twilio.accountTypeFetches).toBe(1);
    await inboundCall(context);
    // The fake counts every call; the real client answers the second from its cache.
    expect(context.twilio.accountTypeFetches).toBe(2);
  });

  it("test calls: the caller-only stream is the outbound track on a Full account, absent on a Trial one", async () => {
    for (const [accountType, expectStream] of [
      ["Full", true],
      ["Trial", false],
    ] as const) {
      const context = await app({ transcriptionSource: "twilio" }, accountType);
      const line = context.db.findCallLine(DEVICE_ID)!;
      const s = context.app.callGuard.sessions.create({
        deviceId: DEVICE_ID,
        line,
        source: "test-call",
        callerNumber: GUARD_NUMBER,
        calledNumber: PROTECTED_NUMBER,
        startedAt: context.clock.now(),
        status: "ringing",
        transcriptionSource: "twilio",
      });
      const res = await postForm(context.app, `/v1/calls/twilio/test-call?${tokenQuery(s, { scenario: "grandparent" })}`, statusForm(TEST_SID, "in-progress"));
      expect(res.statusCode).toBe(200);
      const forks = transcriptionStart(s, "both_tracks", "user", "caller");
      expect(res.body).toContain(expectStream ? `${forks}${voiceStart(s, "outbound_track")}<Say ` : `${forks}<Say `);
      await closeTestApp(context);
      ctx = undefined;
    }
  });
});

describe("start-up logging", () => {
  async function started(options: { voice: boolean; accountType: "Full" | "Trial"; source: "twilio" | "auto" }): Promise<{ lines: Record<string, unknown>[]; close: () => Promise<void> }> {
    const raw: string[] = [];
    const sink = new Writable({
      write(chunk, _encoding, callback) {
        raw.push(String(chunk));
        callback();
      },
    });
    const db = RelayDb.open(":memory:");
    const twilio = new FakeTwilioClient();
    twilio.accountType = options.accountType;
    const app = buildApp({
      config: testConfig({ calls: testCallsConfig({ transcriptionSource: options.source }), logLevel: "info" }),
      db,
      pushSender: new FakeSender(),
      tokenVerifier: new FakeVerifier(),
      logger: { level: "info", stream: sink },
      calls: { twilio, transcriber: new FakeTranscriber(), scorer: new FakeScorer(), ...(options.voice ? { voiceDetector: new FakeVoiceDetector() } : {}) },
    });
    await app.ready();
    await settle();
    const lines = raw
      .join("")
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    return {
      lines,
      close: async () => {
        await app.close();
        db.close();
      },
    };
  }

  const TRIAL_VOICE_WARNING = /AI-voice detection is configured, but a Trial account/;

  it("warns once when voice detection is configured on a Trial account, and says `voice: true` in the ready line", async () => {
    const { lines, close } = await started({ voice: true, accountType: "Trial", source: "twilio" });
    try {
      const warnings = lines.filter((line) => TRIAL_VOICE_WARNING.test(String(line["msg"])));
      expect(warnings).toHaveLength(1);
      expect(warnings[0]!["level"]).toBe(40);
      expect(lines.find((line) => line["msg"] === "calls: Call Guard ready")).toMatchObject({ voice: true, twilio: true, openai: true });
      // The `auto`-only lines are not printed for a configured source.
      expect(lines.some((line) => line["msg"] === "calls: twilio account type resolved")).toBe(false);
    } finally {
      await close();
    }
  });

  it("does not warn on a Full account", async () => {
    const { lines, close } = await started({ voice: true, accountType: "Full", source: "twilio" });
    try {
      expect(lines.some((line) => TRIAL_VOICE_WARNING.test(String(line["msg"])))).toBe(false);
    } finally {
      await close();
    }
  });

  it("with `auto` on a Trial account both warnings appear once each", async () => {
    const { lines, close } = await started({ voice: true, accountType: "Trial", source: "auto" });
    try {
      expect(lines.filter((line) => TRIAL_VOICE_WARNING.test(String(line["msg"])))).toHaveLength(1);
      expect(lines.filter((line) => /Trial account — <Stream> is blocked/.test(String(line["msg"])))).toHaveLength(1);
      expect(lines.filter((line) => line["msg"] === "calls: twilio account type resolved")).toHaveLength(1);
    } finally {
      await close();
    }
  });

  it("without a detector: `voice: false`, no voice warning, and the same start-up lines as before on a Trial account", async () => {
    const { lines, close } = await started({ voice: false, accountType: "Trial", source: "auto" });
    try {
      expect(lines.find((line) => line["msg"] === "calls: Call Guard ready")).toMatchObject({ voice: false });
      expect(lines.some((line) => TRIAL_VOICE_WARNING.test(String(line["msg"])))).toBe(false);
      expect(lines.filter((line) => /Trial account — <Stream> is blocked/.test(String(line["msg"])))).toHaveLength(1);
    } finally {
      await close();
    }
    const configured = await started({ voice: false, accountType: "Trial", source: "twilio" });
    try {
      // A configured source without a detector never asked for the account type, and still does not.
      expect(configured.lines.some((line) => /account type|Trial account/.test(String(line["msg"])))).toBe(false);
    } finally {
      await configured.close();
    }
  });
});

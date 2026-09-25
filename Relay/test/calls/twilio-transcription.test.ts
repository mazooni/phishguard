import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { CallSession } from "../../src/calls/session.js";
import { TranscriptionWebhook, parseTranscript } from "../../src/calls/twilio/transcription.js";
import type { TranscriptSegment } from "../../src/calls/types.js";
import { FakeClock, closeTestApp, createCallsTestApp, type CallsTestContext } from "../helpers.js";
import { CALLER_NUMBER, GUARD_NUMBER, silentLogger } from "./fakes.js";
import { inboundCall, postForm, registerLine, tokenQuery, transcriptionForm } from "./twilio-helpers.js";

function makeSession(source: "twilio" | "test-call" = "twilio", transcriptionSource: "twilio" | "openai" = "twilio", clock = new FakeClock()) {
  const session = new CallSession(
    { deviceId: "device-1", line: null, source, callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: clock.now(), transcriptionSource },
    clock.now,
  );
  const segments: TranscriptSegment[] = [];
  session.on("segment", (segment) => segments.push(segment));
  return { session, segments, clock };
}

describe("TranscriptionWebhook", () => {
  it("partials of one utterance share an id, the final replaces it and the next partial starts a new id", () => {
    const { session, segments, clock } = makeSession();
    const webhook = new TranscriptionWebhook({ logger: silentLogger(), now: clock.now });
    clock.advance(1500);
    expect(webhook.handle(session, transcriptionForm("inbound_track", "I need", false, 1))).toBe("segment");
    expect(webhook.handle(session, transcriptionForm("inbound_track", "I need gift", false, 2))).toBe("segment");
    expect(webhook.handle(session, transcriptionForm("inbound_track", "I need gift cards.", true, 3))).toBe("segment");
    expect(webhook.handle(session, transcriptionForm("inbound_track", "Right now", false, 4))).toBe("segment");

    expect(segments.map((s) => [s.id, s.text, s.final])).toEqual([
      ["caller-tw-1", "I need", false],
      ["caller-tw-1", "I need gift", false],
      ["caller-tw-1", "I need gift cards.", true],
      ["caller-tw-2", "Right now", false],
    ]);
    expect(session.segments.map((s) => s.text)).toEqual(["I need gift cards.", "Right now"]);
    expect(segments[0]!.atMs).toBe(1500);
    expect(session.transcriptText()).toBe("Caller: I need gift cards.");
  });

  it("maps the track to the speaker: inbound → caller, outbound → user on inbound calls, swapped on test calls, labels as-is", () => {
    const { session, segments, clock } = makeSession();
    const webhook = new TranscriptionWebhook({ logger: silentLogger(), now: clock.now });
    webhook.handle(session, transcriptionForm("inbound_track", "Hello", true, 1));
    webhook.handle(session, transcriptionForm("outbound_track", "Who is this?", true, 2));
    webhook.handle(session, transcriptionForm("user", "Hello?", true, 3));
    webhook.handle(session, transcriptionForm("caller", "It's me.", true, 4));
    expect(segments.map((s) => s.speaker)).toEqual(["caller", "user", "user", "caller"]);

    const test = makeSession("test-call");
    const testWebhook = new TranscriptionWebhook({ logger: silentLogger(), now: test.clock.now });
    testWebhook.handle(test.session, transcriptionForm("inbound_track", "Hello", true, 1));
    testWebhook.handle(test.session, transcriptionForm("outbound_track", "Hi Grandma", true, 2));
    expect(test.segments.map((s) => s.speaker)).toEqual(["user", "caller"]);
  });

  it("ignores empty or malformed transcripts, unknown tracks, late partials and content for sessions Twilio does not transcribe", () => {
    const { session, segments, clock } = makeSession();
    const webhook = new TranscriptionWebhook({ logger: silentLogger(), now: clock.now });
    expect(webhook.handle(session, transcriptionForm("inbound_track", "   ", true, 1))).toBe("ignored");
    expect(webhook.handle(session, transcriptionForm("inbound_track", "x", true, 2, { TranscriptionData: "not json" }))).toBe("ignored");
    expect(webhook.handle(session, transcriptionForm("inbound_track", "x", true, 3, { TranscriptionData: '{"confidence":0.5}' }))).toBe("ignored");
    expect(webhook.handle(session, transcriptionForm("sideways", "x", true, 4))).toBe("ignored");
    expect(webhook.handle(session, transcriptionForm("inbound_track", "new", false, 10))).toBe("segment");
    expect(webhook.handle(session, transcriptionForm("inbound_track", "stale", false, 9))).toBe("ignored");
    expect(webhook.handle(session, transcriptionForm("inbound_track", "new final", true, 11))).toBe("segment");
    expect(segments.map((s) => s.text)).toEqual(["new", "new final"]);

    const openai = makeSession("twilio", "openai");
    const openaiWebhook = new TranscriptionWebhook({ logger: silentLogger(), now: openai.clock.now });
    expect(openaiWebhook.handle(openai.session, transcriptionForm("inbound_track", "hello", true, 1))).toBe("ignored");
    expect(openai.segments).toHaveLength(0);
  });

  it("started/stopped/error events end nothing and produce no segments", () => {
    const { session, segments, clock } = makeSession();
    const webhook = new TranscriptionWebhook({ logger: silentLogger(), now: clock.now });
    expect(webhook.handle(session, { TranscriptionEvent: "transcription-started" })).toBe("started");
    expect(webhook.handle(session, { TranscriptionEvent: "transcription-error", Track: "inbound_track" })).toBe("error");
    expect(webhook.handle(session, { TranscriptionEvent: "transcription-stopped" })).toBe("stopped");
    expect(webhook.handle(session, { TranscriptionEvent: "something-new" })).toBe("ignored");
    expect(segments).toHaveLength(0);
    expect(session.isEnded).toBe(false);
    session.end("completed");
    expect(webhook.handle(session, transcriptionForm("inbound_track", "too late", true, 5))).toBe("ignored");
  });

  it("parses TranscriptionData leniently", () => {
    expect(parseTranscript('{"transcript": "  Hi there ", "confidence": 0.8}')).toBe("Hi there");
    expect(parseTranscript('{"transcript": ""}')).toBeUndefined();
    expect(parseTranscript('{"transcript": 3}')).toBeUndefined();
    expect(parseTranscript("[]")).toBeUndefined();
    expect(parseTranscript("")).toBeUndefined();
    expect(parseTranscript(undefined)).toBeUndefined();
  });
});

describe("POST /v1/calls/twilio/transcription", () => {
  let ctx: CallsTestContext;
  beforeEach(async () => {
    ctx = await createCallsTestApp({ transcriptionSource: "twilio" });
    await registerLine(ctx);
  });
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  it("turns signed, token-checked callbacks into segments on the session and rejects the rest", async () => {
    const { session } = await inboundCall(ctx);
    const partial = await postForm(ctx.app, `/v1/calls/twilio/transcription?${tokenQuery(session)}`, transcriptionForm("inbound_track", "Buy gift", false, 1));
    expect(partial.statusCode).toBe(204);
    const final = await postForm(ctx.app, `/v1/calls/twilio/transcription?${tokenQuery(session)}`, transcriptionForm("inbound_track", "Buy gift cards.", true, 2));
    expect(final.statusCode).toBe(204);
    const user = await postForm(ctx.app, `/v1/calls/twilio/transcription?${tokenQuery(session)}`, transcriptionForm("outbound_track", "Why?", true, 3));
    expect(user.statusCode).toBe(204);
    expect(session.segments.map((s) => [s.speaker, s.text, s.final])).toEqual([
      ["caller", "Buy gift cards.", true],
      ["user", "Why?", true],
    ]);

    const badToken = await postForm(ctx.app, `/v1/calls/twilio/transcription?callID=${session.callId}&token=nope`, transcriptionForm("inbound_track", "x", true, 4));
    expect(badToken.statusCode).toBe(403);
    expect(badToken.json()).toEqual({ error: "bad_token" });
    const unknown = await postForm(ctx.app, `/v1/calls/twilio/transcription?callID=missing&token=${session.mediaToken}`, transcriptionForm("inbound_track", "x", true, 5));
    expect(unknown.statusCode).toBe(404);
    ctx.twilio.rejectSignatures = true;
    const unsigned = await postForm(ctx.app, `/v1/calls/twilio/transcription?${tokenQuery(session)}`, transcriptionForm("inbound_track", "x", true, 6));
    expect(unsigned.statusCode).toBe(403);
    expect(session.segments).toHaveLength(2);
  });

  it("never persists transcript text", async () => {
    const { session } = await inboundCall(ctx);
    await postForm(ctx.app, `/v1/calls/twilio/transcription?${tokenQuery(session)}`, transcriptionForm("inbound_track", "SECRET-TRANSCRIPT-TEXT", true, 1));
    const rows = ctx.db.db.prepare("SELECT * FROM calls WHERE call_id = ?").all(session.callId);
    expect(JSON.stringify(rows)).not.toContain("SECRET-TRANSCRIPT-TEXT");
  });
});

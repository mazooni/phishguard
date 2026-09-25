import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { COULD_NOT_REACH_MESSAGE, LOOP_GUARD_MESSAGE, NOT_SET_UP_MESSAGE } from "../../src/calls/twilio/twiml.js";
import { DEVICE_ID, closeTestApp, createCallsTestApp, type CallsTestContext } from "../helpers.js";
import { CALLER_NUMBER, GUARD_NUMBER, PROTECTED_NUMBER } from "./fakes.js";
import { CALLER_SID, inboundCall, postForm, registerLine, settle, voiceForm } from "./twilio-helpers.js";

describe("POST /v1/calls/twilio/voice", () => {
  let ctx: CallsTestContext;
  beforeEach(async () => {
    ctx = await createCallsTestApp();
  });
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  it("answers a number without a line with <Say> + <Hangup/> and creates no session", async () => {
    const res = await postForm(ctx.app, "/v1/calls/twilio/voice", voiceForm());
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toMatch(/^text\/xml/);
    expect(res.body).toContain(`<Say voice="Polly.Joanna-Neural">${NOT_SET_UP_MESSAGE}</Say><Hangup/>`);
    expect(res.body).not.toContain("<Dial");
    await settle();
    expect(ctx.app.callGuard.sessions.all()).toHaveLength(0);
    expect(ctx.twilio.dialed).toHaveLength(0);
  });

  it("validates the signature against the public URL with the parsed form fields", async () => {
    await registerLine(ctx);
    await inboundCall(ctx);
    const check = ctx.twilio.signatureChecks.at(-1);
    expect(check?.url).toBe("https://relay.test/v1/calls/twilio/voice");
    expect(check?.signature).toBeDefined();
    expect(check?.params["CallSid"]).toBe(CALLER_SID);
    expect(check?.params["To"]).toBe(GUARD_NUMBER);
  });

  it("rejects a bad signature with 403 and no session", async () => {
    await registerLine(ctx);
    ctx.twilio.rejectSignatures = true;
    const res = await postForm(ctx.app, "/v1/calls/twilio/voice", voiceForm());
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: "bad_signature" });
    await settle();
    expect(ctx.app.callGuard.sessions.all()).toHaveLength(0);
  });

  it("loop guard: a call from the protected number, the guard number or forwarded from the protected number is refused", async () => {
    await registerLine(ctx);
    for (const form of [
      voiceForm({ From: PROTECTED_NUMBER }),
      voiceForm({ From: GUARD_NUMBER }),
      voiceForm({ ForwardedFrom: PROTECTED_NUMBER }),
    ]) {
      const res = await postForm(ctx.app, "/v1/calls/twilio/voice", form);
      expect(res.statusCode).toBe(200);
      expect(res.body).toContain(`<Say voice="Polly.Joanna-Neural">${LOOP_GUARD_MESSAGE}</Say><Hangup/>`);
      expect(res.body).not.toContain("<Conference");
    }
    await settle();
    expect(ctx.app.callGuard.sessions.all()).toHaveLength(0);
  });

  it("happy path (openai): TwiML with the stream fork and the conference, a ringing session, then the user leg is dialled", async () => {
    const line = await registerLine(ctx);
    const { response, session } = await inboundCall(ctx);
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toMatch(/^text\/xml/);
    expect(response.body).toContain(`<Start><Stream url="wss://relay.test/v1/calls/twilio/media/${session.mediaToken}" track="both_tracks"`);
    expect(response.body).toContain(`<Parameter name="callID" value="${session.callId}"/>`);
    expect(response.body).toContain(`participantLabel="caller">cg-${session.callId}</Conference></Dial><Hangup/>`);

    expect(session.status).toBe("ringing");
    expect(session.source).toBe("twilio");
    expect(session.transcriptionSource).toBe("openai");
    expect(session.deviceId).toBe(DEVICE_ID);
    expect(session.line?.lineId).toBe(line.lineId);
    expect(session.callerNumber).toBe(CALLER_NUMBER);
    expect(session.calledNumber).toBe(GUARD_NUMBER);
    expect(session.twilioCallSid).toBe(CALLER_SID);
    expect(session.conferenceName).toBe(`cg-${session.callId}`);
    expect(session.startedAt).toBe(ctx.clock.now());

    // The dial happened after the response was sent.
    expect(ctx.twilio.dialed).toEqual([{ callId: session.callId, sid: expect.stringMatching(/^CAuser/) }]);
    const userSid = ctx.twilio.dialed[0]!.sid;
    expect(session.userCallSid).toBe(userSid);
    expect(ctx.app.callGuard.sessions.byTwilioSid(userSid)).toBe(session);
    expect(ctx.app.callGuard.sessions.byTwilioSid(CALLER_SID)).toBe(session);

    const record = ctx.db.findCall(session.callId);
    expect(record?.status).toBe("ringing");
    expect(record?.twilioCallSid).toBe(CALLER_SID);
    expect(ctx.twilio.redirected).toHaveLength(0);
  });

  it("uses Twilio's <Transcription> when CALLS_TRANSCRIPTION_SOURCE=twilio", async () => {
    await closeTestApp(ctx);
    ctx = await createCallsTestApp({ transcriptionSource: "twilio" });
    await registerLine(ctx);
    const { response, session } = await inboundCall(ctx);
    expect(session.transcriptionSource).toBe("twilio");
    expect(response.body).toContain('<Start><Transcription name="cg-');
    expect(response.body).toContain('partialResults="true" inboundTrackLabel="caller" outboundTrackLabel="user"/>');
    expect(response.body).not.toContain("<Stream");
    expect(ctx.twilio.accountTypeFetches).toBe(0);
  });

  it("a failed dial redirects the caller to the 'could not reach' message and fails the session", async () => {
    await registerLine(ctx);
    ctx.twilio.failDial = new Error("Participants API: 20404");
    const { response, session } = await inboundCall(ctx);
    expect(response.statusCode).toBe(200);
    expect(ctx.twilio.redirected).toEqual([{ callSid: CALLER_SID, twiml: expect.stringContaining(COULD_NOT_REACH_MESSAGE) }]);
    expect(session.isEnded).toBe(true);
    expect(session.status).toBe("failed");
    expect(ctx.db.findCall(session.callId)?.status).toBe("failed");
  });

  it("accepts a caller without a number", async () => {
    await registerLine(ctx);
    const { session } = await inboundCall(ctx, { From: "" });
    expect(session.callerNumber).toBe("unknown");
    expect(ctx.twilio.dialed).toHaveLength(1);
  });
});

describe("CALLS_TRANSCRIPTION_SOURCE=auto", () => {
  let ctx: CallsTestContext | undefined;
  afterEach(async () => {
    if (ctx) await closeTestApp(ctx);
    ctx = undefined;
  });

  it("picks Twilio transcription on a Trial account", async () => {
    ctx = await createCallsTestApp({ transcriptionSource: "auto" });
    ctx.twilio.accountType = "Trial";
    await registerLine(ctx);
    const { response, session } = await inboundCall(ctx);
    expect(session.transcriptionSource).toBe("twilio");
    expect(response.body).toContain("<Transcription");
    expect(ctx.twilio.accountTypeFetches).toBeGreaterThanOrEqual(1);
  });

  it("picks OpenAI Realtime on a Full account with an OpenAI key", async () => {
    ctx = await createCallsTestApp({ transcriptionSource: "auto" });
    ctx.twilio.accountType = "Full";
    await registerLine(ctx);
    const { response, session } = await inboundCall(ctx);
    expect(session.transcriptionSource).toBe("openai");
    expect(response.body).toContain("<Stream");
  });

  it("falls back to Twilio transcription without an OpenAI key (no account lookup needed) or when the type is unknown", async () => {
    ctx = await createCallsTestApp({ transcriptionSource: "auto", openai: undefined });
    ctx.twilio.accountType = "Full";
    await registerLine(ctx);
    const first = await inboundCall(ctx);
    expect(first.session.transcriptionSource).toBe("twilio");
    await closeTestApp(ctx);

    ctx = await createCallsTestApp({ transcriptionSource: "auto" });
    ctx.twilio.accountType = "unknown";
    await registerLine(ctx);
    const second = await inboundCall(ctx);
    expect(second.session.transcriptionSource).toBe("twilio");
  });
});

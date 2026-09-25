import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { scriptForScenario } from "../../src/calls/demo/scenarios.js";
import type { CallSession } from "../../src/calls/session.js";
import { endedStatusFor, withinDeadline } from "../../src/calls/twilio/routes.js";
import { COULD_NOT_REACH_MESSAGE, DEFAULT_TEST_CALL_SCRIPT } from "../../src/calls/twilio/twiml.js";
import { DEVICE_ID, closeTestApp, createCallsTestApp, type CallsTestContext } from "../helpers.js";
import { GUARD_NUMBER, PROTECTED_NUMBER } from "./fakes.js";
import {
  CALLER_SID,
  CONFERENCE_SID,
  TEST_SID,
  USER_SID,
  conferenceForm,
  inboundCall,
  postForm,
  registerLine,
  settle,
  statusForm,
  tokenQuery,
} from "./twilio-helpers.js";

describe("POST /v1/calls/twilio/status", () => {
  let ctx: CallsTestContext;
  let session: CallSession;
  let userSid: string;
  beforeEach(async () => {
    ctx = await createCallsTestApp();
    await registerLine(ctx);
    ({ session } = await inboundCall(ctx));
    userSid = ctx.twilio.dialed[0]!.sid;
  });
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  function status(leg: string, callSid: string, callStatus: string) {
    return postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg })}`, statusForm(callSid, callStatus));
  }

  it("user leg initiated/ringing → connecting; answered → in_progress", async () => {
    expect((await status("user", userSid, "initiated")).statusCode).toBe(204);
    expect(session.status).toBe("connecting");
    await status("user", userSid, "ringing");
    expect(session.status).toBe("connecting");
    await status("user", userSid, "in-progress");
    expect(session.status).toBe("in_progress");
    expect(ctx.db.findCall(session.callId)?.status).toBe("in_progress");
  });

  it("user leg no-answer before joining → caller hears 'could not reach', session ends no_answer", async () => {
    await status("user", userSid, "ringing");
    await status("user", userSid, "no-answer");
    await settle();
    expect(session.isEnded).toBe(true);
    expect(session.status).toBe("no_answer");
    expect(ctx.twilio.redirected).toEqual([{ callSid: CALLER_SID, twiml: expect.stringContaining(COULD_NOT_REACH_MESSAGE) }]);
  });

  it("user leg busy / failed before joining map to busy / failed; a never-connected 'completed' counts as no_answer", async () => {
    await status("user", userSid, "busy");
    await settle();
    expect(session.status).toBe("busy");

    const second = await inboundCall(ctx, { CallSid: "CA" + "f".repeat(32) });
    const secondUser = ctx.twilio.dialed[1]!.sid;
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(second.session, { leg: "user" })}`, statusForm(secondUser, "failed"));
    await settle();
    expect(second.session.status).toBe("failed");

    const third = await inboundCall(ctx, { CallSid: "CA" + "e".repeat(32) });
    const thirdUser = ctx.twilio.dialed[2]!.sid;
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(third.session, { leg: "user" })}`, statusForm(thirdUser, "completed"));
    await settle();
    expect(third.session.status).toBe("no_answer");
    expect(ctx.twilio.redirected).toHaveLength(3);
  });

  it("user leg completed after the call was in progress → completed, no redirect", async () => {
    await status("user", userSid, "in-progress");
    await status("user", userSid, "completed");
    await settle();
    expect(session.status).toBe("completed");
    expect(session.isEnded).toBe(true);
    expect(ctx.twilio.redirected).toHaveLength(0);
  });

  it("caller leg completed while the user was still ringing → session completed and the user leg is ended", async () => {
    await status("user", userSid, "ringing");
    await status("caller", CALLER_SID, "completed");
    await settle();
    expect(session.status).toBe("completed");
    expect(ctx.twilio.endedCalls).toEqual([userSid]);
  });

  it("caller leg completed after the conversation → completed without touching the user leg", async () => {
    await status("user", userSid, "in-progress");
    await status("caller", CALLER_SID, "completed");
    await settle();
    expect(session.status).toBe("completed");
    expect(ctx.twilio.endedCalls).toHaveLength(0);
  });

  it("caller-leg statuses that are not terminal change nothing", async () => {
    await status("caller", CALLER_SID, "ringing");
    await status("caller", CALLER_SID, "in-progress");
    expect(session.status).toBe("ringing");
  });

  it("without callID (the number's own status callback) the session is found by CallSid; unknown SIDs are ignored", async () => {
    const res = await postForm(ctx.app, "/v1/calls/twilio/status", statusForm(CALLER_SID, "completed"));
    expect(res.statusCode).toBe(204);
    expect(session.status).toBe("completed");
    const unknown = await postForm(ctx.app, "/v1/calls/twilio/status", statusForm("CA" + "9".repeat(32), "completed"));
    expect(unknown.statusCode).toBe(204);
  });

  it("rejects a wrong token with 403 and an unknown callID with 404, and a bad signature with 403", async () => {
    const bad = await postForm(ctx.app, `/v1/calls/twilio/status?callID=${session.callId}&token=nope&leg=user`, statusForm(userSid, "completed"));
    expect(bad.statusCode).toBe(403);
    expect(bad.json()).toEqual({ error: "bad_token" });
    const unknown = await postForm(ctx.app, `/v1/calls/twilio/status?callID=nope&token=${session.mediaToken}`, statusForm(userSid, "completed"));
    expect(unknown.statusCode).toBe(404);
    expect(unknown.json()).toEqual({ error: "not_found" });
    ctx.twilio.rejectSignatures = true;
    const unsigned = await status("user", userSid, "completed");
    expect(unsigned.statusCode).toBe(403);
    expect(unsigned.json()).toEqual({ error: "bad_signature" });
    expect(session.status).toBe("ringing");
  });

  it("callbacks after the session ended change nothing and make no further REST calls", async () => {
    await status("user", userSid, "no-answer");
    await settle();
    expect(session.status).toBe("no_answer");
    expect(ctx.twilio.redirected).toHaveLength(1);
    // Twilio then reports both legs' completion (the caller heard "could not reach"): nothing more to do.
    await status("caller", CALLER_SID, "completed");
    await status("user", userSid, "completed");
    await postForm(ctx.app, `/v1/calls/twilio/conference?${tokenQuery(session)}`, conferenceForm("conference-end"));
    await settle();
    expect(session.status).toBe("no_answer");
    expect(ctx.twilio.redirected).toHaveLength(1);
    expect(ctx.twilio.endedCalls).toHaveLength(0);
    expect(ctx.db.findCall(session.callId)?.status).toBe("no_answer");
  });

  it("withinDeadline answers with the value when it arrives in time, else with the fallback (also on rejection)", async () => {
    await expect(withinDeadline(Promise.resolve("Full"), 50, "unknown")).resolves.toBe("Full");
    await expect(withinDeadline(new Promise<string>(() => undefined), 10, "unknown")).resolves.toBe("unknown");
    await expect(withinDeadline(Promise.reject(new Error("down")), 50, "unknown")).resolves.toBe("unknown");
  });

  it("maps every terminal Twilio status", () => {
    expect(endedStatusFor("completed")).toBe("completed");
    expect(endedStatusFor("busy")).toBe("busy");
    expect(endedStatusFor("failed")).toBe("failed");
    expect(endedStatusFor("no-answer")).toBe("no_answer");
    expect(endedStatusFor("canceled")).toBe("canceled");
    expect(endedStatusFor("in-progress")).toBeUndefined();
    expect(endedStatusFor(undefined)).toBeUndefined();
  });
});

describe("POST /v1/calls/twilio/conference", () => {
  let ctx: CallsTestContext;
  let session: CallSession;
  beforeEach(async () => {
    ctx = await createCallsTestApp();
    await registerLine(ctx);
    ({ session } = await inboundCall(ctx));
  });
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  function conference(form: Record<string, string>) {
    return postForm(ctx.app, `/v1/calls/twilio/conference?${tokenQuery(session)}`, form);
  }

  it("conference-start stores the ConferenceSid", async () => {
    expect(session.conferenceSid).toBeUndefined();
    expect((await conference(conferenceForm("conference-start"))).statusCode).toBe(204);
    expect(session.conferenceSid).toBe(CONFERENCE_SID);
    expect(session.status).toBe("ringing");
  });

  it("participant-join of the user leg → in_progress (and the user SID is indexed); the caller's join changes nothing", async () => {
    await conference(conferenceForm("participant-join", { ParticipantLabel: "caller", CallSid: CALLER_SID }));
    expect(session.status).toBe("ringing");
    await conference(conferenceForm("participant-join", { ParticipantLabel: "user", CallSid: USER_SID }));
    expect(session.status).toBe("in_progress");
    expect(session.userCallSid).toBe(ctx.twilio.dialed[0]!.sid); // set by the dial first; never overwritten
    expect(ctx.app.callGuard.sessions.byTwilioSid(USER_SID)).toBe(session);
  });

  it("conference-end ends the session as completed", async () => {
    await conference(conferenceForm("participant-join", { ParticipantLabel: "user", CallSid: USER_SID }));
    await conference(conferenceForm("conference-end", { ReasonConferenceEnded: "participant-with-end-conference-on-exit-left" }));
    expect(session.isEnded).toBe(true);
    expect(session.status).toBe("completed");
    expect(ctx.db.findCall(session.callId)?.status).toBe("completed");
  });

  it("conference-end before the user joined (the caller hung up while parked) ends the still-ringing user leg", async () => {
    const userSid = ctx.twilio.dialed[0]!.sid;
    await conference(conferenceForm("conference-end", { ReasonConferenceEnded: "last-participant-left" }));
    expect(session.status).toBe("completed");
    expect(ctx.twilio.endedCalls).toEqual([userSid]);
    expect(ctx.twilio.redirected).toEqual([]);
    expect(ctx.db.findCall(session.callId)).toMatchObject({ status: "completed", alerted: false });
  });

  it("conference-end after the conversation touches no leg; repeated and late callbacks change nothing", async () => {
    await conference(conferenceForm("participant-join", { ParticipantLabel: "user", CallSid: USER_SID }));
    await conference(conferenceForm("conference-end"));
    expect(session.status).toBe("completed");
    const endedAt = session.endedAt;
    // Twilio may retry a callback or deliver them out of order once the conference is gone.
    await conference(conferenceForm("conference-end"));
    await conference(conferenceForm("participant-join", { ParticipantLabel: "user", CallSid: USER_SID }));
    await conference(conferenceForm("participant-leave", { ParticipantLabel: "caller", CallSid: CALLER_SID }));
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "user" })}`, statusForm(USER_SID, "in-progress"));
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "user" })}`, statusForm(USER_SID, "completed"));
    await settle();
    expect(session.status).toBe("completed");
    expect(session.endedAt).toBe(endedAt);
    expect(ctx.twilio.endedCalls).toEqual([]);
    expect(ctx.twilio.redirected).toEqual([]);
  });

  it("a duplicated participant-join is idempotent: one status change and one index entry", async () => {
    const before = ctx.app.callGuard.sessions.indexedSidCount;
    const statuses: string[] = [];
    session.on("status", (status) => statuses.push(status));
    await conference(conferenceForm("participant-join", { ParticipantLabel: "user", CallSid: USER_SID }));
    await conference(conferenceForm("participant-join", { ParticipantLabel: "user", CallSid: USER_SID }));
    expect(statuses).toEqual(["in_progress"]);
    expect(ctx.app.callGuard.sessions.indexedSidCount).toBe(before + 1);
  });

  it("rejects a bad token", async () => {
    const res = await postForm(ctx.app, `/v1/calls/twilio/conference?callID=${session.callId}&token=bad`, conferenceForm("conference-end"));
    expect(res.statusCode).toBe(403);
    expect(session.isEnded).toBe(false);
  });
});

describe("test calls, announcements and stream status", () => {
  let ctx: CallsTestContext;
  beforeEach(async () => {
    ctx = await createCallsTestApp();
  });
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  function testCallSession(): CallSession {
    const line = ctx.db.findCallLine(DEVICE_ID)!;
    return ctx.app.callGuard.sessions.create({
      deviceId: DEVICE_ID,
      line,
      source: "test-call",
      callerNumber: GUARD_NUMBER,
      calledNumber: PROTECTED_NUMBER,
      startedAt: ctx.clock.now(),
      status: "ringing",
    });
  }

  it("test-call TwiML: fork plus the scenario's script, and the test leg's status callbacks drive the session", async () => {
    await registerLine(ctx);
    const session = testCallSession();
    const res = await postForm(ctx.app, `/v1/calls/twilio/test-call?${tokenQuery(session, { scenario: "grandparent" })}`, statusForm(TEST_SID, "in-progress"));
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toMatch(/^text\/xml/);
    expect(res.body).toContain(`<Start><Stream url="wss://relay.test/v1/calls/twilio/media/${session.mediaToken}"`);
    expect(res.body).toContain(`<Say voice="Polly.Matthew-Neural">${scriptForScenario("grandparent").lines[0]!.text}</Say>`);
    expect(res.body).toContain("<Hangup/></Response>");
    expect(session.transcriptionSource).toBe("openai");

    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "test" })}`, statusForm(TEST_SID, "ringing"));
    expect(session.status).toBe("ringing");
    expect(session.twilioCallSid).toBe(TEST_SID);
    expect(ctx.app.callGuard.sessions.byTwilioSid(TEST_SID)).toBe(session);
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "test" })}`, statusForm(TEST_SID, "in-progress"));
    expect(session.status).toBe("in_progress");
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "test" })}`, statusForm(TEST_SID, "completed"));
    expect(session.status).toBe("completed");
    expect(ctx.twilio.redirected).toHaveLength(0);
  });

  it("test-call TwiML speaks the scenario the app chose (index.ts wires demo/scenarios.ts in), not always the built-in script", async () => {
    await registerLine(ctx);
    const session = testCallSession();
    const irs = await postForm(ctx.app, `/v1/calls/twilio/test-call?${tokenQuery(session, { scenario: "irs" })}`, statusForm(TEST_SID, "in-progress"));
    expect(irs.statusCode).toBe(200);
    const irsScript = scriptForScenario("irs");
    expect(irsScript.lines.length).toBeGreaterThan(0);
    for (const line of irsScript.lines) expect(irs.body).toContain(`<Say voice="Polly.Matthew-Neural">${line.text}</Say>`);
    expect(irs.body).not.toContain(DEFAULT_TEST_CALL_SCRIPT.lines[0]!.text);

    // Unknown ids (or none) fall back to the built-in grandparent script rather than failing the call.
    const unknown = await postForm(ctx.app, `/v1/calls/twilio/test-call?${tokenQuery(session, { scenario: "not-a-scenario" })}`, statusForm(TEST_SID, "in-progress"));
    expect(unknown.statusCode).toBe(200);
    expect(unknown.body).toContain(`<Say voice="Polly.Matthew-Neural">${DEFAULT_TEST_CALL_SCRIPT.lines[0]!.text}</Say>`);
  });

  it("announce returns the configured warning, or the text the last speakToUser asked for", async () => {
    await registerLine(ctx);
    const { session } = await inboundCall(ctx);
    const configured = await postForm(ctx.app, `/v1/calls/twilio/announce?${tokenQuery(session)}`, conferenceForm("announcement"));
    expect(configured.statusCode).toBe(200);
    expect(configured.body).toBe(
      `<?xml version="1.0" encoding="UTF-8"?><Response><Say voice="Polly.Joanna-Neural">${ctx.config.calls!.spokenWarningText}</Say></Response>`,
    );
    await ctx.twilio.speakToUser(session, "Custom warning.");
    const custom = await postForm(ctx.app, `/v1/calls/twilio/announce?${tokenQuery(session)}`, conferenceForm("announcement"));
    expect(custom.body).toContain('<Say voice="Polly.Joanna-Neural">Custom warning.</Say>');
    const bad = await postForm(ctx.app, `/v1/calls/twilio/announce?callID=${session.callId}&token=guess`, conferenceForm("announcement"));
    expect(bad.statusCode).toBe(403);
  });

  it("stream status callbacks are acknowledged (and token-checked)", async () => {
    await registerLine(ctx);
    const { session } = await inboundCall(ctx);
    const ok = await postForm(ctx.app, `/v1/calls/twilio/stream?${tokenQuery(session)}`, {
      StreamEvent: "stream-error",
      StreamError: "31920 handshake failed",
      CallSid: CALLER_SID,
    });
    expect(ok.statusCode).toBe(204);
    const bad = await postForm(ctx.app, `/v1/calls/twilio/stream?callID=${session.callId}&token=x`, { StreamEvent: "stream-started" });
    expect(bad.statusCode).toBe(403);
  });

  it("serves the ringback WAV publicly with cache headers", async () => {
    const res = await ctx.app.inject({ method: "GET", url: "/v1/calls/twilio/ringback.wav" });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toBe("audio/wav");
    expect(res.headers["cache-control"]).toBe("public, max-age=86400");
    expect(res.rawPayload.subarray(0, 4).toString("ascii")).toBe("RIFF");
    expect(res.rawPayload.length).toBeGreaterThan(96_000);
  });
});

import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";

import { closeTestApp, createCallsTestApp, deviceHeaders, type CallsTestContext } from "../helpers.js";
import { CALLER_NUMBER, GUARD_NUMBER, PROTECTED_NUMBER, scamResult } from "./fakes.js";
import { LiveClient } from "./liveClient.js";
import {
  USER_SID,
  conferenceForm,
  inboundCall,
  postForm,
  registerLine,
  settle,
  statusForm,
  tokenQuery,
  transcriptionForm,
  waitFor,
} from "./twilio-helpers.js";

/**
 * The whole relay in one piece (docs/CALLS.md §3): Twilio webhooks → session → transcript segments → rules +
 * model → verdict → APNs alert push + spoken warning + live feed + history, with every external service faked.
 * The module tests cover each box; these cover the seams between them after the merge.
 */

const GRANDPARENT_CALLER_LINES = [
  "Grandma, it's me, your grandson. I've been in a car accident and I'm at the police station.",
  "They arrested me and I need bail money tonight or I have to stay in jail. Please don't tell Mom or Dad.",
  "The officer says the fastest way is gift cards. Go to the store, buy Apple gift cards, and read me the numbers on the back.",
  "You have to do it right now, within the hour, and you can't call anyone else about this.",
];

describe("Call Guard end to end", () => {
  let ctx: CallsTestContext;
  let baseUrl: string;
  const clients: LiveClient[] = [];
  const sockets: WebSocket[] = [];

  afterEach(async () => {
    for (const client of clients.splice(0)) client.socket.terminate();
    for (const socket of sockets.splice(0)) if (socket.readyState !== WebSocket.CLOSED) socket.terminate();
    await closeTestApp(ctx);
  });

  async function start(overrides: Parameters<typeof createCallsTestApp>[0] = {}): Promise<void> {
    ctx = await createCallsTestApp(overrides);
    await registerLine(ctx);
    await ctx.app.listen({ port: 0, host: "127.0.0.1" });
    const { port } = ctx.app.server.address() as AddressInfo;
    baseUrl = `ws://127.0.0.1:${port}`;
  }

  async function liveFeed(): Promise<LiveClient> {
    const client = await LiveClient.connect(`${baseUrl}/v1/devices/calls/live`, deviceHeaders());
    clients.push(client);
    const hello = await client.next("hello");
    expect(hello.type).toBe("hello");
    return client;
  }

  it("Twilio transcription path: an inbound scam call is transcribed by Twilio, scored, pushed, spoken and listed", async () => {
    await start({ transcriptionSource: "twilio" });
    ctx.twilio.accountType = "Trial";
    ctx.scorer.respond = () => scamResult();
    const live = await liveFeed();

    // 1. The caller reaches the guard number: TwiML uses Twilio's own transcription on a trial account.
    const { response, session } = await inboundCall(ctx);
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("xml");
    expect(response.body).toContain("<Transcription");
    expect(response.body).not.toContain("<Stream");
    expect(response.body).toContain(`cg-${session.callId}`);
    expect(session.transcriptionSource).toBe("twilio");
    expect(session.status).toBe("ringing");
    expect(ctx.twilio.dialed).toHaveLength(1); // the protected phone was dialled into the conference
    const started = await live.next("call.started");
    expect(started.type === "call.started" && started.call.callID).toBe(session.callId);

    // 2. The protected person answers and joins the conference.
    await postForm(ctx.app, `/v1/calls/twilio/conference?${tokenQuery(session)}`, conferenceForm("participant-join", { ParticipantLabel: "user", CallSid: USER_SID, FriendlyName: `cg-${session.callId}` }));
    expect(session.status).toBe("in_progress");

    // 3. Twilio posts what the caller says; the rules answer instantly, the model shortly after.
    let sequence = 0;
    for (const line of GRANDPARENT_CALLER_LINES) {
      sequence += 1;
      ctx.clock.advance(4000);
      const partial = await postForm(ctx.app, `/v1/calls/twilio/transcription?${tokenQuery(session)}`, transcriptionForm("inbound_track", line.slice(0, 20), false, sequence));
      expect(partial.statusCode).toBeLessThan(300);
      sequence += 1;
      const final = await postForm(ctx.app, `/v1/calls/twilio/transcription?${tokenQuery(session)}`, transcriptionForm("inbound_track", line, true, sequence));
      expect(final.statusCode).toBeLessThan(300);
    }
    sequence += 1;
    await postForm(ctx.app, `/v1/calls/twilio/transcription?${tokenQuery(session)}`, transcriptionForm("outbound_track", "Oh no, which store should I go to?", true, sequence));
    await settle();

    const finals = session.segments.filter((segment) => segment.final);
    expect(finals.map((segment) => segment.speaker)).toEqual(["caller", "caller", "caller", "caller", "user"]);
    expect(session.transcriptText()).toContain("Caller: Grandma");
    expect(session.transcriptText()).toContain("You: Oh no");

    await waitFor(() => session.verdict?.level === "high");
    const verdict = session.verdict!;
    expect(verdict.heuristicScore).toBeGreaterThanOrEqual(0.75);
    expect(verdict.reasons.map((reason) => reason.id)).toEqual(expect.arrayContaining(["call.gift_cards", "call.family_emergency", "call.secrecy"]));
    expect(verdict.category).toBe("scam");
    // The model joins once the cadence allows (250 ms in the test config).
    ctx.clock.advance(1000);
    await waitFor(() => session.verdict?.modelIdentifier !== undefined);
    expect(session.verdict?.modelIdentifier).toBe(scamResult().modelIdentifier);
    expect(session.verdict?.modelRiskScore).toBe(92);
    expect(session.verdict?.summary).toBe(scamResult().summary);

    // 4. Alerts: one when the rules first reach the line's level (medium, after the "accident" line) and one more
    //    when the level rises to high (gift cards) — never again at the same level. Each one is pushed (exact
    //    contract keys), spoken (the user had joined) and broadcast.
    await waitFor(() => session.alerts.some((alert) => alert.level === "high") && ctx.sender.alerts.length >= session.alerts.length && ctx.twilio.spoken.length >= session.alerts.length);
    expect(session.alerts.length).toBeGreaterThanOrEqual(1);
    expect(session.alerts.length).toBeLessThanOrEqual(2);
    expect(session.alerts.map((alert) => alert.level)).toEqual(session.alerts.length === 2 ? ["medium", "high"] : ["high"]);
    expect(ctx.sender.alerts).toHaveLength(session.alerts.length);
    expect(ctx.twilio.spoken).toHaveLength(session.alerts.length);
    const push = ctx.sender.alerts[ctx.sender.alerts.length - 1]!;
    expect(push.title).toBe("Likely scam call");
    expect(push.subtitle).toBe(`Call from ${"+1 (555) 010-0003"}`);
    expect(push.category).toBe("PHISHGUARD_CALL_ALERT");
    expect(push.threadId).toBe("com.mazooni.PhishGuard.calls");
    expect(push.interruptionLevel).toBe("time-sensitive");
    expect(push.collapseId).toBe(`call-${session.callId}`);
    expect(push.contentAvailable).toBe(true);
    expect(push.data).toMatchObject({ kind: "call-alert", callID: session.callId, level: "high", category: "scam", callerNumber: CALLER_NUMBER });
    expect(ctx.twilio.spoken[0]).toMatchObject({ callId: session.callId });
    expect(ctx.twilio.spoken[0]!.text).toContain("PhishGuard");
    expect(session.alerts[session.alerts.length - 1]).toMatchObject({ level: "high", pushed: true, spoken: true });
    let alertEvent = await live.next("call.alert");
    if (alertEvent.type === "call.alert" && alertEvent.alert.level === "medium") alertEvent = await live.next("call.alert");
    expect(alertEvent.type === "call.alert" && alertEvent.alert.level).toBe("high");
    // Reason *titles* may name the tactic ("Asks for gift cards"); transcript wording never reaches the push.
    expect(JSON.stringify(push)).not.toContain("Grandma");
    expect(JSON.stringify(push)).not.toContain("numbers on the back");
    expect(JSON.stringify(push)).not.toContain("police station");

    // 5. The call ends; the record survives without a transcript; the app can list it.
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "caller" })}`, statusForm(session.twilioCallSid!, "completed", { From: CALLER_NUMBER, To: GUARD_NUMBER }));
    await settle();
    expect(session.isEnded).toBe(true);
    const ended = await live.next("call.ended");
    expect(ended.type === "call.ended" && ended.call.status).toBe("completed");

    const stored = ctx.db.findCall(session.callId)!;
    expect(stored.alerted).toBe(true);
    expect(stored.alertLevel).toBe("high");
    expect(stored.verdict?.level).toBe("high");
    // The record keeps the verdict — reason details may quote ≤ 120 chars of the line that tripped a rule, exactly
    // like mail evidence — but never the transcript: a line that tripped nothing is nowhere on disk.
    const raw = JSON.stringify(ctx.db.db.prepare("SELECT * FROM calls WHERE call_id = ?").get(session.callId));
    expect(raw).not.toContain("which store should I go to");
    expect(raw).not.toContain("transcript");
    for (const reason of stored.verdict!.reasons) expect(reason.detail.length).toBeLessThanOrEqual(300);

    const listed = await ctx.app.inject({ method: "GET", url: "/v1/devices/calls", headers: deviceHeaders() });
    expect(listed.statusCode).toBe(200);
    const calls = (listed.json() as { calls: { callID: string; alerted: boolean; verdict?: { level: string }; durationSeconds?: number }[] }).calls;
    expect(calls[0]).toMatchObject({ callID: session.callId, alerted: true, verdict: { level: "high" } });
    const detail = await ctx.app.inject({ method: "GET", url: `/v1/devices/calls/${session.callId}`, headers: deviceHeaders() });
    expect(detail.statusCode).toBe(200);
    const body = detail.json() as { transcript?: { text: string }[] };
    expect(body.transcript?.some((segment) => segment.text.includes("Grandma"))).toBe(true); // retained in memory only
  });

  it("Media Streams path: audio reaches one transcriber per track and the caller track's words raise the alert", async () => {
    await start({ transcriptionSource: "openai" });
    ctx.scorer.respond = () => scamResult();
    const { response, session } = await inboundCall(ctx);
    expect(response.body).toContain(`/v1/calls/twilio/media/${session.mediaToken}`);
    expect(response.body).toContain('track="both_tracks"');

    const socket = await new Promise<WebSocket>((resolve, reject) => {
      const ws = new WebSocket(`${baseUrl}/v1/calls/twilio/media/${session.mediaToken}`, { headers: { "x-twilio-signature": "dGVzdA==" } });
      sockets.push(ws);
      ws.once("open", () => resolve(ws));
      ws.once("error", reject);
    });
    socket.send(JSON.stringify({ event: "connected", protocol: "Call", version: "1.0.0" }));
    socket.send(JSON.stringify({
      event: "start",
      sequenceNumber: "1",
      start: {
        accountSid: "AC" + "0".repeat(32),
        streamSid: "MZ" + "1".repeat(32),
        callSid: session.twilioCallSid,
        tracks: ["inbound", "outbound"],
        mediaFormat: { encoding: "audio/x-mulaw", sampleRate: 8000, channels: 1 },
        customParameters: { callID: session.callId },
      },
      streamSid: "MZ" + "1".repeat(32),
    }));
    await waitFor(() => ctx.transcriber.handles.length >= 1);
    const payload = Buffer.alloc(160, 0xff).toString("base64");
    socket.send(JSON.stringify({ event: "media", sequenceNumber: "2", media: { track: "inbound", chunk: "1", timestamp: "20", payload }, streamSid: "MZ" + "1".repeat(32) }));
    await waitFor(() => (ctx.transcriber.handle("caller", session.callId)?.audio.length ?? 0) >= 1);

    // The user answers; from now on the outbound track is transcribed too.
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "user" })}`, statusForm(USER_SID, "in-progress"));
    expect(session.status).toBe("in_progress");
    socket.send(JSON.stringify({ event: "media", sequenceNumber: "3", media: { track: "outbound", chunk: "1", timestamp: "40", payload }, streamSid: "MZ" + "1".repeat(32) }));
    await waitFor(() => (ctx.transcriber.handle("user", session.callId)?.audio.length ?? 0) >= 1);

    // What OpenAI would have transcribed from those bytes.
    const caller = ctx.transcriber.handle("caller", session.callId)!;
    caller.emit("Hello grandma", false);
    for (const line of GRANDPARENT_CALLER_LINES) {
      ctx.clock.advance(4000);
      caller.emit(line, true);
    }
    ctx.transcriber.handle("user", session.callId)!.emit("Which store do I go to?", true);
    await waitFor(() => session.verdict?.level === "high");
    await waitFor(() => session.alerts.some((alert) => alert.level === "high"));
    expect(ctx.sender.alerts[0]!.data["callID"]).toBe(session.callId);
    expect(session.alerts.every((alert) => alert.pushed && alert.spoken)).toBe(true);

    socket.send(JSON.stringify({ event: "stop", sequenceNumber: "9", stop: { accountSid: "AC" + "0".repeat(32), callSid: session.twilioCallSid }, streamSid: "MZ" + "1".repeat(32) }));
    await waitFor(() => ctx.transcriber.handles.every((handle) => handle.closed));
  });

  it("demo path: a scripted scam call from the app runs the same detector and pushes an alert without Twilio", async () => {
    await start({ twilio: undefined });
    const live = await liveFeed();
    const started = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "grandparent", speed: 4 } });
    expect(started.statusCode).toBe(202);
    const { callID } = started.json() as { callID: string };
    const session = ctx.app.callGuard.sessions.get(callID)!;
    expect(session.source).toBe("demo");
    expect(session.line?.phoneNumber).toBe(PROTECTED_NUMBER);
    const first = await live.next("call.started");
    expect(first.type === "call.started" && first.call.callID).toBe(callID);

    await waitFor(() => session.verdict?.level === "high", 8000);
    await waitFor(() => session.alerts.length >= 1, 2000);
    expect(session.alerts[0]).toMatchObject({ pushed: true, spoken: false }); // nobody is on a phone in a demo
    // The default FakeScorer answers "benign, 5": the model is recorded but the rules carry the verdict (max fusion).
    await waitFor(() => session.verdict?.modelIdentifier !== undefined, 4000);
    expect(session.verdict?.modelRiskScore).toBe(5);
    expect(session.verdict?.level).toBe("high");
    await waitFor(() => session.isEnded, 9000);
    expect(ctx.db.findCall(callID)?.status).toBe("completed");
  }, 20_000);

  it("a benign call never alerts anyone", async () => {
    await start({ transcriptionSource: "twilio" });
    const { session } = await inboundCall(ctx);
    await postForm(ctx.app, `/v1/calls/twilio/conference?${tokenQuery(session)}`, conferenceForm("participant-join", { ParticipantLabel: "user", CallSid: USER_SID }));
    const lines = [
      "Hi Margaret, it's Susan from the pharmacy. Your prescription is ready whenever you'd like to pick it up.",
      "We're open until six today and nine to one on Saturday.",
    ];
    let sequence = 0;
    for (const line of lines) {
      sequence += 1;
      ctx.clock.advance(3000);
      await postForm(ctx.app, `/v1/calls/twilio/transcription?${tokenQuery(session)}`, transcriptionForm("inbound_track", line, true, sequence));
    }
    await settle();
    ctx.clock.advance(1000);
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(session.verdict?.level ?? "safe").toBe("safe");
    expect(ctx.sender.alerts).toHaveLength(0);
    expect(ctx.twilio.spoken).toHaveLength(0);
    expect(session.alerts).toHaveLength(0);
  });
});

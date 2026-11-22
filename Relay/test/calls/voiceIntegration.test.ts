import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";

import { VOICE_ALERT_BODY, VOICE_SPOKEN_ADDENDUM } from "../../src/calls/alerts/text.js";
import { DEFAULT_AI_VOICE_WARNING } from "../../src/calls/config.js";
import { MODULATE_VOICE_PROVIDER } from "../../src/calls/modulate/voiceDetector.js";
import { startTestCall } from "../../src/calls/routes/devices.js";
import type { LiveEvent } from "../../src/calls/types.js";
import { closeTestApp, createCallsTestApp, deviceHeaders, type CallsTestContext } from "../helpers.js";
import { CALLER_NUMBER, GUARD_NUMBER, scamResult, silentLogger } from "./fakes.js";
import { LiveClient } from "./liveClient.js";
import { TEST_SID, USER_SID, inboundCall, postForm, registerLine, statusForm, tokenQuery, waitFor } from "./twilio-helpers.js";

/**
 * AI-voice detection through the whole relay, with every external service faked: Twilio webhook → Media Streams →
 * the caller's audio reaches the voice detector → it reports `synthetic` → AI-voice push + voice-slot
 * announcement + `voice.updated` on the device's live socket — while a scam verdict on the same call still
 * produces the scam alert it always did, in its own slot, under its own collapse id.
 */

const SIGNED = { "x-twilio-signature": "dGVzdA==" };
const STREAM_SID = "MZ" + "1".repeat(32);
const CALLER_PAYLOAD = Buffer.alloc(160, 0x11).toString("base64");
const USER_PAYLOAD = Buffer.alloc(160, 0x22).toString("base64");

const SCAM_LINES = [
  "Grandma, it's me, your grandson. I've been in a car accident and I'm at the police station.",
  "They arrested me and I need bail money tonight or I have to stay in jail. Please don't tell Mom or Dad.",
  "The officer says the fastest way is gift cards. Go to the store, buy Apple gift cards, and read me the numbers on the back.",
  "You have to do it right now, within the hour, and you can't call anyone else about this.",
];

type VoiceUpdated = Extract<LiveEvent, { type: "voice.updated" }>;

describe("AI-voice detection end to end", () => {
  let ctx: CallsTestContext;
  let baseUrl: string;
  const clients: LiveClient[] = [];
  const sockets: WebSocket[] = [];

  afterEach(async () => {
    for (const client of clients.splice(0)) client.socket.terminate();
    for (const socket of sockets.splice(0)) if (socket.readyState !== WebSocket.CLOSED) socket.terminate();
    await closeTestApp(ctx);
  });

  async function start(voiceDetector: boolean): Promise<LiveClient> {
    ctx = await createCallsTestApp({ transcriptionSource: "openai" }, {}, { voiceDetector });
    await registerLine(ctx);
    await ctx.app.listen({ port: 0, host: "127.0.0.1" });
    baseUrl = `ws://127.0.0.1:${(ctx.app.server.address() as AddressInfo).port}`;
    const live = await LiveClient.connect(`${baseUrl}/v1/devices/calls/live`, deviceHeaders());
    clients.push(live);
    await live.next("hello");
    return live;
  }

  async function mediaStream(mediaToken: string, callId: string): Promise<WebSocket> {
    const socket = await new Promise<WebSocket>((resolve, reject) => {
      const ws = new WebSocket(`${baseUrl}/v1/calls/twilio/media/${mediaToken}`, { headers: SIGNED });
      sockets.push(ws);
      ws.once("open", () => resolve(ws));
      ws.once("error", reject);
    });
    socket.send(JSON.stringify({ event: "connected", protocol: "Call", version: "1.0.0" }));
    socket.send(JSON.stringify({ event: "start", sequenceNumber: "1", start: { streamSid: STREAM_SID, tracks: ["inbound", "outbound"], customParameters: { callID: callId } }, streamSid: STREAM_SID }));
    return socket;
  }

  const media = (track: string, payload: string): string =>
    JSON.stringify({ event: "media", sequenceNumber: "2", media: { track, chunk: "1", timestamp: "20", payload }, streamSid: STREAM_SID });

  const voiceUpdates = (live: LiveClient): VoiceUpdated[] => live.received.filter((event): event is VoiceUpdated => event.type === "voice.updated");

  it("inbound call: the caller's audio reaches the detector, `synthetic` warns in its own slot, and the scam alert is unchanged", async () => {
    const live = await start(true);
    ctx.scorer.respond = () => scamResult();
    const detector = ctx.voiceDetector!;

    // 1. The call arrives and Twilio opens the media stream; the detector gets a handle for the caller's track.
    const { session } = await inboundCall(ctx);
    const socket = await mediaStream(session.mediaToken, session.callId);
    await waitFor(() => detector.handles.length === 1);
    expect(detector.handles[0]!.session).toBe(session);
    await waitFor(() => voiceUpdates(live).length === 1);
    expect(voiceUpdates(live)[0]).toMatchObject({ callID: session.callId, voice: { status: "analyzing", provider: MODULATE_VOICE_PROVIDER } });

    // 2. The protected person answers; both tracks flow, and only the caller's reaches the detector.
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "user" })}`, statusForm(USER_SID, "in-progress"));
    expect(session.status).toBe("in_progress");
    for (let index = 0; index < 5; index += 1) {
      socket.send(media("inbound", CALLER_PAYLOAD));
      socket.send(media("outbound", USER_PAYLOAD));
    }
    await waitFor(() => detector.audioFor(session.callId).length === 5 && (ctx.transcriber.handle("user", session.callId)?.audio.length ?? 0) === 5);
    expect(new Set(detector.audioFor(session.callId))).toEqual(new Set([CALLER_PAYLOAD]));

    // 3. The detector judges the caller synthetic: its own push, its own announcement, and the live feed says so.
    detector.handle(session.callId)!.report("synthetic", { syntheticShare: 0.93, confidence: 0.91 });
    await waitFor(() => session.voice?.alert !== undefined);
    expect(session.voice).toMatchObject({ status: "synthetic", alert: { title: "AI voice detected", body: VOICE_ALERT_BODY, pushed: true, spoken: true } });
    expect(ctx.sender.alerts).toHaveLength(1);
    expect(ctx.sender.alerts[0]).toMatchObject({
      title: "AI voice detected",
      subtitle: "Call from +1 (555) 010-0003",
      body: VOICE_ALERT_BODY,
      collapseId: `call-voice-${session.callId}`,
      category: "PHISHGUARD_CALL_ALERT",
      threadId: "com.mazooni.PhishGuard.calls",
      interruptionLevel: "time-sensitive",
      contentAvailable: true,
      data: { kind: "call-voice-alert", callID: session.callId, level: "low", confidence: 0.91, category: "safe", callerNumber: CALLER_NUMBER, sequence: 0, voice: "synthetic" },
    });
    expect(ctx.twilio.voiceSpoken).toEqual([{ callId: session.callId, text: DEFAULT_AI_VOICE_WARNING }]);
    expect(ctx.twilio.spoken).toHaveLength(0);
    // What Twilio fetches for that announcement is the AI-voice text; the scam slot still holds its own default.
    const announced = await postForm(ctx.app, `/v1/calls/twilio/announce?${tokenQuery(session, { slot: "voice" })}`, {});
    expect(announced.body).toContain(`<Say voice="Polly.Joanna-Neural">${DEFAULT_AI_VOICE_WARNING}</Say>`);
    expect((await postForm(ctx.app, `/v1/calls/twilio/announce?${tokenQuery(session)}`, {})).body).toContain(ctx.config.calls!.spokenWarningText);

    await waitFor(() => voiceUpdates(live).length === 3);
    expect(voiceUpdates(live).map((event) => [event.voice.status, event.voice.alert?.spoken])).toEqual([["analyzing", undefined], ["synthetic", undefined], ["synthetic", true]]);
    // Not a scam verdict: no verdict, no scam alert, no level.
    expect(session.verdict).toBeUndefined();
    expect(session.alerts).toHaveLength(0);
    expect(live.received.some((event) => event.type === "verdict.updated" || event.type === "call.alert")).toBe(false);

    // 4. Then the words turn out to be a scam too: the scam alert fires exactly as on any other call.
    const caller = ctx.transcriber.handle("caller", session.callId)!;
    for (const text of SCAM_LINES) {
      ctx.clock.advance(4000);
      caller.emit(text, true);
    }
    await waitFor(() => session.alerts.some((alert) => alert.level === "high"));
    const scamPushes = ctx.sender.alerts.filter((request) => request.collapseId === `call-${session.callId}`);
    expect(scamPushes).toHaveLength(session.alerts.length);
    const scamPush = scamPushes.at(-1)!;
    expect(scamPush.title).toBe("Likely scam call");
    expect(Object.keys(scamPush.data)).toEqual(["kind", "callID", "level", "confidence", "category", "callerNumber", "startedAt", "sequence"]);
    expect(scamPush.data).toMatchObject({ kind: "call-alert", callID: session.callId, level: "high", category: "scam" });
    expect(ctx.sender.alerts.filter((request) => request.collapseId === `call-voice-${session.callId}`)).toHaveLength(1);
    expect(ctx.twilio.spoken).toHaveLength(session.alerts.length);
    expect(ctx.twilio.spoken.every((entry) => entry.text === ctx.config.calls!.spokenWarningText)).toBe(true);
    expect(ctx.twilio.voiceSpoken).toHaveLength(1);
    expect(session.alerts.every((alert) => alert.pushed && alert.spoken)).toBe(true);
    await waitFor(() => live.received.some((event) => event.type === "call.alert" && event.alert.level === "high"));
    // The detector never saw the verdict, and the verdict never saw the detector: rules + model, as always.
    expect(session.verdict).toMatchObject({ level: "high", category: "scam" });
    expect(JSON.stringify(session.verdict)).not.toMatch(/synthetic|A\.I\.|AI-generated|voice/i);
    expect(JSON.stringify(ctx.scorer.inputs)).not.toMatch(/synthetic|AI-generated/i);

    // 5. The record keeps both, separately.
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "caller" })}`, statusForm(session.twilioCallSid!, "completed", { From: CALLER_NUMBER, To: GUARD_NUMBER }));
    await waitFor(() => session.isEnded);
    const ended = await live.next("call.ended");
    expect(ended).toMatchObject({ call: { callID: session.callId, alerted: true, alertLevel: "high", voice: { status: "synthetic", alert: { pushed: true, spoken: true } } } });
    const stored = ctx.db.findCall(session.callId)!;
    expect(stored).toMatchObject({ alerted: true, alertLevel: "high", verdict: { level: "high" }, voice: { status: "synthetic", provider: MODULATE_VOICE_PROVIDER } });
    const row = ctx.db.db.prepare("SELECT * FROM calls WHERE call_id = ?").get(session.callId) as Record<string, unknown>;
    expect(JSON.stringify(row)).not.toContain("transcript");
    // The assessment column holds the assessment and its warning — nothing the caller said.
    const voiceJson = JSON.parse(String(row["voice_json"])) as Record<string, unknown>;
    expect(Object.keys(voiceJson).sort()).toEqual(["alert", "confidence", "detectedAt", "provider", "speechMs", "status", "syntheticShare", "updatedAt"]);
    expect(String(row["voice_json"])).not.toMatch(/Grandma|gift cards|police station/);
    await waitFor(() => detector.handles.every((handle) => handle.closed));
  });

  it("inbound call: a caller judged synthetic before the person answers is announced once they join", async () => {
    await start(true);
    const detector = ctx.voiceDetector!;
    const { session } = await inboundCall(ctx);
    const socket = await mediaStream(session.mediaToken, session.callId);
    await waitFor(() => detector.handles.length === 1);
    socket.send(media("inbound", CALLER_PAYLOAD));
    await waitFor(() => detector.audioFor(session.callId).length === 1);

    expect(session.status).not.toBe("in_progress");
    detector.handle(session.callId)!.report("synthetic");
    await waitFor(() => session.voice?.alert !== undefined);
    expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: false });
    expect(ctx.twilio.voiceSpoken).toHaveLength(0);

    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "user" })}`, statusForm(USER_SID, "in-progress"));
    await waitFor(() => session.voice?.alert?.spoken === true);
    expect(ctx.twilio.voiceSpoken).toEqual([{ callId: session.callId, text: DEFAULT_AI_VOICE_WARNING }]);
    expect(ctx.sender.alerts).toHaveLength(1);
    expect(ctx.db.findCall(session.callId)?.voice?.alert).toMatchObject({ pushed: true, spoken: true });
  });

  it("test call: the scripted call is not cut short by the voice warning; the scam warning carries the extra sentence", async () => {
    await start(true);
    const detector = ctx.voiceDetector!;
    const line = ctx.db.findCallLineByGuardNumber(GUARD_NUMBER)!;
    const session = (await startTestCall({ sessions: ctx.app.callGuard.sessions, twilio: ctx.twilio, calls: ctx.config.calls!, line, scenario: "grandparent", now: ctx.clock.now, log: silentLogger() }))!;
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "test" })}`, statusForm(TEST_SID, "in-progress"));
    expect(session.status).toBe("in_progress");
    const socket = await mediaStream(session.mediaToken, session.callId);
    await waitFor(() => detector.handles.length === 1);
    // On a test call the "caller" is Twilio's text-to-speech on the outbound track.
    socket.send(media("outbound", CALLER_PAYLOAD));
    socket.send(media("inbound", USER_PAYLOAD));
    await waitFor(() => detector.audioFor(session.callId).length === 1);
    expect(detector.audioFor(session.callId)).toEqual([CALLER_PAYLOAD]);

    detector.handle(session.callId)!.report("synthetic");
    await waitFor(() => session.voice?.alert !== undefined);
    expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: false });
    // Nothing was said into the call, in either slot: the script plays on.
    expect(ctx.twilio.spoken).toHaveLength(0);
    expect(ctx.twilio.voiceSpoken).toHaveLength(0);

    const caller = ctx.transcriber.handle("caller", session.callId)!;
    for (const text of SCAM_LINES) {
      ctx.clock.advance(4000);
      caller.emit(text, true);
    }
    await waitFor(() => session.alerts.some((alert) => alert.level === "high") && ctx.twilio.spoken.length === session.alerts.length);
    expect(ctx.twilio.spoken.every((entry) => entry.text === `${ctx.config.calls!.spokenWarningText} ${VOICE_SPOKEN_ADDENDUM}`)).toBe(true);
    expect(ctx.twilio.voiceSpoken).toHaveLength(0);
    await waitFor(() => session.voice?.alert?.spoken === true);
    expect(session.alerts.every((alert) => alert.spoken)).toBe(true);
  });

  it("without a voice detector the same call raises the same scam alert and nothing about voices", async () => {
    const live = await start(false);
    expect(ctx.voiceDetector).toBeUndefined();
    ctx.scorer.respond = () => scamResult();
    const { session } = await inboundCall(ctx);
    const socket = await mediaStream(session.mediaToken, session.callId);
    await waitFor(() => ctx.transcriber.handles.length >= 1);
    await postForm(ctx.app, `/v1/calls/twilio/status?${tokenQuery(session, { leg: "user" })}`, statusForm(USER_SID, "in-progress"));
    socket.send(media("inbound", CALLER_PAYLOAD));
    const caller = ctx.transcriber.handle("caller", session.callId)!;
    for (const text of SCAM_LINES) {
      ctx.clock.advance(4000);
      caller.emit(text, true);
    }
    await waitFor(() => session.alerts.some((alert) => alert.level === "high") && ctx.twilio.spoken.length === session.alerts.length);
    expect(session.voice).toBeUndefined();
    expect(ctx.sender.alerts.every((request) => request.collapseId === `call-${session.callId}` && !("voice" in request.data))).toBe(true);
    expect(ctx.twilio.spoken.every((entry) => entry.text === ctx.config.calls!.spokenWarningText)).toBe(true);
    expect(ctx.twilio.voiceSpoken).toHaveLength(0);
    expect(voiceUpdates(live)).toHaveLength(0);
    expect(ctx.app.callGuard.voiceDispatcher.pendingCalls).toBe(0);
    session.end("completed");
    expect(ctx.db.db.prepare("SELECT voice_json FROM calls WHERE call_id = ?").get(session.callId)).toEqual({ voice_json: null });
  });
});

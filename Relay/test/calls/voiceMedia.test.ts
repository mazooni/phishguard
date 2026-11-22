import type { AddressInfo } from "node:net";
import { once } from "node:events";
import type { FastifyBaseLogger } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import WebSocket from "ws";

import { MODULATE_VOICE_PROVIDER, createVoiceDetector } from "../../src/calls/modulate/voiceDetector.js";
import { CallSession } from "../../src/calls/session.js";
import { MediaConnection, type MediaSocket } from "../../src/calls/twilio/media.js";
import type { VoiceDetector, VoiceDetectorHandle } from "../../src/calls/types.js";
import { RelayDb } from "../../src/db.js";
import { buildApp } from "../../src/server.js";
import { API_KEY, DEVICE_ID, FakeClock, FakeSender, FakeVerifier, closeTestApp, createCallsTestApp, registerDevice, testConfig, type CallsTestContext } from "../helpers.js";
import { CALLER_NUMBER, FakeTranscriber, FakeVoiceDetector, GUARD_NUMBER, MODULATE_TEST_KEY, silentLogger, testCallsConfig, testVoiceConfig } from "./fakes.js";
import { LiveClient } from "./liveClient.js";
import { replyDone, startModulateServer, type FakeModulateServer } from "./modulateServer.js";
import { inboundCall, registerLine, waitFor } from "./twilio-helpers.js";

/**
 * Who gets which audio on a Media Streams connection once a voice detector exists: the CALLER's track goes to one
 * voice handle, whoever transcribes the call; the protected person's track never does; and without a detector
 * the connection behaves — and logs — exactly as before.
 */

const SIGNED = { "x-twilio-signature": "dGVzdA==" };
const STREAM_SID = "MZ" + "1".repeat(32);
const CALLER_AUDIO = Buffer.from([0xff, 0x7f, 0x80, 0x00]).toString("base64");
const USER_AUDIO = Buffer.from([0x01, 0x02, 0x03, 0x04]).toString("base64");

function startMessage(callId: string, tracks: string[] | undefined = ["inbound", "outbound"]): string {
  return JSON.stringify({
    event: "start",
    sequenceNumber: "1",
    start: { streamSid: STREAM_SID, callSid: "CA" + "a".repeat(32), ...(tracks ? { tracks } : {}), customParameters: { callID: callId } },
    streamSid: STREAM_SID,
  });
}

function mediaMessage(track: string, payload: string): string {
  return JSON.stringify({ event: "media", sequenceNumber: "2", media: { track, chunk: "1", timestamp: "20", payload }, streamSid: STREAM_SID });
}

const STOP = JSON.stringify({ event: "stop", sequenceNumber: "9", stop: { accountSid: "AC", callSid: "CA" }, streamSid: STREAM_SID });

class StubSocket implements MediaSocket {
  readonly listeners = new Map<string, ((...args: never[]) => void)[]>();
  closedWith: { code: number | undefined; reason: string | undefined } | undefined;
  terminated = false;
  on(event: string, listener: (...args: never[]) => void): this {
    const list = this.listeners.get(event) ?? [];
    list.push(listener);
    this.listeners.set(event, list);
    return this;
  }
  close(code?: number, reason?: string): void {
    this.closedWith = { code, reason };
    for (const listener of this.listeners.get("close") ?? []) (listener as () => void)();
  }
  terminate(): void {
    this.terminated = true;
  }
}

/** Records `[level, message]` for every line; `child()` returns itself. */
function recordingLogger(): { logger: FastifyBaseLogger; lines: [string, string][]; fields: unknown[] } {
  const lines: [string, string][] = [];
  const fields: unknown[] = [];
  const log =
    (level: string) =>
    (data: unknown, message?: string): void => {
      lines.push([level, typeof data === "string" ? data : (message ?? "")]);
      fields.push(data);
    };
  const logger = {
    level: "trace",
    fatal: log("fatal"),
    error: log("error"),
    warn: log("warn"),
    info: log("info"),
    debug: log("debug"),
    trace: log("trace"),
    silent: (): void => undefined,
    child: () => logger,
  } as unknown as FastifyBaseLogger;
  return { logger, lines, fields };
}

function unitSession(source: "twilio" | "test-call" | "replay" = "twilio", transcriptionSource: "twilio" | "openai" = "openai"): CallSession {
  return new CallSession({
    deviceId: "device-1",
    line: null,
    source,
    callerNumber: CALLER_NUMBER,
    calledNumber: GUARD_NUMBER,
    startedAt: 1_760_000_000_000,
    status: "in_progress",
    transcriptionSource,
  });
}

interface Unit {
  session: CallSession;
  socket: StubSocket;
  connection: MediaConnection;
  transcriber: FakeTranscriber | undefined;
  voice: FakeVoiceDetector | undefined;
  lines: [string, string][];
  /** `stopStream` requests made to Twilio: `[callSid, streamSid]`. */
  stopped: [string, string][];
}

function unit(options: {
  source?: "twilio" | "test-call" | "replay";
  transcription?: "twilio" | "openai";
  transcriber?: boolean;
  voice?: boolean;
  transcribeTracks?: "both" | "caller";
  /** `false`: no way to ask Twilio (a replay, or a relay without Twilio). */
  stopStream?: boolean;
}): Unit {
  const session = unitSession(options.source ?? "twilio", options.transcription ?? "openai");
  const socket = new StubSocket();
  const transcriber = options.transcriber === false ? undefined : new FakeTranscriber();
  const voice = options.voice === false ? undefined : new FakeVoiceDetector();
  const { logger, lines } = recordingLogger();
  const stopped: [string, string][] = [];
  const connection = new MediaConnection(socket, {
    session,
    transcriber,
    transcribeTracks: options.transcribeTracks ?? "both",
    logger,
    ...(voice ? { voiceDetector: voice } : {}),
    ...(options.stopStream === false
      ? {}
      : {
          stopStream: async (callSid: string, streamSid: string) => {
            stopped.push([callSid, streamSid]);
            return true;
          },
        }),
  });
  connection.attach();
  return { session, socket, connection, transcriber, voice, lines, stopped };
}

describe("MediaConnection with a voice detector (unit)", () => {
  it("feeds the caller's track to one voice handle and to the transcriber; the user's track only to the transcriber", () => {
    const { session, connection, transcriber, voice } = unit({});
    connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO)); // before `start`: dropped for everyone
    connection.handleMessage(startMessage(session.callId));
    expect(voice!.handles).toHaveLength(1);
    expect(voice!.handles[0]!.session).toBe(session);
    connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    connection.handleMessage(mediaMessage("outbound", USER_AUDIO));
    connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    expect(voice!.handles[0]!.audio).toEqual([CALLER_AUDIO, CALLER_AUDIO]);
    expect(transcriber!.handle("caller")?.audio).toEqual([CALLER_AUDIO, CALLER_AUDIO]);
    expect(transcriber!.handle("user")?.audio).toEqual([USER_AUDIO]);
    // The stats still describe the transcriber path, exactly as without a detector.
    expect(connection.stats).toEqual({ frames: 5, forwarded: 3, dropped: 1, invalid: 0 });
    expect(session.voice?.status).toBe("analyzing");
  });

  it("never gives the voice detector the protected person's track, in any spelling", () => {
    const { session, connection, voice } = unit({});
    connection.handleMessage(startMessage(session.callId));
    for (const track of ["outbound", "outbound_track", "user", "USER", "sideways"]) connection.handleMessage(mediaMessage(track, USER_AUDIO));
    expect(voice!.handles[0]!.audio).toEqual([]);
    for (const track of ["inbound", "inbound_track", "caller"]) connection.handleMessage(mediaMessage(track, CALLER_AUDIO));
    expect(voice!.handles[0]!.audio).toEqual([CALLER_AUDIO, CALLER_AUDIO, CALLER_AUDIO]);
  });

  it("the caller's audio reaches the detector while the phone is still ringing (only the user's track is gated)", () => {
    const session = new CallSession({ deviceId: "d", line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: 1, transcriptionSource: "openai" });
    const voice = new FakeVoiceDetector();
    const transcriber = new FakeTranscriber();
    const connection = new MediaConnection(new StubSocket(), { session, transcriber, transcribeTracks: "both", logger: silentLogger(), voiceDetector: voice });
    connection.attach();
    expect(session.status).toBe("ringing");
    connection.handleMessage(startMessage(session.callId));
    connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    connection.handleMessage(mediaMessage("outbound", USER_AUDIO)); // ringback
    expect(voice.handles[0]!.audio).toEqual([CALLER_AUDIO]);
    expect(transcriber.handle("user")?.audio).toEqual([]);
  });

  it("on a test call the tracks are swapped: the scripted caller is the OUTBOUND track, the person the inbound one", () => {
    const { session, connection, transcriber, voice } = unit({ source: "test-call" });
    connection.handleMessage(startMessage(session.callId));
    connection.handleMessage(mediaMessage("outbound", CALLER_AUDIO));
    connection.handleMessage(mediaMessage("inbound", USER_AUDIO));
    expect(voice!.handles[0]!.audio).toEqual([CALLER_AUDIO]);
    expect(transcriber!.handle("caller")?.audio).toEqual([CALLER_AUDIO]);
    expect(transcriber!.handle("user")?.audio).toEqual([USER_AUDIO]);
  });

  it("works on a session Twilio transcribes: the caller-only stream feeds the detector, no transcriber handle, no warning", () => {
    const { session, connection, transcriber, voice, lines } = unit({ transcription: "twilio" });
    connection.handleMessage(startMessage(session.callId, ["inbound"]));
    connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    expect(voice!.handles[0]!.audio).toEqual([CALLER_AUDIO, CALLER_AUDIO]);
    expect(transcriber!.handles).toHaveLength(0);
    expect(lines.filter(([level]) => level === "warn")).toEqual([]);
    // Nothing went to a transcriber, and the stats say so as they always did.
    expect(connection.stats).toEqual({ frames: 3, forwarded: 0, dropped: 2, invalid: 0 });
  });

  it("stops a stream that fed only the detector once the detector has finished, and no other stream", async () => {
    const flush = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));
    // The caller-only fork of a call Twilio transcribes: nothing else uses it.
    const only = unit({ transcription: "twilio" });
    only.connection.handleMessage(startMessage(only.session.callId, ["inbound"]));
    only.connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    await flush();
    expect(only.stopped).toEqual([]); // still being analysed
    only.voice!.handles[0]!.finish();
    await flush();
    expect(only.stopped).toEqual([["CA" + "a".repeat(32), STREAM_SID]]);
    expect(only.lines).toContainEqual(["info", "calls: voice detector finished; stopping its media stream"]);
    // The socket is not closed from here: Twilio's own `stop` ends the stream, as for any other.
    expect(only.connection.isClosed).toBe(false);

    // A stream that also feeds the transcriber goes on.
    const shared = unit({});
    shared.connection.handleMessage(startMessage(shared.session.callId));
    shared.voice!.handles[0]!.finish();
    await flush();
    expect(shared.stopped).toEqual([]);

    // Finished because the call (or the stream) is over: nothing left to stop.
    const ended = unit({ transcription: "twilio" });
    ended.connection.handleMessage(startMessage(ended.session.callId, ["inbound"]));
    ended.connection.close();
    ended.voice!.handles[0]!.finish();
    await flush();
    expect(ended.stopped).toEqual([]);

    // No Twilio to ask (a replay): nothing happens and nothing throws.
    const replay = unit({ source: "replay", transcriber: false, stopStream: false });
    replay.connection.handleMessage(startMessage(replay.session.callId));
    replay.voice!.handles[0]!.finish();
    await flush();
    expect(replay.connection.isClosed).toBe(false);
  });

  it("works on a Twilio-transcribed test call, whose caller-only stream is the outbound track", () => {
    const { session, connection, voice } = unit({ source: "test-call", transcription: "twilio" });
    connection.handleMessage(startMessage(session.callId, ["outbound"]));
    connection.handleMessage(mediaMessage("outbound", CALLER_AUDIO));
    expect(voice!.handles[0]!.audio).toEqual([CALLER_AUDIO]);
  });

  it("works without any transcriber (a replay on a relay that has only the voice detector)", () => {
    const { session, connection, voice, lines } = unit({ source: "replay", transcriber: false });
    connection.handleMessage(startMessage(session.callId));
    connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    connection.handleMessage(mediaMessage("outbound", USER_AUDIO));
    expect(voice!.handles[0]!.audio).toEqual([CALLER_AUDIO]);
    expect(lines.filter(([level]) => level === "warn")).toEqual([]);
  });

  it("opens no voice handle for a stream that does not carry the caller's track", () => {
    const { session, connection, voice, lines } = unit({ transcription: "twilio" });
    connection.handleMessage(startMessage(session.callId, ["outbound"])); // the person's track only
    connection.handleMessage(mediaMessage("outbound", USER_AUDIO));
    expect(voice!.handles).toHaveLength(0);
    expect(session.voice).toBeUndefined();
    // …so the audio really is ignored, and the existing warning says so.
    expect(lines.filter(([level]) => level === "warn")).toEqual([["warn", "calls: media stream on a session Twilio transcribes; audio ignored"]]);

    const swapped = unit({ source: "test-call" });
    swapped.connection.handleMessage(startMessage(swapped.session.callId, ["inbound"])); // on a test call: the person
    expect(swapped.voice!.handles).toHaveLength(0);
  });

  it("assumes both tracks when `start` names none, and opens one handle even if `start` repeats", () => {
    const { session, connection, voice } = unit({});
    connection.handleMessage(startMessage(session.callId, undefined));
    connection.handleMessage(startMessage(session.callId, undefined));
    expect(voice!.handles).toHaveLength(1);
  });

  it("with CALLS_TRANSCRIBE_TRACKS=caller the single caller stream feeds both consumers", () => {
    const { session, connection, transcriber, voice } = unit({ transcribeTracks: "caller" });
    connection.handleMessage(startMessage(session.callId, ["inbound"]));
    connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    expect(transcriber!.handles.map((handle) => handle.speaker)).toEqual(["caller"]);
    expect(voice!.handles[0]!.audio).toEqual([CALLER_AUDIO]);
  });

  it("closes the voice handle on stop, on the socket's close, when the session ends and on terminate()", () => {
    const stopped = unit({});
    stopped.connection.handleMessage(startMessage(stopped.session.callId));
    stopped.connection.handleMessage(STOP);
    expect(stopped.voice!.handles[0]!.closed).toBe(true);
    stopped.connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    expect(stopped.voice!.handles[0]!.audio).toEqual([]);

    const dropped = unit({ transcription: "twilio" });
    dropped.connection.handleMessage(startMessage(dropped.session.callId, ["inbound"]));
    dropped.socket.close();
    expect(dropped.voice!.handles[0]!.closed).toBe(true);

    const ended = unit({});
    ended.connection.handleMessage(startMessage(ended.session.callId));
    ended.session.end("completed");
    expect(ended.voice!.handles[0]!.closed).toBe(true);
    expect(ended.socket.closedWith?.code).toBe(1000);
    // A call that ended while the detector was still analysing is inconclusive (the session settles it).
    expect(ended.session.voice?.status).toBe("inconclusive");

    const terminated = unit({ transcriber: false });
    terminated.connection.handleMessage(startMessage(terminated.session.callId));
    terminated.connection.terminate();
    expect(terminated.voice!.handles[0]!.closed).toBe(true);
    expect(terminated.socket.terminated).toBe(true);
  });

  it("a voice handle whose close() rejects is logged by name only and does not stop the connection closing", async () => {
    const session = unitSession();
    const { logger, lines, fields } = recordingLogger();
    const leaky = new Error("close failed wss://vendor.example/?api_key=secret-value");
    const detector: VoiceDetector = {
      open: (): VoiceDetectorHandle => ({ pushAudio: () => undefined, close: () => Promise.reject(leaky) }),
      close: async () => undefined,
    };
    const socket = new StubSocket();
    const connection = new MediaConnection(socket, { session, transcriber: undefined, transcribeTracks: "both", logger, voiceDetector: detector });
    connection.attach();
    connection.handleMessage(startMessage(session.callId));
    connection.close();
    await new Promise((resolve) => setImmediate(resolve));
    expect(socket.closedWith).toBeDefined();
    expect(lines).toContainEqual(["warn", "calls: voice detector handle close failed"]);
    expect(JSON.stringify(fields)).not.toContain("secret-value");
    expect(fields.some((entry) => Object.values(entry as object).some((value) => value instanceof Error))).toBe(false);
  });

  it("a detector that cannot be opened costs the call nothing: transcription goes on", () => {
    const session = unitSession();
    const transcriber = new FakeTranscriber();
    const { logger, lines } = recordingLogger();
    const detector: VoiceDetector = {
      open: () => {
        throw new Error("boom");
      },
      close: async () => undefined,
    };
    const connection = new MediaConnection(new StubSocket(), { session, transcriber, transcribeTracks: "both", logger, voiceDetector: detector });
    connection.attach();
    expect(() => connection.handleMessage(startMessage(session.callId))).not.toThrow();
    connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    expect(transcriber.handle("caller")?.audio).toEqual([CALLER_AUDIO]);
    expect(lines).toContainEqual(["warn", "calls: voice detector could not be opened"]);
  });
});

describe("MediaConnection without a voice detector: exactly as before", () => {
  it("logs the same lines for a transcribed stream, with and without the option being spelled out", () => {
    const expected: [string, string][] = [
      ["info", "calls: media stream started"],
      ["info", "calls: media stream stopped"],
    ];
    for (const spelled of [false, true]) {
      const session = unitSession();
      const { logger, lines } = recordingLogger();
      const connection = new MediaConnection(new StubSocket(), {
        session,
        transcriber: new FakeTranscriber(),
        transcribeTracks: "both",
        logger,
        ...(spelled ? { voiceDetector: undefined } : {}),
      });
      connection.attach();
      connection.handleMessage(startMessage(session.callId));
      connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
      connection.handleMessage(STOP);
      expect(lines).toEqual(expected);
      expect(session.voice).toBeUndefined();
    }
  });

  it("keeps the exact warnings for a Twilio-transcribed session and for a missing transcriber, and ignores the audio", () => {
    const twilio = unit({ transcription: "twilio", voice: false });
    twilio.connection.handleMessage(startMessage(twilio.session.callId));
    twilio.connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    expect(twilio.lines).toEqual([["warn", "calls: media stream on a session Twilio transcribes; audio ignored"]]);
    expect(twilio.transcriber!.handles).toHaveLength(0);
    expect(twilio.connection.stats).toEqual({ frames: 2, forwarded: 0, dropped: 1, invalid: 0 });

    const bare = unit({ transcriber: false, voice: false });
    bare.connection.handleMessage(startMessage(bare.session.callId));
    bare.connection.handleMessage(mediaMessage("inbound", CALLER_AUDIO));
    expect(bare.lines).toEqual([["warn", "calls: media stream without a transcriber; audio ignored"]]);
    expect(bare.session.voice).toBeUndefined();
  });
});

describe("the media WebSocket route with a voice detector", () => {
  let ctx: CallsTestContext | undefined;
  const sockets: WebSocket[] = [];
  afterEach(async () => {
    for (const socket of sockets.splice(0)) if (socket.readyState !== WebSocket.CLOSED) socket.terminate();
    if (ctx) await closeTestApp(ctx);
    ctx = undefined;
  });

  async function listen(context: CallsTestContext): Promise<string> {
    await context.app.listen({ port: 0, host: "127.0.0.1" });
    return `ws://127.0.0.1:${(context.app.server.address() as AddressInfo).port}`;
  }

  function connect(url: string, headers: Record<string, string> = SIGNED): Promise<WebSocket> {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(url, { headers });
      sockets.push(socket);
      socket.once("open", () => resolve(socket));
      socket.once("error", reject);
    });
  }

  it("is opt-in for the test app: no detector unless asked for", async () => {
    ctx = await createCallsTestApp();
    expect(ctx.voiceDetector).toBeUndefined();
  });

  it("passes the detector to the connection: a Twilio-transcribed call's caller stream reaches it, per call", async () => {
    ctx = await createCallsTestApp({ transcriptionSource: "twilio" }, {}, { voiceDetector: true });
    const voice = ctx.voiceDetector!;
    await registerLine(ctx);
    const base = await listen(ctx);
    const { session } = await inboundCall(ctx);
    expect(session.transcriptionSource).toBe("twilio");
    const socket = await connect(`${base}/v1/calls/twilio/media/${session.mediaToken}`);
    socket.send('{"event":"connected","protocol":"Call","version":"1.0.0"}');
    socket.send(startMessage(session.callId, ["inbound"]));
    socket.send(mediaMessage("inbound", CALLER_AUDIO));
    socket.send(mediaMessage("inbound", CALLER_AUDIO));
    await waitFor(() => voice.audioFor(session.callId).length === 2);
    expect(voice.handle(session.callId)?.audio).toEqual([CALLER_AUDIO, CALLER_AUDIO]);
    expect(ctx.transcriber.handles).toHaveLength(0);

    // The assessment the detector reports travels the normal way: the session, the database.
    voice.handle(session.callId)!.report("human", { confidence: 0.9 });
    expect(ctx.db.findCall(session.callId)?.voice).toMatchObject({ status: "human", confidence: 0.9 });
    // It never touches the scam verdict.
    expect(session.verdict).toBeUndefined();

    const closed = once(socket, "close");
    socket.send(STOP);
    await closed;
    expect(voice.handle(session.callId)?.closed).toBe(true);
  });

  it("a second media stream for the call supersedes the first: its voice handle is closed, the new one takes over", async () => {
    ctx = await createCallsTestApp({}, {}, { voiceDetector: true });
    const voice = ctx.voiceDetector!;
    await registerLine(ctx);
    const base = await listen(ctx);
    const { session } = await inboundCall(ctx);
    const first = await connect(`${base}/v1/calls/twilio/media/${session.mediaToken}`);
    first.send(startMessage(session.callId));
    await waitFor(() => voice.handles.length === 1);
    const second = await connect(`${base}/v1/calls/twilio/media/${session.mediaToken}`);
    await waitFor(() => voice.handles[0]!.closed);
    second.send(startMessage(session.callId));
    second.send(mediaMessage("inbound", CALLER_AUDIO));
    await waitFor(() => voice.handles.length === 2 && voice.handles[1]!.audio.length === 1);
    expect(voice.handles[1]!.closed).toBe(false);
  });

  it("closes the detector with the app", async () => {
    ctx = await createCallsTestApp({}, {}, { voiceDetector: true });
    const voice = ctx.voiceDetector!;
    expect(voice.closed).toBe(false);
    await closeTestApp(ctx);
    ctx = undefined;
    expect(voice.closed).toBe(true);
  });

  it("a replay is accepted with only a voice detector (no OpenAI), and its caller channel is analysed", async () => {
    const clock = new FakeClock();
    const db = RelayDb.open(":memory:");
    const voice = new FakeVoiceDetector();
    const sender = new FakeSender();
    const verifier = new FakeVerifier();
    const config = testConfig({ calls: testCallsConfig({ twilio: undefined, openai: undefined }) });
    const app = buildApp({
      config,
      db,
      pushSender: sender,
      tokenVerifier: verifier,
      logger: false,
      calls: { twilio: undefined, transcriber: undefined, scorer: undefined, voiceDetector: voice, now: clock.now },
    });
    await app.ready();
    ctx = { app, db, sender, verifier, config, clock } as unknown as CallsTestContext;
    await registerDevice(app, { apnsToken: null });
    const base = await listen(ctx);

    const ticket = await app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: { "x-api-key": API_KEY }, payload: { deviceID: DEVICE_ID } });
    expect(ticket.statusCode).toBe(202);
    const { callID, mediaPath } = ticket.json() as { callID: string; mediaPath: string };
    const socket = await connect(`${base}${mediaPath}`, { "x-api-key": API_KEY });
    socket.send(startMessage(callID));
    socket.send(mediaMessage("inbound", CALLER_AUDIO));
    socket.send(mediaMessage("outbound", USER_AUDIO));
    await waitFor(() => voice.audioFor(callID).length === 1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(voice.audioFor(callID)).toEqual([CALLER_AUDIO]);
    expect(app.callGuard.sessions.get(callID)?.voice?.status).toBe("analyzing");
  });
});

describe("end to end: Twilio-shaped media → the real detector → a server speaking the vendor's protocol", () => {
  let vendor: FakeModulateServer | undefined;
  let ctx: CallsTestContext | undefined;
  const sockets: WebSocket[] = [];
  const clients: LiveClient[] = [];
  afterEach(async () => {
    for (const client of clients.splice(0)) await client.close();
    for (const socket of sockets.splice(0)) if (socket.readyState !== WebSocket.CLOSED) socket.terminate();
    if (ctx) await closeTestApp(ctx);
    ctx = undefined;
    await vendor?.close();
    vendor = undefined;
  });

  it("only the caller's μ-law reaches the vendor; its frames become the call's assessment, live and in the database", async () => {
    vendor = await startModulateServer({
      onEndOfStream: (socket, connection) =>
        replyDone(socket, connection, [
          { start_time_ms: 0, end_time_ms: 4000, verdict: "synthetic", confidence: 0.96 },
          { start_time_ms: 4000, end_time_ms: 8000, verdict: "synthetic", confidence: 0.9 },
        ]),
    });
    const clock = new FakeClock();
    const db = RelayDb.open(":memory:");
    const sender = new FakeSender();
    const verifier = new FakeVerifier();
    const transcriber = new FakeTranscriber();
    const config = testConfig({ calls: testCallsConfig({ twilio: undefined }) });
    // The real client with its real socket factory; only the endpoint is the in-process server.
    const voiceDetector = createVoiceDetector({ config: testVoiceConfig(), logger: silentLogger(), url: vendor.url });
    const app = buildApp({ config, db, pushSender: sender, tokenVerifier: verifier, logger: false, calls: { twilio: undefined, transcriber, voiceDetector, now: clock.now } });
    await app.ready();
    ctx = { app, db, sender, verifier, config, clock } as unknown as CallsTestContext;
    await registerDevice(app, { apnsToken: null });
    await app.listen({ port: 0, host: "127.0.0.1" });
    const base = `ws://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
    const live = await LiveClient.connect(`${base}/v1/calls/console/ws`, { "x-api-key": API_KEY });
    clients.push(live);
    await live.next("hello");

    const ticket = await app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: { "x-api-key": API_KEY }, payload: { deviceID: DEVICE_ID } });
    const { callID, mediaPath } = ticket.json() as { callID: string; mediaPath: string };
    const socket = new WebSocket(`${base}${mediaPath}`, { headers: { "x-api-key": API_KEY } });
    sockets.push(socket);
    await once(socket, "open");
    socket.send(startMessage(callID));
    // 400 ms of each track, 20 ms payloads: the caller's bytes are 0x11, the protected person's 0x22.
    const callerPayload = Buffer.alloc(160, 0x11).toString("base64");
    const userPayload = Buffer.alloc(160, 0x22).toString("base64");
    const sendBoth = (count: number): void => {
      for (let index = 0; index < count; index += 1) {
        socket.send(mediaMessage("inbound", callerPayload));
        socket.send(mediaMessage("outbound", userPayload));
      }
    };
    sendBoth(10);
    // The first 200 ms arrive at the vendor once its socket is open (a stream that stops before that sends nothing).
    await waitFor(() => (vendor?.connections[0]?.messages.length ?? 0) >= 1, 5000);
    sendBoth(10);
    socket.send(STOP);

    const session = app.callGuard.sessions.get(callID)!;
    await waitFor(() => session.voice?.status === "synthetic", 5000);
    expect(session.voice).toMatchObject({ status: "synthetic", syntheticShare: 1, speechMs: 8000, provider: MODULATE_VOICE_PROVIDER });
    expect(session.voice?.confidence).toBeCloseTo((2000 * 0.96 + 4000 * 0.9) / 6000, 10);

    // The vendor saw one connection, binary audio made of the caller's bytes only, then the empty text frame.
    expect(vendor.connections).toHaveLength(1);
    const messages = vendor.connections[0]!.messages;
    const audio = Buffer.concat(messages.filter((message) => message.binary).map((message) => message.data));
    expect(audio.length).toBe(20 * 160);
    expect(audio.every((byte) => byte === 0x11)).toBe(true);
    expect(messages.at(-1)).toMatchObject({ binary: false });
    expect(messages.at(-1)!.data.length).toBe(0);
    expect(vendor.connections[0]!.requestUrl).toBe(`/api/velma-2-synthetic-voice-detection-streaming?api_key=${MODULATE_TEST_KEY}&audio_format=mulaw&sample_rate=8000&num_channels=1`);

    // Both consumers got their audio: the transcriber is untouched by the detector's presence.
    expect(transcriber.handle("caller", callID)?.audio).toHaveLength(20);
    expect(transcriber.handle("user", callID)?.audio).toHaveLength(20);

    // The live feed and the database carry the assessment; the scam verdict was never involved.
    // Three updates: opened (analysing), the first frame moved the share, the second completed the window.
    const updates = await live.collect(3, "voice.updated");
    expect(updates[0]).toMatchObject({ type: "voice.updated", callID, voice: { status: "analyzing", syntheticShare: 0 } });
    expect(updates[1]).toMatchObject({ type: "voice.updated", callID, voice: { status: "analyzing", syntheticShare: 1 } });
    expect(updates[2]).toMatchObject({ type: "voice.updated", callID, voice: { status: "synthetic", speechMs: 8000 } });
    expect(db.findCall(callID)?.voice).toMatchObject({ status: "synthetic", provider: MODULATE_VOICE_PROVIDER });
    expect(session.verdict).toBeUndefined();
    expect(sender.alerts).toEqual([]);
    const raw = db.db.prepare("SELECT * FROM calls WHERE call_id = ?").get(callID) as Record<string, unknown>;
    expect(JSON.stringify(raw)).not.toContain("transcript");
    expect(JSON.stringify(raw)).not.toContain(MODULATE_TEST_KEY);
  });
});

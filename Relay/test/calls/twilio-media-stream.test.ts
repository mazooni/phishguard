import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import WebSocket from "ws";

import { CallSession } from "../../src/calls/session.js";
import { CLOSE_POLICY_VIOLATION, MediaConnection, parseMediaMessage, type MediaSocket } from "../../src/calls/twilio/media.js";
import { RelayDb } from "../../src/db.js";
import { buildApp } from "../../src/server.js";
import { API_KEY, DEVICE_ID, FakeClock, FakeSender, FakeVerifier, closeTestApp, createCallsTestApp, registerDevice, testConfig, type CallsTestContext } from "../helpers.js";
import { CALLER_NUMBER, FakeScorer, FakeTranscriber, FakeTwilioClient, GUARD_NUMBER, silentLogger, testCallsConfig } from "./fakes.js";
import { inboundCall, registerLine, waitFor } from "./twilio-helpers.js";

/** Any value: the fake Twilio client validates every signature unless told to reject. */
const SIGNED = { "x-twilio-signature": "dGVzdA==" };

const STREAM_SID = "MZ" + "1".repeat(32);
const PAYLOAD_A = Buffer.from([0xff, 0x7f, 0x80, 0x00]).toString("base64");
const PAYLOAD_B = Buffer.from([0x01, 0x02, 0x03, 0x04]).toString("base64");

function startMessage(callId: string, tracks = ["inbound", "outbound"]): string {
  return JSON.stringify({
    event: "start",
    sequenceNumber: "1",
    start: {
      accountSid: "AC" + "0".repeat(32),
      streamSid: STREAM_SID,
      callSid: "CA" + "a".repeat(32),
      tracks,
      mediaFormat: { encoding: "audio/x-mulaw", sampleRate: 8000, channels: 1 },
      customParameters: { callID: callId },
    },
    streamSid: STREAM_SID,
  });
}

function mediaMessage(track: string, payload: string, chunk = 1): string {
  return JSON.stringify({ event: "media", sequenceNumber: String(chunk + 1), media: { track, chunk: String(chunk), timestamp: String(chunk * 20), payload }, streamSid: STREAM_SID });
}

describe("parseMediaMessage", () => {
  it("parses every documented event leniently and rejects non-JSON frames", () => {
    expect(parseMediaMessage('{"event":"connected","protocol":"Call","version":"1.0.0"}')).toEqual({ event: "connected" });
    expect(parseMediaMessage(Buffer.from(startMessage("abc")))).toEqual({
      event: "start",
      start: { streamSid: STREAM_SID, callSid: "CA" + "a".repeat(32), tracks: ["inbound", "outbound"], customParameters: { callID: "abc" } },
    });
    expect(parseMediaMessage(mediaMessage("inbound", PAYLOAD_A))).toEqual({ event: "media", track: "inbound", payload: PAYLOAD_A });
    expect(parseMediaMessage('{"event":"media","media":{"track":"inbound"}}')).toEqual({ event: "other", name: "media-invalid" });
    expect(parseMediaMessage('{"event":"dtmf","dtmf":{"track":"inbound_track","digit":"1"}}')).toEqual({ event: "dtmf" });
    expect(parseMediaMessage('{"event":"mark","mark":{"name":"x"}}')).toEqual({ event: "mark" });
    expect(parseMediaMessage('{"event":"stop","stop":{}}')).toEqual({ event: "stop" });
    expect(parseMediaMessage('{"event":"future"}')).toEqual({ event: "other", name: "future" });
    expect(parseMediaMessage("not json")).toBeUndefined();
    expect(parseMediaMessage('{"noEvent":true}')).toBeUndefined();
    expect(parseMediaMessage(42)).toBeUndefined();
  });
});

class StubSocket implements MediaSocket {
  readonly listeners = new Map<string, ((...args: never[]) => void)[]>();
  closedWith: { code: number | undefined; reason: string | undefined } | undefined;
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
}

function unitSession(source: "twilio" | "test-call" = "twilio"): CallSession {
  return new CallSession({
    deviceId: "device-1",
    line: null,
    source,
    callerNumber: CALLER_NUMBER,
    calledNumber: GUARD_NUMBER,
    startedAt: 1_760_000_000_000,
    transcriptionSource: "openai",
  });
}

describe("MediaConnection (unit)", () => {
  it("drops media before start, counts invalid frames, ignores unknown events and forwards after start", () => {
    const session = unitSession();
    const transcriber = new FakeTranscriber();
    const socket = new StubSocket();
    const connection = new MediaConnection(socket, { session, transcriber, transcribeTracks: "both", logger: silentLogger() });
    connection.attach();
    connection.handleMessage(mediaMessage("inbound", PAYLOAD_A));
    connection.handleMessage("garbage");
    connection.handleMessage('{"event":"whatever"}');
    expect(connection.stats).toEqual({ frames: 3, forwarded: 0, dropped: 1, invalid: 1 });
    connection.handleMessage(startMessage(session.callId));
    connection.handleMessage(mediaMessage("inbound", PAYLOAD_A));
    expect(transcriber.handle("caller", session.callId)?.audio).toEqual([PAYLOAD_A]);
    expect(connection.stats.forwarded).toBe(1);
    expect(socket.closedWith).toBeUndefined();
  });

  it("closes the handles when the session ends, and opens no handles for a session Twilio transcribes", () => {
    const session = unitSession();
    const transcriber = new FakeTranscriber();
    const socket = new StubSocket();
    const connection = new MediaConnection(socket, { session, transcriber, transcribeTracks: "both", logger: silentLogger() });
    connection.attach();
    connection.handleMessage(startMessage(session.callId));
    expect(transcriber.handles).toHaveLength(2);
    session.end("completed");
    expect(transcriber.handles.every((handle) => handle.closed)).toBe(true);
    expect(socket.closedWith?.code).toBe(1000);
    expect(connection.isClosed).toBe(true);

    const twilioSession = unitSession();
    twilioSession.transcriptionSource = "twilio";
    const other = new FakeTranscriber();
    const second = new MediaConnection(new StubSocket(), { session: twilioSession, transcriber: other, transcribeTracks: "both", logger: silentLogger() });
    second.attach();
    second.handleMessage(startMessage(twilioSession.callId));
    second.handleMessage(mediaMessage("inbound", PAYLOAD_A));
    expect(other.handles).toHaveLength(0);
    expect(second.stats.dropped).toBe(1);
  });

  it("on a test call the outbound track is the scripted caller and is never gated", () => {
    const session = unitSession("test-call");
    const transcriber = new FakeTranscriber();
    const connection = new MediaConnection(new StubSocket(), { session, transcriber, transcribeTracks: "both", logger: silentLogger() });
    connection.attach();
    connection.handleMessage(startMessage(session.callId));
    connection.handleMessage(mediaMessage("outbound", PAYLOAD_A));
    connection.handleMessage(mediaMessage("inbound", PAYLOAD_B));
    expect(transcriber.handle("caller", session.callId)?.audio).toEqual([PAYLOAD_A]);
    expect(transcriber.handle("user", session.callId)?.audio).toEqual([PAYLOAD_B]);
  });
});

describe("GET /v1/calls/twilio/media/:mediaToken (WebSocket)", () => {
  let ctx: CallsTestContext;
  let baseUrl: string;
  const sockets: WebSocket[] = [];

  beforeEach(async () => {
    ctx = await createCallsTestApp();
    await registerLine(ctx);
    await ctx.app.listen({ port: 0, host: "127.0.0.1" });
    const { port } = ctx.app.server.address() as AddressInfo;
    baseUrl = `ws://127.0.0.1:${port}`;
  });
  afterEach(async () => {
    for (const socket of sockets.splice(0)) if (socket.readyState !== WebSocket.CLOSED) socket.terminate();
    await closeTestApp(ctx);
  });

  function connect(path: string, headers: Record<string, string> = {}): Promise<WebSocket> {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(`${baseUrl}${path}`, { headers });
      sockets.push(socket);
      socket.once("open", () => resolve(socket));
      socket.once("error", reject);
    });
  }

  it("refuses the upgrade for a Twilio-sourced session whose handshake signature is missing or invalid (HTTP 403)", async () => {
    const { session } = await inboundCall(ctx);
    await expect(connect(`/v1/calls/twilio/media/${session.mediaToken}`)).rejects.toThrow(/403/);
    ctx.twilio.rejectSignatures = true;
    await expect(connect(`/v1/calls/twilio/media/${session.mediaToken}`, { "x-twilio-signature": "dGVzdA==" })).rejects.toThrow(/403/);
    expect(ctx.transcriber.handles).toHaveLength(0);
    ctx.twilio.rejectSignatures = false;
    const socket = await connect(`/v1/calls/twilio/media/${session.mediaToken}`, { "x-twilio-signature": "dGVzdA==" });
    expect(socket.readyState).toBe(WebSocket.OPEN);
  });

  it("rejects an unknown token before the upgrade (HTTP 404, no WebSocket)", async () => {
    await expect(connect("/v1/calls/twilio/media/" + "0".repeat(32))).rejects.toThrow(/404/);
    expect(ctx.transcriber.handles).toHaveLength(0);
  });

  it("rejects the token of an ended session", async () => {
    const { session } = await inboundCall(ctx);
    session.end("completed");
    await expect(connect(`/v1/calls/twilio/media/${session.mediaToken}`, SIGNED)).rejects.toThrow(/404/);
  });

  it("closes the socket with 1008 when the start message names another call", async () => {
    const { session } = await inboundCall(ctx);
    const socket = await connect(`/v1/calls/twilio/media/${session.mediaToken}`, SIGNED);
    const closed = once(socket, "close");
    socket.send('{"event":"connected","protocol":"Call","version":"1.0.0"}');
    socket.send(startMessage("some-other-call"));
    const [code] = (await closed) as [number, Buffer];
    expect(code).toBe(CLOSE_POLICY_VIOLATION);
    expect(ctx.transcriber.handles).toHaveLength(0);
  });

  it("forwards inbound audio to the caller handle at once, and outbound audio only once the call is in progress", async () => {
    const { session } = await inboundCall(ctx);
    const socket = await connect(`/v1/calls/twilio/media/${session.mediaToken}`, { "x-twilio-signature": "dGVzdA==" });
    socket.send('{"event":"connected","protocol":"Call","version":"1.0.0"}');
    socket.send(startMessage(session.callId));
    await waitFor(() => ctx.transcriber.handles.length === 2);
    const caller = ctx.transcriber.handle("caller", session.callId)!;
    const user = ctx.transcriber.handle("user", session.callId)!;

    socket.send(mediaMessage("inbound", PAYLOAD_A, 1));
    socket.send(mediaMessage("outbound", PAYLOAD_B, 1)); // ringback: dropped
    await waitFor(() => caller.audio.length === 1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(caller.audio).toEqual([PAYLOAD_A]);
    expect(user.audio).toEqual([]);

    session.setStatus("in_progress");
    socket.send(mediaMessage("outbound", PAYLOAD_B, 2));
    socket.send(mediaMessage("inbound", PAYLOAD_A, 2));
    await waitFor(() => user.audio.length === 1 && caller.audio.length === 2);
    expect(user.audio).toEqual([PAYLOAD_B]);

    // The fake Twilio client accepted the handshake signature above; a rejected one never becomes a socket (below).
    const closed = once(socket, "close");
    socket.send(JSON.stringify({ event: "stop", sequenceNumber: "9", stop: { accountSid: "AC", callSid: "CA" }, streamSid: STREAM_SID }));
    await closed;
    expect(caller.closed).toBe(true);
    expect(user.closed).toBe(true);
  });

  it("a second media stream for the same call supersedes the first: its socket closes and its handles are released", async () => {
    const { session } = await inboundCall(ctx);
    const first = await connect(`/v1/calls/twilio/media/${session.mediaToken}`, SIGNED);
    first.send(startMessage(session.callId));
    await waitFor(() => ctx.transcriber.handles.length === 2);
    const firstClosed = once(first, "close");
    const second = await connect(`/v1/calls/twilio/media/${session.mediaToken}`, SIGNED);
    const [code] = (await firstClosed) as [number, Buffer];
    expect(code).toBe(1000);
    expect(ctx.transcriber.handles.every((handle) => handle.closed)).toBe(true);
    second.send(startMessage(session.callId));
    await waitFor(() => ctx.transcriber.handles.length === 4);
    const live = ctx.transcriber.handles.filter((handle) => !handle.closed);
    expect(live.map((handle) => handle.speaker).sort()).toEqual(["caller", "user"]);
    second.send(mediaMessage("inbound", PAYLOAD_A, 1));
    await waitFor(() => (live.find((handle) => handle.speaker === "caller")?.audio.length ?? 0) === 1);
    expect(session.isEnded).toBe(false);
  });

  it("closes the handles when the client disconnects", async () => {
    const { session } = await inboundCall(ctx);
    const socket = await connect(`/v1/calls/twilio/media/${session.mediaToken}`, SIGNED);
    socket.send(startMessage(session.callId));
    await waitFor(() => ctx.transcriber.handles.length === 2);
    socket.close();
    await waitFor(() => ctx.transcriber.handles.every((handle) => handle.closed));
  });

  it("exists without Twilio, so a replay session (console, deviceID) can be fed on an OpenAI-only relay", async () => {
    await closeTestApp(ctx);
    const clock = new FakeClock();
    const db = RelayDb.open(":memory:");
    const transcriber = new FakeTranscriber();
    const app = buildApp({
      config: testConfig({ calls: testCallsConfig({ twilio: undefined }) }),
      db,
      pushSender: new FakeSender(),
      tokenVerifier: new FakeVerifier(),
      logger: false,
      calls: { twilio: undefined, transcriber, scorer: new FakeScorer(), now: clock.now },
    });
    await app.ready();
    ctx = { app, db, sender: new FakeSender(), verifier: new FakeVerifier(), config: testConfig(), twilio: new FakeTwilioClient(), transcriber, scorer: new FakeScorer(), clock };
    await registerDevice(app, { apnsToken: null });
    await app.listen({ port: 0, host: "127.0.0.1" });
    baseUrl = `ws://127.0.0.1:${(app.server.address() as AddressInfo).port}`;

    // The Twilio webhooks are off…
    expect((await app.inject({ method: "POST", url: "/v1/calls/twilio/voice", payload: "To=x", headers: { "content-type": "application/x-www-form-urlencoded" } })).statusCode).toBe(404);
    // …but the media socket is there for the replay script, with the same token check.
    await expect(connect("/v1/calls/twilio/media/" + "0".repeat(32))).rejects.toThrow(/404/);
    const ticket = await app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: { "x-api-key": API_KEY }, payload: { deviceID: DEVICE_ID } });
    expect(ticket.statusCode).toBe(202);
    const { callID, mediaPath } = ticket.json() as { callID: string; mediaPath: string };
    const socket = await connect(mediaPath, { "x-twilio-signature": "dGVzdA==", "x-api-key": API_KEY });
    socket.send('{"event":"connected","protocol":"Call","version":"1.0.0"}');
    socket.send(startMessage(callID));
    await waitFor(() => transcriber.handles.length === 2);
    socket.send(mediaMessage("inbound", PAYLOAD_A, 1));
    socket.send(mediaMessage("outbound", PAYLOAD_B, 1)); // a replay is in_progress from the start: nothing is gated
    await waitFor(() => transcriber.handle("caller", callID)?.audio.length === 1 && transcriber.handle("user", callID)?.audio.length === 1);
    const closed = once(socket, "close");
    socket.send(JSON.stringify({ event: "stop", sequenceNumber: "9", stop: { accountSid: "AC", callSid: "CA" }, streamSid: STREAM_SID }));
    await closed;
    expect(transcriber.handles.every((handle) => handle.closed)).toBe(true);
    const ended = await app.inject({ method: "POST", url: "/v1/calls/console/replay/end", headers: { "x-api-key": API_KEY }, payload: { callID } });
    expect(ended.json()).toEqual({ callID, status: "completed" });
  });

  it("opens only the caller's handle when CALLS_TRANSCRIBE_TRACKS=caller", async () => {
    await closeTestApp(ctx);
    ctx = await createCallsTestApp({ transcribeTracks: "caller" });
    await registerLine(ctx);
    await ctx.app.listen({ port: 0, host: "127.0.0.1" });
    baseUrl = `ws://127.0.0.1:${(ctx.app.server.address() as AddressInfo).port}`;
    const { session } = await inboundCall(ctx);
    session.setStatus("in_progress");
    const socket = await connect(`/v1/calls/twilio/media/${session.mediaToken}`, SIGNED);
    socket.send(startMessage(session.callId));
    socket.send(mediaMessage("outbound", PAYLOAD_B));
    socket.send(mediaMessage("inbound", PAYLOAD_A));
    await waitFor(() => (ctx.transcriber.handle("caller", session.callId)?.audio.length ?? 0) === 1);
    expect(ctx.transcriber.handles.map((handle) => handle.speaker)).toEqual(["caller"]);
  });
});

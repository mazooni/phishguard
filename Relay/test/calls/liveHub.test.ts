import type { IncomingMessage } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocketServer, type WebSocket } from "ws";

import { CATCH_UP_SEGMENTS, LiveHub } from "../../src/calls/live/hub.js";
import { CallSessionManager, type CallSession, type CallSessionInit } from "../../src/calls/session.js";
import type { CallRecord, CallVerdict, TranscriptSegment } from "../../src/calls/types.js";
import { DEVICE_ID, FakeClock } from "../helpers.js";
import { CALLER_NUMBER, PROTECTED_NUMBER, silentLogger } from "./fakes.js";
import { LiveClient, waitFor } from "./liveClient.js";

const OTHER_DEVICE = "other-device";

function verdict(level: CallVerdict["level"] = "high"): Omit<CallVerdict, "sequence"> {
  return {
    category: "scam",
    confidence: 0.9,
    level,
    reasons: [],
    summary: "Scam.",
    recommendedAction: "Hang up.",
    heuristicScore: 0.9,
    updatedAt: 0,
  };
}

function segment(id: number, final = true, speaker: TranscriptSegment["speaker"] = "caller"): TranscriptSegment {
  return { id: `seg-${id}`, speaker, text: `line ${id}`, atMs: id * 1000, final };
}

describe("LiveHub over a real WebSocket server", () => {
  let server: WebSocketServer;
  let hub: LiveHub;
  let sessions: CallSessionManager;
  let clock: FakeClock;
  let base: string;
  const clients: LiveClient[] = [];

  const create = (overrides: Partial<CallSessionInit> = {}): CallSession =>
    sessions.create({
      deviceId: DEVICE_ID,
      line: null,
      source: "twilio",
      callerNumber: CALLER_NUMBER,
      calledNumber: PROTECTED_NUMBER,
      startedAt: clock.now(),
      status: "in_progress",
      ...overrides,
    });

  const connect = async (path: string): Promise<LiveClient> => {
    const client = await LiveClient.connect(`${base}${path}`);
    clients.push(client);
    return client;
  };

  beforeEach(async () => {
    clock = new FakeClock();
    const store = { upsertCall: (_record: CallRecord): void => undefined };
    sessions = new CallSessionManager({ store, retainEndedMs: 60_000, now: clock.now });
    hub = new LiveHub({ sessions, logger: silentLogger(), now: clock.now });
    sessions.on("created", (session) => hub.attach(session));
    server = new WebSocketServer({ port: 0, host: "127.0.0.1" });
    server.on("connection", (socket: WebSocket, request: IncomingMessage) => {
      const url = request.url ?? "";
      if (url.startsWith("/console")) hub.subscribeConsole(socket);
      else hub.subscribeDevice(decodeURIComponent(url.replace("/device/", "")), socket);
    });
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as { port: number };
    base = `ws://127.0.0.1:${address.port}`;
  });

  afterEach(async () => {
    for (const client of clients.splice(0)) await client.close();
    hub.close();
    sessions.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("sends hello with the device's active calls, then the verdict and the last 50 segments as catch-up", async () => {
    const session = create();
    session.setVerdict(verdict());
    for (let i = 1; i <= 60; i += 1) session.addSegment(segment(i));
    create({ deviceId: OTHER_DEVICE });
    const ended = create();
    ended.end("completed");

    const client = await connect(`/device/${DEVICE_ID}`);
    const hello = await client.next("hello");
    expect(hello).toMatchObject({ type: "hello", serverTime: clock.now() });
    if (hello.type !== "hello") throw new Error("unreachable");
    expect(hello.activeCalls.map((call) => call.callID)).toEqual([session.callId]);
    expect(hello.activeCalls[0]?.verdict?.sequence).toBe(1);

    const catchUpVerdict = await client.next();
    expect(catchUpVerdict).toMatchObject({ type: "verdict.updated", callID: session.callId, verdict: { sequence: 1, level: "high" } });
    const segments = await client.collect(CATCH_UP_SEGMENTS, "transcript.segment");
    expect(segments).toHaveLength(CATCH_UP_SEGMENTS);
    expect(segments[0]).toMatchObject({ type: "transcript.segment", callID: session.callId, segment: { id: "seg-11" } });
    expect(segments[49]).toMatchObject({ segment: { id: "seg-60", final: true } });
  });

  it("relays every event type in order for a session created after subscribing", async () => {
    const client = await connect(`/device/${DEVICE_ID}`);
    await client.next("hello");
    const session = create({ status: "ringing" });
    expect(await client.next()).toMatchObject({ type: "call.started", call: { callID: session.callId, status: "ringing", source: "twilio" } });
    session.setStatus("connecting");
    expect(await client.next()).toEqual({ type: "call.status", callID: session.callId, status: "connecting" });
    session.setStatus("in_progress");
    expect(await client.next()).toEqual({ type: "call.status", callID: session.callId, status: "in_progress" });
    session.addSegment(segment(1, false));
    expect(await client.next()).toEqual({ type: "transcript.segment", callID: session.callId, segment: segment(1, false) });
    session.addSegment(segment(1, true));
    expect(await client.next()).toEqual({ type: "transcript.segment", callID: session.callId, segment: segment(1, true) });
    const stored = session.setVerdict(verdict("medium"));
    expect(await client.next()).toEqual({ type: "verdict.updated", callID: session.callId, verdict: stored });
    const alert = { sequence: 1, level: "medium" as const, title: "Possible scam call", subtitle: "Call from x", body: "b", sentAt: clock.now(), pushed: true, spoken: false };
    session.recordAlert(alert);
    expect(await client.next()).toEqual({ type: "call.alert", callID: session.callId, alert });
    clock.advance(5000);
    session.end("completed");
    const ended = await client.next();
    expect(ended).toMatchObject({ type: "call.ended", call: { callID: session.callId, status: "completed", durationSeconds: 5, alerted: true, alertLevel: "medium" } });
  });

  it("answers ping with pong and ignores malformed frames", async () => {
    const client = await connect(`/device/${DEVICE_ID}`);
    await client.next("hello");
    client.socket.send("not json");
    client.send({ type: "ping" });
    expect(await client.next()).toEqual({ type: "pong" });
    client.send({ type: "something-else" });
    client.send({ type: "ping" });
    expect(await client.next()).toEqual({ type: "pong" });
  });

  it("gives console subscribers every device's calls, and device subscribers only their own", async () => {
    const mine = create();
    const theirs = create({ deviceId: OTHER_DEVICE });
    const console_ = await connect("/console");
    const device = await connect(`/device/${DEVICE_ID}`);
    const consoleHello = await console_.next("hello");
    const deviceHello = await device.next("hello");
    if (consoleHello.type !== "hello" || deviceHello.type !== "hello") throw new Error("unreachable");
    expect(consoleHello.activeCalls.map((call) => call.callID).sort()).toEqual([mine.callId, theirs.callId].sort());
    expect(deviceHello.activeCalls.map((call) => call.callID)).toEqual([mine.callId]);

    theirs.addSegment(segment(1));
    mine.addSegment(segment(2));
    const consoleSegments = await console_.collect(2, "transcript.segment");
    expect(consoleSegments.map((event) => (event.type === "transcript.segment" ? event.callID : ""))).toEqual([theirs.callId, mine.callId]);
    const deviceSegment = await device.next("transcript.segment");
    expect(deviceSegment).toMatchObject({ callID: mine.callId });
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(device.received.filter((event) => event.type === "transcript.segment")).toHaveLength(1);
    expect(hub.subscriberCount).toEqual({ devices: 1, consoles: 1 });
  });

  it("drops sockets that close and keeps broadcasting to the rest", async () => {
    const first = await connect(`/device/${DEVICE_ID}`);
    const second = await connect(`/device/${DEVICE_ID}`);
    await first.next("hello");
    await second.next("hello");
    expect(hub.subscriberCount.devices).toBe(2);
    await first.close();
    await waitFor(() => hub.subscriberCount.devices === 1);
    const session = create();
    expect(await second.next("call.started")).toMatchObject({ call: { callID: session.callId } });
    expect(first.received.some((event) => event.type === "call.started")).toBe(false);
  });

  it("terminates every subscriber on close()", async () => {
    const a = await connect(`/device/${DEVICE_ID}`);
    const b = await connect("/console");
    await a.next("hello");
    await b.next("hello");
    hub.close();
    await waitFor(() => a.closed && b.closed);
    expect(hub.subscriberCount).toEqual({ devices: 0, consoles: 0 });
  });
});

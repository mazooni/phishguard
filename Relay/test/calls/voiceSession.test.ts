import { mkdtempSync, rmSync } from "node:fs";
import type { IncomingMessage } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocketServer, type WebSocket } from "ws";

import { LiveHub } from "../../src/calls/live/hub.js";
import { MODULATE_VOICE_PROVIDER } from "../../src/calls/modulate/voiceDetector.js";
import { CallSession, CallSessionManager, recordToSummaryJSON } from "../../src/calls/session.js";
import type { CallRecord, CallVoiceAlert, CallVoiceAssessment, CallVoiceUpdate, VoiceStatus } from "../../src/calls/types.js";
import { RelayDb } from "../../src/db.js";
import { DEVICE_ID, FakeClock } from "../helpers.js";
import { CALLER_NUMBER, GUARD_NUMBER, PROTECTED_NUMBER, silentLogger } from "./fakes.js";
import { LiveClient } from "./liveClient.js";

/**
 * The shared voice contract below the audio path: what `CallSession.setVoice` / `recordVoiceAlert` / `end` do
 * with a detector's reports, that the manager persists them, that `calls.voice_json` round-trips, and that the
 * live hub relays `voice.updated`. A voice assessment never changes the scam verdict or the scam alerts.
 */

function update(status: VoiceStatus, overrides: Partial<CallVoiceUpdate> = {}): CallVoiceUpdate {
  return { status, syntheticShare: 0, confidence: 0, speechMs: 0, provider: MODULATE_VOICE_PROVIDER, ...overrides };
}

const ALERT: CallVoiceAlert = {
  title: "AI voice detected",
  subtitle: "Call from a number ending 0003",
  body: "The caller's voice appears to be AI-generated.",
  sentAt: 1_760_000_050_000,
  pushed: true,
  spoken: false,
};

describe("CallSession voice assessment", () => {
  let clock: FakeClock;
  let session: CallSession;
  let events: CallVoiceAssessment[];

  beforeEach(() => {
    clock = new FakeClock();
    session = new CallSession(
      { deviceId: DEVICE_ID, line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: clock.now(), status: "in_progress" },
      clock.now,
    );
    events = [];
    session.on("voice", (voice) => events.push(voice));
  });

  it("has no assessment until a detector reports, and none appears in the record or the summary", () => {
    expect(session.voice).toBeUndefined();
    expect(session.toRecord()).not.toHaveProperty("voice");
    expect(session.toSummaryJSON(clock.now())).not.toHaveProperty("voice");
    expect(session.alerted).toBe(false);
  });

  it("stores a report, stamps it and emits `voice`", () => {
    clock.advance(1000);
    const stored = session.setVoice(update("analyzing"));
    expect(stored).toEqual({ status: "analyzing", syntheticShare: 0, confidence: 0, speechMs: 0, provider: MODULATE_VOICE_PROVIDER, updatedAt: clock.now() });
    expect(session.voice).toBe(stored);
    expect(events).toEqual([stored]);
    expect(session.toRecord().voice).toEqual(stored);
    expect(session.toSummaryJSON(clock.now()).voice).toEqual(stored);
    expect(session.toRecord().updatedAt).toBe(clock.now());
  });

  it("dedups to two decimals: counters stay fresh, but nothing is emitted until something visible changes", () => {
    session.setVoice(update("analyzing", { syntheticShare: 0.5, speechMs: 1000 }));
    const firstAt = clock.now();
    clock.advance(1000);
    session.setVoice(update("analyzing", { syntheticShare: 0.504, speechMs: 2000 }));
    expect(events).toHaveLength(1);
    expect(session.voice).toMatchObject({ speechMs: 2000, syntheticShare: 0.504, updatedAt: firstAt });
    // The share moved in the second decimal; then the confidence did; then the status.
    session.setVoice(update("analyzing", { syntheticShare: 0.51, speechMs: 3000 }));
    session.setVoice(update("analyzing", { syntheticShare: 0.51, confidence: 0.01, speechMs: 3000 }));
    session.setVoice(update("human", { syntheticShare: 0.51, confidence: 0.01, speechMs: 3000 }));
    session.setVoice(update("human", { syntheticShare: 0.51, confidence: 0.01, speechMs: 9000 }));
    expect(events.map((voice) => [voice.status, voice.syntheticShare, voice.confidence])).toEqual([
      ["analyzing", 0.5, 0],
      ["analyzing", 0.51, 0],
      ["analyzing", 0.51, 0.01],
      ["human", 0.51, 0.01],
    ]);
    expect(session.voice?.speechMs).toBe(9000);
  });

  it("clamps the share and the confidence to 0…1 and rounds the speech time", () => {
    session.setVoice(update("human", { syntheticShare: 1.7, confidence: -0.2, speechMs: 1234.6 }));
    expect(session.voice).toMatchObject({ syntheticShare: 1, confidence: 0, speechMs: 1235 });
    session.setVoice(update("human", { syntheticShare: 0.2, confidence: 0.9, speechMs: -5 }));
    expect(session.voice?.speechMs).toBe(0);
  });

  it("`synthetic` is sticky: a later report cannot take it back, though its numbers still update", () => {
    clock.advance(4000);
    session.setVoice(update("synthetic", { syntheticShare: 1, confidence: 0.95, speechMs: 6000 }));
    const detectedAt = clock.now();
    expect(session.voice).toMatchObject({ status: "synthetic", detectedAt });
    clock.advance(4000);
    for (const status of ["human", "analyzing", "inconclusive", "unavailable"] as const) {
      session.setVoice(update(status, { syntheticShare: 0.4, confidence: 0.2, speechMs: 15000 }));
      expect(session.voice?.status).toBe("synthetic");
    }
    expect(session.voice).toMatchObject({ syntheticShare: 0.4, confidence: 0.2, speechMs: 15000, detectedAt });
    expect(events.map((voice) => voice.status)).toEqual(["synthetic", "synthetic"]);
  });

  it("`detectedAt` is set only when the status first becomes synthetic", () => {
    session.setVoice(update("human", { confidence: 0.9, speechMs: 6000 }));
    expect(session.voice).not.toHaveProperty("detectedAt");
    clock.advance(500);
    session.setVoice(update("synthetic", { syntheticShare: 0.9, confidence: 0.9, speechMs: 12000 }));
    expect(session.voice?.detectedAt).toBe(clock.now());
  });

  it("never touches the scam verdict, the scam alerts or the alert level", () => {
    session.setVoice(update("synthetic", { syntheticShare: 1, confidence: 0.99, speechMs: 6000 }));
    expect(session.verdict).toBeUndefined();
    expect(session.alerts).toEqual([]);
    expect(session.alertLevel).toBeUndefined();
    expect(session.alerted).toBe(false);
    expect(session.toRecord()).not.toHaveProperty("verdict");
  });

  it("accepts nothing after the call ended", () => {
    session.setVoice(update("human", { confidence: 0.9, speechMs: 6000 }));
    session.end("completed");
    const before = session.voice;
    expect(session.setVoice(update("synthetic", { syntheticShare: 1, confidence: 0.99, speechMs: 12000 }))).toBe(before);
    expect(session.voice).toBe(before);
    expect(events).toHaveLength(1);

    const never = new CallSession({ deviceId: DEVICE_ID, line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: 1 });
    never.end("completed");
    expect(never.setVoice(update("analyzing"))).toBeUndefined();
    expect(never.voice).toBeUndefined();
  });

  it("end() turns a leftover `analyzing` into `inconclusive` in the final record, without a separate voice event", () => {
    session.setVoice(update("analyzing", { syntheticShare: 1, speechMs: 3000 }));
    let ended: CallRecord | undefined;
    session.on("ended", (record) => {
      ended = record;
    });
    clock.advance(2000);
    session.end("completed");
    expect(session.voice).toMatchObject({ status: "inconclusive", syntheticShare: 1, speechMs: 3000, updatedAt: clock.now() });
    expect(ended?.voice?.status).toBe("inconclusive");
    expect(session.toSummaryJSON(clock.now()).voice?.status).toBe("inconclusive");
    expect(events.map((voice) => voice.status)).toEqual(["analyzing"]);
  });

  it.each(["human", "synthetic", "unavailable", "inconclusive"] as const)("end() leaves `%s` as it is", (status) => {
    session.setVoice(update(status, { confidence: 0.9, speechMs: 6000 }));
    session.end("completed");
    expect(session.voice?.status).toBe(status);
  });

  it("recordVoiceAlert stores the warning on the assessment, emits `voice` and marks the call alerted", () => {
    session.setVoice(update("synthetic", { syntheticShare: 1, confidence: 0.95, speechMs: 6000 }));
    clock.advance(300);
    session.recordVoiceAlert(ALERT);
    expect(session.voice).toMatchObject({ status: "synthetic", alert: ALERT, updatedAt: clock.now() });
    expect(events).toHaveLength(2);
    expect(events[1]?.alert).toEqual(ALERT);
    expect(session.alerted).toBe(true);
    expect(session.toRecord()).toMatchObject({ alerted: true, voice: { alert: ALERT } });
    // It is not a scam alert: the scam alert list and level are untouched.
    expect(session.alerts).toEqual([]);
    expect(session.toRecord()).not.toHaveProperty("alertLevel");
    // A later report keeps the alert.
    session.setVoice(update("synthetic", { syntheticShare: 0.5, confidence: 0.95, speechMs: 12000 }));
    expect(session.voice?.alert).toEqual(ALERT);
  });

  it("a second recordVoiceAlert replaces the first (the spoken part confirmed after the push), also after the call ended", () => {
    session.setVoice(update("synthetic", { syntheticShare: 1, confidence: 0.95, speechMs: 6000 }));
    session.recordVoiceAlert(ALERT);
    session.end("completed");
    session.recordVoiceAlert({ ...ALERT, spoken: true });
    expect(session.voice?.alert).toEqual({ ...ALERT, spoken: true });
    expect(events).toHaveLength(3);
  });

  it("recordVoiceAlert is ignored when no detector ever reported", () => {
    session.recordVoiceAlert(ALERT);
    expect(session.voice).toBeUndefined();
    expect(session.alerted).toBe(false);
    expect(events).toEqual([]);
  });
});

describe("persistence of the voice assessment", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  function record(overrides: Partial<CallRecord> = {}): CallRecord {
    return {
      callId: "call-1",
      deviceId: DEVICE_ID,
      source: "twilio",
      callerNumber: CALLER_NUMBER,
      calledNumber: PROTECTED_NUMBER,
      startedAt: 1_760_000_000_000,
      status: "in_progress",
      alerted: false,
      updatedAt: 1_760_000_000_000,
      ...overrides,
    };
  }

  function dbWithDevice(path = ":memory:"): RelayDb {
    const db = RelayDb.open(path);
    db.createDevice({ deviceId: DEVICE_ID, secretHash: "h1", apnsToken: "t1", environment: "sandbox", bundleId: "com.x.y" }, 1);
    return db;
  }

  it("round-trips voice_json, including the alert, and stores NULL without an assessment", () => {
    const db = dbWithDevice();
    const voice: CallVoiceAssessment = {
      status: "synthetic",
      syntheticShare: 0.91,
      confidence: 0.94,
      speechMs: 8000,
      provider: MODULATE_VOICE_PROVIDER,
      detectedAt: 1_760_000_009_000,
      alert: ALERT,
      updatedAt: 1_760_000_010_000,
    };
    db.upsertCall(record({ voice, alerted: true }));
    expect(db.findCall("call-1")?.voice).toEqual(voice);
    expect(db.listCalls(DEVICE_ID, 10)[0]?.voice).toEqual(voice);
    expect(recordToSummaryJSON(db.findCall("call-1")!).voice).toEqual(voice);
    const raw = db.db.prepare("SELECT voice_json FROM calls WHERE call_id = ?").get("call-1") as { voice_json: string };
    expect(JSON.parse(raw.voice_json)).toEqual(voice);
    // The privacy invariant of the calls table: nothing persisted may even mention a transcript.
    expect(raw.voice_json).not.toContain("transcript");

    db.upsertCall(record({ callId: "call-2" }));
    expect(db.findCall("call-2")).not.toHaveProperty("voice");
    expect((db.db.prepare("SELECT voice_json FROM calls WHERE call_id = ?").get("call-2") as { voice_json: string | null }).voice_json).toBeNull();
    db.close();
  });

  it("an update replaces the stored assessment, and can clear it", () => {
    const db = dbWithDevice();
    const analyzing: CallVoiceAssessment = { status: "analyzing", syntheticShare: 0, confidence: 0, speechMs: 0, provider: MODULATE_VOICE_PROVIDER, updatedAt: 1 };
    db.upsertCall(record({ voice: analyzing }));
    db.upsertCall(record({ voice: { ...analyzing, status: "human", confidence: 0.9, speechMs: 6000, updatedAt: 2 } }));
    expect(db.findCall("call-1")?.voice).toMatchObject({ status: "human", speechMs: 6000 });
    db.upsertCall(record());
    expect(db.findCall("call-1")).not.toHaveProperty("voice");
    db.close();
  });

  it("a corrupt voice column loses the assessment, not the call", () => {
    const db = dbWithDevice();
    db.upsertCall(record());
    db.db.prepare("UPDATE calls SET voice_json = ? WHERE call_id = ?").run("{not json", "call-1");
    const loaded = db.findCall("call-1");
    expect(loaded?.callId).toBe("call-1");
    expect(loaded).not.toHaveProperty("voice");
    db.close();
  });

  it("migration v3 adds the column to a version 2 database and keeps its calls", () => {
    const dir = mkdtempSync(join(tmpdir(), "pg-relay-voice-"));
    dirs.push(dir);
    const path = join(dir, "relay.sqlite");
    const old = dbWithDevice(path);
    old.upsertCall(record());
    // Back to what a relay from before voice detection left on disk.
    old.db.exec("ALTER TABLE calls DROP COLUMN voice_json");
    old.db.pragma("user_version = 2");
    old.db.close();

    const upgraded = RelayDb.open(path);
    expect(upgraded.db.pragma("user_version", { simple: true })).toBe(3);
    expect(upgraded.findCall("call-1")).toMatchObject({ callId: "call-1", status: "in_progress" });
    expect(upgraded.findCall("call-1")).not.toHaveProperty("voice");
    upgraded.upsertCall(record({ voice: { status: "human", syntheticShare: 0, confidence: 0.9, speechMs: 6000, provider: MODULATE_VOICE_PROVIDER, updatedAt: 5 } }));
    expect(upgraded.findCall("call-1")?.voice?.status).toBe("human");
    upgraded.close();
  });

  it("the session manager persists on every `voice` event and on the final record", () => {
    const db = dbWithDevice();
    const clock = new FakeClock();
    const sessions = new CallSessionManager({ store: db, retainEndedMs: 60_000, now: clock.now });
    const session = sessions.create({
      deviceId: DEVICE_ID,
      line: null,
      source: "twilio",
      callerNumber: CALLER_NUMBER,
      calledNumber: PROTECTED_NUMBER,
      startedAt: clock.now(),
      status: "in_progress",
    });
    expect(db.findCall(session.callId)).not.toHaveProperty("voice");
    session.setVoice(update("analyzing"));
    expect(db.findCall(session.callId)?.voice?.status).toBe("analyzing");
    session.setVoice(update("synthetic", { syntheticShare: 1, confidence: 0.95, speechMs: 6000 }));
    session.recordVoiceAlert(ALERT);
    expect(db.findCall(session.callId)).toMatchObject({ alerted: true, voice: { status: "synthetic", alert: ALERT } });
    session.end("completed");
    expect(db.findCall(session.callId)).toMatchObject({ status: "completed", voice: { status: "synthetic" } });

    const quiet = sessions.create({ deviceId: DEVICE_ID, line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: PROTECTED_NUMBER, startedAt: clock.now(), status: "in_progress" });
    quiet.setVoice(update("analyzing", { speechMs: 2000 }));
    quiet.end("completed");
    expect(db.findCall(quiet.callId)?.voice?.status).toBe("inconclusive");
    sessions.close();
    db.close();
  });
});

describe("LiveHub voice.updated", () => {
  let server: WebSocketServer;
  let hub: LiveHub;
  let sessions: CallSessionManager;
  let clock: FakeClock;
  let base: string;
  const clients: LiveClient[] = [];

  beforeEach(async () => {
    clock = new FakeClock();
    sessions = new CallSessionManager({ store: { upsertCall: (_record: CallRecord): void => undefined }, retainEndedMs: 60_000, now: clock.now });
    hub = new LiveHub({ sessions, logger: silentLogger(), now: clock.now });
    sessions.on("created", (session) => hub.attach(session));
    server = new WebSocketServer({ port: 0, host: "127.0.0.1" });
    server.on("connection", (socket: WebSocket, request: IncomingMessage) => {
      const url = request.url ?? "";
      if (url.startsWith("/console")) hub.subscribeConsole(socket);
      else hub.subscribeDevice(decodeURIComponent(url.replace("/device/", "")), socket);
    });
    await new Promise<void>((resolve) => server.once("listening", resolve));
    base = `ws://127.0.0.1:${(server.address() as { port: number }).port}`;
  });

  afterEach(async () => {
    for (const client of clients.splice(0)) await client.close();
    hub.close();
    sessions.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const connect = async (path: string): Promise<LiveClient> => {
    const client = await LiveClient.connect(`${base}${path}`);
    clients.push(client);
    return client;
  };

  const create = (deviceId = DEVICE_ID): CallSession =>
    sessions.create({ deviceId, line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: PROTECTED_NUMBER, startedAt: clock.now(), status: "in_progress" });

  it("relays every voice event to the call's device and to the console, and the ended summary carries the assessment", async () => {
    const device = await connect(`/device/${DEVICE_ID}`);
    const console_ = await connect("/console");
    await device.next("hello");
    await console_.next("hello");
    const session = create();
    await device.next("call.started");

    const analyzing = session.setVoice(update("analyzing"))!;
    expect(await device.next()).toEqual({ type: "voice.updated", callID: session.callId, voice: analyzing });
    expect(await console_.next("voice.updated")).toEqual({ type: "voice.updated", callID: session.callId, voice: analyzing });
    // A report that changes nothing visible is not relayed.
    session.setVoice(update("analyzing", { speechMs: 2000 }));
    const synthetic = session.setVoice(update("synthetic", { syntheticShare: 1, confidence: 0.95, speechMs: 6000 }))!;
    expect(await device.next()).toEqual({ type: "voice.updated", callID: session.callId, voice: synthetic });
    session.recordVoiceAlert(ALERT);
    expect(await device.next()).toMatchObject({ type: "voice.updated", callID: session.callId, voice: { status: "synthetic", alert: ALERT } });

    session.end("completed");
    expect(await device.next()).toMatchObject({ type: "call.ended", call: { callID: session.callId, alerted: true, voice: { status: "synthetic", alert: ALERT } } });
    expect(device.received.filter((event) => event.type === "voice.updated")).toHaveLength(3);
    // The scam channel stayed silent throughout.
    expect(device.received.some((event) => event.type === "verdict.updated" || event.type === "call.alert")).toBe(false);
  });

  it("keeps another device's voice events to itself, and a subscriber that joins later gets the assessment in hello", async () => {
    const mine = await connect(`/device/${DEVICE_ID}`);
    await mine.next("hello");
    const theirs = create("other-device");
    theirs.setVoice(update("human", { confidence: 0.9, speechMs: 6000 }));
    const own = create();
    own.setVoice(update("analyzing"));
    expect(await mine.next("voice.updated")).toMatchObject({ callID: own.callId });
    expect(mine.received.some((event) => event.type === "voice.updated" && event.callID === theirs.callId)).toBe(false);

    const late = await connect(`/device/${DEVICE_ID}`);
    const hello = await late.next("hello");
    if (hello.type !== "hello") throw new Error("unreachable");
    expect(hello.activeCalls.find((call) => call.callID === own.callId)?.voice).toMatchObject({ status: "analyzing" });
  });

  it("the ended summary of a call that never had enough speech says inconclusive", async () => {
    const device = await connect(`/device/${DEVICE_ID}`);
    await device.next("hello");
    const session = create();
    session.setVoice(update("analyzing", { speechMs: 1500 }));
    session.end("completed");
    expect(await device.next("call.ended")).toMatchObject({ call: { voice: { status: "inconclusive", speechMs: 1500 } } });
  });
});

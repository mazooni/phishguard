import { beforeEach, describe, expect, it } from "vitest";

import {
  CALL_ALERT_CATEGORY,
  CALL_ALERT_EXPIRATION_SECONDS,
  CALL_ALERT_THREAD_ID,
  CallAlertDispatcher,
  MAX_ALERT_PAYLOAD_BYTES,
  buildAlertPushRequest,
  estimatedPayloadBytes,
} from "../../src/calls/alerts/dispatcher.js";
import { CallSessionManager, type CallSession, type CallSessionInit } from "../../src/calls/session.js";
import type { AlertLevel, CallLine, CallReason, CallRiskLevel, CallVerdict } from "../../src/calls/types.js";
import { RelayDb } from "../../src/db.js";
import { sha256Hex } from "../../src/auth.js";
import { APNS_TOKEN, BUNDLE_ID, DEVICE_ID, DEVICE_SECRET, FakeClock, FakeSender } from "../helpers.js";
import { CALLER_NUMBER, FakeTwilioClient, GUARD_NUMBER, PROTECTED_NUMBER, silentLogger, testCallsConfig } from "./fakes.js";
import { flushPromises, waitFor } from "./liveClient.js";

const REASONS: CallReason[] = [
  { id: "call.gift_cards", title: "Asks for gift cards", detail: "Wants Apple gift cards.", severity: "high", source: "heuristic" },
  { id: "call.family_emergency", title: "Claims to be a grandchild in trouble", detail: "Arrested after an accident.", severity: "high", source: "heuristic" },
  { id: "call.secrecy", title: "Says not to tell anyone", detail: "Don't tell Mom.", severity: "medium", source: "heuristic" },
];

function verdict(level: CallRiskLevel, overrides: Partial<Omit<CallVerdict, "sequence">> = {}): Omit<CallVerdict, "sequence"> {
  const confidence = level === "high" ? 0.9 : level === "medium" ? 0.6 : level === "low" ? 0.35 : 0.1;
  return {
    category: level === "safe" ? "safe" : "scam",
    confidence,
    level,
    reasons: level === "safe" ? [] : REASONS,
    summary: "The caller pretends to be a grandchild in trouble and asks for gift cards.",
    recommendedAction: "Hang up and call your grandchild on their usual number.",
    heuristicScore: confidence,
    updatedAt: 1_760_000_000_000,
    ...overrides,
  };
}

function line(overrides: Partial<CallLine> = {}): CallLine {
  return {
    lineId: "line-1",
    deviceId: DEVICE_ID,
    guardNumber: GUARD_NUMBER,
    phoneNumber: PROTECTED_NUMBER,
    minimumLevel: "medium",
    spokenWarning: true,
    createdAt: 1_760_000_000_000,
    updatedAt: 1_760_000_000_000,
    ...overrides,
  };
}

interface Harness {
  db: RelayDb;
  sender: FakeSender;
  twilio: FakeTwilioClient;
  clock: FakeClock;
  sessions: CallSessionManager;
  dispatcher: CallAlertDispatcher;
  create(overrides?: Partial<CallSessionInit>): CallSession;
}

function harness(options: { apnsConfigured?: boolean; voice?: boolean; token?: string | null; minimumLevel?: AlertLevel } = {}): Harness {
  const db = RelayDb.open(":memory:");
  const clock = new FakeClock();
  db.createDevice(
    { deviceId: DEVICE_ID, secretHash: sha256Hex(DEVICE_SECRET), apnsToken: options.token === undefined ? APNS_TOKEN : (options.token ?? ""), environment: "sandbox", bundleId: BUNDLE_ID },
    clock.now(),
  );
  if (options.token === null) db.clearApnsToken(DEVICE_ID, "");
  const sender = new FakeSender();
  const twilio = new FakeTwilioClient();
  const sessions = new CallSessionManager({ store: db, retainEndedMs: 60_000, now: clock.now });
  const dispatcher = new CallAlertDispatcher({
    db,
    pushSender: sender,
    apnsConfigured: options.apnsConfigured ?? true,
    voice: options.voice === false ? undefined : twilio,
    config: testCallsConfig({ defaultMinimumLevel: options.minimumLevel ?? "medium" }),
    logger: silentLogger(),
    now: clock.now,
  });
  sessions.on("created", (session) => dispatcher.attach(session));
  const create = (overrides: Partial<CallSessionInit> = {}): CallSession =>
    sessions.create({
      deviceId: DEVICE_ID,
      line: line(),
      source: "twilio",
      callerNumber: CALLER_NUMBER,
      calledNumber: PROTECTED_NUMBER,
      startedAt: clock.now(),
      status: "in_progress",
      ...overrides,
    });
  return { db, sender, twilio, clock, sessions, dispatcher, create };
}

describe("CallAlertDispatcher", () => {
  let h: Harness;
  beforeEach(() => {
    h = harness();
  });

  it("does nothing below the line's minimum level", async () => {
    const session = h.create();
    session.setVerdict(verdict("safe"));
    session.setVerdict(verdict("low"));
    await flushPromises();
    expect(session.alerts).toHaveLength(0);
    expect(h.sender.alerts).toHaveLength(0);
    expect(h.twilio.spoken).toHaveLength(0);
  });

  it("alerts at medium and again when the level rises to high, with the matching titles", async () => {
    const session = h.create();
    session.setVerdict(verdict("medium"));
    await waitFor(() => session.alerts.length === 1);
    session.setVerdict(verdict("high"));
    await waitFor(() => session.alerts.length === 2);
    expect(session.alerts.map((alert) => alert.title)).toEqual(["Possible scam call", "Likely scam call"]);
    expect(session.alerts.map((alert) => alert.level)).toEqual(["medium", "high"]);
    expect(session.alerts.map((alert) => alert.sequence)).toEqual([1, 2]);
    expect(session.alerts.every((alert) => alert.pushed && alert.spoken)).toBe(true);
    expect(h.sender.alerts).toHaveLength(2);
    expect(session.alertLevel).toBe("high");
    expect(h.db.findCall(session.callId)?.alertLevel).toBe("high");
  });

  it("does not re-alert for the same or a lower level", async () => {
    const session = h.create();
    session.setVerdict(verdict("high"));
    await waitFor(() => session.alerts.length === 1);
    session.setVerdict(verdict("high", { confidence: 0.99 }));
    session.setVerdict(verdict("medium"));
    await flushPromises();
    expect(session.alerts).toHaveLength(1);
    expect(h.sender.alerts).toHaveLength(1);
  });

  it("alerts once for a burst of verdicts at the same level while the first alert is still in flight", async () => {
    const session = h.create();
    session.setVerdict(verdict("medium"));
    session.setVerdict(verdict("medium", { confidence: 0.65 }));
    session.setVerdict(verdict("medium", { confidence: 0.7 }));
    await waitFor(() => session.alerts.length === 1);
    await flushPromises();
    expect(session.alerts).toHaveLength(1);
    expect(h.sender.alerts).toHaveLength(1);
  });

  it("builds the exact AlertPushRequest of docs/CALLS.md §5.4", async () => {
    const session = h.create();
    session.setVerdict(verdict("high"));
    await waitFor(() => session.alerts.length === 1);
    const request = h.sender.alerts[0]!;
    expect(request).toEqual({
      deviceId: DEVICE_ID,
      apnsToken: APNS_TOKEN,
      environment: "sandbox",
      title: "Likely scam call",
      subtitle: "Call from +1 (555) 010-0003",
      body: "Asks for gift cards · Claims to be a grandchild in trouble · Says not to tell anyone",
      threadId: CALL_ALERT_THREAD_ID,
      category: CALL_ALERT_CATEGORY,
      interruptionLevel: "time-sensitive",
      relevanceScore: 1,
      collapseId: `call-${session.callId}`,
      expirationSeconds: CALL_ALERT_EXPIRATION_SECONDS,
      contentAvailable: true,
      data: {
        kind: "call-alert",
        callID: session.callId,
        level: "high",
        confidence: 0.9,
        category: "scam",
        callerNumber: CALLER_NUMBER,
        startedAt: session.startedAt,
        sequence: 1,
      },
    });
    expect(CALL_ALERT_THREAD_ID).toBe("com.mazooni.PhishGuard.calls");
    expect(CALL_ALERT_CATEGORY).toBe("PHISHGUARD_CALL_ALERT");
    expect(CALL_ALERT_EXPIRATION_SECONDS).toBe(120);
    expect(Object.keys(request.data)).toEqual(["kind", "callID", "level", "confidence", "category", "callerNumber", "startedAt", "sequence"]);
    expect(estimatedPayloadBytes(request)).toBeLessThan(MAX_ALERT_PAYLOAD_BYTES);
  });

  it("keeps the payload under the size guard by trimming the body", () => {
    const session = h.create();
    const stored = session.setVerdict(verdict("high"));
    const request = buildAlertPushRequest(session, stored, "high", { title: "Likely scam call", subtitle: "Call from x", body: "B".repeat(6000) }, {
      deviceId: DEVICE_ID,
      environment: "sandbox",
      apnsToken: APNS_TOKEN,
    });
    expect(estimatedPayloadBytes(request)).toBeLessThan(MAX_ALERT_PAYLOAD_BYTES);
    expect(request.body.length).toBeLessThan(6000);
    expect(request.data["callID"]).toBe(session.callId);
  });

  it("skips the push when the device has no APNs token but still speaks and records", async () => {
    h = harness({ token: null });
    const session = h.create();
    session.setVerdict(verdict("high"));
    await waitFor(() => session.alerts.length === 1);
    expect(h.sender.alerts).toHaveLength(0);
    expect(session.alerts[0]).toMatchObject({ pushed: false, spoken: true, level: "high" });
    expect(h.twilio.spoken).toEqual([{ callId: session.callId, text: testCallsConfig().spokenWarningText }]);
  });

  it("records pushed=false when APNs is not configured", async () => {
    h = harness({ apnsConfigured: false });
    const session = h.create();
    session.setVerdict(verdict("high"));
    await waitFor(() => session.alerts.length === 1);
    expect(h.sender.alerts).toHaveLength(0);
    expect(session.alerts[0]?.pushed).toBe(false);
    expect(session.alerts[0]?.spoken).toBe(true);
  });

  it("clears the device token on a dropToken outcome, unless the token was re-registered after APNs' timestamp", async () => {
    h.sender.respondAlert = () => ({ ok: false, dropToken: true, reason: "Unregistered", status: 410, retried: false });
    const session = h.create();
    session.setVerdict(verdict("high"));
    await waitFor(() => session.alerts.length === 1);
    expect(session.alerts[0]?.pushed).toBe(false);
    expect(h.db.findDevice(DEVICE_ID)?.apnsToken).toBeNull();

    const kept = harness();
    const registeredAt = kept.db.findDevice(DEVICE_ID)!.updatedAt;
    kept.sender.respondAlert = () => ({ ok: false, dropToken: true, reason: "Unregistered", status: 410, invalidSince: registeredAt - 1000, retried: false });
    const session2 = kept.create();
    session2.setVerdict(verdict("high"));
    await waitFor(() => session2.alerts.length === 1);
    expect(kept.db.findDevice(DEVICE_ID)?.apnsToken).toBe(APNS_TOKEN);
  });

  it("records pushed=false on an ordinary push failure and never throws into the emitter", async () => {
    h.sender.respondAlert = () => {
      throw new Error("apns down");
    };
    const session = h.create();
    session.setVerdict(verdict("high"));
    await waitFor(() => session.alerts.length === 1);
    expect(session.alerts[0]).toMatchObject({ pushed: false, spoken: true });
  });

  it("speaks only while the call is in progress", async () => {
    const ringing = h.create({ status: "ringing" });
    ringing.setVerdict(verdict("high"));
    await waitFor(() => ringing.alerts.length === 1);
    expect(ringing.alerts[0]?.spoken).toBe(false);
    expect(h.twilio.spoken).toHaveLength(0);

    const connecting = h.create({ status: "connecting" });
    connecting.setVerdict(verdict("high"));
    await waitFor(() => connecting.alerts.length === 1);
    expect(connecting.alerts[0]?.spoken).toBe(false);
  });

  it("does not speak when the line turned the spoken warning off, or without a voice", async () => {
    const muted = h.create({ line: line({ spokenWarning: false }) });
    muted.setVerdict(verdict("high"));
    await waitFor(() => muted.alerts.length === 1);
    expect(muted.alerts[0]).toMatchObject({ pushed: true, spoken: false });
    expect(h.twilio.spoken).toHaveLength(0);

    const voiceless = harness({ voice: false });
    const session = voiceless.create();
    session.setVerdict(verdict("high"));
    await waitFor(() => session.alerts.length === 1);
    expect(session.alerts[0]).toMatchObject({ pushed: true, spoken: false });
  });

  it("never speaks into a demo or replay session (no Twilio leg), but still pushes", async () => {
    const demo = h.create({ source: "demo", line: null });
    demo.setVerdict(verdict("high"));
    await waitFor(() => demo.alerts.length === 1);
    expect(demo.alerts[0]).toMatchObject({ pushed: true, spoken: false });
    expect(h.twilio.spoken).toHaveLength(0);

    const replay = h.create({ source: "replay" });
    replay.setVerdict(verdict("high"));
    await waitFor(() => replay.alerts.length === 1);
    expect(replay.alerts[0]?.spoken).toBe(false);
  });

  it("uses the line's minimum level, or the configured default without a line", async () => {
    const strict = h.create({ line: line({ minimumLevel: "high" }) });
    strict.setVerdict(verdict("medium"));
    await flushPromises();
    expect(strict.alerts).toHaveLength(0);
    strict.setVerdict(verdict("high"));
    await waitFor(() => strict.alerts.length === 1);

    const sensitive = h.create({ line: line({ minimumLevel: "low" }) });
    sensitive.setVerdict(verdict("low"));
    await waitFor(() => sensitive.alerts.length === 1);
    expect(sensitive.alerts[0]?.title).toBe("Suspicious call");

    const lowDefault = harness({ minimumLevel: "low" });
    const noLine = lowDefault.create({ line: null, source: "demo" });
    noLine.setVerdict(verdict("low"));
    await waitFor(() => noLine.alerts.length === 1);
  });

  it("uses the verdict summary as the body when there are no reasons", async () => {
    const session = h.create();
    session.setVerdict(verdict("high", { reasons: [], summary: "Model-only verdict." }));
    await waitFor(() => session.alerts.length === 1);
    expect(session.alerts[0]?.body).toBe("Model-only verdict.");
    expect(session.alerts[0]?.sentAt).toBe(h.clock.now());
  });

  it("records spoken=false when the spoken warning throws, still pushes, and never throws into the emitter", async () => {
    h.twilio.speakToUser = async () => {
      throw new Error("twilio down");
    };
    const session = h.create();
    session.setVerdict(verdict("high"));
    await waitFor(() => session.alerts.length === 1);
    expect(session.alerts[0]).toMatchObject({ level: "high", pushed: true, spoken: false });
    expect(h.sender.alerts).toHaveLength(1);
  });

  it("never alerts for a verdict that rises after the call ended: no push, no speech, but the verdict is persisted", async () => {
    const session = h.create();
    session.setVerdict(verdict("medium"));
    await waitFor(() => session.alerts.length === 1);
    expect(session.alerts[0]).toMatchObject({ level: "medium", pushed: true, spoken: true });
    session.end("completed");
    // The detector's final pass at call end can still raise the level (docs/CALLS.md §6.3): summary only.
    const final = session.setVerdict(verdict("high"));
    await flushPromises();
    expect(session.alerts).toHaveLength(1);
    expect(h.twilio.spoken).toHaveLength(1);
    expect(h.sender.alerts).toHaveLength(1);
    expect(h.db.findCall(session.callId)).toMatchObject({
      status: "completed",
      alerted: true,
      alertLevel: "medium",
      verdict: { sequence: final.sequence, level: "high" },
    });
  });

  it("never alerts on a call that ended before its first qualifying verdict", async () => {
    const session = h.create();
    session.end("completed");
    session.setVerdict(verdict("high"));
    await flushPromises();
    expect(session.alerts).toHaveLength(0);
    expect(h.sender.alerts).toHaveLength(0);
    expect(h.twilio.spoken).toHaveLength(0);
    expect(h.db.findCall(session.callId)).toMatchObject({ status: "completed", alerted: false, verdict: { level: "high" } });
    expect(h.db.findCall(session.callId)?.alertLevel).toBeUndefined();
  });
});

import type { FastifyBaseLogger } from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  CALL_ALERT_CATEGORY,
  CALL_ALERT_EXPIRATION_SECONDS,
  CALL_ALERT_THREAD_ID,
  CallAlertDispatcher,
  MAX_ALERT_PAYLOAD_BYTES,
  estimatedPayloadBytes,
} from "../../src/calls/alerts/dispatcher.js";
import { VOICE_ALERT_BODY, VOICE_ALERT_TITLE, VOICE_SPOKEN_ADDENDUM, voiceAlertText } from "../../src/calls/alerts/text.js";
import { ANNOUNCEMENT_GAP_MS, JOIN_DELAY_MS, VOICE_ALERT_PUSH_KIND, VoiceAlertDispatcher, announcementMs, buildVoiceAlertPushRequest } from "../../src/calls/alerts/voiceDispatcher.js";
import { DEFAULT_AI_VOICE_WARNING, DEFAULT_SPOKEN_WARNING, type VoiceDetectionConfig } from "../../src/calls/config.js";
import { MODULATE_VOICE_PROVIDER } from "../../src/calls/modulate/voiceDetector.js";
import { CallSession, CallSessionManager, type CallSessionInit } from "../../src/calls/session.js";
import type { CallLine, CallReason, CallRiskLevel, CallVerdict, CallVoiceAssessment, CallVoiceUpdate, VoiceStatus } from "../../src/calls/types.js";
import { RelayDb } from "../../src/db.js";
import { sha256Hex } from "../../src/auth.js";
import { APNS_TOKEN, BUNDLE_ID, DEVICE_ID, DEVICE_SECRET, FakeClock, FakeSender } from "../helpers.js";
import { CALLER_NUMBER, FakeTwilioClient, GUARD_NUMBER, PROTECTED_NUMBER, silentLogger, testCallsConfig, testVoiceConfig } from "./fakes.js";
import { flushPromises, waitFor } from "./liveClient.js";

/**
 * The AI-voice warning (alerts/voiceDispatcher.ts): once per call on the first `synthetic` assessment of a live
 * call — its own push, its own announcement slot, recorded on the voice assessment and never in `session.alerts`.
 * Both dispatchers are attached the way calls/index.ts attaches them, so the last blocks can show that neither
 * changes what the other does, except for the one sentence a test call's scam warning carries.
 */

const REASONS: CallReason[] = [
  { id: "call.gift_cards", title: "Asks for gift cards", detail: "Wants Apple gift cards.", severity: "high", source: "heuristic" },
  { id: "call.secrecy", title: "Says not to tell anyone", detail: "Don't tell Mom.", severity: "medium", source: "heuristic" },
];

function verdict(level: CallRiskLevel, overrides: Partial<Omit<CallVerdict, "sequence">> = {}): Omit<CallVerdict, "sequence"> {
  const confidence = level === "high" ? 0.9 : level === "medium" ? 0.6 : level === "low" ? 0.35 : 0.1;
  return {
    category: level === "safe" ? "safe" : "scam",
    confidence,
    level,
    reasons: level === "safe" ? [] : REASONS,
    summary: "The caller asks for gift cards.",
    recommendedAction: "Hang up.",
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

function report(status: VoiceStatus, overrides: Partial<CallVoiceUpdate> = {}): CallVoiceUpdate {
  const decided = status === "synthetic" || status === "human";
  return {
    status,
    syntheticShare: status === "synthetic" ? 1 : 0,
    confidence: decided ? 0.95 : 0,
    speechMs: decided ? 6000 : 0,
    provider: MODULATE_VOICE_PROVIDER,
    ...overrides,
  };
}

/** Records every line's fields and message; `child()` returns itself. */
function recordingLogger(): { logger: FastifyBaseLogger; lines: { level: string; fields: unknown; message: string }[] } {
  const lines: { level: string; fields: unknown; message: string }[] = [];
  const log =
    (level: string) =>
    (fields: unknown, message?: string): void => {
      lines.push({ level, fields, message: typeof fields === "string" ? fields : (message ?? "") });
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
  return { logger, lines };
}

interface HarnessOptions {
  apnsConfigured?: boolean;
  /** `false`: a relay without Twilio. */
  twilio?: boolean;
  token?: string | null;
  /** The `voice` config section; `null` = no MODULATE_API_KEY (a demo call's scripted detector still reports). */
  voiceConfig?: Partial<VoiceDetectionConfig> | null;
  /** Default 12 s (`ANNOUNCEMENT_GAP_MS`); `null` = derived from the warning texts, as in production. */
  gapMs?: number | null;
  /** Default 0: the announcement owed to someone who has just joined is scheduled without a pause. */
  joinDelayMs?: number;
  logger?: FastifyBaseLogger;
}

interface Harness {
  db: RelayDb;
  sender: FakeSender;
  twilio: FakeTwilioClient;
  clock: FakeClock;
  sessions: CallSessionManager;
  scam: CallAlertDispatcher;
  voice: VoiceAlertDispatcher;
  /** Every `voice` event of every session, in order. */
  events: CallVoiceAssessment[];
  create(overrides?: Partial<CallSessionInit>): CallSession;
}

function harness(options: HarnessOptions = {}): Harness {
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
  const config = testCallsConfig({ voice: options.voiceConfig === null ? undefined : testVoiceConfig(options.voiceConfig ?? {}) });
  const shared = {
    db,
    pushSender: sender,
    apnsConfigured: options.apnsConfigured ?? true,
    voice: options.twilio === false ? undefined : twilio,
    config,
    logger: options.logger ?? silentLogger(),
    now: clock.now,
  };
  const voice: VoiceAlertDispatcher = new VoiceAlertDispatcher({
    ...shared,
    announcementGapMs: options.gapMs === null ? undefined : (options.gapMs ?? ANNOUNCEMENT_GAP_MS),
    joinDelayMs: options.joinDelayMs ?? 0,
    inFlightRetryMs: 5,
    refusedRetryMs: 5,
    scamAlertInFlight: (callId) => scam.isAlerting(callId),
  });
  const scam: CallAlertDispatcher = new CallAlertDispatcher({ ...shared, voiceAddendum: voice });
  const events: CallVoiceAssessment[] = [];
  sessions.on("created", (session) => {
    session.on("voice", (assessment) => events.push(assessment));
    scam.attach(session);
    voice.attach(session);
  });
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
  return { db, sender, twilio, clock, sessions, scam, voice, events, create };
}

const warned = (session: CallSession): boolean => session.voice?.alert !== undefined;

describe("VoiceAlertDispatcher", () => {
  let h: Harness;
  beforeEach(() => {
    h = harness();
  });

  it("stays silent for every assessment that is not `synthetic`", async () => {
    const session = h.create();
    for (const status of ["analyzing", "human", "inconclusive", "unavailable"] as const) session.setVoice(report(status));
    await flushPromises();
    expect(session.voice?.alert).toBeUndefined();
    expect(session.alerted).toBe(false);
    expect(h.sender.alerts).toHaveLength(0);
    expect(h.twilio.voiceSpoken).toHaveLength(0);
    expect(h.voice.pendingCalls).toBe(0);
  });

  it("warns on the first `synthetic`: one push, one voice-slot announcement, recorded on the assessment", async () => {
    const session = h.create();
    session.setVoice(report("analyzing"));
    h.clock.advance(7000);
    session.setVoice(report("synthetic"));
    await waitFor(() => warned(session));
    expect(session.voice).toMatchObject({ status: "synthetic", detectedAt: h.clock.now() });
    expect(session.voice?.alert).toEqual({
      title: "AI voice detected",
      subtitle: "Call from +1 (555) 010-0003",
      body: "The caller's voice appears to be AI-generated. If they say they are someone you know, hang up and call them back on a number you trust.",
      sentAt: h.clock.now(),
      pushed: true,
      spoken: true,
    });
    expect(VOICE_ALERT_TITLE).toBe("AI voice detected");
    expect(voiceAlertText(CALLER_NUMBER)).toEqual({ title: VOICE_ALERT_TITLE, subtitle: "Call from +1 (555) 010-0003", body: VOICE_ALERT_BODY });
    expect(h.sender.alerts).toHaveLength(1);
    expect(h.twilio.voiceSpoken).toEqual([{ callId: session.callId, text: DEFAULT_AI_VOICE_WARNING }]);
    // The scam channel is untouched: nothing in `alerts`, no level, nothing in the scam announcement slot.
    expect(h.twilio.spoken).toHaveLength(0);
    expect(session.alerts).toHaveLength(0);
    expect(session.alertLevel).toBeUndefined();
    expect(session.verdict).toBeUndefined();
    expect(session.alerted).toBe(true);
    const stored = h.db.findCall(session.callId)!;
    expect(stored).toMatchObject({ alerted: true, voice: { status: "synthetic", alert: { pushed: true, spoken: true } } });
    expect(stored.alertLevel).toBeUndefined();
    // analysing, synthetic, the recorded warning — and nothing else.
    expect(h.events.map((event) => [event.status, event.alert !== undefined])).toEqual([["analyzing", false], ["synthetic", false], ["synthetic", true]]);
  });

  it("warns exactly once per call, whatever follows", async () => {
    const session = h.create();
    session.setVoice(report("synthetic", { syntheticShare: 0.85 }));
    session.setVoice(report("synthetic", { syntheticShare: 0.9 })); // a burst while the first warning is in flight
    session.setVoice(report("synthetic", { syntheticShare: 1 }));
    await waitFor(() => warned(session));
    session.setVoice(report("synthetic", { syntheticShare: 0.7, confidence: 0.8 }));
    session.setVoice(report("human")); // `synthetic` is sticky, and still no second warning
    await flushPromises();
    expect(h.sender.alerts).toHaveLength(1);
    expect(h.twilio.voiceSpoken).toHaveLength(1);
    expect(h.sender.alerts[0]!.data["confidence"]).toBe(0.95); // the assessment that triggered it
    expect(session.voice).toMatchObject({ status: "synthetic", alert: { pushed: true, spoken: true } });
    expect(h.voice.pendingCalls).toBe(1); // remembered until the call ends
    session.end("completed");
    expect(h.voice.pendingCalls).toBe(0);
  });

  it("warns each call separately", async () => {
    const first = h.create();
    const second = h.create({ callerNumber: "+15550100009" });
    first.setVoice(report("synthetic"));
    second.setVoice(report("synthetic"));
    await waitFor(() => warned(first) && warned(second));
    expect(h.sender.alerts.map((request) => request.collapseId).sort()).toEqual([`call-voice-${first.callId}`, `call-voice-${second.callId}`].sort());
    expect(h.twilio.voiceSpoken.map((entry) => entry.callId).sort()).toEqual([first.callId, second.callId].sort());
  });

  it("never warns about a call that has ended", async () => {
    // The session itself ignores a detector's report after the end…
    const session = h.create();
    session.setVoice(report("analyzing"));
    session.end("completed");
    session.setVoice(report("synthetic"));
    await flushPromises();
    expect(session.voice).toMatchObject({ status: "inconclusive" });
    expect(h.sender.alerts).toHaveLength(0);

    // …and a `voice` event that does fire on an ended call (a warning recorded late) starts nothing either.
    const late = new CallSession({ deviceId: DEVICE_ID, line: line(), source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: PROTECTED_NUMBER, startedAt: h.clock.now(), status: "in_progress" }, h.clock.now);
    late.setVoice(report("synthetic"));
    late.end("completed");
    h.voice.attach(late);
    const strayEvents: CallVoiceAssessment[] = [];
    late.on("voice", (assessment) => strayEvents.push(assessment));
    late.recordVoiceAlert({ ...voiceAlertText(CALLER_NUMBER), sentAt: h.clock.now(), pushed: false, spoken: false });
    await flushPromises();
    expect(strayEvents).toHaveLength(1);
    expect(h.sender.alerts).toHaveLength(0);
    expect(h.twilio.voiceSpoken).toHaveLength(0);
    expect(h.voice.pendingCalls).toBe(0);
  });

  it("keeps a warning that was already sent when the call ends while the push is in flight, without speaking", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    h.sender.sendAlert = async (request) => {
      h.sender.alerts.push(request);
      await gate;
      return { ok: true, retried: false };
    };
    const session = h.create({ status: "ringing" });
    session.setVoice(report("synthetic"));
    await flushPromises();
    session.end("canceled");
    release();
    await waitFor(() => warned(session));
    expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: false });
    expect(h.db.findCall(session.callId)).toMatchObject({ status: "canceled", alerted: true, voice: { alert: { pushed: true, spoken: false } } });
    expect(h.twilio.voiceSpoken).toHaveLength(0);
    expect(h.voice.pendingCalls).toBe(0);
  });

  describe("push", () => {
    it("builds the request: the scam alert's constants, its own collapse id, and `voice: synthetic` on top of the usual keys", async () => {
      const session = h.create();
      session.setVoice(report("synthetic", { confidence: 0.91 }));
      await waitFor(() => warned(session));
      const request = h.sender.alerts[0]!;
      expect(request).toEqual({
        deviceId: DEVICE_ID,
        apnsToken: APNS_TOKEN,
        environment: "sandbox",
        title: "AI voice detected",
        subtitle: "Call from +1 (555) 010-0003",
        body: VOICE_ALERT_BODY,
        threadId: CALL_ALERT_THREAD_ID,
        category: CALL_ALERT_CATEGORY,
        interruptionLevel: "time-sensitive",
        relevanceScore: 1,
        collapseId: `call-voice-${session.callId}`,
        expirationSeconds: CALL_ALERT_EXPIRATION_SECONDS,
        contentAvailable: true,
        data: {
          kind: "call-voice-alert",
          callID: session.callId,
          level: "low",
          confidence: 0.91,
          category: "safe",
          callerNumber: CALLER_NUMBER,
          startedAt: session.startedAt,
          sequence: 0,
          voice: "synthetic",
        },
      });
      expect(Object.keys(request.data)).toEqual(["kind", "callID", "level", "confidence", "category", "callerNumber", "startedAt", "sequence", "voice"]);
      expect(request.collapseId).not.toBe(`call-${session.callId}`);
      expect(estimatedPayloadBytes(request)).toBeLessThan(MAX_ALERT_PAYLOAD_BYTES);
    });

    it("mirrors the scam verdict as it stands in `level`, `category` and `sequence` — and `low`/`safe` when it is safe", async () => {
      const scammy = h.create({ line: line({ minimumLevel: "high" }) }); // medium stays below the line's level: no scam alert
      scammy.setVerdict(verdict("low"));
      const current = scammy.setVerdict(verdict("medium", { category: "phishing" }));
      scammy.setVoice(report("synthetic"));
      await waitFor(() => warned(scammy));
      expect(h.sender.alerts).toHaveLength(1);
      expect(h.sender.alerts[0]!.data).toMatchObject({ level: "medium", category: "phishing", sequence: current.sequence, confidence: 0.95, voice: "synthetic" });
      expect(scammy.alerts).toHaveLength(0);

      const benign = h.create();
      const safe = benign.setVerdict(verdict("safe"));
      benign.setVoice(report("synthetic"));
      await waitFor(() => warned(benign));
      expect(h.sender.alerts[1]!.data).toMatchObject({ level: "low", category: "safe", sequence: safe.sequence });
    });

    it("keeps the payload under the size guard", () => {
      const session = h.create();
      const request = buildVoiceAlertPushRequest(session, { confidence: 0.9 }, { title: VOICE_ALERT_TITLE, subtitle: "Call from x", body: "B".repeat(6000) }, {
        deviceId: DEVICE_ID,
        environment: "sandbox",
        apnsToken: APNS_TOKEN,
      });
      expect(estimatedPayloadBytes(request)).toBeLessThan(MAX_ALERT_PAYLOAD_BYTES);
      expect(request.body.length).toBeLessThan(6000);
      expect(request.data).toMatchObject({ kind: "call-voice-alert", callID: session.callId, voice: "synthetic" });
    });

    it("is skipped when the device has no APNs token, or APNs is not configured — the warning is still spoken and recorded", async () => {
      h = harness({ token: null });
      const tokenless = h.create();
      tokenless.setVoice(report("synthetic"));
      await waitFor(() => warned(tokenless));
      expect(h.sender.alerts).toHaveLength(0);
      expect(tokenless.voice?.alert).toMatchObject({ pushed: false, spoken: true });

      h = harness({ apnsConfigured: false });
      const unconfigured = h.create();
      unconfigured.setVoice(report("synthetic"));
      await waitFor(() => warned(unconfigured));
      expect(h.sender.alerts).toHaveLength(0);
      expect(unconfigured.voice?.alert).toMatchObject({ pushed: false, spoken: true });
      expect(unconfigured.alerted).toBe(true);
    });

    it("clears the device token on a dropToken outcome, unless the token was re-registered after APNs' timestamp", async () => {
      h.sender.respondAlert = () => ({ ok: false, dropToken: true, reason: "Unregistered", status: 410, retried: false });
      const session = h.create();
      session.setVoice(report("synthetic"));
      await waitFor(() => warned(session));
      expect(session.voice?.alert?.pushed).toBe(false);
      expect(h.db.findDevice(DEVICE_ID)?.apnsToken).toBeNull();

      const kept = harness();
      const registeredAt = kept.db.findDevice(DEVICE_ID)!.updatedAt;
      kept.sender.respondAlert = () => ({ ok: false, dropToken: true, reason: "Unregistered", status: 410, invalidSince: registeredAt - 1000, retried: false });
      const session2 = kept.create();
      session2.setVoice(report("synthetic"));
      await waitFor(() => warned(session2));
      expect(session2.voice?.alert?.pushed).toBe(false);
      expect(kept.db.findDevice(DEVICE_ID)?.apnsToken).toBe(APNS_TOKEN);
    });

    it("records pushed=false on an ordinary failure or a throwing sender, and never throws into the emitter", async () => {
      h.sender.respondAlert = () => ({ ok: false, dropToken: false, reason: "InternalServerError", status: 500, retried: true });
      const failed = h.create();
      failed.setVoice(report("synthetic"));
      await waitFor(() => warned(failed));
      expect(failed.voice?.alert).toMatchObject({ pushed: false, spoken: true });
      expect(h.db.findDevice(DEVICE_ID)?.apnsToken).toBe(APNS_TOKEN);

      h.sender.respondAlert = () => {
        throw new Error("apns down");
      };
      const thrown = h.create();
      expect(() => thrown.setVoice(report("synthetic"))).not.toThrow();
      await waitFor(() => warned(thrown));
      expect(thrown.voice?.alert).toMatchObject({ pushed: false, spoken: true });
    });
  });

  describe("speech", () => {
    it("speaks the configured text in the voice slot", async () => {
      h = harness({ voiceConfig: { warningText: "Careful: that voice is a machine." } });
      const session = h.create();
      session.setVoice(report("synthetic"));
      await waitFor(() => warned(session));
      expect(h.twilio.voiceSpoken).toEqual([{ callId: session.callId, text: "Careful: that voice is a machine." }]);
      expect(h.twilio.spoken).toHaveLength(0);
    });

    it("does not speak when the line turned spoken warnings off, when the operator turned this one off, or without Twilio", async () => {
      const muted = h.create({ line: line({ spokenWarning: false }) });
      muted.setVoice(report("synthetic"));
      await waitFor(() => warned(muted));
      expect(muted.voice?.alert).toMatchObject({ pushed: true, spoken: false });
      expect(h.twilio.voiceSpoken).toHaveLength(0);

      h = harness({ voiceConfig: { spokenWarning: false } });
      const operatorOff = h.create();
      operatorOff.setVoice(report("synthetic"));
      await waitFor(() => warned(operatorOff));
      expect(operatorOff.voice?.alert).toMatchObject({ pushed: true, spoken: false });
      expect(h.twilio.voiceSpoken).toHaveLength(0);
      expect(h.voice.pendingCalls).toBe(1);

      h = harness({ twilio: false });
      const voiceless = h.create();
      voiceless.setVoice(report("synthetic"));
      await waitFor(() => warned(voiceless));
      expect(voiceless.voice?.alert).toMatchObject({ pushed: true, spoken: false });
    });

    it("never speaks into a demo or replay session, with or without a `voice` config section, but still pushes", async () => {
      for (const options of [{}, { voiceConfig: null }] as HarnessOptions[]) {
        h = harness(options);
        const requests: string[] = [];
        const speak = h.twilio.speakToUser.bind(h.twilio);
        h.twilio.speakToUser = async (session, text, slot) => {
          requests.push(session.source);
          return speak(session, text, slot);
        };
        const demo = h.create({ source: "demo", line: null });
        demo.setVoice(report("synthetic", { provider: "demo:scripted" }));
        const replay = h.create({ source: "replay" });
        replay.setVoice(report("synthetic"));
        await waitFor(() => warned(demo) && warned(replay));
        expect(demo.voice?.alert).toMatchObject({ pushed: true, spoken: false });
        expect(replay.voice?.alert).toMatchObject({ pushed: true, spoken: false });
        expect(requests).toEqual([]);
        expect(h.sender.alerts).toHaveLength(2);
      }
    });

    it("never speaks a standalone announcement on a test call (it would replace the scripted call), and never asks Twilio to", async () => {
      const requests: unknown[] = [];
      h.twilio.speakToUser = async (session, text, slot) => {
        requests.push({ callId: session.callId, text, slot });
        return true;
      };
      const session = h.create({ source: "test-call", callerNumber: GUARD_NUMBER, twilioCallSid: "CA" + "d".repeat(32) });
      session.setVoice(report("synthetic"));
      await waitFor(() => warned(session));
      // Not when the status changes later either.
      const ringing = h.create({ source: "test-call", callerNumber: GUARD_NUMBER, status: "ringing" });
      ringing.setVoice(report("synthetic"));
      await waitFor(() => warned(ringing));
      ringing.setStatus("in_progress");
      await flushPromises();
      expect(requests).toEqual([]);
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: false });
      expect(ringing.voice?.alert).toMatchObject({ pushed: true, spoken: false });
      expect(h.sender.alerts).toHaveLength(2);
    });

    it("waits for the protected person to join: recorded with spoken=false at once, spoken and recorded again on `in_progress`", async () => {
      const session = h.create({ status: "ringing" });
      session.setVoice(report("synthetic"));
      await waitFor(() => warned(session));
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: false });
      const sentAt = session.voice!.alert!.sentAt;
      expect(h.twilio.voiceSpoken).toHaveLength(0);

      session.setStatus("connecting");
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(0);

      h.clock.advance(9000);
      session.setStatus("in_progress");
      await waitFor(() => session.voice?.alert?.spoken === true);
      expect(h.twilio.voiceSpoken).toEqual([{ callId: session.callId, text: DEFAULT_AI_VOICE_WARNING }]);
      // The same warning, confirmed: only `spoken` changed, and there was still exactly one push.
      expect(session.voice?.alert).toEqual({ ...voiceAlertText(CALLER_NUMBER), sentAt, pushed: true, spoken: true });
      expect(h.sender.alerts).toHaveLength(1);
      expect(h.events.filter((event) => event.alert).map((event) => event.alert!.spoken)).toEqual([false, true]);
      expect(h.db.findCall(session.callId)?.voice?.alert).toMatchObject({ pushed: true, spoken: true });
    });

    it("gives up the announcement when the call ends before the person joined", async () => {
      const session = h.create({ status: "ringing" });
      session.setVoice(report("synthetic"));
      await waitFor(() => warned(session));
      expect(h.voice.pendingCalls).toBe(1);
      session.end("no_answer");
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(0);
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: false });
      expect(h.voice.pendingCalls).toBe(0);
    });

    it("records spoken=false when Twilio refuses or the request throws, still pushes, and never throws into the emitter", async () => {
      h.twilio.speakToUser = async () => false;
      const refused = h.create();
      refused.setVoice(report("synthetic"));
      await waitFor(() => warned(refused));
      expect(refused.voice?.alert).toMatchObject({ pushed: true, spoken: false });

      h.twilio.speakToUser = async () => {
        throw new Error("twilio down");
      };
      const thrown = h.create();
      expect(() => thrown.setVoice(report("synthetic"))).not.toThrow();
      await waitFor(() => warned(thrown));
      expect(thrown.voice?.alert).toMatchObject({ pushed: true, spoken: false });

      // The deferred path fails just as quietly (one more attempt, see the timer tests, then it is dropped).
      const deferred = h.create({ status: "ringing" });
      deferred.setVoice(report("synthetic"));
      await waitFor(() => warned(deferred));
      expect(() => deferred.setStatus("in_progress")).not.toThrow();
      await flushPromises();
      expect(deferred.voice?.alert).toMatchObject({ pushed: true, spoken: false });
      expect(h.sender.alerts).toHaveLength(3);
    });
  });

  describe("speech after a scam warning (timers)", () => {
    beforeEach(() => {
      // Only the timers the dispatcher waits on are faked; `flushPromises` keeps running on real `setImmediate`.
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    /** A scam warning that was pushed and spoken, as the scam dispatcher records it. */
    async function scamWarning(session: CallSession, level: CallRiskLevel = "medium"): Promise<void> {
      const before = session.alerts.length;
      session.setVerdict(verdict(level));
      await flushPromises();
      expect(session.alerts).toHaveLength(before + 1);
      expect(session.alerts.at(-1)).toMatchObject({ level, spoken: true });
    }

    it("defaults to a 12 second gap", () => {
      expect(ANNOUNCEMENT_GAP_MS).toBe(12_000);
    });

    it("waits out the rest of the gap, then speaks and confirms the record", async () => {
      const session = h.create();
      await scamWarning(session);
      h.clock.advance(4000); // 4 s of the scam warning have played
      session.setVoice(report("synthetic"));
      await flushPromises();
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: false }); // recorded as soon as the push settled
      expect(h.twilio.voiceSpoken).toHaveLength(0);

      vi.advanceTimersByTime(7999);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(0);
      vi.advanceTimersByTime(1);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toEqual([{ callId: session.callId, text: DEFAULT_AI_VOICE_WARNING }]);
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: true });
      expect(h.twilio.spoken).toHaveLength(1); // the scam warning, once
      expect(vi.getTimerCount()).toBe(0);
    });

    it("speaks at once when the scam warning is older than the gap, or was never spoken", async () => {
      const old = h.create();
      await scamWarning(old);
      h.clock.advance(ANNOUNCEMENT_GAP_MS);
      old.setVoice(report("synthetic"));
      await flushPromises();
      expect(old.voice?.alert).toMatchObject({ spoken: true });

      // Alerted while still ringing: the scam warning was pushed but not spoken, so there is nothing to wait for.
      const unspoken = h.create({ status: "ringing" });
      unspoken.setVerdict(verdict("high"));
      await flushPromises();
      expect(unspoken.alerts[0]).toMatchObject({ spoken: false });
      unspoken.setStatus("in_progress");
      unspoken.setVoice(report("synthetic"));
      await flushPromises();
      expect(unspoken.voice?.alert).toMatchObject({ spoken: true });
      expect(vi.getTimerCount()).toBe(0);
    });

    it("applies the gap when the person joins after both warnings were raised", async () => {
      const session = h.create({ status: "connecting" });
      session.setVoice(report("synthetic"));
      await flushPromises();
      expect(session.voice?.alert).toMatchObject({ spoken: false });
      session.setStatus("in_progress");
      await flushPromises();
      // Joined with nothing just spoken: only the pause after the join (none in this harness).
      vi.advanceTimersByTime(0);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(1);
    });

    it("gives the line a moment after the person joins before it speaks", async () => {
      expect(JOIN_DELAY_MS).toBe(1500);
      const paused = harness({ joinDelayMs: JOIN_DELAY_MS });
      const session = paused.create({ status: "ringing" });
      session.setVoice(report("synthetic"));
      await flushPromises();
      session.setStatus("in_progress");
      await flushPromises();
      vi.advanceTimersByTime(1499);
      await flushPromises();
      expect(paused.twilio.voiceSpoken).toHaveLength(0);
      vi.advanceTimersByTime(1);
      await flushPromises();
      expect(paused.twilio.voiceSpoken).toHaveLength(1);
      expect(session.voice?.alert).toMatchObject({ spoken: true });
    });

    it("asks once more when Twilio refuses the announcement, and only once", async () => {
      const session = h.create();
      const answers = [false, true];
      const requests: string[] = [];
      h.twilio.speakToUser = async (_session, _text, slot = "scam") => {
        requests.push(slot);
        return answers.shift() ?? false;
      };
      session.setVoice(report("synthetic"));
      await flushPromises();
      expect(requests).toEqual(["voice"]);
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: false });
      vi.advanceTimersByTime(5); // the harness's refusedRetryMs
      await flushPromises();
      expect(requests).toEqual(["voice", "voice"]);
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: true });

      const refusedTwice = h.create();
      h.twilio.speakToUser = async (_session, _text, slot = "scam") => {
        requests.push(slot);
        return false;
      };
      refusedTwice.setVoice(report("synthetic"));
      await flushPromises();
      vi.advanceTimersByTime(5);
      await flushPromises();
      vi.advanceTimersByTime(60_000);
      await flushPromises();
      expect(requests).toHaveLength(4);
      expect(refusedTwice.voice?.alert).toMatchObject({ pushed: true, spoken: false });
    });

    it("does not start on top of a scam alert that is still being sent: it waits for it, then for its warning", async () => {
      // The scam push hangs for a while: the scam warning is already playing but the alert is not recorded yet.
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const send = h.sender.sendAlert.bind(h.sender);
      h.sender.sendAlert = async (request) => {
        if (request.data?.["kind"] === "call-alert") await gate;
        return send(request);
      };
      const session = h.create();
      session.setVerdict(verdict("medium"));
      await flushPromises();
      expect(h.twilio.spoken).toHaveLength(1); // requested at once, as always
      expect(session.alerts).toHaveLength(0); // …but not recorded: the push is in flight
      expect(h.scam.isAlerting(session.callId)).toBe(true);

      session.setVoice(report("synthetic"));
      await flushPromises();
      vi.advanceTimersByTime(20); // several looks while the scam alert is in flight
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(0);

      release();
      await flushPromises();
      expect(session.alerts.at(-1)).toMatchObject({ spoken: true });
      // Recorded as spoken: now the full gap runs from here.
      vi.advanceTimersByTime(ANNOUNCEMENT_GAP_MS - 1);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(0);
      vi.advanceTimersByTime(1);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(1);
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: true });
    });

    it("speaks as soon as an in-flight scam alert turns out not to have been spoken", async () => {
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const send = h.sender.sendAlert.bind(h.sender);
      h.sender.sendAlert = async (request) => {
        if (request.data?.["kind"] === "call-alert") await gate;
        return send(request);
      };
      // The line has spoken scam warnings off… for the scam warning only in this test: Twilio refuses that slot.
      h.twilio.speakToUser = async (session, text, slot = "scam") => {
        if (slot === "scam") return false;
        h.twilio.voiceSpoken.push({ callId: session.callId, text });
        return true;
      };
      const session = h.create();
      session.setVerdict(verdict("medium"));
      await flushPromises();
      session.setVoice(report("synthetic"));
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(0);
      release();
      await flushPromises();
      expect(session.alerts.at(-1)).toMatchObject({ spoken: false });
      vi.advanceTimersByTime(5); // the next look
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(1);
    });

    it("a timer that fires while a risen scam alert is in flight waits again instead of speaking over it", async () => {
      const session = h.create();
      await scamWarning(session, "medium");
      session.setVoice(report("synthetic"));
      await flushPromises();
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const send = h.sender.sendAlert.bind(h.sender);
      h.sender.sendAlert = async (request) => {
        if (request.data?.["kind"] === "call-alert") await gate;
        return send(request);
      };
      vi.advanceTimersByTime(ANNOUNCEMENT_GAP_MS - 100);
      h.clock.advance(ANNOUNCEMENT_GAP_MS - 100);
      session.setVerdict(verdict("high")); // the level rises 100 ms before our turn; its push hangs
      await flushPromises();
      expect(h.twilio.spoken).toHaveLength(2);
      vi.advanceTimersByTime(100); // our timer fires now
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(0);
      release();
      await flushPromises();
      vi.advanceTimersByTime(ANNOUNCEMENT_GAP_MS);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(1);
    });

    it("is said once more when a scam warning follows it closely and may have cut it short", async () => {
      const session = h.create();
      session.setVoice(report("synthetic"));
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(1);
      h.clock.advance(2000);
      await scamWarning(session, "medium"); // 2 s into our announcement
      expect(h.twilio.voiceSpoken).toHaveLength(1);
      vi.advanceTimersByTime(ANNOUNCEMENT_GAP_MS - 1);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(1);
      vi.advanceTimersByTime(1);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(2);
      // Once: a second scam warning (the level rose) does not bring it back a third time.
      h.clock.advance(1000);
      await scamWarning(session, "high");
      vi.advanceTimersByTime(60_000);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(2);
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: true });
      expect(h.sender.alerts.filter((alert) => alert.data?.["kind"] === VOICE_ALERT_PUSH_KIND)).toHaveLength(1);
    });

    it("is not repeated when the scam warning comes after it has finished", async () => {
      const session = h.create();
      session.setVoice(report("synthetic"));
      await flushPromises();
      h.clock.advance(ANNOUNCEMENT_GAP_MS);
      await scamWarning(session, "medium");
      vi.advanceTimersByTime(60_000);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(1);
    });

    it("by default gives each warning the time its text takes to read, never less than 12 s", async () => {
      expect(announcementMs("Short.")).toBe(ANNOUNCEMENT_GAP_MS);
      expect(announcementMs(DEFAULT_SPOKEN_WARNING)).toBeGreaterThan(ANNOUNCEMENT_GAP_MS);
      expect(announcementMs(Array.from({ length: 100 }, () => "word").join(" "))).toBe(42_500);
      const derived = harness({ gapMs: null });
      const session = derived.create();
      session.setVerdict(verdict("medium"));
      await flushPromises();
      session.setVoice(report("synthetic"));
      await flushPromises();
      vi.advanceTimersByTime(announcementMs(DEFAULT_SPOKEN_WARNING) - 1);
      await flushPromises();
      expect(derived.twilio.voiceSpoken).toHaveLength(0);
      vi.advanceTimersByTime(1);
      await flushPromises();
      expect(derived.twilio.voiceSpoken).toHaveLength(1);
    });

    it("is pushed back again by a scam warning spoken while it waits", async () => {
      const session = h.create();
      await scamWarning(session, "medium");
      session.setVoice(report("synthetic"));
      await flushPromises();
      vi.advanceTimersByTime(10_000);
      h.clock.advance(10_000);
      await scamWarning(session, "high"); // the level rose: the scam warning is spoken again
      vi.advanceTimersByTime(11_999); // the first wait would have ended 2 s in
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(0);
      vi.advanceTimersByTime(1);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(1);
      expect(session.voice?.alert).toMatchObject({ spoken: true });
      expect(h.twilio.spoken).toHaveLength(2);
    });

    it("cancels the wait when the call ends: nothing is spoken afterwards and no timer is left", async () => {
      const session = h.create();
      await scamWarning(session);
      session.setVoice(report("synthetic"));
      await flushPromises();
      expect(vi.getTimerCount()).toBe(1);
      session.end("completed");
      // Still one timer, but a different one: the wait is gone and the manager's eviction of the ended session is new.
      expect(vi.getTimerCount()).toBe(1);
      vi.advanceTimersByTime(59_999);
      await flushPromises();
      expect(h.twilio.voiceSpoken).toHaveLength(0);
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: false });
      expect(h.voice.pendingCalls).toBe(0);
    });

    it("close() cancels every wait (shutdown)", async () => {
      const session = h.create();
      await scamWarning(session);
      session.setVoice(report("synthetic"));
      await flushPromises();
      expect(vi.getTimerCount()).toBe(1);
      h.voice.close();
      expect(vi.getTimerCount()).toBe(0);
      expect(h.voice.pendingCalls).toBe(0);
    });

    it("uses a timer that does not keep the process alive", async () => {
      vi.useRealTimers();
      h = harness({ gapMs: 60_000 });
      const unref = vi.spyOn(globalThis, "setTimeout");
      try {
        const session = h.create();
        session.setVerdict(verdict("medium"));
        await waitFor(() => session.alerts.length === 1);
        const before = unref.mock.results.length;
        session.setVoice(report("synthetic"));
        await waitFor(() => warned(session));
        const timers = unref.mock.results.slice(before).map((result) => result.value as NodeJS.Timeout).filter((timer) => typeof timer.hasRef === "function");
        expect(timers.some((timer) => !timer.hasRef())).toBe(true);
        session.end("completed");
      } finally {
        unref.mockRestore();
      }
    });
  });

  describe("the scam alert is unaffected", () => {
    it("alerts at its own level after a voice warning, with the unchanged push and the unchanged spoken text", async () => {
      const session = h.create();
      session.setVoice(report("synthetic"));
      await waitFor(() => warned(session));
      expect(h.scam.decide(session, { ...verdict("medium"), sequence: 1 })).toBe("medium");

      const medium = session.setVerdict(verdict("medium"));
      await waitFor(() => session.alerts.length === 1);
      const high = session.setVerdict(verdict("high"));
      await waitFor(() => session.alerts.length === 2);
      expect(session.alerts.map((alert) => [alert.level, alert.sequence, alert.pushed, alert.spoken])).toEqual([
        ["medium", medium.sequence, true, true],
        ["high", high.sequence, true, true],
      ]);
      expect(session.alertLevel).toBe("high");
      const scamPushes = h.sender.alerts.filter((request) => request.collapseId === `call-${session.callId}`);
      expect(scamPushes).toHaveLength(2);
      expect(scamPushes[1]).toMatchObject({ title: "Likely scam call", body: "Asks for gift cards · Says not to tell anyone" });
      expect(Object.keys(scamPushes[1]!.data)).toEqual(["kind", "callID", "level", "confidence", "category", "callerNumber", "startedAt", "sequence"]);
      // The scam slot got the configured warning, word for word, both times; the voice slot its own text, once.
      expect(h.twilio.spoken).toEqual([
        { callId: session.callId, text: testCallsConfig().spokenWarningText },
        { callId: session.callId, text: testCallsConfig().spokenWarningText },
      ]);
      expect(h.twilio.voiceSpoken).toHaveLength(1);
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: true });
      expect(h.db.findCall(session.callId)).toMatchObject({ alerted: true, alertLevel: "high", voice: { status: "synthetic" } });
    });

    it("a voice warning never raises, lowers or satisfies the scam alert's level", async () => {
      const session = h.create({ line: line({ minimumLevel: "high" }) });
      session.setVoice(report("synthetic"));
      await waitFor(() => warned(session));
      session.setVerdict(verdict("medium"));
      await flushPromises();
      expect(session.alerts).toHaveLength(0); // below the line's level, voice warning or not
      expect(session.alertLevel).toBeUndefined();
      expect(session.alerted).toBe(true); // the person was warned — about the voice
      session.setVerdict(verdict("high"));
      await waitFor(() => session.alerts.length === 1);
      expect(session.alerts[0]).toMatchObject({ level: "high", title: "Likely scam call" });
    });

    it("does nothing at all on a call without voice events", async () => {
      const session = h.create();
      session.setVerdict(verdict("high"));
      await waitFor(() => session.alerts.length === 1);
      session.end("completed");
      expect(h.sender.alerts).toHaveLength(1);
      expect(h.sender.alerts[0]!.collapseId).toBe(`call-${session.callId}`);
      expect(h.twilio.spoken).toEqual([{ callId: session.callId, text: testCallsConfig().spokenWarningText }]);
      expect(h.twilio.voiceSpoken).toHaveLength(0);
      expect(h.events).toHaveLength(0);
      expect(session.voice).toBeUndefined();
      expect(h.voice.pendingCalls).toBe(0);
    });
  });

  describe("test calls: the scam warning carries the AI-voice sentence", () => {
    const testCall = (overrides: Partial<CallSessionInit> = {}): CallSession =>
      h.create({ source: "test-call", callerNumber: GUARD_NUMBER, twilioCallSid: "CA" + "d".repeat(32), ...overrides });

    it("appends one sentence to the scam warning when the voice is already `synthetic`, and marks the voice warning spoken", async () => {
      const session = testCall();
      session.setVoice(report("synthetic"));
      await waitFor(() => warned(session));
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: false });
      expect(h.twilio.spoken).toHaveLength(0);

      session.setVerdict(verdict("high"));
      await waitFor(() => session.alerts.length === 1);
      expect(VOICE_SPOKEN_ADDENDUM).toBe("Also, the caller's voice appears to be A.I. generated.");
      expect(h.twilio.spoken).toEqual([{ callId: session.callId, text: `${testCallsConfig().spokenWarningText} ${VOICE_SPOKEN_ADDENDUM}` }]);
      expect(h.twilio.voiceSpoken).toHaveLength(0);
      expect(session.alerts[0]).toMatchObject({ level: "high", pushed: true, spoken: true });
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: true });
      expect(h.db.findCall(session.callId)?.voice?.alert).toMatchObject({ spoken: true });
      expect(h.sender.alerts.map((request) => request.collapseId)).toEqual([`call-voice-${session.callId}`, `call-${session.callId}`]);
    });

    it("marks the voice warning spoken even when its own push is still in flight", async () => {
      let release!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      const respond = h.sender.sendAlert.bind(h.sender);
      h.sender.sendAlert = async (request) => {
        if (request.collapseId.startsWith("call-voice-")) await gate;
        return respond(request);
      };
      const session = testCall();
      session.setVoice(report("synthetic"));
      session.setVerdict(verdict("high"));
      await waitFor(() => session.alerts.length === 1);
      expect(h.twilio.spoken[0]!.text).toContain(VOICE_SPOKEN_ADDENDUM);
      expect(session.voice?.alert).toBeUndefined();
      release();
      await waitFor(() => warned(session));
      expect(session.voice?.alert).toMatchObject({ pushed: true, spoken: true });
      expect(h.events.filter((event) => event.alert)).toHaveLength(1); // recorded once, already complete
    });

    it("is a no-op unless the voice is `synthetic`", async () => {
      for (const status of [undefined, "analyzing", "human", "unavailable"] as const) {
        h = harness();
        const session = testCall();
        if (status) session.setVoice(report(status));
        session.setVerdict(verdict("high"));
        await waitFor(() => session.alerts.length === 1);
        expect(h.twilio.spoken, String(status)).toEqual([{ callId: session.callId, text: testCallsConfig().spokenWarningText }]);
        expect(session.voice?.alert).toBeUndefined();
      }
    });

    it("is a no-op when the operator turned the AI-voice announcement off, and nothing is spoken when the line turned warnings off", async () => {
      h = harness({ voiceConfig: { spokenWarning: false } });
      const operatorOff = testCall();
      operatorOff.setVoice(report("synthetic"));
      await waitFor(() => warned(operatorOff));
      operatorOff.setVerdict(verdict("high"));
      await waitFor(() => operatorOff.alerts.length === 1);
      expect(h.twilio.spoken).toEqual([{ callId: operatorOff.callId, text: testCallsConfig().spokenWarningText }]);
      expect(operatorOff.voice?.alert).toMatchObject({ spoken: false });

      h = harness();
      const muted = testCall({ line: line({ spokenWarning: false }) });
      muted.setVoice(report("synthetic"));
      await waitFor(() => warned(muted));
      muted.setVerdict(verdict("high"));
      await waitFor(() => muted.alerts.length === 1);
      expect(h.twilio.spoken).toHaveLength(0);
      expect(muted.alerts[0]).toMatchObject({ spoken: false });
      expect(muted.voice?.alert).toMatchObject({ spoken: false });
    });

    it("leaves the voice warning unspoken when Twilio refuses the combined warning", async () => {
      h.twilio.speakToUser = async () => false;
      const session = testCall();
      session.setVoice(report("synthetic"));
      await waitFor(() => warned(session));
      session.setVerdict(verdict("high"));
      await waitFor(() => session.alerts.length === 1);
      expect(session.alerts[0]).toMatchObject({ spoken: false });
      expect(session.voice?.alert).toMatchObject({ spoken: false });
    });

    it("never adds the sentence on an ordinary call, where the voice warning has its own announcement", async () => {
      const session = h.create();
      session.setVoice(report("synthetic"));
      await waitFor(() => warned(session));
      expect(h.voice.addendumFor(session)).toBeUndefined();
      expect(h.voice.addendumFor(testCall())).toBeUndefined(); // a test call whose voice was not judged
    });
  });

  it("logs the call, the device and a redacted caller — never a full number, a token or the warning's words", async () => {
    const { logger, lines } = recordingLogger();
    h = harness({ logger });
    const session = h.create({ status: "ringing" });
    session.setVoice(report("synthetic"));
    await waitFor(() => warned(session));
    session.setStatus("in_progress");
    await waitFor(() => session.voice?.alert?.spoken === true);
    h.sender.respondAlert = () => {
      throw new Error(`could not reach ${PROTECTED_NUMBER} with token ${APNS_TOKEN}`);
    };
    const failing = h.create();
    failing.setVoice(report("synthetic"));
    await waitFor(() => warned(failing));

    const messages = lines.map((entry) => entry.message);
    expect(messages).toEqual(expect.arrayContaining(["call-voice-alert: alerting", "call-voice-alert: pushed", "call-voice-alert: recorded", "call-voice-alert: spoken warning requested", "call-voice-alert: push failed"]));
    expect(messages.every((message) => message.startsWith("call-voice-alert: "))).toBe(true);
    const alerting = lines.find((entry) => entry.message === "call-voice-alert: alerting")!;
    expect(alerting.fields).toEqual({ callId: session.callId, deviceId: DEVICE_ID, caller: "…0003", confidence: 0.95, syntheticShare: 1 });
    expect(lines.find((entry) => entry.message === "call-voice-alert: push failed")).toMatchObject({ level: "error", fields: { errorName: "Error", callId: failing.callId } });
    const output = JSON.stringify(lines);
    for (const secret of [CALLER_NUMBER, PROTECTED_NUMBER, CALLER_NUMBER.slice(1), APNS_TOKEN, session.mediaToken, failing.mediaToken, VOICE_ALERT_BODY, DEFAULT_AI_VOICE_WARNING, "could not reach"]) {
      expect(output).not.toContain(secret);
    }
  });
});

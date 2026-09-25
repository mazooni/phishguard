import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CallSessionManager, MIN_RETAIN_ENDED_MS, type CallSession } from "../../src/calls/session.js";
import type { CallRecord, CallVerdict } from "../../src/calls/types.js";
import { DEVICE_ID, FakeClock, closeTestApp, createCallsTestApp, deviceHeaders, registerDevice, type CallsTestContext } from "../helpers.js";
import { CALLER_NUMBER, PROTECTED_NUMBER, scamResult } from "./fakes.js";
import { LiveClient, waitFor } from "./liveClient.js";
import { USER_SID, conferenceForm, inboundCall, postForm, registerLine, tokenQuery, transcriptionForm } from "./twilio-helpers.js";

/**
 * Lifecycle and failure paths of the merged relay: what is released when a session ends and is evicted, what a
 * verdict after the end does downstream (db, hub, dispatcher), what late callbacks do, and what the runtime's
 * `close()` leaves behind.
 */

function highVerdict(): Omit<CallVerdict, "sequence"> {
  return { category: "scam", confidence: 0.9, level: "high", reasons: [], summary: "Scam.", recommendedAction: "Hang up.", heuristicScore: 0.9, updatedAt: 0 };
}

describe("CallSessionManager eviction", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  function manager(retainEndedMs: number): { sessions: CallSessionManager; records: CallRecord[]; clock: FakeClock } {
    const records: CallRecord[] = [];
    const clock = new FakeClock();
    const sessions = new CallSessionManager({ store: { upsertCall: (record) => records.push(record) }, retainEndedMs, now: clock.now });
    return { sessions, records, clock };
  }

  function create(sessions: CallSessionManager, clock: FakeClock, twilioCallSid?: string): CallSession {
    return sessions.create({
      deviceId: DEVICE_ID,
      line: null,
      source: "twilio",
      callerNumber: CALLER_NUMBER,
      calledNumber: PROTECTED_NUMBER,
      startedAt: clock.now(),
      status: "in_progress",
      ...(twilioCallSid ? { twilioCallSid } : {}),
    });
  }

  it("removes every SID bound with index() — not only twilioCallSid/userCallSid — and ignores index() after eviction", () => {
    vi.useFakeTimers();
    const { sessions, clock } = manager(60_000);
    const session = create(sessions, clock, "CA-caller");
    sessions.index(session, "CA-participant"); // a conference participant SID that differs from the dialled one
    sessions.index(session, "CA-participant");
    session.userCallSid = "CA-user";
    sessions.index(session, "CA-user");
    expect(sessions.indexedSidCount).toBe(3);
    expect(sessions.byTwilioSid("CA-participant")).toBe(session);
    let listeners = 0;
    session.on("verdict", () => (listeners += 1));

    session.end("completed");
    vi.advanceTimersByTime(60_000);
    expect(sessions.get(session.callId)).toBeUndefined();
    expect(sessions.indexedSidCount).toBe(0);
    expect(sessions.byTwilioSid("CA-participant")).toBeUndefined();
    expect(session.listenerCount("verdict")).toBe(0);
    expect(session.listenerCount("ended")).toBe(0);
    session.setVerdict(highVerdict());
    expect(listeners).toBe(0);

    sessions.index(session, "CA-late"); // a late Twilio callback for an evicted session leaks nothing
    expect(sessions.indexedSidCount).toBe(0);
    expect(sessions.all()).toHaveLength(0);
  });

  it("evicting one session never unbinds a SID that a newer session took over", () => {
    vi.useFakeTimers();
    const { sessions, clock } = manager(1_000);
    const older = create(sessions, clock, "CA-shared");
    const newer = create(sessions, clock, "CA-shared");
    expect(sessions.byTwilioSid("CA-shared")).toBe(newer);
    older.end("completed");
    vi.advanceTimersByTime(MIN_RETAIN_ENDED_MS);
    expect(sessions.get(older.callId)).toBeUndefined();
    expect(sessions.byTwilioSid("CA-shared")).toBe(newer);
    expect(sessions.indexedSidCount).toBe(1);
  });

  it("keeps an ended session at least MIN_RETAIN_ENDED_MS even with CALLS_RETAIN_ENDED_MINUTES=0, so the detector's final verdict is still persisted", () => {
    vi.useFakeTimers();
    const { sessions, records, clock } = manager(0);
    const session = create(sessions, clock);
    session.end("completed");
    vi.advanceTimersByTime(MIN_RETAIN_ENDED_MS - 1);
    expect(sessions.get(session.callId)).toBe(session);
    const stored = session.setVerdict(highVerdict()); // the detector's final pass, ≤ 10 s after `ended`
    expect(records.at(-1)).toMatchObject({ callId: session.callId, status: "completed", verdict: { sequence: stored.sequence, level: "high" } });
    vi.advanceTimersByTime(1);
    expect(sessions.get(session.callId)).toBeUndefined();
    expect(session.listenerCount("verdict")).toBe(0);
  });

  it("close() ends every active session as canceled, persists it and clears the eviction timers", () => {
    vi.useFakeTimers();
    const { sessions, records, clock } = manager(60_000);
    const live = create(sessions, clock, "CA-live");
    const done = create(sessions, clock);
    done.end("completed");
    sessions.close();
    expect(live.status).toBe("canceled");
    expect(live.isEnded).toBe(true);
    expect(records.filter((record) => record.callId === live.callId).at(-1)).toMatchObject({ status: "canceled" });
    expect(vi.getTimerCount()).toBe(0);
    sessions.close(); // idempotent
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("verdicts and callbacks after the call ended", () => {
  let ctx: CallsTestContext;
  const clients: LiveClient[] = [];

  afterEach(async () => {
    for (const client of clients.splice(0)) client.socket.terminate();
    await closeTestApp(ctx);
  });

  async function liveFeed(): Promise<LiveClient> {
    await ctx.app.listen({ port: 0, host: "127.0.0.1" });
    const { port } = ctx.app.server.address() as AddressInfo;
    const client = await LiveClient.connect(`ws://127.0.0.1:${port}/v1/devices/calls/live`, deviceHeaders());
    clients.push(client);
    await client.next("hello");
    return client;
  }

  it("the detector's final pass after `ended` is persisted and broadcast as verdict.updated, but never pushed or spoken", async () => {
    ctx = await createCallsTestApp({ transcriptionSource: "twilio" });
    await registerLine(ctx);
    const live = await liveFeed();
    const { session } = await inboundCall(ctx);
    await postForm(ctx.app, `/v1/calls/twilio/conference?${tokenQuery(session)}`, conferenceForm("participant-join", { ParticipantLabel: "user", CallSid: USER_SID }));
    expect(session.status).toBe("in_progress");

    // Hold the model's first answer until after the call ends: the detector's final pass then delivers it.
    let release: () => void = () => undefined;
    ctx.scorer.gate = new Promise<void>((resolve) => (release = resolve));
    ctx.scorer.respond = () => scamResult();
    await postForm(
      ctx.app,
      `/v1/calls/twilio/transcription?${tokenQuery(session)}`,
      transcriptionForm("inbound_track", "Go to the store, buy Apple gift cards, and read me the numbers on the back.", true, 1),
    );
    await waitFor(() => session.alerts.length === 1); // the rules alone alert at medium during the call
    expect(session.alerts[0]).toMatchObject({ level: "medium", pushed: true, spoken: true });
    expect(ctx.scorer.inputs).toHaveLength(1);

    await postForm(ctx.app, `/v1/calls/twilio/conference?${tokenQuery(session)}`, conferenceForm("conference-end"));
    expect(session.isEnded).toBe(true);
    release();
    await waitFor(() => ctx.db.findCall(session.callId)?.verdict?.modelRiskScore === 92);

    const record = ctx.db.findCall(session.callId)!;
    expect(record).toMatchObject({ status: "completed", alerted: true, alertLevel: "medium", verdict: { level: "high", modelRiskScore: 92 } });
    expect(session.alerts).toHaveLength(1);
    expect(ctx.sender.alerts).toHaveLength(1);
    expect(ctx.twilio.spoken).toHaveLength(1);

    await waitFor(() => live.received.some((event) => event.type === "verdict.updated" && event.verdict.level === "high"));
    const types = live.received.map((event) => event.type);
    const ended = types.indexOf("call.ended");
    expect(ended).toBeGreaterThan(-1);
    expect(types.lastIndexOf("verdict.updated")).toBeGreaterThan(ended);
    expect(types.filter((type, index) => type === "call.alert" && index > ended)).toEqual([]);
  });

  it("transcription content after the session ended is acknowledged and dropped", async () => {
    ctx = await createCallsTestApp({ transcriptionSource: "twilio" });
    await registerLine(ctx);
    const { session } = await inboundCall(ctx);
    await postForm(ctx.app, `/v1/calls/twilio/transcription?${tokenQuery(session)}`, transcriptionForm("inbound_track", "hello there", true, 1));
    expect(session.segments).toHaveLength(1);
    session.end("completed");
    const late = await postForm(ctx.app, `/v1/calls/twilio/transcription?${tokenQuery(session)}`, transcriptionForm("inbound_track", "and one more thing", true, 2));
    expect(late.statusCode).toBe(204);
    expect(session.segments).toHaveLength(1);
    expect(ctx.app.callGuard.detector.attachedCount).toBe(0);
  });

  it("the runtime's close() releases demo timers, detector state, live subscribers and sessions (canceled, persisted), and is idempotent", async () => {
    ctx = await createCallsTestApp();
    await registerDevice(ctx.app);
    const live = await liveFeed();
    const demo = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "grandparent", speed: 0.25 } });
    expect(demo.statusCode).toBe(202);
    const { callID } = demo.json() as { callID: string };
    await live.next("call.started");
    const runtime = ctx.app.callGuard;
    expect(runtime.demo.activeRuns).toBe(1);
    expect(runtime.detector.attachedCount).toBe(1);
    expect(runtime.hub.subscriberCount.devices).toBe(1);

    await runtime.close();
    expect(runtime.demo.activeRuns).toBe(0);
    expect(runtime.detector.attachedCount).toBe(0);
    expect(runtime.hub.subscriberCount).toEqual({ devices: 0, consoles: 0 });
    expect(runtime.sessions.active()).toEqual([]);
    expect(runtime.sessions.get(callID)?.status).toBe("canceled");
    expect(ctx.db.findCall(callID)).toMatchObject({ status: "canceled", alerted: false });
    expect(ctx.db.findCall(callID)?.endedAt).toBeDefined();
    await waitFor(() => live.closed);
    await runtime.close(); // the app's onClose hook will call it once more
  });
});

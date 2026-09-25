import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { buildApp } from "../../src/server.js";
import { RelayDb } from "../../src/db.js";
import type { CallRecord } from "../../src/calls/types.js";
import { MAX_ACTIVE_DEMO_CALLS_PER_DEVICE } from "../../src/calls/routes/devices.js";
import {
  API_KEY,
  DEVICE_ID,
  DEVICE_SECRET,
  FakeClock,
  FakeSender,
  FakeVerifier,
  OTHER_DEVICE_SECRET,
  closeTestApp,
  createCallsTestApp,
  deviceHeaders,
  registerDevice,
  testConfig,
  type CallsTestContext,
} from "../helpers.js";
import { CALLER_NUMBER, FakeScorer, FakeTranscriber, GUARD_NUMBER, PROTECTED_NUMBER, testCallsConfig } from "./fakes.js";
import { LiveClient, waitFor } from "./liveClient.js";

const OTHER_DEVICE_ID = "other-device-0001";

async function putLine(ctx: CallsTestContext, overrides: Record<string, unknown> = {}, secret = DEVICE_SECRET) {
  return ctx.app.inject({
    method: "PUT",
    url: "/v1/devices/call-line",
    headers: deviceHeaders(secret),
    payload: { phoneNumber: PROTECTED_NUMBER, minimumLevel: "medium", spokenWarning: true, ...overrides },
  });
}

function storedCall(ctx: CallsTestContext, callId: string, startedAt: number, deviceId = DEVICE_ID): CallRecord {
  const record: CallRecord = {
    callId,
    deviceId,
    source: "twilio",
    callerNumber: CALLER_NUMBER,
    calledNumber: PROTECTED_NUMBER,
    startedAt,
    endedAt: startedAt + 60_000,
    status: "completed",
    alerted: false,
    updatedAt: startedAt + 60_000,
  };
  ctx.db.upsertCall(record);
  return record;
}

async function listen(ctx: CallsTestContext): Promise<string> {
  await ctx.app.listen({ port: 0, host: "127.0.0.1" });
  const { port } = ctx.app.server.address() as AddressInfo;
  return `ws://127.0.0.1:${port}`;
}

describe("call-line routes", () => {
  let ctx: CallsTestContext;
  beforeEach(async () => {
    ctx = await createCallsTestApp();
    await registerDevice(ctx.app);
  });
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  it("requires the API key and a registered device on every route", async () => {
    const noKey = await ctx.app.inject({ method: "GET", url: "/v1/devices/call-line", headers: { authorization: `Bearer ${DEVICE_SECRET}` } });
    expect(noKey.statusCode).toBe(401);
    expect(noKey.json()).toEqual({ error: "invalid_api_key" });
    const badSecret = await ctx.app.inject({ method: "GET", url: "/v1/devices/calls", headers: deviceHeaders("c".repeat(64)) });
    expect(badSecret.statusCode).toBe(401);
    const noAuth = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: { "x-api-key": API_KEY }, payload: { scenario: "irs" } });
    expect(noAuth.statusCode).toBe(401);
    expect(ctx.app.callGuard.sessions.all()).toHaveLength(0);
  });

  it("rejects an invalid registration body with 400", async () => {
    expect((await putLine(ctx, { phoneNumber: "555-0102" })).statusCode).toBe(400);
    expect((await putLine(ctx, { phoneNumber: "+1555010000212345" })).statusCode).toBe(400);
    expect((await putLine(ctx, { minimumLevel: "safe" })).statusCode).toBe(400);
    expect((await putLine(ctx, { spokenWarning: "yes" })).statusCode).toBe(400);
    const missing = await ctx.app.inject({ method: "PUT", url: "/v1/devices/call-line", headers: deviceHeaders(), payload: { phoneNumber: PROTECTED_NUMBER } });
    expect(missing.statusCode).toBe(400);
    expect(ctx.db.findCallLine(DEVICE_ID)).toBeUndefined();
  });

  it("registers, returns and updates the line, keeping its id and creation time", async () => {
    const created = await putLine(ctx);
    expect(created.statusCode).toBe(200);
    const json = created.json() as Record<string, unknown>;
    expect(json).toEqual({
      lineID: expect.any(String),
      guardNumber: GUARD_NUMBER,
      phoneNumber: PROTECTED_NUMBER,
      minimumLevel: "medium",
      spokenWarning: true,
      createdAt: ctx.clock.now(),
    });

    const fetched = await ctx.app.inject({ method: "GET", url: "/v1/devices/call-line", headers: deviceHeaders() });
    expect(fetched.statusCode).toBe(200);
    expect(fetched.json()).toEqual(json);

    ctx.clock.advance(60_000);
    const updated = await putLine(ctx, { minimumLevel: "high", spokenWarning: false });
    expect(updated.statusCode).toBe(200);
    expect(updated.json()).toEqual({ ...json, minimumLevel: "high", spokenWarning: false });
    expect(ctx.db.findCallLine(DEVICE_ID)?.updatedAt).toBe(ctx.clock.now());
  });

  it("answers 404 no_line before registration and 204 for DELETE (idempotent)", async () => {
    const none = await ctx.app.inject({ method: "GET", url: "/v1/devices/call-line", headers: deviceHeaders() });
    expect(none.statusCode).toBe(404);
    expect(none.json()).toEqual({ error: "no_line" });
    await putLine(ctx);
    const removed = await ctx.app.inject({ method: "DELETE", url: "/v1/devices/call-line", headers: deviceHeaders() });
    expect(removed.statusCode).toBe(204);
    expect((await ctx.app.inject({ method: "GET", url: "/v1/devices/call-line", headers: deviceHeaders() })).statusCode).toBe(404);
    expect((await ctx.app.inject({ method: "DELETE", url: "/v1/devices/call-line", headers: deviceHeaders() })).statusCode).toBe(204);
  });

  it("reassigns the guard number to a device that registers later (a reinstalled app takes over)", async () => {
    await putLine(ctx);
    await registerDevice(ctx.app, { deviceID: OTHER_DEVICE_ID, secret: OTHER_DEVICE_SECRET });
    const taken = await putLine(ctx, { phoneNumber: "+15550100009" }, OTHER_DEVICE_SECRET);
    expect(taken.statusCode).toBe(200);
    expect(taken.json()).toMatchObject({ guardNumber: GUARD_NUMBER, phoneNumber: "+15550100009" });
    const displaced = await ctx.app.inject({ method: "GET", url: "/v1/devices/call-line", headers: deviceHeaders() });
    expect(displaced.statusCode).toBe(404);
    expect(ctx.db.findCallLineByGuardNumber(GUARD_NUMBER)?.deviceId).toBe(OTHER_DEVICE_ID);
  });

  it("answers 503 twilio_not_configured without a Twilio number", async () => {
    const bare = await createCallsTestApp({ twilio: undefined });
    try {
      await registerDevice(bare.app);
      const response = await putLine(bare);
      expect(response.statusCode).toBe(503);
      expect(response.json()).toEqual({ error: "twilio_not_configured" });
    } finally {
      await closeTestApp(bare);
    }
  });
});

describe("calls routes", () => {
  let ctx: CallsTestContext;
  const clients: LiveClient[] = [];
  beforeEach(async () => {
    ctx = await createCallsTestApp();
    await registerDevice(ctx.app);
  });
  afterEach(async () => {
    for (const client of clients.splice(0)) await client.close();
    await closeTestApp(ctx);
  });

  it("lists active sessions first, then stored records, newest first, honouring limit", async () => {
    await registerDevice(ctx.app, { deviceID: OTHER_DEVICE_ID, secret: OTHER_DEVICE_SECRET });
    const t0 = ctx.clock.now();
    storedCall(ctx, "old", t0 - 3 * 3_600_000);
    storedCall(ctx, "mid", t0 - 2 * 3_600_000);
    storedCall(ctx, "new", t0 - 3_600_000);
    storedCall(ctx, "theirs", t0, OTHER_DEVICE_ID);
    const demo = ctx.app.callGuard.demo.start({ deviceId: DEVICE_ID, line: null, scenario: "benign", speed: 4 });

    const all = await ctx.app.inject({ method: "GET", url: "/v1/devices/calls", headers: deviceHeaders() });
    expect(all.statusCode).toBe(200);
    const calls = (all.json() as { calls: { callID: string; status: string; durationSeconds?: number }[] }).calls;
    expect(calls.map((call) => call.callID)).toEqual([demo.callId, "new", "mid", "old"]);
    expect(calls[0]).toMatchObject({ status: "in_progress", source: "demo", durationSeconds: 0 });
    expect(calls[1]).toMatchObject({ status: "completed", durationSeconds: 60 });

    const limited = await ctx.app.inject({ method: "GET", url: "/v1/devices/calls?limit=2", headers: deviceHeaders() });
    expect((limited.json() as { calls: { callID: string }[] }).calls.map((call) => call.callID)).toEqual([demo.callId, "new"]);
    expect((await ctx.app.inject({ method: "GET", url: "/v1/devices/calls?limit=0", headers: deviceHeaders() })).statusCode).toBe(400);
    expect((await ctx.app.inject({ method: "GET", url: "/v1/devices/calls?limit=201", headers: deviceHeaders() })).statusCode).toBe(400);
  });

  it("does not list an ended session twice once it is also in the database", async () => {
    const demo = ctx.app.callGuard.demo.start({ deviceId: DEVICE_ID, line: null, scenario: "benign", speed: 4 });
    demo.end("completed");
    const response = await ctx.app.inject({ method: "GET", url: "/v1/devices/calls", headers: deviceHeaders() });
    const calls = (response.json() as { calls: { callID: string; status: string }[] }).calls;
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ callID: demo.callId, status: "completed" });
  });

  it("returns one call with its transcript while the session is retained, and without it from the database", async () => {
    const started = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "grandparent", speed: 4 } });
    expect(started.statusCode).toBe(202);
    const { callID } = started.json() as { callID: string };
    const session = ctx.app.callGuard.sessions.get(callID)!;
    await waitFor(() => session.segments.some((segment) => segment.final));

    const live = await ctx.app.inject({ method: "GET", url: `/v1/devices/calls/${callID}`, headers: deviceHeaders() });
    expect(live.statusCode).toBe(200);
    const body = live.json() as { callID: string; transcript: { speaker: string; text: string; final: boolean }[] };
    expect(body.callID).toBe(callID);
    expect(body.transcript.length).toBeGreaterThan(0);
    expect(body.transcript[0]).toMatchObject({ speaker: "caller", final: true });

    storedCall(ctx, "stored-1", ctx.clock.now() - 1000);
    const stored = await ctx.app.inject({ method: "GET", url: "/v1/devices/calls/stored-1", headers: deviceHeaders() });
    expect(stored.statusCode).toBe(200);
    expect(stored.json()).not.toHaveProperty("transcript");
    expect(stored.json()).toMatchObject({ callID: "stored-1", status: "completed", durationSeconds: 60 });
  });

  it("hides other devices' calls and unknown ids behind 404", async () => {
    await registerDevice(ctx.app, { deviceID: OTHER_DEVICE_ID, secret: OTHER_DEVICE_SECRET });
    storedCall(ctx, "theirs", ctx.clock.now(), OTHER_DEVICE_ID);
    const theirs = ctx.app.callGuard.demo.start({ deviceId: OTHER_DEVICE_ID, line: null, scenario: "benign", speed: 4 });
    for (const id of ["theirs", theirs.callId, "nope"]) {
      const response = await ctx.app.inject({ method: "GET", url: `/v1/devices/calls/${id}`, headers: deviceHeaders() });
      expect(response.statusCode, id).toBe(404);
      expect(response.json()).toEqual({ error: "not_found" });
    }
  });

  it("starts a demo call (202) whose events flow to the device's live socket", async () => {
    const base = await listen(ctx);
    const client = await LiveClient.connect(`${base}/v1/devices/calls/live`, deviceHeaders());
    clients.push(client);
    const hello = await client.next("hello");
    expect(hello).toMatchObject({ type: "hello", activeCalls: [] });

    const started = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "irs", speed: 4 } });
    expect(started.statusCode).toBe(202);
    const { callID } = started.json() as { callID: string };
    const session = ctx.app.callGuard.sessions.get(callID);
    expect(session).toBeDefined();
    expect(session).toMatchObject({ source: "demo", deviceId: DEVICE_ID, status: "in_progress" });
    expect(await client.next("call.started")).toMatchObject({ call: { callID, source: "demo", status: "in_progress" } });
    expect(await client.next("transcript.segment")).toMatchObject({ callID, segment: { speaker: "caller", final: false } });
    expect(await client.next("transcript.segment")).toMatchObject({ callID, segment: { speaker: "caller", final: true } });
    client.send({ type: "ping" });
    expect(await client.next("pong")).toEqual({ type: "pong" });
  });

  it("caps the demo calls a device runs at once (429 too_many_calls) and frees the slot when one ends", async () => {
    const start = () =>
      ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "benign", speed: 0.25 } });
    const ids: string[] = [];
    for (let index = 0; index < MAX_ACTIVE_DEMO_CALLS_PER_DEVICE; index += 1) {
      const response = await start();
      expect(response.statusCode).toBe(202);
      ids.push((response.json() as { callID: string }).callID);
    }
    const refused = await start();
    expect(refused.statusCode).toBe(429);
    expect(refused.json()).toEqual({ error: "too_many_calls" });
    expect(ctx.app.callGuard.demo.activeRuns).toBe(MAX_ACTIVE_DEMO_CALLS_PER_DEVICE);
    ctx.app.callGuard.sessions.get(ids[0]!)!.end("completed");
    expect(ctx.app.callGuard.demo.activeRuns).toBe(MAX_ACTIVE_DEMO_CALLS_PER_DEVICE - 1);
    expect((await start()).statusCode).toBe(202);
  });

  it("refuses the live socket without valid device credentials", async () => {
    const base = await listen(ctx);
    await expect(LiveClient.connect(`${base}/v1/devices/calls/live`, { authorization: `Bearer ${DEVICE_SECRET}` })).rejects.toThrow(/401/);
    await expect(LiveClient.connect(`${base}/v1/devices/calls/live`, deviceHeaders("d".repeat(64)))).rejects.toThrow(/401/);
    expect(ctx.app.callGuard.hub.subscriberCount.devices).toBe(0);
  });

  it("validates the demo body and answers 403 when demos are disabled", async () => {
    const badScenario = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "lottery" } });
    expect(badScenario.statusCode).toBe(400);
    const badSpeed = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "irs", speed: 9 } });
    expect(badSpeed.statusCode).toBe(400);
    expect(ctx.app.callGuard.sessions.all()).toHaveLength(0);

    const disabled = await createCallsTestApp({ demoEnabled: false });
    try {
      await registerDevice(disabled.app);
      const response = await disabled.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "irs" } });
      expect(response.statusCode).toBe(403);
      expect(response.json()).toEqual({ error: "demo_disabled" });
    } finally {
      await closeTestApp(disabled);
    }
  });

  it("places a test call through Twilio once a line exists (409 no_line before)", async () => {
    const noLine = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/test-call", headers: deviceHeaders(), payload: { scenario: "prize" } });
    expect(noLine.statusCode).toBe(409);
    expect(noLine.json()).toEqual({ error: "no_line" });

    await putLine(ctx);
    const placed = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/test-call", headers: deviceHeaders(), payload: { scenario: "prize" } });
    expect(placed.statusCode).toBe(202);
    const { callID } = placed.json() as { callID: string };
    const session = ctx.app.callGuard.sessions.get(callID)!;
    expect(session).toMatchObject({ source: "test-call", status: "ringing", callerNumber: GUARD_NUMBER, calledNumber: PROTECTED_NUMBER, transcriptionSource: "openai" });
    expect(session.line?.phoneNumber).toBe(PROTECTED_NUMBER);
    expect(ctx.twilio.testCalls).toEqual([{ callId: callID, scenario: "prize", sid: expect.any(String) }]);
    expect(session.twilioCallSid).toBe(ctx.twilio.testCalls[0]!.sid);
    expect(ctx.app.callGuard.sessions.byTwilioSid(session.twilioCallSid!)).toBe(session);

    ctx.twilio.failDial = new Error("trial account");
    const failed = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/test-call", headers: deviceHeaders(), payload: { scenario: "irs" } });
    expect(failed.statusCode).toBe(502);
    const failedSession = ctx.app.callGuard.sessions.all().find((s) => s.callId !== callID)!;
    expect(failedSession.status).toBe("failed");
  });

  it("answers 503 twilio_not_configured for a test call when no Twilio client exists", async () => {
    const clock = new FakeClock();
    const db = RelayDb.open(":memory:");
    const app = buildApp({
      config: testConfig({ calls: testCallsConfig({ twilio: undefined }) }),
      db,
      pushSender: new FakeSender(),
      tokenVerifier: new FakeVerifier(),
      logger: false,
      calls: { twilio: undefined, transcriber: new FakeTranscriber(), scorer: new FakeScorer(), now: clock.now },
    });
    await app.ready();
    try {
      await registerDevice(app);
      db.upsertCallLine({ lineId: "line-x", deviceId: DEVICE_ID, guardNumber: GUARD_NUMBER, phoneNumber: PROTECTED_NUMBER, minimumLevel: "medium", spokenWarning: true }, clock.now());
      const response = await app.inject({ method: "POST", url: "/v1/devices/calls/test-call", headers: deviceHeaders(), payload: { scenario: "irs" } });
      expect(response.statusCode).toBe(503);
      expect(response.json()).toEqual({ error: "twilio_not_configured" });
      expect(app.callGuard.sessions.all()).toHaveLength(0);
    } finally {
      await app.close();
      db.close();
    }
  });
});

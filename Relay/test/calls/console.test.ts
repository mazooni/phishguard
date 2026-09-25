import type { AddressInfo } from "node:net";
import { Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { DEMO_CALLED_NUMBER } from "../../src/calls/demo/runner.js";
import { MEDIA_PATH_PREFIX, REPLAY_CALLER_NUMBER } from "../../src/calls/live/console.js";
import { RelayDb } from "../../src/db.js";
import { buildApp } from "../../src/server.js";
import {
  API_KEY,
  DEVICE_ID,
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
import { FakeScorer, FakeTranscriber, FakeTwilioClient, GUARD_NUMBER, PROTECTED_NUMBER, testCallsConfig } from "./fakes.js";
import { LiveClient } from "./liveClient.js";

async function registerLine(ctx: CallsTestContext): Promise<string> {
  await registerDevice(ctx.app);
  const response = await ctx.app.inject({
    method: "PUT",
    url: "/v1/devices/call-line",
    headers: deviceHeaders(),
    payload: { phoneNumber: PROTECTED_NUMBER, minimumLevel: "medium", spokenWarning: true },
  });
  expect(response.statusCode).toBe(200);
  return (response.json() as { lineID: string }).lineID;
}

const keyHeaders = { "x-api-key": API_KEY };

describe("operator console", () => {
  let ctx: CallsTestContext;
  let lineID: string;
  const clients: LiveClient[] = [];
  beforeEach(async () => {
    ctx = await createCallsTestApp();
    lineID = await registerLine(ctx);
  });
  afterEach(async () => {
    for (const client of clients.splice(0)) await client.close();
    await closeTestApp(ctx);
  });

  it("sets a console cookie when the key arrives as ?key=, and accepts that cookie on a bare reload", async () => {
    const first = await ctx.app.inject({ method: "GET", url: `/v1/calls/console?key=${encodeURIComponent(API_KEY)}` });
    expect(first.statusCode).toBe(200);
    const setCookie = String(first.headers["set-cookie"]);
    expect(setCookie).toContain(`pg_console_key=${encodeURIComponent(API_KEY)}`);
    expect(setCookie).toContain("Path=/v1/calls/console");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Strict");
    // The page strips ?key= from the address bar; the browser's reload carries only the cookie.
    const reload = await ctx.app.inject({ method: "GET", url: "/v1/calls/console", headers: { cookie: `pg_console_key=${encodeURIComponent(API_KEY)}` } });
    expect(reload.statusCode).toBe(200);
    expect(reload.headers["set-cookie"]).toBeUndefined();
    const ws = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: { cookie: `other=1; pg_console_key=${encodeURIComponent(API_KEY)}` }, payload: { lineID: "nope", scenario: "irs" } });
    expect(ws.statusCode).toBe(404); // authenticated by the cookie; the line just does not exist
    const wrong = await ctx.app.inject({ method: "GET", url: "/v1/calls/console", headers: { cookie: `pg_console_key=${API_KEY}x` } });
    expect(wrong.statusCode).toBe(401);
    const viaHeader = await ctx.app.inject({ method: "GET", url: "/v1/calls/console", headers: keyHeaders });
    expect(viaHeader.headers["set-cookie"]).toBeUndefined(); // only a query-string key is turned into a cookie
  });

  it("answers 401 without the relay key, and accepts it as ?key= or X-API-Key", async () => {
    expect((await ctx.app.inject({ method: "GET", url: "/v1/calls/console" })).statusCode).toBe(401);
    expect((await ctx.app.inject({ method: "GET", url: `/v1/calls/console?key=${API_KEY}x` })).statusCode).toBe(401);
    expect((await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", payload: { lineID, scenario: "irs" } })).statusCode).toBe(401);
    expect((await ctx.app.inject({ method: "GET", url: `/v1/calls/console?key=${encodeURIComponent(API_KEY)}` })).statusCode).toBe(200);
    expect((await ctx.app.inject({ method: "GET", url: "/v1/calls/console", headers: keyHeaders })).statusCode).toBe(200);
    expect(ctx.app.callGuard.sessions.all()).toHaveLength(0);
  });

  it("serves one self-contained HTML page listing the lines, with a nonce-based CSP", async () => {
    const response = await ctx.app.inject({ method: "GET", url: "/v1/calls/console", headers: keyHeaders });
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toMatch(/^text\/html/);
    const csp = String(response.headers["content-security-policy"]);
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(csp).toContain("connect-src 'self' ws: wss:");
    const html = response.body;
    expect(html).toContain("<!doctype html>");
    expect(html).toContain(`<script nonce="${nonce}"`);
    expect(html).toContain(`<style nonce="${nonce}"`);
    expect(html).not.toMatch(/<script[^>]+src=/);
    expect(html).not.toMatch(/<link[^>]+href=/);
    expect(html).toContain("prefers-color-scheme");
    expect(html).toContain(`"lineID":"${lineID}"`);
    expect(html).toContain(`"guardNumber":"${GUARD_NUMBER}"`);
    expect(html).toContain('"protectedLast4":"…0002"');
    expect(html).not.toContain(PROTECTED_NUMBER);
    expect(html).toContain('"twilioConfigured":true');
    expect(html).toContain("/v1/calls/console/ws");
    for (const id of ["grandparent", "irs", "techSupport", "bankFraud", "prize", "benign"]) expect(html).toContain(`"id":"${id}"`);
  });

  it("starts a demo call for a line (202) and validates the body", async () => {
    const response = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { lineID, scenario: "bankFraud", speed: 2 } });
    expect(response.statusCode).toBe(202);
    const { callID } = response.json() as { callID: string };
    const session = ctx.app.callGuard.sessions.get(callID)!;
    expect(session).toMatchObject({ source: "demo", deviceId: DEVICE_ID, calledNumber: PROTECTED_NUMBER, status: "in_progress" });
    expect(session.line?.lineId).toBe(lineID);

    const unknown = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { lineID: "nope", scenario: "irs" } });
    expect(unknown.statusCode).toBe(404);
    expect(unknown.json()).toEqual({ error: "no_line" });
    expect((await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { lineID, scenario: "x" } })).statusCode).toBe(400);
    expect((await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { lineID, scenario: "irs", speed: 0.1 } })).statusCode).toBe(400);
  });

  it("starts a demo for a registered device without a line (deviceID) and lists such devices on the page", async () => {
    await registerDevice(ctx.app, { deviceID: "device-without-a-line", secret: OTHER_DEVICE_SECRET, apnsToken: null });
    const page = await ctx.app.inject({ method: "GET", url: "/v1/calls/console", headers: keyHeaders });
    expect(page.body).toContain('"deviceID":"device-without-a-line"');
    expect(page.body).not.toContain(`"deviceID":"${DEVICE_ID}"`); // it has a line: listed as a line, not twice
    expect(page.body).not.toContain(OTHER_DEVICE_SECRET);

    const response = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { deviceID: "device-without-a-line", scenario: "prize", speed: 4 } });
    expect(response.statusCode).toBe(202);
    const session = ctx.app.callGuard.sessions.get((response.json() as { callID: string }).callID)!;
    expect(session).toMatchObject({ source: "demo", deviceId: "device-without-a-line", line: null, calledNumber: DEMO_CALLED_NUMBER, status: "in_progress" });

    // A device that does have a line gets its line (the protected number) even when addressed by deviceID.
    const byDevice = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { deviceID: DEVICE_ID, scenario: "benign", speed: 4 } });
    expect(byDevice.statusCode).toBe(202);
    expect(ctx.app.callGuard.sessions.get((byDevice.json() as { callID: string }).callID)?.line?.lineId).toBe(lineID);

    const unknown = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { deviceID: "nope", scenario: "irs" } });
    expect(unknown.statusCode).toBe(404);
    expect(unknown.json()).toEqual({ error: "unknown_device" });
    const neither = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { scenario: "irs" } });
    expect(neither.statusCode).toBe(400);
    expect(neither.json()).toMatchObject({ error: "bad_request" });
    const both = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { lineID, deviceID: DEVICE_ID, scenario: "irs" } });
    expect(both.statusCode).toBe(400);
    expect(ctx.app.callGuard.sessions.all()).toHaveLength(2);
  });

  it("answers 403 demo_disabled when scripted demos are turned off", async () => {
    const off = await createCallsTestApp({ demoEnabled: false });
    try {
      const id = await registerLine(off);
      const response = await off.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { lineID: id, scenario: "irs" } });
      expect(response.statusCode).toBe(403);
      expect(response.json()).toEqual({ error: "demo_disabled" });
      expect(off.app.callGuard.sessions.all()).toHaveLength(0);
    } finally {
      await closeTestApp(off);
    }
  });

  it("places a test call for a line through Twilio", async () => {
    const response = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/test-call", headers: keyHeaders, payload: { lineID, scenario: "techSupport" } });
    expect(response.statusCode).toBe(202);
    const { callID } = response.json() as { callID: string };
    expect(ctx.twilio.testCalls).toEqual([{ callId: callID, scenario: "techSupport", sid: expect.any(String) }]);
    expect(ctx.app.callGuard.sessions.get(callID)).toMatchObject({ source: "test-call", status: "ringing", callerNumber: GUARD_NUMBER });
    const unknown = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/test-call", headers: keyHeaders, payload: { lineID: "nope", scenario: "irs" } });
    expect(unknown.statusCode).toBe(404);
  });

  it("creates a replay session for a device without a line, and refuses a replay without a transcriber", async () => {
    await registerDevice(ctx.app, { deviceID: "device-without-a-line", secret: OTHER_DEVICE_SECRET, apnsToken: null });
    const response = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: keyHeaders, payload: { deviceID: "device-without-a-line" } });
    expect(response.statusCode).toBe(202);
    const session = ctx.app.callGuard.sessions.get((response.json() as { callID: string }).callID)!;
    expect(session).toMatchObject({ source: "replay", deviceId: "device-without-a-line", line: null, calledNumber: DEMO_CALLED_NUMBER, transcriptionSource: "openai" });
    expect((await ctx.app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: keyHeaders, payload: { deviceID: "nope" } })).statusCode).toBe(404);
    expect((await ctx.app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: keyHeaders, payload: {} })).statusCode).toBe(400);

    // No OPENAI_API_KEY ⇒ no transcriber ⇒ a replay would produce nothing: refused up front, and the script says why.
    const db = RelayDb.open(":memory:");
    const clock = new FakeClock();
    const app = buildApp({
      config: testConfig({ calls: testCallsConfig({ openai: undefined }) }),
      db,
      pushSender: new FakeSender(),
      tokenVerifier: new FakeVerifier(),
      logger: false,
      calls: { twilio: new FakeTwilioClient(), transcriber: undefined, scorer: undefined, now: clock.now },
    });
    await app.ready();
    try {
      await registerDevice(app);
      const refused = await app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: keyHeaders, payload: { deviceID: DEVICE_ID } });
      expect(refused.statusCode).toBe(503);
      expect(refused.json()).toEqual({ error: "openai_not_configured" });
      expect(app.callGuard.sessions.all()).toHaveLength(0);
    } finally {
      await app.close();
      db.close();
    }
  });

  it("creates a replay session with its media token, and ends it on request", async () => {
    const response = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: keyHeaders, payload: { lineID } });
    expect(response.statusCode).toBe(202);
    const body = response.json() as { callID: string; mediaToken: string; mediaPath: string };
    const session = ctx.app.callGuard.sessions.get(body.callID)!;
    expect(body.mediaToken).toBe(session.mediaToken);
    expect(body.mediaPath).toBe(`${MEDIA_PATH_PREFIX}${session.mediaToken}`);
    expect(body.mediaPath).toBe(`/v1/calls/twilio/media/${session.mediaToken}`);
    expect(session).toMatchObject({ source: "replay", status: "in_progress", callerNumber: REPLAY_CALLER_NUMBER, calledNumber: PROTECTED_NUMBER, transcriptionSource: "openai" });

    const ended = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/replay/end", headers: keyHeaders, payload: { callID: body.callID } });
    expect(ended.statusCode).toBe(200);
    expect(ended.json()).toEqual({ callID: body.callID, status: "completed" });
    expect(session.isEnded).toBe(true);
    expect((await ctx.app.inject({ method: "POST", url: "/v1/calls/console/replay/end", headers: keyHeaders, payload: { callID: body.callID } })).statusCode).toBe(200);
    expect((await ctx.app.inject({ method: "POST", url: "/v1/calls/console/replay/end", headers: keyHeaders, payload: { callID: "nope" } })).statusCode).toBe(404);
    const demo = ctx.app.callGuard.demo.start({ deviceId: DEVICE_ID, line: null, scenario: "benign", speed: 4 });
    expect((await ctx.app.inject({ method: "POST", url: "/v1/calls/console/replay/end", headers: keyHeaders, payload: { callID: demo.callId } })).statusCode).toBe(404);
    expect(demo.isEnded).toBe(false);
  });

  it("streams every device's events to the console socket (401 without the key)", async () => {
    await ctx.app.listen({ port: 0, host: "127.0.0.1" });
    const { port } = ctx.app.server.address() as AddressInfo;
    await expect(LiveClient.connect(`ws://127.0.0.1:${port}/v1/calls/console/ws`)).rejects.toThrow(/401/);
    const client = await LiveClient.connect(`ws://127.0.0.1:${port}/v1/calls/console/ws?key=${encodeURIComponent(API_KEY)}`);
    clients.push(client);
    expect(await client.next("hello")).toMatchObject({ type: "hello", activeCalls: [] });
    await registerDevice(ctx.app, { deviceID: "some-other-device", secret: OTHER_DEVICE_SECRET });
    const session = ctx.app.callGuard.demo.start({ deviceId: "some-other-device", line: null, scenario: "prize", speed: 4 });
    expect(await client.next("call.started")).toMatchObject({ call: { callID: session.callId, source: "demo" } });
    expect(await client.next("transcript.segment")).toMatchObject({ callID: session.callId });
    expect(ctx.app.callGuard.hub.subscriberCount.consoles).toBe(1);
  });

  it("is absent (404) when CALLS_CONSOLE_ENABLED is false", async () => {
    const off = await createCallsTestApp({ consoleEnabled: false });
    try {
      for (const [method, url] of [
        ["GET", "/v1/calls/console"],
        ["GET", "/v1/calls/console/ws"],
        ["POST", "/v1/calls/console/demo"],
        ["POST", "/v1/calls/console/test-call"],
        ["POST", "/v1/calls/console/replay"],
      ] as const) {
        const response =
          method === "POST"
            ? await off.app.inject({ method, url, headers: keyHeaders, payload: { lineID: "x", scenario: "irs" } })
            : await off.app.inject({ method, url, headers: keyHeaders });
        expect(response.statusCode, `${method} ${url}`).toBe(404);
        expect(response.json()).toEqual({ error: "not_found" });
      }
    } finally {
      await closeTestApp(off);
    }
  });

  it("answers 503 twilio_not_configured for a test call without Twilio", async () => {
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
      const page = await app.inject({ method: "GET", url: "/v1/calls/console", headers: keyHeaders });
      expect(page.body).toContain('"twilioConfigured":false');
      const response = await app.inject({ method: "POST", url: "/v1/calls/console/test-call", headers: keyHeaders, payload: { lineID: "line-x", scenario: "irs" } });
      expect(response.statusCode).toBe(503);
      expect(response.json()).toEqual({ error: "twilio_not_configured" });
    } finally {
      await app.close();
      db.close();
    }
  });

  it("answers 503 openai_not_configured for a replay without a transcriber, instead of a session that never transcribes", async () => {
    const clock = new FakeClock();
    const db = RelayDb.open(":memory:");
    const app = buildApp({
      config: testConfig({ calls: testCallsConfig({ openai: undefined }) }),
      db,
      pushSender: new FakeSender(),
      tokenVerifier: new FakeVerifier(),
      logger: false,
      calls: { twilio: new FakeTwilioClient(), transcriber: undefined, scorer: undefined, now: clock.now },
    });
    await app.ready();
    try {
      await registerDevice(app);
      db.upsertCallLine({ lineId: "line-x", deviceId: DEVICE_ID, guardNumber: GUARD_NUMBER, phoneNumber: PROTECTED_NUMBER, minimumLevel: "medium", spokenWarning: true }, clock.now());
      const response = await app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: keyHeaders, payload: { lineID: "line-x" } });
      expect(response.statusCode).toBe(503);
      expect(response.json()).toEqual({ error: "openai_not_configured" });
      expect(app.callGuard.sessions.all()).toHaveLength(0);
    } finally {
      await app.close();
      db.close();
    }
  });

  it("never logs the protected number when Twilio refuses a test call (error 21219 carries it)", async () => {
    const lines: string[] = [];
    const sink = new Writable({
      write(chunk, _encoding, callback) {
        lines.push(String(chunk));
        callback();
      },
    });
    const clock = new FakeClock();
    const db = RelayDb.open(":memory:");
    const twilio = new FakeTwilioClient();
    twilio.failDial = Object.assign(new Error(`The number ${PROTECTED_NUMBER} is unverified. Trial accounts cannot make calls to unverified numbers.`), { code: 21219, status: 400 });
    const app = buildApp({
      config: testConfig({ calls: testCallsConfig(), logLevel: "info" }),
      db,
      pushSender: new FakeSender(),
      tokenVerifier: new FakeVerifier(),
      logger: { level: "info", stream: sink },
      calls: { twilio, transcriber: new FakeTranscriber(), scorer: new FakeScorer(), now: clock.now },
    });
    await app.ready();
    try {
      await registerDevice(app);
      const { line } = db.upsertCallLine({ lineId: "line-x", deviceId: DEVICE_ID, guardNumber: GUARD_NUMBER, phoneNumber: PROTECTED_NUMBER, minimumLevel: "medium", spokenWarning: true }, clock.now());
      const viaConsole = await app.inject({ method: "POST", url: "/v1/calls/console/test-call", headers: keyHeaders, payload: { lineID: line.lineId, scenario: "irs" } });
      expect(viaConsole.statusCode).toBe(502);
      expect(viaConsole.json()).toEqual({ error: "twilio_error" });
      const viaDevice = await app.inject({ method: "POST", url: "/v1/devices/calls/test-call", headers: deviceHeaders(), payload: { scenario: "irs" } });
      expect(viaDevice.statusCode).toBe(502);
      const output = lines.join("\n");
      expect(output).toContain("test-call: Twilio refused the call");
      expect(output).toContain("21219");
      expect(output).toContain("…0002");
      expect(output).not.toContain(PROTECTED_NUMBER);
      expect(output).not.toContain(PROTECTED_NUMBER.slice(1));
      expect(output).not.toContain("RestException");
      for (const session of app.callGuard.sessions.all()) expect(session.status).toBe("failed");
    } finally {
      await app.close();
      db.close();
    }
  });

  it("runs a demo from the console on a relay with only CALLS_ENABLED=true (no Twilio: no line can exist)", async () => {
    // The operator's smallest relay: no Twilio, no OpenAI, no APNs. PUT /v1/devices/call-line answers 503 there,
    // so the console must be able to start a demo for a bare device, or it can start nothing at all.
    const clock = new FakeClock();
    const db = RelayDb.open(":memory:");
    const app = buildApp({
      config: testConfig({ apns: undefined, pubsub: undefined, calls: testCallsConfig({ twilio: undefined, openai: undefined, transcriptionSource: "auto" }) }),
      db,
      pushSender: new FakeSender(),
      tokenVerifier: new FakeVerifier(),
      logger: false,
      calls: { twilio: undefined, transcriber: undefined, scorer: undefined, now: clock.now },
    });
    await app.ready();
    try {
      await registerDevice(app, { apnsToken: null });
      const line = await app.inject({ method: "PUT", url: "/v1/devices/call-line", headers: deviceHeaders(), payload: { phoneNumber: PROTECTED_NUMBER, minimumLevel: "medium", spokenWarning: true } });
      expect(line.statusCode).toBe(503);
      expect(line.json()).toEqual({ error: "twilio_not_configured" });

      const page = await app.inject({ method: "GET", url: "/v1/calls/console", headers: keyHeaders });
      expect(page.statusCode).toBe(200);
      expect(page.body).toContain('"lines":[]');
      expect(page.body).toContain(`"deviceID":"${DEVICE_ID}"`);
      expect(page.body).toContain("Twilio is not configured on this relay");

      const started = await app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { deviceID: DEVICE_ID, scenario: "grandparent", speed: 4 } });
      expect(started.statusCode).toBe(202);
      const { callID } = started.json() as { callID: string };
      expect(app.callGuard.sessions.get(callID)).toMatchObject({ source: "demo", deviceId: DEVICE_ID, line: null, status: "in_progress" });
      // …and the device sees it in its own history, transcript included while the session is retained.
      const detail = await app.inject({ method: "GET", url: `/v1/devices/calls/${callID}`, headers: deviceHeaders() });
      expect(detail.statusCode).toBe(200);
      expect(detail.json()).toMatchObject({ callID, source: "demo", calledNumber: DEMO_CALLED_NUMBER, transcript: expect.any(Array) });
    } finally {
      await app.close();
      db.close();
    }
  });

});

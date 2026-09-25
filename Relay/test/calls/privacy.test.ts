import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";

import { loadCallsConfig } from "../../src/calls/config.js";
import { MAX_ACTIVE_DEMO_CALLS_PER_DEVICE } from "../../src/calls/routes/devices.js";
import { RelayDb } from "../../src/db.js";
import { buildApp } from "../../src/server.js";
import {
  API_KEY,
  DEVICE_SECRET,
  FakeSender,
  FakeVerifier,
  OTHER_DEVICE_SECRET,
  closeTestApp,
  createCallsTestApp,
  deviceHeaders,
  registerDevice,
  testConfig,
  type CallsTestContext,
  type TestContext,
} from "../helpers.js";
import { FakeScorer, FakeTranscriber, FakeTwilioClient, PROTECTED_NUMBER, TWILIO_ACCOUNT_SID, testCallsConfig } from "./fakes.js";

/**
 * Privacy and abuse guards on the merged Call Guard routes (docs/CALLS.md §10: logs never carry a full phone
 * number; §5.3: who may open the operator console; §7.1: scripted demo calls are cheap for the caller and
 * not free for the relay).
 */

const CONSOLE_KEY = "console-key-0123456789abcdef";

/** Twilio's usual trial-account rejection (error 21219): the message names the dialled number in full. */
function unverifiedNumberError(number: string): Error {
  return Object.assign(new Error(`The number ${number} is unverified. Trial accounts cannot make calls to unverified numbers.`), {
    code: 21219,
    status: 400,
    moreInfo: "https://www.twilio.com/docs/errors/21219",
  });
}

function baseEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN: "twilio-auth-token-for-tests-0123",
    TWILIO_NUMBER: "+15550100001",
    ...overrides,
  };
}

describe("test-call failures never put the protected number in the log", () => {
  let ctx: TestContext | undefined;
  afterEach(async () => {
    if (ctx) await closeTestApp(ctx);
    ctx = undefined;
  });

  async function appWithLogSink(twilio: FakeTwilioClient): Promise<{ ctx: TestContext; lines: string[] }> {
    const lines: string[] = [];
    const sink = new Writable({
      write(chunk, _encoding, callback) {
        lines.push(String(chunk));
        callback();
      },
    });
    const config = testConfig({ calls: testCallsConfig(), logLevel: "info" });
    const db = RelayDb.open(":memory:");
    const sender = new FakeSender();
    const verifier = new FakeVerifier();
    const app = buildApp({
      config,
      db,
      pushSender: sender,
      tokenVerifier: verifier,
      logger: { level: "info", stream: sink },
      calls: { twilio, transcriber: new FakeTranscriber(), scorer: new FakeScorer() },
    });
    await app.ready();
    return { ctx: { app, db, sender, verifier, config }, lines };
  }

  it("logs a Twilio rejection by code and redacted message on the device route and the console route", async () => {
    const twilio = new FakeTwilioClient();
    twilio.failDial = unverifiedNumberError(PROTECTED_NUMBER);
    const built = await appWithLogSink(twilio);
    ctx = built.ctx;
    const { app } = ctx;
    await registerDevice(app);
    const line = await app.inject({
      method: "PUT",
      url: "/v1/devices/call-line",
      headers: deviceHeaders(),
      payload: { phoneNumber: PROTECTED_NUMBER, minimumLevel: "medium", spokenWarning: true },
    });
    expect(line.statusCode).toBe(200);
    const { lineID } = line.json() as { lineID: string };

    const viaDevice = await app.inject({ method: "POST", url: "/v1/devices/calls/test-call", headers: deviceHeaders(), payload: { scenario: "irs" } });
    expect(viaDevice.statusCode).toBe(502);
    expect(viaDevice.json()).toEqual({ error: "twilio_error" });
    const viaConsole = await app.inject({ method: "POST", url: "/v1/calls/console/test-call", headers: { "x-api-key": API_KEY }, payload: { lineID, scenario: "irs" } });
    expect(viaConsole.statusCode).toBe(502);
    expect(viaConsole.json()).toEqual({ error: "twilio_error" });
    // Both sessions were created and then failed, so the failure was really logged (twice).
    const failed = app.callGuard.sessions.all().filter((session) => session.source === "test-call" && session.status === "failed");
    expect(failed).toHaveLength(2);

    const joined = built.lines.join("");
    expect(joined).toContain("test-call: Twilio refused the call");
    expect(joined.split("test-call: Twilio refused the call")).toHaveLength(3);
    expect(joined).toContain("21219");
    expect(joined).toContain("…0002");
    expect(joined).not.toContain(PROTECTED_NUMBER);
    expect(joined).not.toContain(PROTECTED_NUMBER.slice(1));
    expect(joined).not.toContain('"stack"');
    expect(joined).not.toContain(API_KEY);
    expect(joined).not.toContain(DEVICE_SECRET);
  });
});

describe("demo call flooding", () => {
  let ctx: CallsTestContext;
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  it(`caps running demo sessions per device at ${MAX_ACTIVE_DEMO_CALLS_PER_DEVICE}, per device, until one ends`, async () => {
    ctx = await createCallsTestApp();
    await registerDevice(ctx.app);
    const start = (secret = DEVICE_SECRET) =>
      ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(secret), payload: { scenario: "benign", speed: 0.25 } });

    const ids: string[] = [];
    for (let i = 0; i < MAX_ACTIVE_DEMO_CALLS_PER_DEVICE; i += 1) {
      const response = await start();
      expect(response.statusCode).toBe(202);
      ids.push((response.json() as { callID: string }).callID);
    }
    const overflow = await start();
    expect(overflow.statusCode).toBe(429);
    expect(overflow.json()).toEqual({ error: "too_many_calls" });
    expect(ctx.app.callGuard.sessions.all()).toHaveLength(MAX_ACTIVE_DEMO_CALLS_PER_DEVICE);

    // Another device has its own allowance.
    await registerDevice(ctx.app, { deviceID: "other-device-0001", secret: OTHER_DEVICE_SECRET });
    expect((await start(OTHER_DEVICE_SECRET)).statusCode).toBe(202);

    // An ended session no longer counts, even while it is still retained in memory.
    ctx.app.callGuard.sessions.get(ids[0]!)!.end("completed");
    expect(ctx.app.callGuard.sessions.all()).toHaveLength(MAX_ACTIVE_DEMO_CALLS_PER_DEVICE + 1);
    const again = await start();
    expect(again.statusCode).toBe(202);
    expect((await start()).statusCode).toBe(429);
  });
});

describe("operator console key", () => {
  it("CALLS_CONSOLE_KEY is optional, must be at least 16 characters, and is otherwise undefined", () => {
    expect(loadCallsConfig(baseEnv()).consoleKey).toBeUndefined();
    expect(loadCallsConfig(baseEnv({ CALLS_CONSOLE_KEY: "   " })).consoleKey).toBeUndefined();
    expect(loadCallsConfig(baseEnv({ CALLS_CONSOLE_KEY: `  ${CONSOLE_KEY}  ` })).consoleKey).toBe(CONSOLE_KEY);
    expect(() => loadCallsConfig(baseEnv({ CALLS_CONSOLE_KEY: "short-key" }))).toThrow(/CALLS_CONSOLE_KEY/);
  });

  describe("with a console key of its own", () => {
    let ctx: CallsTestContext;
    afterEach(async () => {
      await closeTestApp(ctx);
    });

    it("the console takes only that key, and the device routes still take only RELAY_API_KEY", async () => {
      ctx = await createCallsTestApp({ consoleKey: CONSOLE_KEY });
      await registerDevice(ctx.app);
      const line = await ctx.app.inject({
        method: "PUT",
        url: "/v1/devices/call-line",
        headers: deviceHeaders(),
        payload: { phoneNumber: PROTECTED_NUMBER, minimumLevel: "medium", spokenWarning: true },
      });
      expect(line.statusCode).toBe(200);
      const { lineID } = line.json() as { lineID: string };

      // The key every app build carries no longer opens the console…
      expect((await ctx.app.inject({ method: "GET", url: "/v1/calls/console", headers: { "x-api-key": API_KEY } })).statusCode).toBe(401);
      expect((await ctx.app.inject({ method: "GET", url: `/v1/calls/console?key=${encodeURIComponent(API_KEY)}` })).statusCode).toBe(401);
      expect((await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: { "x-api-key": API_KEY }, payload: { lineID, scenario: "irs" } })).statusCode).toBe(401);
      expect((await ctx.app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: { "x-api-key": API_KEY }, payload: { lineID } })).statusCode).toBe(401);
      expect((await ctx.app.inject({ method: "POST", url: "/v1/calls/console/test-call", headers: { "x-api-key": API_KEY }, payload: { lineID, scenario: "irs" } })).statusCode).toBe(401);
      expect(ctx.app.callGuard.sessions.all()).toHaveLength(0);

      // …the console key does…
      expect((await ctx.app.inject({ method: "GET", url: "/v1/calls/console", headers: { "x-api-key": CONSOLE_KEY } })).statusCode).toBe(200);
      expect((await ctx.app.inject({ method: "GET", url: `/v1/calls/console?key=${encodeURIComponent(CONSOLE_KEY)}` })).statusCode).toBe(200);
      const replay = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: { "x-api-key": CONSOLE_KEY }, payload: { lineID } });
      expect(replay.statusCode).toBe(202);

      // …and it is not an API key for the app's routes.
      const asApiKey = await ctx.app.inject({ method: "GET", url: "/v1/devices/call-line", headers: deviceHeaders(DEVICE_SECRET, CONSOLE_KEY) });
      expect(asApiKey.statusCode).toBe(401);
      expect(asApiKey.json()).toEqual({ error: "invalid_api_key" });
    });
  });
});

import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";

import { buildApp, redactRequestUrl } from "../../src/server.js";
import { RelayDb } from "../../src/db.js";
import { API_KEY, DEVICE_SECRET, FakeSender, FakeVerifier, closeTestApp, deviceHeaders, registerDevice, testConfig, type TestContext } from "../helpers.js";
import { FakeScorer, FakeTranscriber, FakeTwilioClient, PROTECTED_NUMBER, testCallsConfig } from "./fakes.js";

/**
 * Fastify logs every incoming request with its URL at `info`. The console accepts `?key=<RELAY_API_KEY>` and the
 * Twilio callbacks carry `?token=` / `/media/<mediaToken>` (docs/CALLS.md §5.2, §5.3), so those values must be
 * redacted before they reach the log, exactly like the `X-API-Key` header is.
 */

describe("redactRequestUrl", () => {
  it("masks key and token query values and the Media Streams path token, keeping everything else", () => {
    expect(redactRequestUrl("/v1/calls/console?key=abc123")).toBe("/v1/calls/console?key=[redacted]");
    expect(redactRequestUrl("/v1/calls/console/ws?key=abc%20123&x=1")).toBe("/v1/calls/console/ws?key=[redacted]&x=1");
    expect(redactRequestUrl("/v1/calls/twilio/transcription?callID=c-1&token=deadbeef")).toBe("/v1/calls/twilio/transcription?callID=c-1&token=[redacted]");
    expect(redactRequestUrl("/v1/calls/twilio/announce?token=t&callID=c-1")).toBe("/v1/calls/twilio/announce?token=[redacted]&callID=c-1");
    expect(redactRequestUrl("/v1/calls/twilio/media/0123456789abcdef0123456789abcdef")).toBe("/v1/calls/twilio/media/[redacted]");
    expect(redactRequestUrl("/v1/calls/twilio/media/0123456789abcdef0123456789abcdef/")).toBe("/v1/calls/twilio/media/[redacted]/");
    expect(redactRequestUrl("/v1/devices/calls?limit=5")).toBe("/v1/devices/calls?limit=5");
    expect(redactRequestUrl("/v1/devices/calls/abc?keyword=1&tokens=2")).toBe("/v1/devices/calls/abc?keyword=1&tokens=2");
    expect(redactRequestUrl("/v1/calls/console?key")).toBe("/v1/calls/console?key=[redacted]");
    expect(redactRequestUrl(undefined)).toBeUndefined();
  });
});

describe("request logging", () => {
  let ctx: TestContext | undefined;
  afterEach(async () => {
    if (ctx) await closeTestApp(ctx);
    ctx = undefined;
  });

  async function appWithLogSink(): Promise<{ ctx: TestContext; lines: string[] }> {
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
      calls: { twilio: new FakeTwilioClient(), transcriber: new FakeTranscriber(), scorer: new FakeScorer() },
    });
    await app.ready();
    return { ctx: { app, db, sender, verifier, config }, lines };
  }

  it("never writes the console key, a callback token or a media token to the log", async () => {
    const built = await appWithLogSink();
    ctx = built.ctx;
    const { app } = ctx;
    await registerDevice(app);
    const line = await app.inject({ method: "PUT", url: "/v1/devices/call-line", headers: deviceHeaders(), payload: { phoneNumber: PROTECTED_NUMBER, minimumLevel: "medium", spokenWarning: true } });
    expect(line.statusCode).toBe(200);
    const page = await app.inject({ method: "GET", url: `/v1/calls/console?key=${encodeURIComponent(API_KEY)}` });
    expect(page.statusCode).toBe(200);
    const replay = await app.inject({ method: "POST", url: "/v1/calls/console/replay", headers: { "x-api-key": API_KEY }, payload: { lineID: (line.json() as { lineID: string }).lineID } });
    expect(replay.statusCode).toBe(202);
    const { mediaToken, mediaPath } = replay.json() as { mediaToken: string; mediaPath: string };
    // The media route belongs to the Twilio module; whatever it answers, the request line is logged.
    await app.inject({ method: "GET", url: mediaPath });
    await app.inject({ method: "POST", url: `/v1/calls/twilio/transcription?callID=x&token=${mediaToken}`, payload: {} });

    const joined = built.lines.join("");
    expect(joined).toContain("incoming request");
    expect(joined).toContain("/v1/calls/console?key=[redacted]");
    // The Twilio routes log at `warn` and above, so their request lines (which would carry the media path
    // token and `?token=`) are never written at all; if a future change lowers that level, the serializer
    // still redacts them — the direct `redactRequestUrl` cases above pin that.
    expect(joined).not.toContain("/v1/calls/twilio/media/" + mediaToken);
    expect(joined).not.toContain("token=" + mediaToken);
    expect(joined).not.toContain(API_KEY);
    expect(joined).not.toContain(mediaToken);
    expect(joined).not.toContain(DEVICE_SECRET);
  });
});

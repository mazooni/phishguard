import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, connect, type AddressInfo, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";

import { RelayDb } from "../../src/db.js";
import {
  API_KEY,
  APNS_TOKEN,
  BUNDLE_ID,
  DEVICE_ID,
  DEVICE_SECRET,
  RELAY_SALT,
  closeTestApp,
  createCallsTestApp,
  deviceHeaders,
  registerDevice,
  type CallsTestContext,
} from "../helpers.js";
import { LiveClient, waitFor } from "./liveClient.js";
import { USER_SID, conferenceForm, inboundCall, registerLine, postForm, tokenQuery } from "./twilio-helpers.js";

/**
 * Graceful shutdown while a call is live (docs/CALLS.md §4): `app.close()` — what the SIGTERM handler in
 * src/index.ts awaits — must finish promptly whatever the peers do, close every socket, abort the model pass and
 * persist the record before the process exits.
 */

const RELAY_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
/** Well under a platform's SIGKILL grace period (typically 10 s) and ws's 30 s close timeout. */
const CLOSE_BUDGET_MS = 3_000;

function startMessage(callId: string): string {
  return JSON.stringify({
    event: "start",
    sequenceNumber: "1",
    start: { streamSid: "MZ" + "1".repeat(32), callSid: "CA" + "a".repeat(32), tracks: ["inbound", "outbound"], customParameters: { callID: callId } },
    streamSid: "MZ" + "1".repeat(32),
  });
}

/** Completes the live-feed upgrade by hand and then never reads or answers again: a phone that dropped off the network. */
async function stuckSubscriber(port: number): Promise<Socket> {
  const socket = connect(port, "127.0.0.1");
  await once(socket, "connect");
  socket.write(
    [
      "GET /v1/devices/calls/live HTTP/1.1",
      `Host: 127.0.0.1:${port}`,
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Key: ${randomBytes(16).toString("base64")}`,
      "Sec-WebSocket-Version: 13",
      `Authorization: Bearer ${DEVICE_SECRET}`,
      `X-API-Key: ${API_KEY}`,
      "",
      "",
    ].join("\r\n"),
  );
  const [head] = (await once(socket, "data")) as [Buffer];
  expect(head.toString("utf8").split("\r\n")[0]).toBe("HTTP/1.1 101 Switching Protocols");
  socket.pause();
  return socket;
}

async function timed(work: Promise<unknown>): Promise<number> {
  const started = Date.now();
  await work;
  return Date.now() - started;
}

function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      server.close(() => resolvePort(port));
    });
  });
}

describe("app.close() while a call is live", () => {
  let ctx: CallsTestContext;
  const cleanup: (() => void)[] = [];

  afterEach(async () => {
    for (const fn of cleanup.splice(0)) fn();
    await closeTestApp(ctx);
  });

  async function listen(): Promise<number> {
    await ctx.app.listen({ port: 0, host: "127.0.0.1" });
    return (ctx.app.server.address() as AddressInfo).port;
  }

  it("does not wait for a live subscriber that never answers the close handshake, and still persists the call", async () => {
    ctx = await createCallsTestApp();
    await registerDevice(ctx.app);
    const port = await listen();
    const stuck = await stuckSubscriber(port);
    cleanup.push(() => stuck.destroy());
    await waitFor(() => ctx.app.callGuard.hub.subscriberCount.devices === 1);
    const demo = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "irs", speed: 0.25 } });
    const { callID } = demo.json() as { callID: string };

    const elapsed = await timed(ctx.app.close());
    expect(elapsed).toBeLessThan(CLOSE_BUDGET_MS);
    expect(ctx.app.callGuard.hub.subscriberCount.devices).toBe(0);
    expect(ctx.db.findCall(callID)).toMatchObject({ status: "canceled" });
    stuck.resume(); // the server destroyed its end without waiting for us: the FIN is already there
    await waitFor(() => stuck.closed);
  });

  it("during a Twilio call with a media stream and a model pass in flight: nothing throws, every socket and handle closes, the pass is aborted, the record is persisted as canceled", async () => {
    ctx = await createCallsTestApp();
    await registerLine(ctx);
    const port = await listen();
    const live = await LiveClient.connect(`ws://127.0.0.1:${port}/v1/devices/calls/live`, deviceHeaders());
    cleanup.push(() => live.socket.terminate());
    await live.next("hello");

    const { session } = await inboundCall(ctx);
    await postForm(ctx.app, `/v1/calls/twilio/conference?${tokenQuery(session)}`, conferenceForm("participant-join", { ParticipantLabel: "user", CallSid: USER_SID }));
    const media = new WebSocket(`ws://127.0.0.1:${port}/v1/calls/twilio/media/${session.mediaToken}`, { headers: { "x-twilio-signature": "dGVzdA==" } });
    cleanup.push(() => media.terminate());
    await once(media, "open");
    media.send(startMessage(session.callId));
    await waitFor(() => ctx.transcriber.handles.length === 2);

    // A benign final segment long enough for the model, whose answer is held back: the pass is in flight at shutdown.
    let release: () => void = () => undefined;
    ctx.scorer.gate = new Promise<void>((resolve) => (release = resolve));
    ctx.transcriber.handle("caller", session.callId)!.emit("Hello Margaret, this is the pharmacy, your prescription is ready for pickup this week.");
    await waitFor(() => ctx.scorer.inputs.length === 1);
    const verdictBefore = session.verdict?.sequence;

    const closing = ctx.app.close();
    // The real scorer's fetch rejects on abort; the fake only checks the signal once its gate opens.
    await new Promise((resolveTick) => setTimeout(resolveTick, 20));
    release();
    const elapsed = await timed(closing);
    expect(elapsed).toBeLessThan(CLOSE_BUDGET_MS);

    expect(session.isEnded).toBe(true);
    expect(session.status).toBe("canceled");
    expect(ctx.db.findCall(session.callId)).toMatchObject({ status: "canceled", alerted: false });
    expect(ctx.db.findCall(session.callId)?.endedAt).toBeDefined();
    expect(ctx.transcriber.handles.every((handle) => handle.closed)).toBe(true);
    await waitFor(() => media.readyState === WebSocket.CLOSED);
    await waitFor(() => live.closed);
    expect(ctx.app.callGuard.detector.attachedCount).toBe(0);
    expect(ctx.app.callGuard.hub.subscriberCount).toEqual({ devices: 0, consoles: 0 });
    // The aborted pass produced no verdict after the end, and nothing was pushed or spoken.
    await new Promise((resolveTick) => setTimeout(resolveTick, 30));
    expect(session.verdict?.sequence).toBe(verdictBefore);
    expect(session.verdict?.modelRiskScore).toBeUndefined();
    expect(ctx.sender.alerts).toHaveLength(0);
    expect(ctx.twilio.spoken).toHaveLength(0);
    expect(live.received.filter((event) => event.type === "call.alert")).toEqual([]);
  });
});

describe("SIGTERM (src/index.ts)", () => {
  it("exits 0 while a demo call and a live subscriber are active, after persisting the call as canceled", async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "phishguard-relay-"));
    const port = await freePort();
    const child = spawn(process.execPath, ["--import", "tsx", "src/index.ts"], {
      cwd: RELAY_DIR,
      env: {
        ...process.env,
        PORT: String(port),
        HOST: "127.0.0.1",
        PUBLIC_BASE_URL: `http://127.0.0.1:${port}`,
        RELAY_API_KEY: API_KEY,
        RELAY_SALT,
        APNS_BUNDLE_ID: BUNDLE_ID,
        DATA_DIR: dataDir,
        CALLS_ENABLED: "true",
        LOG_LEVEL: "info",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk: Buffer) => (output += chunk.toString("utf8")));
    child.stderr.on("data", (chunk: Buffer) => (output += chunk.toString("utf8")));
    const exited = new Promise<number | null>((resolveCode) => child.once("exit", (code) => resolveCode(code)));
    let live: LiveClient | undefined;
    try {
      await waitFor(() => output.includes("phishguard-relay ready") || child.exitCode !== null, 20_000);
      expect(child.exitCode).toBeNull();
      const base = `http://127.0.0.1:${port}`;
      const json = { ...deviceHeaders(), "content-type": "application/json" };
      const registered = await fetch(`${base}/v1/devices`, {
        method: "POST",
        headers: json,
        body: JSON.stringify({ deviceID: DEVICE_ID, apnsToken: APNS_TOKEN, environment: "sandbox", bundleID: BUNDLE_ID }),
      });
      expect(registered.status).toBeLessThan(300);
      const started = await fetch(`${base}/v1/devices/calls/demo`, { method: "POST", headers: json, body: JSON.stringify({ scenario: "grandparent", speed: 0.25 }) });
      expect(started.status).toBe(202);
      const { callID } = (await started.json()) as { callID: string };
      live = await LiveClient.connect(`ws://127.0.0.1:${port}/v1/devices/calls/live`, deviceHeaders());
      await live.next("hello");

      child.kill("SIGTERM");
      const code = await Promise.race([exited, new Promise<"timeout">((resolveTimeout) => setTimeout(() => resolveTimeout("timeout"), 8_000))]);
      expect(code).toBe(0);
      expect(output).toContain("shutting down");
      expect(output).not.toContain("shutdown failed");
      await waitFor(() => live!.closed);

      const db = RelayDb.open(join(dataDir, "relay.sqlite"));
      try {
        expect(db.findCall(callID)).toMatchObject({ status: "canceled", alerted: false, deviceId: DEVICE_ID });
        expect(db.findCall(callID)?.endedAt).toBeDefined();
      } finally {
        db.close();
      }
    } finally {
      live?.socket.terminate();
      if (child.exitCode === null) child.kill("SIGKILL");
      rmSync(dataDir, { recursive: true, force: true });
    }
  }, 40_000);
});

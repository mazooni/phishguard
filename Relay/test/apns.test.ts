import { ApnsError, Notification, SilentNotification } from "apns2";
import { describe, expect, it } from "vitest";

import { type ApnsClientLike, type PushRequest, buildDoorbell, createApnsSender } from "../src/apns.js";
import { BUNDLE_ID, testConfig } from "./helpers.js";

const REQUEST: PushRequest = {
  deviceId: "device-1",
  apnsToken: "0f".repeat(32),
  environment: "sandbox",
  bundleId: BUNDLE_ID,
  provider: "gmail",
  accountKey: "a".repeat(64),
};

function apnsError(statusCode: number, reason: string, timestamp = 0): ApnsError {
  return new ApnsError({ statusCode, notification: new Notification("t"), response: { reason, timestamp } });
}

class FakeClient implements ApnsClientLike {
  readonly sent: Notification[] = [];
  closed = false;
  constructor(private readonly script: (attempt: number) => unknown) {}

  async send(notification: Notification): Promise<unknown> {
    this.sent.push(notification);
    const result = this.script(this.sent.length);
    if (result instanceof Error) throw result;
    return notification;
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

function makeSender(script: (attempt: number) => unknown) {
  const clients = new Map<string, FakeClient>();
  const sender = createApnsSender({
    config: testConfig().apns!,
    retryDelayMs: 0,
    clientFactory: (environment) => {
      const client = new FakeClient(script);
      clients.set(environment, client);
      return client;
    },
  });
  return { sender, clients };
}

describe("buildDoorbell", () => {
  it("builds exactly the PhishGuard silent-push payload and headers", () => {
    const notification = buildDoorbell(REQUEST, 600, 1_700_000_000_000);
    expect(notification).toBeInstanceOf(SilentNotification);
    expect(notification.deviceToken).toBe(REQUEST.apnsToken);
    expect(notification.pushType).toBe("background");
    expect(notification.priority).toBe(5);
    expect(notification.options.topic).toBe(BUNDLE_ID);
    expect(notification.options.collapseId).toBe(`gmail:${"a".repeat(64)}`.slice(0, 64));
    expect(notification.options.expiration).toBe(1_700_000_000 + 600);
    expect(notification.buildApnsOptions()).toEqual({
      aps: { "content-available": 1 },
      provider: "gmail",
      accountKey: "a".repeat(64),
    });
  });

  it("adds extra keys without letting them override provider/accountKey", () => {
    const notification = buildDoorbell(
      { ...REQUEST, provider: "microsoft", extra: { lifecycleEvent: "missed", provider: "evil" } },
      600,
    );
    expect(notification.buildApnsOptions()).toEqual({
      aps: { "content-available": 1 },
      lifecycleEvent: "missed",
      provider: "microsoft",
      accountKey: "a".repeat(64),
    });
    expect(JSON.stringify(notification.buildApnsOptions()).length).toBeLessThan(4096);
  });
});

describe("createApnsSender", () => {
  it("sends through the client for the device's environment and reports success", async () => {
    const { sender, clients } = makeSender(() => undefined);
    expect(await sender.send(REQUEST)).toEqual({ ok: true, retried: false });
    expect(await sender.send({ ...REQUEST, environment: "production" })).toEqual({ ok: true, retried: false });
    expect([...clients.keys()].sort()).toEqual(["production", "sandbox"]);
    expect(clients.get("sandbox")?.sent).toHaveLength(1);
    expect(clients.get("production")?.sent).toHaveLength(1);
    await sender.close();
    expect(clients.get("sandbox")?.closed).toBe(true);
    expect(clients.get("production")?.closed).toBe(true);
  });

  it("always uses the configured APNS_BUNDLE_ID as apns-topic, whatever bundle id the device row carries", async () => {
    const { sender, clients } = makeSender(() => undefined);
    expect(await sender.send({ ...REQUEST, bundleId: "com.example.OtherApp" })).toEqual({ ok: true, retried: false });
    const sent = clients.get("sandbox")?.sent[0];
    expect(sent?.options.topic).toBe(BUNDLE_ID);
    expect(sent?.deviceToken).toBe(REQUEST.apnsToken);
  });

  it("retries exactly once on 5xx", async () => {
    const recovers = makeSender((attempt) => (attempt === 1 ? apnsError(503, "ServiceUnavailable") : undefined));
    expect(await recovers.sender.send(REQUEST)).toEqual({ ok: true, retried: true });
    expect(recovers.clients.get("sandbox")?.sent).toHaveLength(2);

    const persistent = makeSender(() => apnsError(500, "InternalServerError"));
    expect(await persistent.sender.send(REQUEST)).toEqual({
      ok: false,
      dropToken: false,
      reason: "InternalServerError",
      status: 500,
      retried: true,
    });
    expect(persistent.clients.get("sandbox")?.sent).toHaveLength(2);
  });

  it("retries exactly once on transport errors", async () => {
    const { sender, clients } = makeSender(() => new Error("connect ECONNRESET"));
    const outcome = await sender.send(REQUEST);
    expect(outcome.ok).toBe(false);
    expect(outcome).toMatchObject({ dropToken: false, status: undefined, retried: true });
    expect(clients.get("sandbox")?.sent).toHaveLength(2);
  });

  it("asks for token removal on 410 Unregistered, carrying APNs' timestamp", async () => {
    const { sender, clients } = makeSender(() => apnsError(410, "Unregistered", 1_700_000_000_000));
    expect(await sender.send(REQUEST)).toEqual({
      ok: false,
      dropToken: true,
      reason: "Unregistered",
      status: 410,
      invalidSince: 1_700_000_000_000,
      retried: false,
    });
    expect(clients.get("sandbox")?.sent).toHaveLength(1); // never retried
  });

  it("asks for token removal on 400 BadDeviceToken / DeviceTokenNotForTopic without retrying", async () => {
    for (const reason of ["BadDeviceToken", "DeviceTokenNotForTopic"]) {
      const { sender, clients } = makeSender(() => apnsError(400, reason));
      expect(await sender.send(REQUEST)).toEqual({ ok: false, dropToken: true, reason, status: 400, retried: false });
      expect(clients.get("sandbox")?.sent).toHaveLength(1);
    }
  });

  it("keeps the token and does not retry on other 4xx (403 key problems, 429 throttling)", async () => {
    for (const [status, reason] of [
      [403, "InvalidProviderToken"],
      [429, "TooManyRequests"],
      [400, "BadTopic"],
    ] as const) {
      const { sender, clients } = makeSender(() => apnsError(status, reason));
      expect(await sender.send(REQUEST)).toEqual({ ok: false, dropToken: false, reason, status, retried: false });
      expect(clients.get("sandbox")?.sent).toHaveLength(1);
    }
  });
});

describe("buildCallAlert", () => {
  it("builds the Call Guard alert push exactly as docs/CALLS.md §5.4 specifies", async () => {
    const { buildCallAlert } = await import("../src/apns.js");
    const notification = buildCallAlert(
      {
        deviceId: "device-1",
        apnsToken: "0f".repeat(32),
        environment: "sandbox",
        title: "Likely scam call",
        subtitle: "Call from +1 (415) 555-0134",
        body: "Asks for gift cards · Claims to be a grandchild in trouble",
        threadId: "com.mazooni.PhishGuard.calls",
        category: "PHISHGUARD_CALL_ALERT",
        interruptionLevel: "time-sensitive",
        relevanceScore: 1,
        collapseId: "call-abc",
        expirationSeconds: 120,
        contentAvailable: true,
        data: { kind: "call-alert", callID: "abc", level: "high", confidence: 0.92, category: "scam", callerNumber: "+14155550134", startedAt: 1, sequence: 3 },
      },
      BUNDLE_ID,
      1_700_000_000_000,
    );
    expect(notification.pushType).toBe("alert");
    expect(notification.priority).toBe(10);
    expect(notification.options.topic).toBe(BUNDLE_ID);
    expect(notification.options.collapseId).toBe("call-abc");
    expect(notification.options.expiration).toBe(1_700_000_000 + 120);
    const payload = notification.buildApnsOptions();
    expect(payload.aps).toEqual({
      alert: { title: "Likely scam call", subtitle: "Call from +1 (415) 555-0134", body: "Asks for gift cards · Claims to be a grandchild in trouble" },
      sound: "default",
      category: "PHISHGUARD_CALL_ALERT",
      "thread-id": "com.mazooni.PhishGuard.calls",
      "content-available": 1,
      "interruption-level": "time-sensitive",
      "relevance-score": 1,
    });
    expect(payload["kind"]).toBe("call-alert");
    expect(payload["callID"]).toBe("abc");
    expect(payload["level"]).toBe("high");
    expect(JSON.stringify(payload).length).toBeLessThan(4096);
  });

  it("omits content-available entirely when it is false (apns2 would otherwise write 0)", async () => {
    const { buildCallAlert } = await import("../src/apns.js");
    const notification = buildCallAlert(
      {
        deviceId: "d", apnsToken: "0f".repeat(32), environment: "sandbox", title: "t", subtitle: "s", body: "b",
        threadId: "th", category: "c", interruptionLevel: "active", relevanceScore: 0.5, collapseId: "x",
        expirationSeconds: 10, contentAvailable: false, data: {},
      },
      BUNDLE_ID,
    );
    expect(notification.buildApnsOptions().aps).not.toHaveProperty("content-available");
  });

  it("times out a hung send and retries once", async () => {
    let calls = 0;
    const sender = createApnsSender({
      config: testConfig().apns!,
      retryDelayMs: 0,
      sendTimeoutMs: 20,
      clientFactory: () => ({
        async send() {
          calls += 1;
          await new Promise(() => undefined); // never resolves
        },
        async close() {},
      }),
    });
    const outcome = await sender.send(REQUEST);
    expect(calls).toBe(2);
    expect(outcome.ok).toBe(false);
    expect(outcome.retried).toBe(true);
    if (!outcome.ok) expect(outcome.reason).toContain("timed out");
  });
});

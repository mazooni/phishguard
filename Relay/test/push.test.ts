import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { deriveAccountKey } from "../src/accountKey.js";
import {
  APNS_TOKEN,
  DEVICE_ID,
  OTHER_DEVICE_SECRET,
  RELAY_SALT,
  type TestContext,
  closeTestApp,
  createTestApp,
  registerAccount,
  registerDevice,
} from "./helpers.js";

const ACCOUNT_KEY = deriveAccountKey("user@example.com", RELAY_SALT);

describe("PushDispatcher token cleanup", () => {
  let ctx: TestContext;
  beforeEach(async () => {
    ctx = await createTestApp({ debounceSeconds: 0 });
    await registerDevice(ctx.app);
    await registerAccount(ctx.app, ACCOUNT_KEY, "gmail");
  });
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  it("forgets the token after 410 Unregistered and stops pushing to it", async () => {
    ctx.sender.failWith({ dropToken: true, reason: "Unregistered", status: 410, invalidSince: Date.now() + 1 });
    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "gmail" })).toBe("sent");
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(1);

    const device = ctx.db.findDevice(DEVICE_ID);
    expect(device).toBeDefined(); // the device row and its accounts survive; only the token is gone
    expect(device?.apnsToken).toBeNull();
    expect(ctx.db.listDeviceAccounts(DEVICE_ID)).toHaveLength(1);
    expect(ctx.db.pushTargets(ACCOUNT_KEY, "gmail")).toHaveLength(0);

    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "gmail" })).toBe("no_targets");
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(1);

    // A fresh registration restores pushes.
    await registerDevice(ctx.app, { apnsToken: "cd".repeat(32) });
    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "gmail" })).toBe("sent");
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls[1]?.apnsToken).toBe("cd".repeat(32));
  });

  it("forgets the token after 400 BadDeviceToken", async () => {
    ctx.sender.failWith({ dropToken: true, reason: "BadDeviceToken", status: 400 });
    ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "gmail" });
    await ctx.app.dispatcher.drain();
    expect(ctx.db.findDevice(DEVICE_ID)?.apnsToken).toBeNull();
  });

  it("keeps a token that was re-registered after APNs' 410 timestamp", async () => {
    const registeredAt = ctx.db.findDevice(DEVICE_ID)?.updatedAt ?? 0;
    ctx.sender.failWith({ dropToken: true, reason: "Unregistered", status: 410, invalidSince: registeredAt - 60_000 });
    ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "gmail" });
    await ctx.app.dispatcher.drain();
    expect(ctx.db.findDevice(DEVICE_ID)?.apnsToken).toBe(APNS_TOKEN);
  });

  it("keeps the token on other failures (5xx, 429, transport)", async () => {
    ctx.sender.failWith({ dropToken: false, reason: "ServiceUnavailable", status: 503 });
    ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "gmail" });
    await ctx.app.dispatcher.drain();
    expect(ctx.db.findDevice(DEVICE_ID)?.apnsToken).toBe(APNS_TOKEN);
  });

  it("pushes to every device registered for the account and cleans up only the dead one", async () => {
    await registerDevice(ctx.app, { deviceID: "second", secret: OTHER_DEVICE_SECRET, apnsToken: "ee".repeat(32), environment: "production" });
    await registerAccount(ctx.app, ACCOUNT_KEY, "gmail", OTHER_DEVICE_SECRET);
    ctx.sender.respond = (request) =>
      request.deviceId === "second"
        ? { ok: false, dropToken: true, reason: "Unregistered", status: 410, retried: false }
        : { ok: true, retried: false };

    ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "gmail" });
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls.map((call) => [call.deviceId, call.environment]).sort()).toEqual([
      [DEVICE_ID, "sandbox"],
      ["second", "production"],
    ]);
    expect(ctx.db.findDevice(DEVICE_ID)?.apnsToken).toBe(APNS_TOKEN);
    expect(ctx.db.findDevice("second")?.apnsToken).toBeNull();
  });

  it("reports no_targets when nothing is registered and closed after close()", async () => {
    expect(ctx.app.dispatcher.request({ accountKey: "0".repeat(64), provider: "gmail" })).toBe("no_targets");
    ctx.app.dispatcher.close();
    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "gmail" })).toBe("closed");
    expect(ctx.sender.calls).toHaveLength(0);
  });
});

describe("PushDispatcher debounce window", () => {
  const OTHER_ACCOUNT_KEY = deriveAccountKey("other@example.com", RELAY_SALT);
  let ctx: TestContext;
  beforeEach(async () => {
    ctx = await createTestApp({ debounceSeconds: 10 });
    await registerDevice(ctx.app);
    await registerAccount(ctx.app, ACCOUNT_KEY, "microsoft");
    await registerAccount(ctx.app, OTHER_ACCOUNT_KEY, "gmail");
  });
  afterEach(async () => {
    vi.useRealTimers();
    await closeTestApp(ctx);
  });

  it("flushes the pending trailing doorbell (latest coalesced payload) when the app shuts down", async () => {
    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "microsoft" })).toBe("sent");
    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "microsoft" })).toBe("scheduled");
    expect(
      ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "microsoft", extra: { lifecycleEvent: "missed" } }),
    ).toBe("coalesced");
    expect(ctx.app.dispatcher.pendingCount).toBe(1);

    // SIGTERM path: app.close() → onClose → dispatcher.close(); drain(); pushSender.close().
    await ctx.app.close();

    expect(ctx.app.dispatcher.pendingCount).toBe(0);
    expect(ctx.sender.calls).toHaveLength(2);
    expect(ctx.sender.calls[1]).toMatchObject({ accountKey: ACCOUNT_KEY, provider: "microsoft", extra: { lifecycleEvent: "missed" } });
    expect(ctx.sender.closed).toBe(true); // the flushed send completed before the APNs clients were closed
    expect(ctx.db.lastPushAt(ACCOUNT_KEY)).toBeDefined();
    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "microsoft" })).toBe("closed");
  });

  it("logs and drops a scheduled doorbell whose storage write fails instead of crashing the process", async () => {
    vi.useFakeTimers();
    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "microsoft" })).toBe("sent");
    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "microsoft" })).toBe("scheduled");

    vi.spyOn(ctx.db, "recordPush").mockImplementationOnce(() => {
      throw new Error("SQLITE_FULL: database or disk is full");
    });
    const logged = vi.spyOn(ctx.app.log, "error");

    // Without the guard the SqliteError escapes the timer callback (an uncaught exception in production).
    await expect(vi.advanceTimersByTimeAsync(10_000)).resolves.toBeDefined();

    expect(logged).toHaveBeenCalledTimes(1);
    const [context, message] = logged.mock.calls[0] as [Record<string, unknown>, string];
    expect(message).toBe("push: scheduled doorbell dropped");
    expect(context["err"]).toBeInstanceOf(Error);
    expect(context["accountKey"]).toBe(ACCOUNT_KEY.slice(0, 12)); // prefix only, like the webhook logs
    expect(ctx.app.dispatcher.pendingCount).toBe(0);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(1);

    // The dispatcher keeps working once storage recovers.
    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "microsoft" })).toBe("sent");
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(2);
  });

  it("keeps flushing the other pending doorbells at shutdown when one storage write fails", async () => {
    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "microsoft" })).toBe("sent");
    expect(ctx.app.dispatcher.request({ accountKey: OTHER_ACCOUNT_KEY, provider: "gmail" })).toBe("sent");
    expect(ctx.app.dispatcher.request({ accountKey: ACCOUNT_KEY, provider: "microsoft" })).toBe("scheduled");
    expect(ctx.app.dispatcher.request({ accountKey: OTHER_ACCOUNT_KEY, provider: "gmail" })).toBe("scheduled");
    expect(ctx.app.dispatcher.pendingCount).toBe(2);

    vi.spyOn(ctx.db, "recordPush").mockImplementationOnce(() => {
      throw new Error("SQLITE_IOERR: disk I/O error");
    });
    const logged = vi.spyOn(ctx.app.log, "error");

    await expect(ctx.app.close()).resolves.toBeUndefined();

    expect(logged).toHaveBeenCalledTimes(1);
    expect(logged.mock.calls[0]?.[1]).toBe("push: pending doorbell dropped at shutdown");
    expect(ctx.app.dispatcher.pendingCount).toBe(0);
    // Two initial sends plus the one flush that survived (the first pending hit the failing write).
    expect(ctx.sender.calls.map((call) => call.accountKey)).toEqual([ACCOUNT_KEY, OTHER_ACCOUNT_KEY, OTHER_ACCOUNT_KEY]);
    expect(ctx.sender.closed).toBe(true);
  });
});

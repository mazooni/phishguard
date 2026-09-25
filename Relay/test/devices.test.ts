import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { deriveAccountKey } from "../src/accountKey.js";
import { sha256Hex } from "../src/auth.js";
import {
  API_KEY,
  APNS_TOKEN,
  BUNDLE_ID,
  DEVICE_ID,
  DEVICE_SECRET,
  OTHER_DEVICE_SECRET,
  RELAY_SALT,
  type TestContext,
  closeTestApp,
  createTestApp,
  deviceHeaders,
  registerAccount,
  registerDevice,
  registerGraphSubscription,
} from "./helpers.js";

const ACCOUNT_KEY = deriveAccountKey("user@example.com", RELAY_SALT);

describe("POST /v1/devices", () => {
  let ctx: TestContext;
  beforeEach(async () => {
    ctx = await createTestApp();
  });
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  it("creates the device on first use and updates it afterwards", async () => {
    const created = await registerDevice(ctx.app);
    expect(created.statusCode).toBe(201);
    expect(created.json()).toEqual({ deviceID: DEVICE_ID, created: true });

    const row = ctx.db.findDevice(DEVICE_ID);
    expect(row).toBeDefined();
    expect(row?.secretHash).toBe(sha256Hex(DEVICE_SECRET));
    expect(row?.apnsToken).toBe(APNS_TOKEN);
    expect(row?.environment).toBe("sandbox");

    const updated = await registerDevice(ctx.app, { apnsToken: "AB".repeat(32), environment: "production" });
    expect(updated.statusCode).toBe(200);
    expect(updated.json()).toEqual({ deviceID: DEVICE_ID, created: false });
    const after = ctx.db.findDevice(DEVICE_ID);
    expect(after?.apnsToken).toBe("ab".repeat(32)); // normalized to lowercase
    expect(after?.environment).toBe("production");
    expect(after?.createdAt).toBe(row?.createdAt);
  });

  it("registers without an APNs token and keeps a stored token on a tokenless update", async () => {
    const created = await registerDevice(ctx.app, { apnsToken: null });
    expect(created.statusCode).toBe(201);
    expect(ctx.db.findDevice(DEVICE_ID)?.apnsToken).toBeNull();
    // Device-scoped routes work without a token (Call Guard on a free Apple team / Simulator).
    const account = await registerAccount(ctx.app, ACCOUNT_KEY, "gmail");
    expect(account.statusCode).toBe(204);
    expect(ctx.db.pushTargets(ACCOUNT_KEY, "gmail")).toEqual([]);

    const withToken = await registerDevice(ctx.app);
    expect(withToken.statusCode).toBe(200);
    expect(ctx.db.findDevice(DEVICE_ID)?.apnsToken).toBe(APNS_TOKEN);

    const tokenless = await registerDevice(ctx.app, { apnsToken: null, environment: "production" });
    expect(tokenless.statusCode).toBe(200);
    const row = ctx.db.findDevice(DEVICE_ID);
    expect(row?.apnsToken).toBe(APNS_TOKEN);
    expect(row?.environment).toBe("production");
  });

  it("answers 503 calls_not_configured on every Call Guard route while the module is off", async () => {
    await registerDevice(ctx.app);
    for (const [method, url] of [
      ["PUT", "/v1/devices/call-line"],
      ["GET", "/v1/devices/calls"],
      ["GET", "/v1/devices/calls/abc"],
      ["POST", "/v1/devices/calls/demo"],
      ["POST", "/v1/calls/twilio/voice"],
      ["GET", "/v1/calls/console"],
    ] as const) {
      const response = await ctx.app.inject({ method, url, headers: deviceHeaders(), ...(method === "GET" ? {} : { payload: {} }) });
      expect(response.statusCode, `${method} ${url}`).toBe(503);
      expect(response.json()).toEqual({ error: "calls_not_configured" });
    }
  });

  it("stores only a hash of the device secret", async () => {
    await registerDevice(ctx.app);
    const raw = ctx.db.db.prepare("SELECT secret_hash FROM devices WHERE device_id = ?").get(DEVICE_ID) as {
      secret_hash: string;
    };
    expect(raw.secret_hash).not.toContain(DEVICE_SECRET);
    expect(raw.secret_hash).toHaveLength(64);
  });

  it("rejects a missing or wrong X-API-Key before touching the body", async () => {
    const missing = await ctx.app.inject({
      method: "POST",
      url: "/v1/devices",
      headers: { authorization: `Bearer ${DEVICE_SECRET}`, "content-type": "application/json" },
      payload: "{not json",
    });
    expect(missing.statusCode).toBe(401);
    expect(missing.json()).toEqual({ error: "invalid_api_key" });

    const wrong = await ctx.app.inject({
      method: "POST",
      url: "/v1/devices",
      headers: deviceHeaders(DEVICE_SECRET, `${API_KEY}x`),
      payload: {},
    });
    expect(wrong.statusCode).toBe(401);
    expect(ctx.db.findDevice(DEVICE_ID)).toBeUndefined();
  });

  it("rejects a missing, malformed or implausible bearer secret", async () => {
    for (const authorization of [undefined, "Basic abc", "Bearer short", `Bearer ${"x".repeat(600)}`]) {
      const response = await ctx.app.inject({
        method: "POST",
        url: "/v1/devices",
        headers: { "x-api-key": API_KEY, ...(authorization ? { authorization } : {}) },
        payload: { deviceID: DEVICE_ID, apnsToken: APNS_TOKEN, environment: "sandbox", bundleID: "com.x.y" },
      });
      expect(response.statusCode).toBe(401);
      expect(response.headers["www-authenticate"]).toContain("Bearer");
    }
    expect(ctx.db.findDevice(DEVICE_ID)).toBeUndefined();
  });

  it("refuses to update an existing device with a different secret", async () => {
    expect((await registerDevice(ctx.app)).statusCode).toBe(201);
    const hijack = await registerDevice(ctx.app, { secret: OTHER_DEVICE_SECRET, apnsToken: "ff".repeat(32) });
    expect(hijack.statusCode).toBe(401);
    expect(ctx.db.findDevice(DEVICE_ID)?.apnsToken).toBe(APNS_TOKEN);
  });

  it("refuses to create a second device with an already used secret", async () => {
    expect((await registerDevice(ctx.app)).statusCode).toBe(201);
    const duplicate = await registerDevice(ctx.app, { deviceID: "other-device" });
    expect(duplicate.statusCode).toBe(409);
    expect(ctx.db.findDevice("other-device")).toBeUndefined();
  });

  it("rejects a bundleID other than the configured APNS_BUNDLE_ID, on create and on update", async () => {
    const foreign = await registerDevice(ctx.app, { bundleID: "com.example.OtherApp" });
    expect(foreign.statusCode).toBe(400);
    expect(foreign.json()).toEqual({ error: "bundle_id_mismatch" });
    expect(ctx.db.findDevice(DEVICE_ID)).toBeUndefined();

    expect((await registerDevice(ctx.app)).statusCode).toBe(201);
    const before = ctx.db.findDevice(DEVICE_ID);
    const retarget = await registerDevice(ctx.app, { bundleID: "com.example.OtherApp", apnsToken: "ff".repeat(32) });
    expect(retarget.statusCode).toBe(400);
    expect(ctx.db.findDevice(DEVICE_ID)).toEqual(before);
    expect(ctx.db.findDevice(DEVICE_ID)?.bundleId).toBe(BUNDLE_ID);
  });

  it("validates the body", async () => {
    const bad = await registerDevice(ctx.app, { apnsToken: "not-hex!", environment: "sandbox" });
    expect(bad.statusCode).toBe(400);
    const badEnv = await ctx.app.inject({
      method: "POST",
      url: "/v1/devices",
      headers: deviceHeaders(),
      payload: { deviceID: DEVICE_ID, apnsToken: APNS_TOKEN, environment: "staging", bundleID: "com.x.y" },
    });
    expect(badEnv.statusCode).toBe(400);
    expect(ctx.db.findDevice(DEVICE_ID)).toBeUndefined();
  });

  it("sends security headers and never a cacheable response", async () => {
    const response = await registerDevice(ctx.app);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
    expect(response.headers["strict-transport-security"]).toContain("max-age=");
  });
});

describe("device account and subscription routes", () => {
  let ctx: TestContext;
  beforeEach(async () => {
    ctx = await createTestApp();
    expect((await registerDevice(ctx.app)).statusCode).toBe(201);
  });
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  it("registers and unregisters an account", async () => {
    const added = await registerAccount(ctx.app, ACCOUNT_KEY, "gmail");
    expect(added.statusCode).toBe(204);
    expect(ctx.db.listDeviceAccounts(DEVICE_ID)).toMatchObject([{ accountKey: ACCOUNT_KEY, provider: "gmail" }]);
    expect(ctx.db.pushTargets(ACCOUNT_KEY, "gmail")).toHaveLength(1);
    expect(ctx.db.pushTargets(ACCOUNT_KEY, "microsoft")).toHaveLength(0);

    // Re-registering is idempotent and can change the provider.
    expect((await registerAccount(ctx.app, ACCOUNT_KEY, "microsoft")).statusCode).toBe(204);
    expect(ctx.db.listDeviceAccounts(DEVICE_ID)).toHaveLength(1);
    expect(ctx.db.pushTargets(ACCOUNT_KEY, "microsoft")).toHaveLength(1);

    const removed = await ctx.app.inject({
      method: "DELETE",
      url: `/v1/devices/accounts/${ACCOUNT_KEY}`,
      headers: deviceHeaders(),
    });
    expect(removed.statusCode).toBe(204);
    expect(ctx.db.listDeviceAccounts(DEVICE_ID)).toHaveLength(0);

    // Deleting again is still a 204 (idempotent for the app's unlink flow).
    const again = await ctx.app.inject({
      method: "DELETE",
      url: `/v1/devices/accounts/${ACCOUNT_KEY}`,
      headers: deviceHeaders(),
    });
    expect(again.statusCode).toBe(204);
  });

  it("rejects malformed account keys and providers", async () => {
    expect((await registerAccount(ctx.app, "not-a-key", "gmail")).statusCode).toBe(400);
    expect((await registerAccount(ctx.app, ACCOUNT_KEY.toUpperCase(), "gmail")).statusCode).toBe(400);
    const badProvider = await ctx.app.inject({
      method: "POST",
      url: "/v1/devices/accounts",
      headers: deviceHeaders(),
      payload: { accountKey: ACCOUNT_KEY, provider: "yahoo" },
    });
    expect(badProvider.statusCode).toBe(400);
    const badParam = await ctx.app.inject({ method: "DELETE", url: "/v1/devices/accounts/xyz", headers: deviceHeaders() });
    expect(badParam.statusCode).toBe(400);
  });

  it("requires a registered device (unknown secret → 401, missing API key → 401)", async () => {
    const unknown = await registerAccount(ctx.app, ACCOUNT_KEY, "gmail", OTHER_DEVICE_SECRET);
    expect(unknown.statusCode).toBe(401);
    const noKey = await ctx.app.inject({
      method: "POST",
      url: "/v1/devices/accounts",
      headers: { authorization: `Bearer ${DEVICE_SECRET}`, "content-type": "application/json" },
      payload: { accountKey: ACCOUNT_KEY, provider: "gmail" },
    });
    expect(noKey.statusCode).toBe(401);
    expect(ctx.db.listDeviceAccounts(DEVICE_ID)).toHaveLength(0);
  });

  it("registers a Graph subscription storing only the clientState hash, scoped to the device", async () => {
    const clientState = "c".repeat(32);
    const response = await registerGraphSubscription(ctx.app, {
      subscriptionID: "sub-1",
      accountKey: ACCOUNT_KEY,
      clientState,
    });
    expect(response.statusCode).toBe(204);
    const row = ctx.db.findGraphSubscription("sub-1");
    expect(row).toMatchObject({ subscriptionId: "sub-1", accountKey: ACCOUNT_KEY, deviceId: DEVICE_ID });
    expect(row?.clientStateHash).toBe(sha256Hex(clientState));
    expect(row?.clientStateHash).not.toContain(clientState);

    const tooShort = await registerGraphSubscription(ctx.app, {
      subscriptionID: "sub-2",
      accountKey: ACCOUNT_KEY,
      clientState: "short",
    });
    expect(tooShort.statusCode).toBe(400);
  });

  it("drops the account's Graph subscriptions when the account is unregistered", async () => {
    await registerAccount(ctx.app, ACCOUNT_KEY, "microsoft");
    await registerGraphSubscription(ctx.app, { subscriptionID: "sub-1", accountKey: ACCOUNT_KEY, clientState: "c".repeat(32) });
    await ctx.app.inject({ method: "DELETE", url: `/v1/devices/accounts/${ACCOUNT_KEY}`, headers: deviceHeaders() });
    expect(ctx.db.findGraphSubscription("sub-1")).toBeUndefined();
  });

  it("DELETE /v1/devices removes the device and cascades", async () => {
    await registerAccount(ctx.app, ACCOUNT_KEY, "microsoft");
    await registerGraphSubscription(ctx.app, { subscriptionID: "sub-1", accountKey: ACCOUNT_KEY, clientState: "c".repeat(32) });

    const response = await ctx.app.inject({ method: "DELETE", url: "/v1/devices", headers: deviceHeaders() });
    expect(response.statusCode).toBe(204);
    expect(ctx.db.findDevice(DEVICE_ID)).toBeUndefined();
    expect(ctx.db.pushTargets(ACCOUNT_KEY, "microsoft")).toHaveLength(0);
    expect(ctx.db.findGraphSubscription("sub-1")).toBeUndefined();

    // The secret no longer authenticates anything.
    expect((await registerAccount(ctx.app, ACCOUNT_KEY, "gmail")).statusCode).toBe(401);
  });
});

describe("GET /healthz", () => {
  it("answers without any auth", async () => {
    const ctx = await createTestApp();
    const response = await ctx.app.inject({ method: "GET", url: "/healthz" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ status: "ok" });
    const missing = await ctx.app.inject({ method: "GET", url: "/nope" });
    expect(missing.statusCode).toBe(404);
    expect(missing.json()).toEqual({ error: "not_found" });
    await closeTestApp(ctx);
  });
});

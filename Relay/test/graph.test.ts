import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { deriveAccountKey } from "../src/accountKey.js";
import {
  APNS_TOKEN,
  DEVICE_ID,
  OTHER_DEVICE_SECRET,
  RELAY_SALT,
  type TestContext,
  closeTestApp,
  createTestApp,
  graphNotification,
  registerAccount,
  registerDevice,
  registerGraphSubscription,
} from "./helpers.js";

const ACCOUNT_KEY = deriveAccountKey("someone@outlook.com", RELAY_SALT);
const SUBSCRIPTION_ID = "7f105c7d-2dc5-4530-97cd-4e7ae6534c07";
const CLIENT_STATE = "5f3a9c1e2b7d4e8fa0c1b2d3e4f5a6b7c8d9e0f1";

describe("POST /v1/graph/notifications", () => {
  let ctx: TestContext;
  beforeEach(async () => {
    ctx = await createTestApp();
    await registerDevice(ctx.app);
    await registerAccount(ctx.app, ACCOUNT_KEY, "microsoft");
    await registerGraphSubscription(ctx.app, { subscriptionID: SUBSCRIPTION_ID, accountKey: ACCOUNT_KEY, clientState: CLIENT_STATE });
  });
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  it("echoes the validation token as text/plain 200, URL-decoded, without X-API-Key", async () => {
    const token = "Validation: Testing client application reachability for subscription Request-Id: 9c4f9e8a";
    const response = await ctx.app.inject({
      method: "POST",
      url: `/v1/graph/notifications?validationToken=${encodeURIComponent(token)}`,
      headers: { "content-type": "text/plain; charset=utf-8" },
      payload: "",
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toMatch(/^text\/plain/);
    expect(response.body).toBe(token);
    expect(ctx.sender.calls).toHaveLength(0);
  });

  it("echoes the validation token when Graph sends no body or content-type at all", async () => {
    const response = await ctx.app.inject({
      method: "POST",
      url: "/v1/graph/notifications?validationToken=abc%3A123",
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toBe("abc:123");
  });

  it("validates the lifecycle URL the same way", async () => {
    const response = await ctx.app.inject({
      method: "POST",
      url: "/v1/graph/lifecycle?validationToken=hello%20world",
      headers: { "content-type": "text/plain; charset=utf-8" },
      payload: "",
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toBe("hello world");
  });

  it("accepts a matching notification with 202 and pushes asynchronously", async () => {
    const response = await ctx.app.inject({
      method: "POST",
      url: "/v1/graph/notifications",
      headers: { "content-type": "application/json" },
      payload: graphNotification(SUBSCRIPTION_ID, CLIENT_STATE),
    });
    expect(response.statusCode).toBe(202);
    expect(response.body).toBe("");

    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(1);
    expect(ctx.sender.calls[0]).toMatchObject({
      deviceId: DEVICE_ID,
      apnsToken: APNS_TOKEN,
      provider: "microsoft",
      accountKey: ACCOUNT_KEY,
    });
    expect(ctx.sender.calls[0]?.extra).toBeUndefined();
  });

  it("drops notifications whose clientState does not match, still answering 202", async () => {
    for (const clientState of ["wrong-client-state", CLIENT_STATE.toUpperCase(), "", undefined]) {
      const response = await ctx.app.inject({
        method: "POST",
        url: "/v1/graph/notifications",
        headers: { "content-type": "application/json" },
        payload: graphNotification(SUBSCRIPTION_ID, clientState as string),
      });
      expect(response.statusCode).toBe(202);
    }
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(0);
  });

  it("ignores unknown subscriptions and malformed items", async () => {
    const response = await ctx.app.inject({
      method: "POST",
      url: "/v1/graph/notifications",
      headers: { "content-type": "application/json" },
      payload: { value: [{ subscriptionId: "unknown", clientState: CLIENT_STATE }, { clientState: CLIENT_STATE }, "junk", 42] },
    });
    expect(response.statusCode).toBe(202);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(0);
  });

  it("rejects bodies that are not Graph notification batches", async () => {
    const response = await ctx.app.inject({
      method: "POST",
      url: "/v1/graph/notifications",
      headers: { "content-type": "application/json" },
      payload: { hello: "world" },
    });
    expect(response.statusCode).toBe(400);
  });

  it("handles batches with several items, pushing once per matching subscription", async () => {
    const otherKey = deriveAccountKey("other@outlook.com", RELAY_SALT);
    await registerDevice(ctx.app, { deviceID: "second", secret: OTHER_DEVICE_SECRET, apnsToken: "ee".repeat(32) });
    await registerAccount(ctx.app, otherKey, "microsoft", OTHER_DEVICE_SECRET);
    await registerGraphSubscription(ctx.app, { subscriptionID: "sub-other", accountKey: otherKey, clientState: "d".repeat(40) }, OTHER_DEVICE_SECRET);

    const first = graphNotification(SUBSCRIPTION_ID, CLIENT_STATE).value[0];
    const second = graphNotification("sub-other", "d".repeat(40)).value[0];
    const forged = graphNotification("sub-other", CLIENT_STATE).value[0];
    const response = await ctx.app.inject({
      method: "POST",
      url: "/v1/graph/notifications",
      headers: { "content-type": "application/json" },
      payload: { value: [first, second, forged] },
    });
    expect(response.statusCode).toBe(202);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls.map((call) => [call.deviceId, call.accountKey]).sort()).toEqual(
      [
        [DEVICE_ID, ACCOUNT_KEY],
        ["second", otherKey],
      ].sort(),
    );
  });

  it("forwards lifecycle events as an extra payload key after verifying clientState", async () => {
    const response = await ctx.app.inject({
      method: "POST",
      url: "/v1/graph/lifecycle",
      headers: { "content-type": "application/json" },
      payload: {
        value: [
          {
            subscriptionId: SUBSCRIPTION_ID,
            subscriptionExpirationDateTime: "2026-09-27T10:00:00.000Z",
            tenantId: "9188040d-6c67-4c5b-b112-36a304b66dad",
            clientState: CLIENT_STATE,
            lifecycleEvent: "reauthorizationRequired",
          },
        ],
      },
    });
    expect(response.statusCode).toBe(202);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(1);
    expect(ctx.sender.calls[0]?.extra).toEqual({ lifecycleEvent: "reauthorizationRequired" });

    const forged = await ctx.app.inject({
      method: "POST",
      url: "/v1/graph/lifecycle",
      headers: { "content-type": "application/json" },
      payload: { value: [{ subscriptionId: SUBSCRIPTION_ID, clientState: "nope", lifecycleEvent: "subscriptionRemoved" }] },
    });
    expect(forged.statusCode).toBe(202);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(1);
  });
});

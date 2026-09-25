import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { deriveAccountKey } from "../src/accountKey.js";
import { classifyVerifyError, decodeEnvelope } from "../src/routes/gmail.js";
import {
  APNS_TOKEN,
  AUDIENCE,
  BUNDLE_ID,
  DEVICE_ID,
  OTHER_DEVICE_SECRET,
  RELAY_SALT,
  type TestContext,
  closeTestApp,
  createTestApp,
  pubsubEnvelope,
  pubsubToken,
  registerAccount,
  registerDevice,
} from "./helpers.js";

const EMAIL = "User@Example.com";
const ACCOUNT_KEY = deriveAccountKey(EMAIL, RELAY_SALT);

function post(ctx: TestContext, token: string | undefined, payload: unknown) {
  return ctx.app.inject({
    method: "POST",
    url: "/v1/gmail/pubsub",
    headers: {
      "content-type": "application/json",
      ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
    },
    payload: payload as Record<string, unknown>,
  });
}

describe("POST /v1/gmail/pubsub", () => {
  let ctx: TestContext;
  beforeEach(async () => {
    ctx = await createTestApp();
    await registerDevice(ctx.app);
    await registerAccount(ctx.app, ACCOUNT_KEY, "gmail");
  });
  afterEach(async () => {
    await closeTestApp(ctx);
    vi.useRealTimers();
  });

  it("verifies the OIDC token against the configured audience and pushes a doorbell", async () => {
    const response = await post(ctx, pubsubToken(), pubsubEnvelope(EMAIL));
    expect(response.statusCode).toBe(204);
    expect(ctx.verifier.calls).toEqual([{ idToken: pubsubToken(), audience: AUDIENCE }]);

    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(1);
    expect(ctx.sender.calls[0]).toEqual({
      deviceId: DEVICE_ID,
      apnsToken: APNS_TOKEN,
      environment: "sandbox",
      bundleId: BUNDLE_ID,
      provider: "gmail",
      accountKey: ACCOUNT_KEY,
    });
  });

  it("does not require X-API-Key (Pub/Sub cannot send one)", async () => {
    const response = await post(ctx, pubsubToken(), pubsubEnvelope(EMAIL));
    expect(response.statusCode).toBe(204);
  });

  it("rejects a missing bearer token", async () => {
    const response = await post(ctx, undefined, pubsubEnvelope(EMAIL));
    expect(response.statusCode).toBe(401);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(0);
  });

  it("rejects a token for the wrong audience", async () => {
    const response = await post(ctx, pubsubToken({ aud: "https://someone-else.example/v1/gmail/pubsub" }), pubsubEnvelope(EMAIL));
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: "invalid_token" });
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(0);
  });

  it("rejects a garbage token", async () => {
    const response = await post(ctx, "definitely.not.a.jwt", pubsubEnvelope(EMAIL));
    expect(response.statusCode).toBe(401);
    expect(ctx.sender.calls).toHaveLength(0);
  });

  it("rejects a valid token from a different service account", async () => {
    const response = await post(ctx, pubsubToken({ email: "attacker@other-project.iam.gserviceaccount.com" }), pubsubEnvelope(EMAIL));
    expect(response.statusCode).toBe(403);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(0);
  });

  it("rejects a token whose email is not verified", async () => {
    const response = await post(ctx, pubsubToken({ email_verified: false }), pubsubEnvelope(EMAIL));
    expect(response.statusCode).toBe(403);
    expect(ctx.sender.calls).toHaveLength(0);
  });

  it("compares the service account email case-insensitively", async () => {
    const response = await post(ctx, pubsubToken({ email: "PhishGuard-Push@Example-Project.iam.gserviceaccount.com" }), pubsubEnvelope(EMAIL));
    expect(response.statusCode).toBe(204);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(1);
  });

  it("acknowledges (204) notifications for addresses nobody registered, without pushing", async () => {
    const response = await post(ctx, pubsubToken(), pubsubEnvelope("stranger@example.com"));
    expect(response.statusCode).toBe(204);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(0);
  });

  it("acknowledges (204) unparseable messages so Pub/Sub stops redelivering them", async () => {
    const notBase64Json = { message: { data: Buffer.from("hello").toString("base64"), messageId: "1" }, subscription: "s" };
    expect((await post(ctx, pubsubToken(), notBase64Json)).statusCode).toBe(204);
    expect((await post(ctx, pubsubToken(), { message: { messageId: "2" } })).statusCode).toBe(204);
    expect((await post(ctx, pubsubToken(), { nope: true })).statusCode).toBe(204);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(0);
  });

  it("does not push to devices that registered the key for another provider", async () => {
    // Register the same key as microsoft on a second device; a Gmail doorbell must not reach it.
    await registerDevice(ctx.app, { deviceID: "second", secret: OTHER_DEVICE_SECRET, apnsToken: "ee".repeat(32) });
    await registerAccount(ctx.app, ACCOUNT_KEY, "microsoft", OTHER_DEVICE_SECRET);
    await post(ctx, pubsubToken(), pubsubEnvelope(EMAIL));
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls.map((call) => call.deviceId)).toEqual([DEVICE_ID]);
  });

  it("debounces: one push per accountKey per window, with a trailing push for coalesced notifications", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    vi.setSystemTime(new Date("2026-09-21T10:00:00.000Z"));

    expect((await post(ctx, pubsubToken(), pubsubEnvelope(EMAIL, "1"))).statusCode).toBe(204);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(1);

    vi.advanceTimersByTime(2_000);
    expect((await post(ctx, pubsubToken(), pubsubEnvelope(EMAIL, "2"))).statusCode).toBe(204);
    vi.advanceTimersByTime(1_000);
    expect((await post(ctx, pubsubToken(), pubsubEnvelope(EMAIL, "3"))).statusCode).toBe(204);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(1);
    expect(ctx.app.dispatcher.pendingCount).toBe(1);

    // The window (10 s from the first push) elapses: exactly one trailing push goes out.
    vi.advanceTimersByTime(7_000);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(2);
    expect(ctx.app.dispatcher.pendingCount).toBe(0);

    // A notification well after the window is sent immediately again.
    vi.advanceTimersByTime(15_000);
    expect((await post(ctx, pubsubToken(), pubsubEnvelope(EMAIL, "4"))).statusCode).toBe(204);
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls).toHaveLength(3);
  });

  it("debounces per accountKey, not globally", async () => {
    const otherKey = deriveAccountKey("other@example.com", RELAY_SALT);
    await registerAccount(ctx.app, otherKey, "gmail");
    await post(ctx, pubsubToken(), pubsubEnvelope(EMAIL));
    await post(ctx, pubsubToken(), pubsubEnvelope("other@example.com"));
    await ctx.app.dispatcher.drain();
    expect(ctx.sender.calls.map((call) => call.accountKey).sort()).toEqual([ACCOUNT_KEY, otherKey].sort());
  });
});

describe("classifyVerifyError", () => {
  it("maps google-auth-library failures to categories that never contain token material", () => {
    const secretFragment = "eyJhbGciOiJSUzI1NiIs";
    const cases: [string, string][] = [
      ["Wrong recipient, payload audience != requiredAudience", "audience_mismatch"],
      ["Token used too late, 1 > 0", "expired"],
      ["Token used too early", "not_yet_valid"],
      ["Invalid token signature", "bad_signature"],
      ["Invalid issuer, expected one of [accounts.google.com]", "bad_issuer"],
      [`Can't parse token envelope: ${secretFragment}': Unexpected token`, "malformed"],
      ["Wrong number of segments in token: junk", "malformed"],
      [`something new ${secretFragment}`, "invalid"],
    ];
    for (const [message, expected] of cases) {
      const category = classifyVerifyError(new Error(message));
      expect(category).toBe(expected);
      expect(category).not.toContain(secretFragment);
    }
    expect(classifyVerifyError("not an error")).toBe("invalid");
  });
});

describe("decodeEnvelope", () => {
  it("decodes the documented Pub/Sub push format", () => {
    const envelope = decodeEnvelope(pubsubEnvelope("user@example.com", "9876543210", "2070443601311540"));
    expect(envelope).toEqual({
      messageId: "2070443601311540",
      subscription: "projects/example-project/subscriptions/gmail-push",
      notification: { emailAddress: "user@example.com", historyId: "9876543210" },
    });
  });

  it("accepts a numeric historyId", () => {
    const data = Buffer.from(JSON.stringify({ emailAddress: "a@b.c", historyId: 42 })).toString("base64");
    expect(decodeEnvelope({ message: { data } }).notification).toEqual({ emailAddress: "a@b.c", historyId: "42" });
  });

  it("returns no notification for anything else", () => {
    expect(decodeEnvelope(null).notification).toBeUndefined();
    expect(decodeEnvelope("string").notification).toBeUndefined();
    expect(decodeEnvelope({ message: { data: 5 } }).notification).toBeUndefined();
    const noEmail = Buffer.from(JSON.stringify({ historyId: "1" })).toString("base64");
    expect(decodeEnvelope({ message: { data: noEmail } }).notification).toBeUndefined();
    const arrayData = Buffer.from(JSON.stringify(["x"])).toString("base64");
    expect(decodeEnvelope({ message: { data: arrayData } }).notification).toBeUndefined();
  });
});

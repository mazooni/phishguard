import type { FastifyInstance } from "fastify";

import type { PushFailure, PushOutcome, PushRequest, PushSender } from "../src/apns.js";
import type { CallsConfig } from "../src/calls/config.js";
import type { AlertPushRequest } from "../src/calls/types.js";
import { FakeScorer, FakeTranscriber, FakeTwilioClient, testCallsConfig } from "./calls/fakes.js";
import type { RelayConfig } from "../src/config.js";
import { RelayDb, type Provider } from "../src/db.js";
import type { IdTokenClaims, TokenVerifier } from "../src/routes/gmail.js";
import { buildApp } from "../src/server.js";

export const API_KEY = "test-api-key-0123456789abcdef";
export const RELAY_SALT = "test-salt-0123456789abcdef";
export const AUDIENCE = "https://relay.test/v1/gmail/pubsub";
export const PUSH_SA_EMAIL = "phishguard-push@example-project.iam.gserviceaccount.com";
export const BUNDLE_ID = "com.mazooni.PhishGuard";

export const DEVICE_SECRET = "a".repeat(32) + "0123456789abcdef0123456789abcdef";
export const OTHER_DEVICE_SECRET = "b".repeat(32) + "fedcba9876543210fedcba9876543210";
export const DEVICE_ID = "6F9619FF-8B86-D011-B42D-00C04FC964FF";
export const APNS_TOKEN = "0f".repeat(32);

/** A throwaway PEM so `loadConfig` accepts the key without touching a real Apple key. */
export const FAKE_P8 =
  "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n";

export function testConfig(overrides: Partial<RelayConfig> = {}): RelayConfig {
  return {
    port: 0,
    host: "127.0.0.1",
    publicBaseUrl: "https://relay.test",
    relayApiKey: API_KEY,
    relaySalt: RELAY_SALT,
    dataDir: ":memory:",
    apns: { keyId: "ABC123DEFG", teamId: "TEAM123456", signingKey: Buffer.from(FAKE_P8), bundleId: BUNDLE_ID },
    pubsub: { audience: AUDIENCE, serviceAccountEmail: PUSH_SA_EMAIL },
    bundleId: BUNDLE_ID,
    calls: undefined,
    debounceSeconds: 10,
    logLevel: "silent",
    ...overrides,
  };
}

/** Records every push and answers with a scripted outcome (default: success). */
export class FakeSender implements PushSender {
  readonly calls: PushRequest[] = [];
  /** Call Guard alert pushes (`sendAlert`). */
  readonly alerts: AlertPushRequest[] = [];
  readonly outcomes: PushOutcome[] = [];
  closed = false;
  respond: (request: PushRequest) => PushOutcome = () => ({ ok: true, retried: false });
  respondAlert: (request: AlertPushRequest) => PushOutcome = () => ({ ok: true, retried: false });

  async send(request: PushRequest): Promise<PushOutcome> {
    this.calls.push(request);
    const outcome = this.respond(request);
    this.outcomes.push(outcome);
    return outcome;
  }

  async sendAlert(request: AlertPushRequest): Promise<PushOutcome> {
    this.alerts.push(request);
    const outcome = this.respondAlert(request);
    this.outcomes.push(outcome);
    return outcome;
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  failWith(failure: Omit<PushFailure, "ok">, times = Number.POSITIVE_INFINITY): void {
    let remaining = times;
    this.respond = () => {
      if (remaining > 0) {
        remaining -= 1;
        return { ok: false, ...failure, retried: false };
      }
      return { ok: true, retried: false };
    };
  }
}

interface FakeTokenBody {
  aud: string;
  email?: string;
  email_verified?: boolean;
  exp?: number;
}

/** Fake OIDC tokens: `fake.<base64url json>`; verification checks the audience like Google would. */
export function makeIdToken(body: FakeTokenBody): string {
  return `fake.${Buffer.from(JSON.stringify(body), "utf8").toString("base64url")}`;
}

export function pubsubToken(overrides: Partial<FakeTokenBody> = {}): string {
  return makeIdToken({ aud: AUDIENCE, email: PUSH_SA_EMAIL, email_verified: true, ...overrides });
}

export class FakeVerifier implements TokenVerifier {
  readonly calls: { idToken: string; audience: string }[] = [];

  async verifyIdToken(idToken: string, audience: string): Promise<IdTokenClaims> {
    this.calls.push({ idToken, audience });
    if (!idToken.startsWith("fake.")) throw new Error("Wrong number of segments in token");
    const body = JSON.parse(Buffer.from(idToken.slice(5), "base64url").toString("utf8")) as FakeTokenBody;
    if (body.aud !== audience) throw new Error("Wrong recipient, payload audience != requiredAudience");
    if (body.exp !== undefined && body.exp * 1000 < Date.now()) throw new Error("Token used too late");
    const claims: IdTokenClaims = {};
    if (body.email !== undefined) claims.email = body.email;
    if (body.email_verified !== undefined) claims.email_verified = body.email_verified;
    return claims;
  }
}

export interface TestContext {
  app: FastifyInstance;
  db: RelayDb;
  sender: FakeSender;
  verifier: FakeVerifier;
  config: RelayConfig;
}

export async function createTestApp(overrides: Partial<RelayConfig> = {}): Promise<TestContext> {
  const config = testConfig(overrides);
  const db = RelayDb.open(":memory:");
  const sender = new FakeSender();
  const verifier = new FakeVerifier();
  const app = buildApp({ config, db, pushSender: sender, tokenVerifier: verifier, logger: false });
  await app.ready();
  return { app, db, sender, verifier, config };
}

export interface CallsTestContext extends TestContext {
  twilio: FakeTwilioClient;
  transcriber: FakeTranscriber;
  scorer: FakeScorer;
  /** Every test starts at this fake clock; advance it with `ctx.clock.advance(ms)`. */
  clock: FakeClock;
}

export class FakeClock {
  private current: number;
  constructor(start = 1_760_000_000_000) {
    this.current = start;
  }
  now = (): number => this.current;
  advance(ms: number): void {
    this.current += ms;
  }
  set(value: number): void {
    this.current = value;
  }
}

/**
 * A relay with Call Guard enabled and every external service replaced by the fakes in test/calls/fakes.ts.
 * `callsOverrides` tweaks the Call Guard config (e.g. `{ openai: undefined }` for a rules-only relay).
 */
export async function createCallsTestApp(
  callsOverrides: Partial<CallsConfig> = {},
  overrides: Partial<RelayConfig> = {},
): Promise<CallsTestContext> {
  const config = testConfig({ calls: testCallsConfig(callsOverrides), ...overrides });
  const db = RelayDb.open(":memory:");
  const sender = new FakeSender();
  const verifier = new FakeVerifier();
  const twilio = new FakeTwilioClient();
  const transcriber = new FakeTranscriber();
  const scorer = new FakeScorer();
  const clock = new FakeClock();
  const app = buildApp({
    config,
    db,
    pushSender: sender,
    tokenVerifier: verifier,
    logger: false,
    calls: { twilio, transcriber, scorer, now: clock.now },
  });
  await app.ready();
  return { app, db, sender, verifier, config, twilio, transcriber, scorer, clock };
}

export async function closeTestApp(context: TestContext): Promise<void> {
  await context.app.close();
  context.db.close();
}

/** Like the app's RelayClient: bearer + API key; `inject` adds `content-type: application/json` when a payload is given. */
export function deviceHeaders(secret = DEVICE_SECRET, apiKey = API_KEY): Record<string, string> {
  return { authorization: `Bearer ${secret}`, "x-api-key": apiKey, accept: "application/json" };
}

export interface RegisterOptions {
  deviceID?: string;
  secret?: string;
  /** `null` sends no token at all (a build without the push entitlement). */
  apnsToken?: string | null;
  environment?: "sandbox" | "production";
  bundleID?: string;
}

export async function registerDevice(app: FastifyInstance, options: RegisterOptions = {}) {
  const token = options.apnsToken === undefined ? APNS_TOKEN : options.apnsToken;
  return app.inject({
    method: "POST",
    url: "/v1/devices",
    headers: deviceHeaders(options.secret ?? DEVICE_SECRET),
    payload: {
      deviceID: options.deviceID ?? DEVICE_ID,
      ...(token === null ? {} : { apnsToken: token }),
      environment: options.environment ?? "sandbox",
      bundleID: options.bundleID ?? BUNDLE_ID,
    },
  });
}

export async function registerAccount(app: FastifyInstance, accountKey: string, provider: Provider, secret = DEVICE_SECRET) {
  return app.inject({
    method: "POST",
    url: "/v1/devices/accounts",
    headers: deviceHeaders(secret),
    payload: { accountKey, provider },
  });
}

export async function registerGraphSubscription(
  app: FastifyInstance,
  body: { subscriptionID: string; accountKey: string; clientState: string },
  secret = DEVICE_SECRET,
) {
  return app.inject({
    method: "POST",
    url: "/v1/devices/graph-subscriptions",
    headers: deviceHeaders(secret),
    payload: body,
  });
}

/** Pub/Sub push envelope for a Gmail watch notification. */
export function pubsubEnvelope(emailAddress: string, historyId = "9876543210", messageId = "2070443601311540") {
  const data = Buffer.from(JSON.stringify({ emailAddress, historyId }), "utf8").toString("base64");
  return {
    message: { data, messageId, message_id: messageId, publishTime: "2026-09-21T10:00:00.000Z", attributes: {} },
    subscription: "projects/example-project/subscriptions/gmail-push",
    deliveryAttempt: 1,
  };
}

export function graphNotification(subscriptionId: string, clientState: string, extra: Record<string, unknown> = {}) {
  return {
    value: [
      {
        id: "lsgTZMr9KwAAA",
        subscriptionId,
        subscriptionExpirationDateTime: "2026-09-27T10:00:00.000Z",
        clientState,
        changeType: "created",
        resource: "users/00000000-0000-0000-0000-000000000000@tenant/messages/AAMkAGI2",
        tenantId: "9188040d-6c67-4c5b-b112-36a304b66dad",
        resourceData: {
          "@odata.type": "#Microsoft.Graph.Message",
          "@odata.id": "Users/00000000-0000-0000-0000-000000000000@tenant/Messages/AAMkAGI2",
          "@odata.etag": 'W/"CQAAABYAAADkrWGo7bouTKlsgTZMr9KwAAAUWRHf"',
          id: "AAMkAGI2",
        },
        ...extra,
      },
    ],
  };
}

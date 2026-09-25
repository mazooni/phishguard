import { ApnsClient, ApnsError, Errors, Host, Notification, Priority, PushType, SilentNotification } from "apns2";

import type { ApnsConfig, ApnsEnvironment } from "./config.js";
import type { AlertPushRequest, AlertPushSender } from "./calls/types.js";
import type { Provider } from "./db.js";

/**
 * APNs sender. One `ApnsClient` per environment: sandbox tokens (Debug builds, `aps-environment=development`)
 * must go to api.sandbox.push.apple.com, production tokens to api.push.apple.com — sending to the wrong host
 * fails with `400 BadDeviceToken`.
 *
 * The payload is exactly the PhishGuard doorbell:
 *   { "aps": { "content-available": 1 }, "provider": "gmail" | "microsoft", "accountKey": "<sha256 hex>" }
 * with headers `apns-push-type: background`, `apns-priority: 5`, `apns-topic: <bundle id>`
 * (`SilentNotification` sets the first two; `topic` sets the third). The topic is always the configured
 * `APNS_BUNDLE_ID`: the relay serves exactly one app, and a per-device value must not be able to steer the
 * team-scoped APNs key at another topic.
 */

export interface PushRequest {
  deviceId: string;
  apnsToken: string;
  environment: ApnsEnvironment;
  /** The bundle id the device registered with. `createApnsSender` replaces it with the configured topic. */
  bundleId: string;
  provider: Provider;
  accountKey: string;
  /** Extra top-level payload keys (e.g. `lifecycleEvent` for Graph lifecycle notifications). */
  extra?: Record<string, string>;
}

export interface PushSuccess {
  ok: true;
}

export interface PushFailure {
  ok: false;
  /** The token is dead (410 Unregistered / ExpiredToken, 400 BadDeviceToken / DeviceTokenNotForTopic). */
  dropToken: boolean;
  reason: string;
  status: number | undefined;
  /** APNs' `timestamp` (ms since epoch) on 410: when the token stopped being valid. */
  invalidSince?: number;
}

export type PushOutcome = (PushSuccess | PushFailure) & { retried: boolean };

export interface PushSender extends AlertPushSender {
  /** The silent doorbell (mail). */
  send(request: PushRequest): Promise<PushOutcome>;
  close(): Promise<void>;
}

/** A relay without an APNs key: every push is skipped with a `not_configured` failure the caller logs once. */
export function createNoopPushSender(): PushSender {
  const outcome: PushOutcome = { ok: false, dropToken: false, reason: "not_configured", status: undefined, retried: false };
  return {
    async send() {
      return outcome;
    },
    async sendAlert() {
      return outcome;
    },
    async close() {
      // nothing to close
    },
  };
}

/** The subset of `ApnsClient` the sender uses; tests substitute a fake. */
export interface ApnsClientLike {
  send(notification: Notification): Promise<unknown>;
  close(): Promise<void>;
}

export interface ApnsSenderOptions {
  config: ApnsConfig;
  clientFactory?: (environment: ApnsEnvironment) => ApnsClientLike;
  /** Pause before the single retry of a 5xx / transport failure. */
  retryDelayMs?: number;
  /** `apns-expiration` horizon; a doorbell older than this is useless, so let APNs drop it. */
  expirationSeconds?: number;
  /** Per-send deadline (apns2's own `requestTimeout` is not applied by the library). */
  sendTimeoutMs?: number;
}

const DROP_TOKEN_REASONS: ReadonlySet<string> = new Set<string>([
  Errors.unregistered,
  Errors.badDeviceToken,
  Errors.deviceTokenNotForTopic,
  "ExpiredToken",
]);

export function buildDoorbell(request: PushRequest, expirationSeconds: number, now = Date.now()): SilentNotification {
  return new SilentNotification(request.apnsToken, {
    topic: request.bundleId,
    data: { ...(request.extra ?? {}), provider: request.provider, accountKey: request.accountKey },
    // ≤ 64 bytes; lets APNs coalesce doorbells for the same account while the device is offline.
    collapseId: `${request.provider}:${request.accountKey}`.slice(0, 64),
    expiration: Math.floor(now / 1000) + expirationSeconds,
  });
}

/**
 * Call Guard alert push (docs/CALLS.md §5.4): `apns-push-type: alert`, priority 10, the fixed topic, a per-call
 * collapse id and a short expiration, with `interruption-level` / `relevance-score` / `thread-id` / `category` in
 * `aps` and the custom keys at the top level. See docs/research/apnsAlerts.md for the apns2 API used.
 */
export function buildCallAlert(request: AlertPushRequest, topic: string, now = Date.now()): Notification {
  return new Notification(request.apnsToken, {
    topic,
    type: PushType.alert,
    priority: Priority.immediate,
    collapseId: request.collapseId.slice(0, 64),
    expiration: Math.floor(now / 1000) + request.expirationSeconds,
    alert: { title: request.title, subtitle: request.subtitle, body: request.body },
    sound: "default",
    threadId: request.threadId,
    category: request.category,
    // apns2 writes `"content-available": 0` for `false`; omit the key instead (docs/research/apnsAlerts.md §4).
    ...(request.contentAvailable ? { contentAvailable: true } : {}),
    aps: {
      "interruption-level": request.interruptionLevel,
      "relevance-score": request.relevanceScore,
    },
    data: request.data,
  });
}

interface Attempt {
  outcome: PushSuccess | PushFailure;
  retryable: boolean;
}

function classify(error: unknown): Attempt {
  if (error instanceof ApnsError) {
    const status = error.statusCode;
    const reason = error.reason;
    if (status === 410 || DROP_TOKEN_REASONS.has(reason)) {
      const outcome: PushFailure = { ok: false, dropToken: true, reason, status };
      if (status === 410 && typeof error.timestamp === "number" && Number.isFinite(error.timestamp)) {
        outcome.invalidSince = error.timestamp;
      }
      return { outcome, retryable: false };
    }
    return { outcome: { ok: false, dropToken: false, reason, status }, retryable: status >= 500 };
  }
  // Transport-level failure (connection reset, timeout, TLS): worth exactly one retry.
  const reason = error instanceof Error ? `${error.name}: ${error.message}` : "TransportError";
  return { outcome: { ok: false, dropToken: false, reason, status: undefined }, retryable: true };
}

function delay(ms: number): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function createApnsSender(options: ApnsSenderOptions): PushSender {
  const { config } = options;
  const retryDelayMs = options.retryDelayMs ?? 250;
  const expirationSeconds = options.expirationSeconds ?? 10 * 60;
  const clients = new Map<ApnsEnvironment, ApnsClientLike>();

  const factory =
    options.clientFactory ??
    ((environment: ApnsEnvironment): ApnsClientLike =>
      new ApnsClient({
        team: config.teamId,
        keyId: config.keyId,
        signingKey: config.signingKey,
        defaultTopic: config.bundleId,
        host: environment === "production" ? Host.production : Host.development,
        requestTimeout: 10_000,
      }));

  function clientFor(environment: ApnsEnvironment): ApnsClientLike {
    let client = clients.get(environment);
    if (!client) {
      client = factory(environment);
      clients.set(environment, client);
    }
    return client;
  }

  // apns2 12.2.0 declares `requestTimeout` but never applies it (docs/research/apnsAlerts.md §4), so every send
  // races its own deadline; a hung HTTP/2 stream then counts as a transport failure (one retry).
  const sendTimeoutMs = options.sendTimeoutMs ?? 10_000;
  async function sendWithDeadline(environment: ApnsEnvironment, notification: Notification): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`APNs send timed out after ${sendTimeoutMs} ms`)), sendTimeoutMs);
      timer.unref();
    });
    try {
      await Promise.race([clientFor(environment).send(notification), deadline]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async function attempt(request: PushRequest): Promise<Attempt> {
    try {
      // Pin the topic to the configured bundle id regardless of what the device row says.
      const doorbell = buildDoorbell({ ...request, bundleId: config.bundleId }, expirationSeconds);
      await sendWithDeadline(request.environment, doorbell);
      return { outcome: { ok: true }, retryable: false };
    } catch (error) {
      return classify(error);
    }
  }

  async function attemptAlert(request: AlertPushRequest): Promise<Attempt> {
    try {
      const notification = buildCallAlert(request, config.bundleId);
      await sendWithDeadline(request.environment, notification);
      return { outcome: { ok: true }, retryable: false };
    } catch (error) {
      return classify(error);
    }
  }

  return {
    async send(request) {
      const first = await attempt(request);
      if (!first.retryable) return { ...first.outcome, retried: false };
      await delay(retryDelayMs);
      const second = await attempt(request);
      return { ...second.outcome, retried: true };
    },
    async sendAlert(request) {
      const first = await attemptAlert(request);
      if (!first.retryable) return { ...first.outcome, retried: false };
      await delay(retryDelayMs);
      const second = await attemptAlert(request);
      return { ...second.outcome, retried: true };
    },
    async close() {
      const open = [...clients.values()];
      clients.clear();
      await Promise.allSettled(open.map((client) => client.close()));
    },
  };
}

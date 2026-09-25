import type { FastifyBaseLogger } from "fastify";

import type { PushSender } from "./apns.js";
import type { Provider, PushTarget, RelayDb } from "./db.js";

/**
 * Turns "something changed for accountKey" into at most one silent push per device per debounce window.
 *
 * Debounce is trailing-edge: the first doorbell in a window goes out immediately; further ones inside the
 * window are coalesced into a single push fired when the window ends, so a burst never exceeds one push per
 * `debounceMs` and no change is ever dropped. The last send time lives in `push_log`, so the window survives
 * restarts; pending timers are in memory only, so `close()` flushes them (the webhook that scheduled them was
 * already acknowledged and the provider will not redeliver it).
 *
 * Webhook handlers call `request()` synchronously and respond; the APNs traffic happens afterwards. A storage
 * error inside `request()` propagates to the handler (Fastify answers 500 and the provider redelivers); the
 * same error inside a timer or during shutdown has nobody to report to, so it drops that one doorbell and is
 * logged instead of terminating the process.
 */

export interface DispatchRequest {
  accountKey: string;
  provider: Provider;
  extra?: Record<string, string>;
}

export type DispatchDecision = "sent" | "scheduled" | "coalesced" | "no_targets" | "closed";

export interface PushDispatcherOptions {
  db: RelayDb;
  sender: PushSender;
  debounceMs: number;
  logger: FastifyBaseLogger;
}

interface Pending {
  timer: NodeJS.Timeout;
  request: DispatchRequest;
}

const PUSH_LOG_RETENTION_MS = 60 * 60 * 1000;

export class PushDispatcher {
  private readonly db: RelayDb;
  private readonly sender: PushSender;
  private readonly debounceMs: number;
  private readonly logger: FastifyBaseLogger;
  private readonly pending = new Map<string, Pending>();
  private readonly inFlight = new Set<Promise<void>>();
  private closed = false;

  constructor(options: PushDispatcherOptions) {
    this.db = options.db;
    this.sender = options.sender;
    this.debounceMs = options.debounceMs;
    this.logger = options.logger;
  }

  get pendingCount(): number {
    return this.pending.size;
  }

  request(request: DispatchRequest): DispatchDecision {
    if (this.closed) return "closed";
    if (this.db.pushTargets(request.accountKey, request.provider).length === 0) return "no_targets";

    const existing = this.pending.get(request.accountKey);
    if (existing) {
      existing.request = request;
      return "coalesced";
    }

    const now = Date.now();
    const last = this.db.lastPushAt(request.accountKey);
    if (last !== undefined && this.debounceMs > 0 && now - last < this.debounceMs) {
      const wait = Math.max(0, last + this.debounceMs - now);
      const timer = setTimeout(() => {
        const due = this.pending.get(request.accountKey);
        this.pending.delete(request.accountKey);
        if (due && !this.closed) this.fireSafely(due.request, "push: scheduled doorbell dropped");
      }, wait);
      timer.unref();
      this.pending.set(request.accountKey, { timer, request });
      return "scheduled";
    }

    this.fire(request);
    return "sent";
  }

  /** Resolves once every push started so far has finished (tests and graceful shutdown). */
  async drain(): Promise<void> {
    while (this.inFlight.size > 0) {
      await Promise.allSettled([...this.inFlight]);
    }
  }

  /**
   * Refuses further requests and flushes every pending trailing doorbell right away (ignoring the rest of its
   * debounce window: one early push at shutdown beats losing an acknowledged change). Idempotent. The caller
   * awaits `drain()` afterwards so the flushed sends complete before the APNs clients close.
   */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    const flush = [...this.pending.values()];
    this.pending.clear();
    for (const pending of flush) {
      clearTimeout(pending.timer);
      this.fireSafely(pending.request, "push: pending doorbell dropped at shutdown");
    }
  }

  /** `fire()` for paths without a request to answer (timers, shutdown): a storage error is logged, not thrown. */
  private fireSafely(request: DispatchRequest, failureMessage: string): void {
    try {
      this.fire(request);
    } catch (error: unknown) {
      this.logger.error(
        { err: error, provider: request.provider, accountKey: request.accountKey.slice(0, 12) },
        failureMessage,
      );
    }
  }

  private fire(request: DispatchRequest): void {
    const now = Date.now();
    this.db.recordPush(request.accountKey, now);
    this.db.prunePushLog(now - PUSH_LOG_RETENTION_MS);
    // Re-read targets at send time: tokens may have been re-registered while the doorbell was waiting.
    const targets = this.db.pushTargets(request.accountKey, request.provider);
    const task = this.sendAll(request, targets).catch((error: unknown) => {
      this.logger.error({ err: error }, "push: unexpected failure");
    });
    this.inFlight.add(task);
    void task.finally(() => this.inFlight.delete(task));
  }

  private async sendAll(request: DispatchRequest, targets: PushTarget[]): Promise<void> {
    await Promise.all(targets.map((target) => this.sendOne(request, target)));
  }

  private async sendOne(request: DispatchRequest, target: PushTarget): Promise<void> {
    const outcome = await this.sender.send({
      deviceId: target.deviceId,
      apnsToken: target.apnsToken,
      environment: target.environment,
      bundleId: target.bundleId,
      provider: request.provider,
      accountKey: request.accountKey,
      ...(request.extra ? { extra: request.extra } : {}),
    });

    const context = { deviceId: target.deviceId, environment: target.environment, provider: request.provider };
    if (outcome.ok) {
      this.logger.debug({ ...context, retried: outcome.retried }, "push: sent");
      return;
    }
    if (outcome.dropToken) {
      // Apple: for 410, drop the token only if it was not re-registered after APNs' `timestamp`.
      if (outcome.invalidSince !== undefined && target.updatedAt > outcome.invalidSince) {
        this.logger.info({ ...context, reason: outcome.reason }, "push: token re-registered after APNs 410; keeping");
        return;
      }
      const cleared = this.db.clearApnsToken(target.deviceId, target.apnsToken);
      this.logger.warn({ ...context, reason: outcome.reason, status: outcome.status, cleared }, "push: token dropped");
      return;
    }
    this.logger.warn(
      { ...context, reason: outcome.reason, status: outcome.status, retried: outcome.retried },
      "push: failed",
    );
  }
}

import type { FastifyBaseLogger } from "fastify";

import type { PushSender } from "../../apns.js";
import type { DeviceRow, RelayDb } from "../../db.js";
import type { CallsConfig } from "../config.js";
import type { CallSession } from "../session.js";
import {
  redactNumber,
  riskLevelRank,
  truncate,
  type AlertLevel,
  type AlertPushRequest,
  type CallAlert,
  type CallVerdict,
  type SessionObserver,
  type VoiceControl,
} from "../types.js";
import { alertText, type AlertText } from "./text.js";

/**
 * Turns verdicts into alerts (docs/CALLS.md §5.4, §6.3): the first verdict at or above the line's minimum level
 * alerts; later verdicts alert again only when the level *rises*. Each alert sends the APNs alert push (when the
 * device has a token and APNs is configured), speaks the warning to the protected person (Twilio-backed calls
 * only, once the user is in the call), and records the alert on the session — which the live hub relays as
 * `call.alert` and the manager persists. Push and speech run concurrently; nothing here throws into the emitter.
 * A verdict emitted after the session ended (the detector's final pass) never alerts: it is persisted and
 * broadcast as `verdict.updated` only.
 */

export const CALL_ALERT_THREAD_ID = "com.mazooni.PhishGuard.calls";
export const CALL_ALERT_CATEGORY = "PHISHGUARD_CALL_ALERT";
export const CALL_ALERT_EXPIRATION_SECONDS = 120;
/** APNs allows 4096 bytes; the guard keeps a margin for the headers apns2 adds nothing to and for `aps` extras. */
export const MAX_ALERT_PAYLOAD_BYTES = 3500;

export interface CallAlertDispatcherOptions {
  db: RelayDb;
  pushSender: PushSender;
  apnsConfigured: boolean;
  voice: VoiceControl | undefined;
  config: CallsConfig;
  logger: FastifyBaseLogger;
  now: () => number;
}

export class CallAlertDispatcher implements SessionObserver {
  /** The level currently being alerted per call, set synchronously so a burst of verdicts cannot double-alert. */
  private readonly pending = new Map<string, AlertLevel>();

  constructor(private readonly options: CallAlertDispatcherOptions) {}

  attach(session: CallSession): void {
    session.on("verdict", (verdict) => {
      this.handleVerdict(session, verdict).catch((error: unknown) => {
        this.options.logger.error({ err: error, callId: session.callId }, "call-alert: dispatch failed");
      });
    });
    session.once("ended", () => this.pending.delete(session.callId));
  }

  /** The level an alert for this verdict would carry, or undefined when no alert is due. */
  decide(session: CallSession, verdict: CallVerdict): AlertLevel | undefined {
    if (verdict.level === "safe") return undefined;
    const minimum = session.line?.minimumLevel ?? this.options.config.defaultMinimumLevel;
    if (riskLevelRank(verdict.level) < riskLevelRank(minimum)) return undefined;
    const highest = highestOf(session.alertLevel, this.pending.get(session.callId));
    if (highest && riskLevelRank(verdict.level) <= riskLevelRank(highest)) return undefined;
    return verdict.level;
  }

  private async handleVerdict(session: CallSession, verdict: CallVerdict): Promise<void> {
    if (session.isEnded) {
      // The detector's final pass (≤ 10 s after `ended`) may still raise the level: the verdict is persisted and
      // broadcast as `verdict.updated`, but nobody is pushed or spoken to about a call that is over.
      this.options.logger.info({ callId: session.callId, sequence: verdict.sequence, level: verdict.level }, "call-alert: verdict after the call ended; no alert");
      return;
    }
    const level = this.decide(session, verdict);
    if (!level) return;
    this.pending.set(session.callId, level);
    const { logger, now } = this.options;
    const text = alertText(level, session.callerNumber, verdict.reasons, verdict.summary);
    const context = { callId: session.callId, deviceId: session.deviceId, level, sequence: verdict.sequence, caller: redactNumber(session.callerNumber) };
    logger.info(context, "call-alert: alerting");

    const [pushed, spoken] = await Promise.all([
      this.push(session, verdict, level, text).catch((error: unknown) => {
        logger.error({ err: error, ...context }, "call-alert: push failed");
        return false;
      }),
      this.speak(session).catch((error: unknown) => {
        logger.error({ err: error, ...context }, "call-alert: spoken warning failed");
        return false;
      }),
    ]);

    const alert: CallAlert = { sequence: verdict.sequence, level, ...text, sentAt: now(), pushed, spoken };
    try {
      session.recordAlert(alert);
    } finally {
      this.pending.delete(session.callId);
    }
    logger.info({ ...context, pushed, spoken }, "call-alert: recorded");
  }

  private async push(session: CallSession, verdict: CallVerdict, level: AlertLevel, text: AlertText): Promise<boolean> {
    const { db, logger, pushSender, apnsConfigured } = this.options;
    const device = db.findDevice(session.deviceId);
    const context = { callId: session.callId, deviceId: session.deviceId, level };
    if (!device?.apnsToken) {
      logger.info(context, "call-alert: device has no APNs token; push skipped");
      return false;
    }
    if (!apnsConfigured) {
      logger.info(context, "call-alert: apns not configured; push skipped");
      return false;
    }
    const apnsToken = device.apnsToken;
    const request = buildAlertPushRequest(session, verdict, level, text, { deviceId: device.deviceId, environment: device.environment, apnsToken });
    const outcome = await pushSender.sendAlert(request);
    if (outcome.ok) {
      logger.info({ ...context, retried: outcome.retried }, "call-alert: pushed");
      return true;
    }
    if (outcome.dropToken) {
      // Apple: on 410, drop the token only if it was not re-registered after APNs' `timestamp` (as push.ts does).
      if (outcome.invalidSince !== undefined && device.updatedAt > outcome.invalidSince) {
        logger.info({ ...context, reason: outcome.reason }, "call-alert: token re-registered after APNs 410; keeping");
        return false;
      }
      const cleared = db.clearApnsToken(device.deviceId, apnsToken);
      logger.warn({ ...context, reason: outcome.reason, status: outcome.status, cleared }, "call-alert: token dropped");
      return false;
    }
    logger.warn({ ...context, reason: outcome.reason, status: outcome.status, retried: outcome.retried }, "call-alert: push failed");
    return false;
  }

  private async speak(session: CallSession): Promise<boolean> {
    const voice = voiceFor(session, this.options.voice);
    if (!voice) return false;
    if (session.line?.spokenWarning === false) return false;
    if (session.status !== "in_progress") return false;
    const accepted = await voice.speakToUser(session, this.options.config.spokenWarningText);
    this.options.logger.info({ callId: session.callId, accepted }, "call-alert: spoken warning requested");
    return accepted;
  }
}

/** Only calls that actually run through Twilio have a leg to speak into; demo and replay sessions get no voice. */
export function voiceFor(session: CallSession, voice: VoiceControl | undefined): VoiceControl | undefined {
  if (!voice) return undefined;
  return session.source === "twilio" || session.source === "test-call" ? voice : undefined;
}

function highestOf(a: AlertLevel | undefined, b: AlertLevel | undefined): AlertLevel | undefined {
  if (!a) return b;
  if (!b) return a;
  return riskLevelRank(a) >= riskLevelRank(b) ? a : b;
}

/** The exact `AlertPushRequest` of docs/CALLS.md §5.4, with the body trimmed until the payload fits. */
export function buildAlertPushRequest(
  session: CallSession,
  verdict: CallVerdict,
  level: AlertLevel,
  text: AlertText,
  device: Pick<DeviceRow, "deviceId" | "environment"> & { apnsToken: string },
): AlertPushRequest {
  const data: Record<string, string | number | boolean> = {
    kind: "call-alert",
    callID: session.callId,
    level,
    confidence: verdict.confidence,
    category: verdict.category,
    callerNumber: session.callerNumber,
    startedAt: session.startedAt,
    sequence: verdict.sequence,
  };
  const request: AlertPushRequest = {
    deviceId: device.deviceId,
    apnsToken: device.apnsToken,
    environment: device.environment,
    title: text.title,
    subtitle: text.subtitle,
    body: text.body,
    threadId: CALL_ALERT_THREAD_ID,
    category: CALL_ALERT_CATEGORY,
    interruptionLevel: "time-sensitive",
    relevanceScore: 1,
    collapseId: `call-${session.callId}`,
    expirationSeconds: CALL_ALERT_EXPIRATION_SECONDS,
    contentAvailable: true,
    data,
  };
  // Size guard: shrink the body (then the subtitle) until the wire payload is comfortably under APNs' 4 KB.
  while (estimatedPayloadBytes(request) > MAX_ALERT_PAYLOAD_BYTES) {
    if (request.body.length > 20) {
      request.body = truncate(request.body, Math.floor(request.body.length / 2));
    } else if (request.subtitle.length > 0) {
      request.subtitle = "";
    } else {
      break;
    }
  }
  return request;
}

/** The JSON apns2 will send for this request (aps + custom keys), in bytes. */
export function estimatedPayloadBytes(request: AlertPushRequest): number {
  const payload = {
    aps: {
      alert: { title: request.title, subtitle: request.subtitle, body: request.body },
      sound: "default",
      "interruption-level": request.interruptionLevel,
      "relevance-score": request.relevanceScore,
      "thread-id": request.threadId,
      category: request.category,
      "content-available": request.contentAvailable ? 1 : 0,
    },
    ...request.data,
  };
  return Buffer.byteLength(JSON.stringify(payload), "utf8");
}

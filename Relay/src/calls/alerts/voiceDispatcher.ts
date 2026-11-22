import type { FastifyBaseLogger } from "fastify";

import type { PushSender } from "../../apns.js";
import type { RelayDb } from "../../db.js";
import { DEFAULT_AI_VOICE_WARNING, type CallsConfig } from "../config.js";
import type { CallSession } from "../session.js";
import {
  redactNumber,
  type AlertPushRequest,
  type CallVoiceAlert,
  type CallVoiceAssessment,
  type SessionObserver,
  type VoiceControl,
} from "../types.js";
import { composeAlertPushRequest, deliverAlertPush, voiceFor, type AlertPushDevice, type SpokenAddendum } from "./dispatcher.js";
import { VOICE_SPOKEN_ADDENDUM, voiceAlertText, type AlertText } from "./text.js";

/**
 * The AI-voice warning: once per call, the first time the caller's voice is judged `synthetic` while the call is
 * live. It sends its own APNs alert (same device-token rules as the scam alert, its own collapse id so neither
 * banner replaces the other), speaks its own announcement to the protected person, and records both on the voice
 * assessment — never in `session.alerts`, so the scam dispatcher's levels are untouched. A synthetic voice is not
 * a scam verdict and nothing here reads or writes one beyond copying the current level into the push for display.
 *
 * Speech, unlike the scam warning, yields: the scam dispatcher's timing is never touched, so this announcement
 * is the one that waits. It waits until the protected person has joined (`in_progress`, plus a moment for the
 * line to settle), while a scam alert is being sent (its warning may already be playing), and until a scam
 * warning spoken moments ago has had time to finish. When a scam warning is spoken right after this one — which
 * may have cut it short; what Twilio does with a second announcement during the first is not documented — this
 * one is repeated once, after the scam warning. A test call is never spoken to on its own — that would replace
 * its TwiML and cut the scripted "scammer" short; there the scam warning carries one extra sentence instead
 * (`SpokenAddendum`), when the voice was judged before that warning went out. Nothing here throws into the emitter.
 */

/** The least an announcement is given to finish before the other one may start. */
export const ANNOUNCEMENT_GAP_MS = 12_000;
/** After the person joins: Twilio can still refuse an announcement at the instant of the join, and they say hello. */
export const JOIN_DELAY_MS = 1_500;
/** How often a waiting announcement looks again while a scam alert is being sent, and for how long at most. */
export const IN_FLIGHT_RETRY_MS = 1_000;
export const MAX_IN_FLIGHT_WAITS = 15;
/** One more attempt, this long after Twilio refused the first. */
export const REFUSED_RETRY_MS = 3_000;

/**
 * How long an announcement of `text` takes: about 150 words a minute, plus the time Twilio needs to fetch the
 * announcement and start it — never less than `ANNOUNCEMENT_GAP_MS`, so a custom, longer warning is not talked over.
 */
export function announcementMs(text: string): number {
  const words = text.trim().split(/\s+/).filter((word) => word.length > 0).length;
  return Math.max(ANNOUNCEMENT_GAP_MS, words * 400 + 2_500);
}

export interface VoiceAlertDispatcherOptions {
  db: RelayDb;
  pushSender: PushSender;
  apnsConfigured: boolean;
  voice: VoiceControl | undefined;
  config: CallsConfig;
  logger: FastifyBaseLogger;
  now: () => number;
  /** Whether a scam alert for this call is being sent right now (`CallAlertDispatcher.isAlerting`). */
  scamAlertInFlight?: ((callId: string) => boolean) | undefined;
  /** Defaults to `announcementMs` of each warning's text; tests shorten it. */
  announcementGapMs?: number | undefined;
  /** Defaults to `JOIN_DELAY_MS`, `IN_FLIGHT_RETRY_MS` and `REFUSED_RETRY_MS`; tests shorten them. */
  joinDelayMs?: number | undefined;
  inFlightRetryMs?: number | undefined;
  refusedRetryMs?: number | undefined;
}

/** One call's warning: set synchronously on the first `synthetic` so a burst of voice events cannot double-alert. */
interface VoiceAlertState {
  /** The alert as recorded on the session; undefined while the push is still in flight. */
  alert: CallVoiceAlert | undefined;
  /** Twilio accepted the announcement (or a test call's scam warning carried the sentence). */
  spoken: boolean;
  /** An announcement is still due: waiting for the person to join, or for `timer`. */
  owed: boolean;
  timer: NodeJS.Timeout | undefined;
  /** When Twilio last accepted the announcement. */
  spokenAt: number | undefined;
  /** Requests made to Twilio so far (a refused one is retried once). */
  attempts: number;
  /** The announcement was already repeated after a scam warning that followed it closely. */
  repeated: boolean;
  /** Consecutive looks at a scam alert still in flight. */
  inFlightWaits: number;
}

export class VoiceAlertDispatcher implements SessionObserver, SpokenAddendum {
  private readonly calls = new Map<string, VoiceAlertState>();
  /** How long a spoken scam warning is given before this announcement may start. */
  private readonly gapMs: number;
  /** How long this announcement takes: a scam warning spoken within it may have cut it short. */
  private readonly ownMs: number;
  private readonly joinDelayMs: number;
  private readonly inFlightRetryMs: number;
  private readonly refusedRetryMs: number;

  constructor(private readonly options: VoiceAlertDispatcherOptions) {
    const fixed = options.announcementGapMs;
    this.gapMs = Math.max(0, fixed ?? announcementMs(options.config.spokenWarningText));
    this.ownMs = Math.max(0, fixed ?? announcementMs(this.warningText()));
    this.joinDelayMs = Math.max(0, options.joinDelayMs ?? JOIN_DELAY_MS);
    this.inFlightRetryMs = Math.max(1, options.inFlightRetryMs ?? IN_FLIGHT_RETRY_MS);
    this.refusedRetryMs = Math.max(1, options.refusedRetryMs ?? REFUSED_RETRY_MS);
  }

  private warningText(): string {
    return this.options.config.voice?.warningText ?? DEFAULT_AI_VOICE_WARNING;
  }

  /** Calls with a warning in progress or an announcement still due (tests). */
  get pendingCalls(): number {
    return this.calls.size;
  }

  attach(session: CallSession): void {
    session.on("voice", (voice) => this.guard(session, () => this.handleVoice(session, voice)));
    // The person joined: an announcement that was waiting for them goes out once the line has settled.
    session.on("status", (status) => {
      if (status !== "in_progress") return;
      const state = this.calls.get(session.callId);
      if (!state?.owed || state.timer) return;
      this.guard(session, () => this.schedule(session, state, Math.max(this.joinDelayMs, this.waitAfterScamWarning(session)), "joined"));
    });
    session.on("alert", (alert) => {
      if (!alert.spoken) return;
      const state = this.calls.get(session.callId);
      if (!state) return;
      this.guard(session, () => this.scamWarningSpoken(session, state));
    });
    session.once("ended", () => this.forget(session.callId));
  }

  /** Shutdown: cancels every announcement still waiting. */
  close(): void {
    for (const callId of [...this.calls.keys()]) this.forget(callId);
  }

  // MARK: SpokenAddendum (the scam dispatcher's one question to this module)

  addendumFor(session: CallSession): string | undefined {
    if (session.source !== "test-call" || session.voice?.status !== "synthetic") return undefined;
    return this.speechAllowed(session) ? VOICE_SPOKEN_ADDENDUM : undefined;
  }

  addendumSpoken(session: CallSession): void {
    try {
      const state = this.calls.get(session.callId);
      if (state) {
        state.spoken = true;
        // Not recorded yet ⇒ the push is still in flight and `alert()` records `spoken: true` itself.
        if (state.alert) this.confirmSpoken(session, state);
      } else {
        const alert = session.voice?.alert;
        if (alert && !alert.spoken) session.recordVoiceAlert({ ...alert, spoken: true });
      }
      this.options.logger.info({ callId: session.callId }, "call-voice-alert: spoken with the scam warning (test call)");
    } catch (error) {
      this.options.logger.error({ errorName: errorName(error), callId: session.callId }, "call-voice-alert: could not record the spoken warning");
    }
  }

  // MARK: the warning

  private handleVoice(session: CallSession, voice: CallVoiceAssessment): void {
    if (voice.status !== "synthetic") return;
    // `recordVoiceAlert` emits `voice` too, also after the call ended: neither may start a second warning.
    if (session.isEnded || voice.alert || this.calls.has(session.callId)) return;
    const state: VoiceAlertState = { alert: undefined, spoken: false, owed: false, timer: undefined, spokenAt: undefined, attempts: 0, repeated: false, inFlightWaits: 0 };
    this.calls.set(session.callId, state);
    this.alert(session, voice, state).catch((error: unknown) => {
      this.options.logger.error({ errorName: errorName(error), callId: session.callId }, "call-voice-alert: dispatch failed");
    });
  }

  private async alert(session: CallSession, voice: CallVoiceAssessment, state: VoiceAlertState): Promise<void> {
    const { logger, now } = this.options;
    const text = voiceAlertText(session.callerNumber);
    const context = { callId: session.callId, deviceId: session.deviceId, caller: redactNumber(session.callerNumber) };
    logger.info({ ...context, confidence: voice.confidence, syntheticShare: voice.syntheticShare }, "call-voice-alert: alerting");

    // Push and speech run concurrently, as for the scam alert; a deferred announcement does not hold the record back.
    const [pushed] = await Promise.all([
      this.push(session, voice, text).catch((error: unknown) => {
        logger.error({ errorName: errorName(error), ...context }, "call-voice-alert: push failed");
        return false;
      }),
      this.beginSpeech(session, state),
    ]);

    const alert: CallVoiceAlert = { ...text, sentAt: now(), pushed, spoken: state.spoken };
    state.alert = alert;
    // Accepted after the call ended too: a warning that was sent is never lost from the record.
    session.recordVoiceAlert(alert);
    logger.info({ ...context, pushed, spoken: alert.spoken, speechDeferred: state.owed }, "call-voice-alert: recorded");
  }

  private push(session: CallSession, voice: CallVoiceAssessment, text: AlertText): Promise<boolean> {
    const context = { callId: session.callId, deviceId: session.deviceId };
    return deliverAlertPush(this.options, session.deviceId, "call-voice-alert", context, (device) => buildVoiceAlertPushRequest(session, voice, text, device));
  }

  // MARK: speech

  /** The line, the operator and the call's source all allow speaking about the caller's voice. */
  private speechAllowed(session: CallSession): boolean {
    if (!voiceFor(session, this.options.voice)) return false;
    if (session.line?.spokenWarning === false) return false;
    return this.options.config.voice?.spokenWarning !== false;
  }

  /** Speaks at once when nothing stands in the way, otherwise leaves the announcement owed. Never rejects. */
  private async beginSpeech(session: CallSession, state: VoiceAlertState): Promise<void> {
    try {
      // A test call gets no announcement of its own (see `addendumFor`).
      if (!this.speechAllowed(session) || session.source === "test-call") return;
      state.owed = true;
      await this.speakWhenClear(session, state);
    } catch (error) {
      this.options.logger.error({ errorName: errorName(error), callId: session.callId }, "call-voice-alert: spoken warning failed");
    }
  }

  private async speakWhenClear(session: CallSession, state: VoiceAlertState): Promise<void> {
    if (!state.owed || state.timer || session.isEnded) return;
    // Not joined yet: the `status` listener comes back here.
    if (session.status !== "in_progress") return;
    if (this.waitWhileScamAlertInFlight(session, state)) return;
    const wait = this.waitAfterScamWarning(session);
    if (wait > 0) {
      this.schedule(session, state, wait, "after the scam warning");
      return;
    }
    await this.speakNow(session, state);
  }

  /**
   * A scam alert is being sent: its warning may be playing although it is not recorded yet. Looks again shortly;
   * the `alert` listener takes over the moment it is recorded as spoken. Bounded, so an alert that never settles
   * cannot hold this one back for the rest of the call. True when the announcement was put off.
   */
  private waitWhileScamAlertInFlight(session: CallSession, state: VoiceAlertState): boolean {
    if (!this.options.scamAlertInFlight?.(session.callId)) return false;
    if (state.inFlightWaits >= MAX_IN_FLIGHT_WAITS) return false;
    state.inFlightWaits += 1;
    this.schedule(session, state, this.inFlightRetryMs, "scam alert in flight");
    return true;
  }

  /** A scam warning has just been spoken on this call (its alert was recorded). */
  private scamWarningSpoken(session: CallSession, state: VoiceAlertState): void {
    if (session.isEnded) return;
    state.inFlightWaits = 0;
    if (state.owed) {
      // Ours is still due: it waits its turn, from now.
      this.schedule(session, state, this.gapMs, "after the scam warning");
      return;
    }
    // Ours went out moments ago and the scam warning came on top of it: say it once more, after that one.
    if (state.spokenAt === undefined || state.repeated) return;
    if (this.options.now() - state.spokenAt >= this.ownMs || !this.speechAllowed(session)) return;
    state.repeated = true;
    state.owed = true;
    this.schedule(session, state, this.gapMs, "repeated after the scam warning");
  }

  /** How much of the gap after the last spoken scam warning is still to run, in ms. */
  private waitAfterScamWarning(session: CallSession): number {
    let last: number | undefined;
    for (const alert of session.alerts) if (alert.spoken && (last === undefined || alert.sentAt > last)) last = alert.sentAt;
    if (last === undefined) return 0;
    return Math.min(this.gapMs, Math.max(0, this.gapMs - (this.options.now() - last)));
  }

  /**
   * Puts the announcement off by `delayMs` (replacing any wait already running). When the timer fires the wait it
   * stood for is over and is not measured again — only a scam alert that is in flight at that moment delays it
   * further — so the announcement cannot be put off indefinitely.
   */
  private schedule(session: CallSession, state: VoiceAlertState, delayMs: number, reason: string): void {
    if (state.timer) clearTimeout(state.timer);
    state.timer = setTimeout(() => {
      state.timer = undefined;
      this.guard(session, () => {
        if (!state.owed || session.isEnded) return undefined;
        if (this.waitWhileScamAlertInFlight(session, state)) return undefined;
        return this.speakNow(session, state);
      });
    }, delayMs);
    state.timer.unref();
    this.options.logger.info({ callId: session.callId, delayMs, reason }, "call-voice-alert: spoken warning waits");
  }

  /** One request to Twilio. A refused or failed first request is retried once; after that it is no longer owed. */
  private async speakNow(session: CallSession, state: VoiceAlertState): Promise<void> {
    if (!state.owed || session.isEnded || session.status !== "in_progress") return;
    const voice = voiceFor(session, this.options.voice);
    if (!voice) return;
    state.owed = false;
    state.attempts += 1;
    let accepted = false;
    try {
      accepted = await voice.speakToUser(session, this.warningText(), "voice");
    } catch (error) {
      this.options.logger.error({ errorName: errorName(error), callId: session.callId }, "call-voice-alert: spoken warning failed");
    }
    this.options.logger.info({ callId: session.callId, accepted, attempt: state.attempts }, "call-voice-alert: spoken warning requested");
    if (!accepted) {
      // Never spoken so far and only asked once: Twilio may not have had the person in the conference yet.
      if (state.attempts === 1 && !state.spoken && !session.isEnded && this.calls.get(session.callId) === state) {
        state.owed = true;
        this.schedule(session, state, this.refusedRetryMs, "refused; one more attempt");
      }
      return;
    }
    state.spoken = true;
    state.spokenAt = this.options.now();
    if (state.alert) this.confirmSpoken(session, state);
  }

  /** A warning recorded with `spoken: false` whose announcement was accepted afterwards is recorded again. */
  private confirmSpoken(session: CallSession, state: VoiceAlertState): void {
    if (!state.alert || state.alert.spoken) return;
    state.alert = { ...state.alert, spoken: true };
    session.recordVoiceAlert(state.alert);
  }

  private forget(callId: string): void {
    const state = this.calls.get(callId);
    if (!state) return;
    if (state.timer) clearTimeout(state.timer);
    state.timer = undefined;
    state.owed = false;
    this.calls.delete(callId);
  }

  /** Runs listener work so that neither a throw nor a rejection reaches the session's emitter. */
  private guard(session: CallSession, work: () => void | Promise<void>): void {
    const failed = (error: unknown): void => {
      this.options.logger.error({ errorName: errorName(error), callId: session.callId }, "call-voice-alert: dispatch failed");
    };
    try {
      const result = work();
      if (result instanceof Promise) result.catch(failed);
    } catch (error) {
      failed(error);
    }
  }
}

/** Errors are logged by name only: a vendor error's message can carry a phone number or a URL with a key in it. */
function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "unknown";
}

/** The push `kind` of the AI-voice warning; the scam alert's is "call-alert". */
export const VOICE_ALERT_PUSH_KIND = "call-voice-alert";

/**
 * The AI-voice alert push. It has a `kind` of its own, deliberately not "call-alert": this push can arrive before
 * the call has any scam verdict, and app builds from before AI-voice detection handle a "call-alert" for a call
 * without a verdict by trapping (Swift exclusivity) when that call is on screen. An unknown kind is harmless to
 * them: iOS still shows the banner, and the app treats the wake-up as a mail doorbell and checks the mailbox.
 * Builds that know the feature read `kind` and the `voice` key. `level`, `category` and `sequence` mirror the scam
 * verdict as it stands (for the app's call row), not the voice finding; `confidence` is the voice detector's.
 */
export function buildVoiceAlertPushRequest(
  session: CallSession,
  voice: Pick<CallVoiceAssessment, "confidence">,
  text: AlertText,
  device: AlertPushDevice,
): AlertPushRequest {
  const verdict = session.verdict;
  const data: Record<string, string | number | boolean> = {
    kind: VOICE_ALERT_PUSH_KIND,
    callID: session.callId,
    level: verdict && verdict.level !== "safe" ? verdict.level : "low",
    confidence: voice.confidence,
    category: verdict?.category ?? "safe",
    callerNumber: session.callerNumber,
    startedAt: session.startedAt,
    sequence: verdict?.sequence ?? 0,
    voice: "synthetic",
  };
  return composeAlertPushRequest(text, device, `call-voice-${session.callId}`, data);
}

import { EventEmitter } from "node:events";
import { randomBytes, randomUUID } from "node:crypto";

import {
  ENDED_STATUSES,
  truncate,
  type AlertLevel,
  type CallAlert,
  type CallLine,
  type CallRecord,
  type CallSource,
  type CallStatus,
  type CallSummaryJSON,
  type CallVerdict,
  type TranscriptSegment,
} from "./types.js";

/**
 * One live (or recently ended) call. The hub every Call Guard module talks to (docs/CALLS.md §4):
 * the Twilio path and the demo runner feed it status and transcript segments, the detector sets verdicts, the
 * alert dispatcher records alerts, the live hub relays everything, and the manager persists `toRecord()`.
 *
 * Events (typed): `status`, `segment`, `verdict`, `alert`, `ended`. Transcripts live here in memory only.
 */

export interface CallSessionEvents {
  status: [status: CallStatus];
  segment: [segment: TranscriptSegment];
  verdict: [verdict: CallVerdict];
  alert: [alert: CallAlert];
  ended: [record: CallRecord];
}

export interface CallSessionInit {
  callId?: string;
  deviceId: string;
  line: CallLine | null;
  source: CallSource;
  callerNumber: string;
  calledNumber: string;
  startedAt: number;
  twilioCallSid?: string;
  status?: CallStatus;
  /** Which service transcribes this call (Twilio path); demo/replay sessions leave it undefined. */
  transcriptionSource?: "twilio" | "openai";
}

/** Segments kept per session; the oldest finals are dropped beyond this (partials are replaced in place). */
export const MAX_SEGMENTS = 2000;
export const DEFAULT_TRANSCRIPT_CHARS = 6000;

export class CallSession extends EventEmitter<CallSessionEvents> {
  readonly callId: string;
  readonly deviceId: string;
  readonly line: CallLine | null;
  readonly source: CallSource;
  readonly callerNumber: string;
  readonly calledNumber: string;
  readonly startedAt: number;
  /**
   * Random per-call secret placed in Twilio callback URLs (`?token=`) and the Media Streams path, so a guessed
   * URL cannot inject transcript text or make the relay speak. Never logged.
   */
  readonly mediaToken: string;
  transcriptionSource: "twilio" | "openai" | undefined;
  twilioCallSid: string | undefined;
  /** The protected phone's leg (set by the Twilio path once it is dialled). */
  userCallSid: string | undefined;
  conferenceName: string | undefined;
  /** The conference's CF… SID once Twilio reports `conference-start`; participant/conference updates prefer it. */
  conferenceSid: string | undefined;
  private _status: CallStatus;
  private _endedAt: number | undefined;
  private _verdict: CallVerdict | undefined;
  private _sequence = 0;
  private readonly _alerts: CallAlert[] = [];
  private readonly _segments: TranscriptSegment[] = [];
  private _updatedAt: number;
  private readonly now: () => number;

  constructor(init: CallSessionInit, now: () => number = Date.now) {
    super();
    this.callId = init.callId ?? randomUUID();
    this.deviceId = init.deviceId;
    this.line = init.line;
    this.source = init.source;
    this.callerNumber = init.callerNumber;
    this.calledNumber = init.calledNumber;
    this.startedAt = init.startedAt;
    this.mediaToken = randomBytes(16).toString("hex");
    this.transcriptionSource = init.transcriptionSource;
    this.twilioCallSid = init.twilioCallSid;
    this._status = init.status ?? "ringing";
    this._updatedAt = init.startedAt;
    this.now = now;
  }

  get status(): CallStatus {
    return this._status;
  }

  get endedAt(): number | undefined {
    return this._endedAt;
  }

  get isEnded(): boolean {
    return this._endedAt !== undefined;
  }

  get verdict(): CallVerdict | undefined {
    return this._verdict;
  }

  get alerts(): readonly CallAlert[] {
    return this._alerts;
  }

  get alerted(): boolean {
    return this._alerts.length > 0;
  }

  /** The highest level alerted so far. */
  get alertLevel(): AlertLevel | undefined {
    let best: AlertLevel | undefined;
    for (const alert of this._alerts) {
      if (!best || rank(alert.level) > rank(best)) best = alert.level;
    }
    return best;
  }

  get segments(): readonly TranscriptSegment[] {
    return this._segments;
  }

  get updatedAt(): number {
    return this._updatedAt;
  }

  elapsedMs(now: number = this.now()): number {
    return Math.max(0, (this._endedAt ?? now) - this.startedAt);
  }

  // MARK: mutations

  setStatus(status: CallStatus): void {
    if (this.isEnded) return;
    if (ENDED_STATUSES.has(status)) {
      this.end(status);
      return;
    }
    if (status === this._status) return;
    this._status = status;
    this._updatedAt = this.now();
    this.emit("status", status);
  }

  /**
   * Adds or replaces a segment: a partial with the same id as an existing partial replaces it; a final replaces
   * its partial. Nothing is accepted after the session ended.
   */
  addSegment(segment: TranscriptSegment): void {
    if (this.isEnded) return;
    const index = this._segments.findIndex((existing) => existing.id === segment.id);
    if (index >= 0) {
      const existing = this._segments[index]!;
      // A final never regresses to a partial.
      if (existing.final && !segment.final) return;
      this._segments[index] = segment;
    } else {
      this._segments.push(segment);
      if (this._segments.length > MAX_SEGMENTS) this._segments.splice(0, this._segments.length - MAX_SEGMENTS);
    }
    this._updatedAt = this.now();
    this.emit("segment", segment);
  }

  /** Assigns the next `sequence`, stores and emits. Returns the stored verdict. */
  setVerdict(verdict: Omit<CallVerdict, "sequence">): CallVerdict {
    this._sequence += 1;
    const stored: CallVerdict = { ...verdict, sequence: this._sequence };
    this._verdict = stored;
    this._updatedAt = this.now();
    this.emit("verdict", stored);
    return stored;
  }

  recordAlert(alert: CallAlert): void {
    this._alerts.push(alert);
    this._updatedAt = this.now();
    this.emit("alert", alert);
  }

  /** Idempotent. Emits `ended` exactly once with the final record. */
  end(status: CallStatus = "completed", at: number = this.now()): void {
    if (this.isEnded) return;
    this._status = ENDED_STATUSES.has(status) ? status : "completed";
    this._endedAt = at;
    this._updatedAt = at;
    this.emit("ended", this.toRecord());
  }

  // MARK: transcript

  /**
   * "Caller: …" / "You: …" with consecutive same-speaker finals merged; the oldest lines are dropped first when
   * the text exceeds `maxChars`. Partials are excluded.
   */
  transcriptText(maxChars: number = DEFAULT_TRANSCRIPT_CHARS): string {
    const lines: { speaker: string; text: string }[] = [];
    for (const segment of this._segments) {
      if (!segment.final) continue;
      const text = segment.text.trim();
      if (!text) continue;
      const label = segment.speaker === "caller" ? "Caller" : "You";
      const last = lines[lines.length - 1];
      if (last && last.speaker === label) {
        last.text += ` ${text}`;
      } else {
        lines.push({ speaker: label, text });
      }
    }
    const rendered = lines.map((line) => `${line.speaker}: ${line.text}`);
    let total = rendered.reduce((sum, line) => sum + line.length + 1, 0);
    while (rendered.length > 1 && total > maxChars) {
      const dropped = rendered.shift()!;
      total -= dropped.length + 1;
    }
    const joined = rendered.join("\n");
    return joined.length > maxChars ? joined.slice(joined.length - maxChars) : joined;
  }

  /** Characters of final transcript text (used by the detector's "enough to score" gate). */
  finalTranscriptChars(): number {
    let count = 0;
    for (const segment of this._segments) if (segment.final) count += segment.text.trim().length;
    return count;
  }

  // MARK: projections

  toRecord(): CallRecord {
    const record: CallRecord = {
      callId: this.callId,
      deviceId: this.deviceId,
      source: this.source,
      callerNumber: this.callerNumber,
      calledNumber: this.calledNumber,
      startedAt: this.startedAt,
      status: this._status,
      alerted: this.alerted,
      updatedAt: this._updatedAt,
    };
    if (this._endedAt !== undefined) record.endedAt = this._endedAt;
    if (this._verdict) record.verdict = this._verdict;
    const level = this.alertLevel;
    if (level) record.alertLevel = level;
    if (this.twilioCallSid) record.twilioCallSid = this.twilioCallSid;
    return record;
  }

  toSummaryJSON(now: number = this.now()): CallSummaryJSON {
    return recordToSummaryJSON(this.toRecord(), now);
  }
}

export function recordToSummaryJSON(record: CallRecord, now: number = Date.now()): CallSummaryJSON {
  const summary: CallSummaryJSON = {
    callID: record.callId,
    source: record.source,
    callerNumber: record.callerNumber,
    calledNumber: record.calledNumber,
    startedAt: record.startedAt,
    status: record.status,
    alerted: record.alerted,
  };
  if (record.endedAt !== undefined) {
    summary.endedAt = record.endedAt;
    summary.durationSeconds = Math.max(0, Math.round((record.endedAt - record.startedAt) / 1000));
  } else if (!ENDED_STATUSES.has(record.status)) {
    summary.durationSeconds = Math.max(0, Math.round((now - record.startedAt) / 1000));
  }
  if (record.verdict) summary.verdict = record.verdict;
  if (record.alertLevel) summary.alertLevel = record.alertLevel;
  return summary;
}

function rank(level: AlertLevel): number {
  return level === "high" ? 3 : level === "medium" ? 2 : 1;
}

/** A verdict as the app should see it: bounded strings, ordered reasons. */
export function normalizeVerdictText(verdict: CallVerdict): CallVerdict {
  return {
    ...verdict,
    summary: truncate(verdict.summary, 500),
    recommendedAction: truncate(verdict.recommendedAction, 200),
    reasons: verdict.reasons.map((reason) => ({ ...reason, detail: truncate(reason.detail, 300) })),
  };
}

// MARK: manager

export interface CallSessionStore {
  upsertCall(record: CallRecord): void;
}

export interface CallSessionManagerEvents {
  created: [session: CallSession];
}

export interface CallSessionManagerOptions {
  store: CallSessionStore;
  /** How long an ended session stays in memory (transcript included); never less than `MIN_RETAIN_ENDED_MS`. */
  retainEndedMs: number;
  now?: () => number;
  onError?: (error: unknown, context: string) => void;
}

/**
 * The floor for `retainEndedMs`: the detector's final model pass may call `setVerdict` up to 10 s after `ended`
 * (scoring/detector.ts `FINAL_PASS_CAP_MS`), and that verdict reaches SQLite only through the listeners eviction
 * removes. `CALLS_RETAIN_ENDED_MINUTES=0` therefore still keeps a session for these seconds.
 */
export const MIN_RETAIN_ENDED_MS = 15_000;

/**
 * Registry of sessions plus persistence. Attaches nothing itself: the detector, the alert dispatcher and the
 * live hub subscribe to `created` (docs/CALLS.md §4) so the Twilio path, the demo runner and the replay script
 * all get the same downstream behaviour by calling `create`.
 */
export class CallSessionManager extends EventEmitter<CallSessionManagerEvents> {
  private readonly sessions = new Map<string, CallSession>();
  private readonly bySid = new Map<string, CallSession>();
  /** Every Twilio SID bound to a session (`create` and `index`), so eviction removes each of them from `bySid`. */
  private readonly sidsByCall = new Map<string, Set<string>>();
  private readonly evictions = new Map<string, NodeJS.Timeout>();
  private readonly store: CallSessionStore;
  private readonly retainEndedMs: number;
  private readonly now: () => number;
  private readonly onError: (error: unknown, context: string) => void;

  constructor(options: CallSessionManagerOptions) {
    super();
    this.store = options.store;
    this.retainEndedMs = options.retainEndedMs;
    this.now = options.now ?? Date.now;
    this.onError = options.onError ?? (() => undefined);
  }

  create(init: CallSessionInit): CallSession {
    const session = new CallSession(init, this.now);
    this.sessions.set(session.callId, session);
    if (session.twilioCallSid) this.bind(session, session.twilioCallSid);
    const persist = (context: string): void => {
      try {
        this.store.upsertCall(session.toRecord());
      } catch (error) {
        this.onError(error, context);
      }
    };
    session.on("status", () => persist("status"));
    session.on("verdict", () => persist("verdict"));
    session.on("alert", () => persist("alert"));
    session.on("ended", () => {
      persist("ended");
      this.scheduleEviction(session);
    });
    persist("created");
    this.emit("created", session);
    return session;
  }

  /** Lets the Twilio path bind a SID assigned after creation (e.g. the user leg). Ignored once the session was evicted. */
  index(session: CallSession, twilioCallSid: string): void {
    if (this.sessions.get(session.callId) !== session) return;
    this.bind(session, twilioCallSid);
  }

  /** Twilio SIDs currently resolvable through `byTwilioSid` (tests). */
  get indexedSidCount(): number {
    return this.bySid.size;
  }

  private bind(session: CallSession, sid: string): void {
    this.bySid.set(sid, session);
    let sids = this.sidsByCall.get(session.callId);
    if (!sids) {
      sids = new Set();
      this.sidsByCall.set(session.callId, sids);
    }
    sids.add(sid);
  }

  get(callId: string): CallSession | undefined {
    return this.sessions.get(callId);
  }

  byTwilioSid(sid: string): CallSession | undefined {
    return this.bySid.get(sid);
  }

  active(): CallSession[] {
    return [...this.sessions.values()].filter((session) => !session.isEnded);
  }

  activeForDevice(deviceId: string): CallSession[] {
    return this.active().filter((session) => session.deviceId === deviceId);
  }

  /** Every retained session (active and recently ended). */
  all(): CallSession[] {
    return [...this.sessions.values()];
  }

  /** Ends every active session (shutdown) and clears eviction timers. */
  close(): void {
    for (const session of this.sessions.values()) {
      if (!session.isEnded) session.end("canceled");
    }
    for (const timer of this.evictions.values()) clearTimeout(timer);
    this.evictions.clear();
  }

  private scheduleEviction(session: CallSession): void {
    const timer = setTimeout(() => this.evict(session), Math.max(this.retainEndedMs, MIN_RETAIN_ENDED_MS));
    timer.unref();
    this.evictions.set(session.callId, timer);
  }

  /** Forgets an ended session: every SID bound to it, then every listener the modules attached. */
  private evict(session: CallSession): void {
    this.evictions.delete(session.callId);
    this.sessions.delete(session.callId);
    const sids = this.sidsByCall.get(session.callId) ?? new Set<string>();
    if (session.twilioCallSid) sids.add(session.twilioCallSid);
    if (session.userCallSid) sids.add(session.userCallSid);
    for (const sid of sids) if (this.bySid.get(sid) === session) this.bySid.delete(sid);
    this.sidsByCall.delete(session.callId);
    session.removeAllListeners();
  }
}

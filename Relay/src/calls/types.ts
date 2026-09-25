/**
 * Call Guard — shared types. This file is the contract in docs/CALLS.md §4; every module under `calls/` and the
 * iOS app's `CallModels.swift` compile against these exact names. Keep JSON projections (`*JSON`) stable.
 */

import type { PushOutcome } from "../apns.js";

export type CallSource = "twilio" | "test-call" | "demo" | "replay";
export const CALL_SOURCES: readonly CallSource[] = ["twilio", "test-call", "demo", "replay"];

export type Speaker = "caller" | "user";

export type CallStatus =
  | "ringing"
  | "connecting"
  | "in_progress"
  | "completed"
  | "failed"
  | "no_answer"
  | "busy"
  | "canceled";
export const CALL_STATUSES: readonly CallStatus[] = [
  "ringing",
  "connecting",
  "in_progress",
  "completed",
  "failed",
  "no_answer",
  "busy",
  "canceled",
];
export const ENDED_STATUSES: ReadonlySet<CallStatus> = new Set<CallStatus>([
  "completed",
  "failed",
  "no_answer",
  "busy",
  "canceled",
]);

/** Ordered like PhishCore.RiskLevel: safe < low < medium < high. */
export type CallRiskLevel = "safe" | "low" | "medium" | "high";
export const CALL_RISK_LEVELS: readonly CallRiskLevel[] = ["safe", "low", "medium", "high"];
export type AlertLevel = Exclude<CallRiskLevel, "safe">;
export const ALERT_LEVELS: readonly AlertLevel[] = ["low", "medium", "high"];

export function riskLevelRank(level: CallRiskLevel): number {
  return CALL_RISK_LEVELS.indexOf(level);
}

/** PhishCore thresholds: ≥0.75 high, ≥0.5 medium, ≥0.3 low, else safe. */
export function riskLevelForConfidence(confidence: number): CallRiskLevel {
  if (confidence >= 0.75) return "high";
  if (confidence >= 0.5) return "medium";
  if (confidence >= 0.3) return "low";
  return "safe";
}

export type CallCategory = "scam" | "phishing" | "spam" | "safe";
export const CALL_CATEGORIES: readonly CallCategory[] = ["scam", "phishing", "spam", "safe"];

export type CallSeverity = "info" | "low" | "medium" | "high";
export const CALL_SEVERITIES: readonly CallSeverity[] = ["info", "low", "medium", "high"];
export function severityRank(severity: CallSeverity): number {
  return CALL_SEVERITIES.indexOf(severity);
}

export type CallReasonSource = "heuristic" | "model";

export interface TranscriptSegment {
  /** Stable per utterance; a partial and its final share the id. */
  id: string;
  speaker: Speaker;
  text: string;
  /** Offset from `CallSession.startedAt`, in ms. */
  atMs: number;
  /** Partials are display-only; the detector consumes finals only. */
  final: boolean;
}

export const MAX_REASON_DETAIL_CHARS = 300;
export const MAX_SUMMARY_CHARS = 500;
export const MAX_RECOMMENDED_ACTION_CHARS = 200;
export const MAX_VERDICT_REASONS = 8;

export interface CallReason {
  id: string;
  title: string;
  /** ≤ 300 characters; quoted transcript evidence is trimmed to that. */
  detail: string;
  severity: CallSeverity;
  source: CallReasonSource;
}

export interface CallVerdict {
  /** Monotonically increasing per session; consumers ignore stale ones. */
  sequence: number;
  category: CallCategory;
  /** 0…1, fused. */
  confidence: number;
  level: CallRiskLevel;
  /** Ordered by severity desc, ≤ 8. */
  reasons: CallReason[];
  /** ≤ 500 chars, user-facing. */
  summary: string;
  /** ≤ 200 chars, imperative, user-facing. */
  recommendedAction: string;
  /** 0…1 from the rules. */
  heuristicScore: number;
  /** 0…100 from the model; absent when the model did not answer. */
  modelRiskScore?: number;
  /** "openai:<model id>"; absent ⇒ rules only. */
  modelIdentifier?: string;
  /** ms since epoch. */
  updatedAt: number;
}

export interface CallAlert {
  sequence: number;
  level: AlertLevel;
  title: string;
  subtitle: string;
  body: string;
  sentAt: number;
  pushed: boolean;
  spoken: boolean;
}

export interface CallLine {
  lineId: string;
  deviceId: string;
  /** The Twilio number, E.164. */
  guardNumber: string;
  /** The protected person's real number, E.164 (plaintext: the relay dials it). */
  phoneNumber: string;
  minimumLevel: AlertLevel;
  spokenWarning: boolean;
  createdAt: number;
  updatedAt: number;
}

/** What SQLite keeps about a call — never a transcript. */
export interface CallRecord {
  callId: string;
  deviceId: string;
  source: CallSource;
  callerNumber: string;
  calledNumber: string;
  startedAt: number;
  endedAt?: number;
  status: CallStatus;
  verdict?: CallVerdict;
  alerted: boolean;
  alertLevel?: AlertLevel;
  twilioCallSid?: string;
  updatedAt: number;
}

// MARK: JSON projections for the app (camelCase; `callID` spelled like the app's `deviceID`).

export interface CallSummaryJSON {
  callID: string;
  source: CallSource;
  callerNumber: string;
  calledNumber: string;
  startedAt: number;
  endedAt?: number;
  durationSeconds?: number;
  status: CallStatus;
  verdict?: CallVerdict;
  alerted: boolean;
  alertLevel?: AlertLevel;
}

export interface CallLineJSON {
  lineID: string;
  guardNumber: string;
  phoneNumber: string;
  minimumLevel: AlertLevel;
  spokenWarning: boolean;
  createdAt: number;
}

export type LiveEvent =
  | { type: "hello"; activeCalls: CallSummaryJSON[]; serverTime: number }
  | { type: "call.started"; call: CallSummaryJSON }
  | { type: "call.status"; callID: string; status: CallStatus }
  | { type: "transcript.segment"; callID: string; segment: TranscriptSegment }
  | { type: "verdict.updated"; callID: string; verdict: CallVerdict }
  | { type: "call.alert"; callID: string; alert: CallAlert }
  | { type: "call.ended"; call: CallSummaryJSON }
  | { type: "pong" };

export type DemoScenarioId = "grandparent" | "irs" | "techSupport" | "bankFraud" | "prize" | "benign";
export const DEMO_SCENARIO_IDS: readonly DemoScenarioId[] = ["grandparent", "irs", "techSupport", "bankFraud", "prize", "benign"];

// MARK: Cross-module interfaces (docs/CALLS.md §4). `CallSession` lives in session.ts; imported as a type to
// avoid a cycle.

import type { CallSession } from "./session.js";

export interface TranscriberHandle {
  /** One Twilio media payload: base64 μ-law 8 kHz mono. */
  pushAudio(base64Mulaw: string): void;
  close(): Promise<void>;
}

export interface Transcriber {
  open(session: CallSession, speaker: Speaker): TranscriberHandle;
}

/** Modules that follow every session (detector, alert dispatcher, live hub) attach on `CallSessionManager` `created`. */
export interface SessionObserver {
  attach(session: CallSession): void;
}

export interface VoiceControl {
  /** Speaks `text` to the protected person only. Resolves true when Twilio accepted the request. */
  speakToUser(session: CallSession, text: string): Promise<boolean>;
  hangUp(session: CallSession): Promise<boolean>;
}

export interface AlertPushRequest {
  deviceId: string;
  apnsToken: string;
  environment: "sandbox" | "production";
  title: string;
  subtitle: string;
  body: string;
  threadId: string;
  category: string;
  interruptionLevel: "active" | "time-sensitive";
  relevanceScore: number;
  collapseId: string;
  expirationSeconds: number;
  contentAvailable: boolean;
  /** Top-level custom keys (`kind`, `callID`, `level`, …). */
  data: Record<string, string | number | boolean>;
}

export interface AlertPushSender {
  sendAlert(request: AlertPushRequest): Promise<PushOutcome>;
}

// MARK: Helpers shared by several modules.

export function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

export function truncate(text: string, max: number): string {
  const trimmed = text.trim();
  if (trimmed.length <= max) return trimmed;
  return `${trimmed.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

/** Phone numbers are logged with the last four digits only. */
export function redactNumber(number: string): string {
  const digits = number.replace(/\D/g, "");
  if (digits.length <= 4) return "…";
  return `…${digits.slice(-4)}`;
}

/** E.164: "+" then 8–15 digits, first digit 1–9. */
export const E164_PATTERN = "^\\+[1-9]\\d{7,14}$";
export function isE164(value: string): boolean {
  return new RegExp(E164_PATTERN).test(value);
}

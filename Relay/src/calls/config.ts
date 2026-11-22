import type { AlertLevel } from "./types.js";
import { ALERT_LEVELS, isE164 } from "./types.js";

/**
 * Call Guard configuration (docs/CALLS.md §9). Read only when `CALLS_ENABLED=true`; every other value is
 * optional with a default. Error messages name variables, never values.
 */

export interface TwilioConfig {
  accountSid: string;
  authToken: string;
  /** The guard number, E.164. */
  number: string;
}

export interface OpenAIConfig {
  apiKey: string;
  transcribeModel: string;
  scoringModel: string;
}

/**
 * AI-voice (synthetic speech) detection on the caller's audio, through Modulate's streaming Deepfake Detection
 * API. Present only when `MODULATE_API_KEY` is set; without it nothing about a call changes.
 */
export interface VoiceDetectionConfig {
  /** `MODULATE_API_KEY`. Travels in the WebSocket URL's query string (Modulate's only scheme): never log the URL. */
  apiKey: string;
  /** `CALLS_AI_VOICE_WINDOW_MS`: how much of the caller's most recent speech a decision is based on. */
  windowMs: number;
  /** `CALLS_AI_VOICE_MIN_SHARE_PERCENT` / 100: the share of that window that must be judged synthetic. */
  minShare: number;
  /** `CALLS_AI_VOICE_MIN_CONFIDENCE_PERCENT` / 100: a synthetic frame counts only at or above this confidence. */
  minConfidence: number;
  /** `CALLS_AI_VOICE_MAX_SECONDS` × 1000: caller audio streamed to the vendor per call at most; 0 = the whole call. */
  maxStreamMs: number;
  /** `CALLS_AI_VOICE_SPOKEN_WARNING`: speak the AI-voice warning into the call (the line's own `spokenWarning` must allow it too). */
  spokenWarning: boolean;
  /** `CALLS_AI_VOICE_WARNING_TEXT`. */
  warningText: string;
}

export interface CallsConfig {
  twilio: TwilioConfig | undefined;
  openai: OpenAIConfig | undefined;
  /** AI-voice detection; `undefined` (no `MODULATE_API_KEY`) leaves Call Guard exactly as it is without it. */
  voice: VoiceDetectionConfig | undefined;
  transcribeTracks: "both" | "caller";
  /** `auto` resolves to `twilio` on a Trial account or without an OpenAI key, else `openai`. */
  transcriptionSource: TranscriptionSource;
  modelMinIntervalMs: number;
  modelTranscriptChars: number;
  defaultMinimumLevel: AlertLevel;
  spokenWarningText: string;
  retainEndedMs: number;
  retentionDays: number;
  demoEnabled: boolean;
  consoleEnabled: boolean;
  /** `CALLS_CONSOLE_KEY`: the operator console's own key; without it the console accepts `RELAY_API_KEY` (docs/CALLS.md §5.3). */
  consoleKey?: string | undefined;
}

export const DEFAULT_SPOKEN_WARNING =
  "This is PhishGuard. This call shows signs of a scam. Do not share codes, card numbers or passwords, " +
  "and do not buy gift cards. It is safe to hang up now.";

/** Spoken to the protected person only, once per call, when the caller's voice is judged AI-generated. */
export const DEFAULT_AI_VOICE_WARNING =
  "This is PhishGuard. The caller's voice appears to be A.I. generated. If they say they are someone you know, " +
  "hang up and call that person back on a number you trust.";

// Starting points, not values Modulate defines (docs.modulate.ai "Screen a call for voice fraud": set the
// threshold against your own labelled audio). 8 kHz telephone audio is outside the vendor's published benchmarks.
export const DEFAULT_AI_VOICE_WINDOW_MS = 6000;
export const DEFAULT_AI_VOICE_MIN_SHARE_PERCENT = 80;
export const DEFAULT_AI_VOICE_MIN_CONFIDENCE_PERCENT = 80;
export const DEFAULT_AI_VOICE_MAX_SECONDS = 180;

// Defaults verified in docs/research/openaiRealtime.md §0 on 2026-09-23; override with the env variables.
// `gpt-live-transcribe` streams deltas but has no server VAD (the relay commits turns on silence it measures);
// `gpt-6-luna` is called with `reasoning_effort: "none"` and a strict JSON schema.
export const DEFAULT_TRANSCRIBE_MODEL = "gpt-live-transcribe";
export const DEFAULT_SCORING_MODEL = "gpt-6-luna";

/** Which service turns call audio into text (docs/CALLS.md §2, §9). */
export type TranscriptionSource = "auto" | "twilio" | "openai";
export const TRANSCRIPTION_SOURCES: readonly TranscriptionSource[] = ["auto", "twilio", "openai"];

export class CallsConfigError extends Error {
  override readonly name = "CallsConfigError";
}

function read(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const raw = env[name];
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}

function readBool(env: NodeJS.ProcessEnv, name: string, fallback: boolean): boolean {
  const raw = read(env, name);
  if (raw === undefined) return fallback;
  const lower = raw.toLowerCase();
  if (["1", "true", "yes", "on"].includes(lower)) return true;
  if (["0", "false", "no", "off"].includes(lower)) return false;
  throw new CallsConfigError(`${name} must be true or false`);
}

function readInteger(env: NodeJS.ProcessEnv, name: string, fallback: number, min: number, max: number): number {
  const raw = read(env, name);
  if (raw === undefined) return fallback;
  if (!/^\d+$/.test(raw)) throw new CallsConfigError(`${name} must be an integer`);
  const value = Number.parseInt(raw, 10);
  if (value < min || value > max) throw new CallsConfigError(`${name} must be between ${min} and ${max}`);
  return value;
}

/** True when the operator asked for Call Guard at all. */
export function isCallsEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return readBool(env, "CALLS_ENABLED", false);
}

/**
 * Parses the Call Guard section. Twilio and OpenAI are each optional as a *pair*: the module can run demo calls
 * with neither, forward calls without OpenAI (no analysis), and analyse demo transcripts without Twilio.
 */
export function loadCallsConfig(env: NodeJS.ProcessEnv = process.env): CallsConfig {
  const accountSid = read(env, "TWILIO_ACCOUNT_SID");
  const authToken = read(env, "TWILIO_AUTH_TOKEN");
  const number = read(env, "TWILIO_NUMBER");
  let twilio: TwilioConfig | undefined;
  if (accountSid || authToken || number) {
    if (!accountSid || !authToken || !number) {
      throw new CallsConfigError("Set all of TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_NUMBER, or none");
    }
    if (!/^AC[0-9a-fA-F]{32}$/.test(accountSid)) throw new CallsConfigError("TWILIO_ACCOUNT_SID does not look like an account SID");
    if (!isE164(number)) throw new CallsConfigError("TWILIO_NUMBER must be an E.164 number (+15551234567)");
    twilio = { accountSid, authToken, number };
  }

  const apiKey = read(env, "OPENAI_API_KEY");
  const openai: OpenAIConfig | undefined = apiKey
    ? {
        apiKey,
        transcribeModel: read(env, "OPENAI_TRANSCRIBE_MODEL") ?? DEFAULT_TRANSCRIBE_MODEL,
        scoringModel: read(env, "OPENAI_SCORING_MODEL") ?? DEFAULT_SCORING_MODEL,
      }
    : undefined;

  const modulateKey = read(env, "MODULATE_API_KEY");
  const voice: VoiceDetectionConfig | undefined = modulateKey
    ? {
        apiKey: modulateKey,
        windowMs: readInteger(env, "CALLS_AI_VOICE_WINDOW_MS", DEFAULT_AI_VOICE_WINDOW_MS, 2500, 60_000),
        minShare: readInteger(env, "CALLS_AI_VOICE_MIN_SHARE_PERCENT", DEFAULT_AI_VOICE_MIN_SHARE_PERCENT, 50, 100) / 100,
        minConfidence: readInteger(env, "CALLS_AI_VOICE_MIN_CONFIDENCE_PERCENT", DEFAULT_AI_VOICE_MIN_CONFIDENCE_PERCENT, 50, 100) / 100,
        maxStreamMs: readInteger(env, "CALLS_AI_VOICE_MAX_SECONDS", DEFAULT_AI_VOICE_MAX_SECONDS, 0, 4 * 60 * 60) * 1000,
        spokenWarning: readBool(env, "CALLS_AI_VOICE_SPOKEN_WARNING", true),
        warningText: read(env, "CALLS_AI_VOICE_WARNING_TEXT") ?? DEFAULT_AI_VOICE_WARNING,
      }
    : undefined;

  const tracksRaw = read(env, "CALLS_TRANSCRIBE_TRACKS") ?? "both";
  if (tracksRaw !== "both" && tracksRaw !== "caller") throw new CallsConfigError("CALLS_TRANSCRIBE_TRACKS must be both or caller");

  const sourceRaw = read(env, "CALLS_TRANSCRIPTION_SOURCE") ?? "auto";
  if (!(TRANSCRIPTION_SOURCES as readonly string[]).includes(sourceRaw)) {
    throw new CallsConfigError(`CALLS_TRANSCRIPTION_SOURCE must be one of ${TRANSCRIPTION_SOURCES.join(", ")}`);
  }
  if (sourceRaw === "openai" && !openai) throw new CallsConfigError("CALLS_TRANSCRIPTION_SOURCE=openai needs OPENAI_API_KEY");

  const consoleKey = read(env, "CALLS_CONSOLE_KEY");
  if (consoleKey !== undefined && consoleKey.length < 16) throw new CallsConfigError("CALLS_CONSOLE_KEY must be at least 16 characters");

  const levelRaw = read(env, "CALLS_ALERT_MIN_LEVEL") ?? "medium";
  if (!(ALERT_LEVELS as readonly string[]).includes(levelRaw)) {
    throw new CallsConfigError(`CALLS_ALERT_MIN_LEVEL must be one of ${ALERT_LEVELS.join(", ")}`);
  }

  return {
    twilio,
    openai,
    voice,
    transcribeTracks: tracksRaw,
    transcriptionSource: sourceRaw as TranscriptionSource,
    modelMinIntervalMs: readInteger(env, "CALLS_MODEL_MIN_INTERVAL_MS", 3000, 250, 60_000),
    modelTranscriptChars: readInteger(env, "CALLS_MODEL_TRANSCRIPT_CHARS", 6000, 500, 50_000),
    defaultMinimumLevel: levelRaw as AlertLevel,
    spokenWarningText: read(env, "CALLS_SPOKEN_WARNING_TEXT") ?? DEFAULT_SPOKEN_WARNING,
    retainEndedMs: readInteger(env, "CALLS_RETAIN_ENDED_MINUTES", 30, 0, 24 * 60) * 60 * 1000,
    retentionDays: readInteger(env, "CALLS_RETENTION_DAYS", 30, 1, 3650),
    demoEnabled: readBool(env, "CALLS_DEMO_ENABLED", true),
    consoleEnabled: readBool(env, "CALLS_CONSOLE_ENABLED", true),
    consoleKey,
  };
}

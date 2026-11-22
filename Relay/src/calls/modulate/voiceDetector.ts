import type { FastifyBaseLogger } from "fastify";
import { WebSocket } from "ws";

import { MULAW_SAMPLE_RATE } from "../audio.js";
import type { VoiceDetectionConfig } from "../config.js";
import type { CallSession } from "../session.js";
import type { CallVoiceUpdate, VoiceDetector, VoiceDetectorHandle } from "../types.js";

/**
 * Modulate streaming Deepfake Detection (docs.modulate.ai "Deepfake Detection Streaming", AsyncAPI
 * `velma_2_synthetic_voice_detection_streaming`): one WebSocket per call, for the CALLER's track only. Twilio's
 * payloads are already what the vendor's "Telephony (mu-law)" row asks for (`mulaw` / 8000 / 1), so nothing is
 * transcoded: each payload is base64-decoded and sent as binary frames (coalesced to ~200 ms; the vendor accepts
 * any size). End of stream is an EMPTY TEXT frame; the vendor then flushes, sends `done` and closes.
 *
 * The vendor answers with `frame` messages (a verdict and the confidence in THAT verdict for a stretch of audio);
 * `VoiceFrameAggregator` turns them into the call's assessment, reported through `session.setVoice(...)`. A
 * synthetic voice is not a scam verdict: nothing here touches `CallVerdict`.
 *
 * THE API KEY TRAVELS IN THE URL (the vendor's only scheme for WebSockets). The URL is never logged, a socket's
 * Error object is never logged (it can carry the request URL), and every string that does reach the log — the
 * vendor's `error` text, close reasons, error messages — goes through `scrubModulateSecrets` first.
 *
 * Resilience: audio that arrives before the socket is open is buffered (10 s, oldest dropped); retryable closes
 * (4030 concurrency cap, 1013 capacity, 1011, abnormal drops, failed handshakes) reconnect with jittered backoff
 * for a bounded number of consecutive attempts; every other documented code ends detection for the call as
 * `unavailable`, and the account-level ones (bad key, no access, credits, monthly limit) pause the whole detector
 * for a few minutes so a dead key costs one handshake, not one per call.
 *
 * Every external side effect is injectable: the socket factory (default `new WebSocket(url)` from `ws`), the
 * clock, the jitter source and every timing constant.
 */

export const MODULATE_VOICE_STREAMING_URL = "wss://platform.modulate.ai/api/velma-2-synthetic-voice-detection-streaming";
export const MODULATE_VOICE_PROVIDER = "modulate:velma-2-synthetic-voice-detection-streaming";
/** The vendor's "Telephony (mu-law)" raw configuration — exactly what Twilio Media Streams carries. */
export const MODULATE_AUDIO_FORMAT = "mulaw";
export const MODULATE_NUM_CHANNELS = 1;
/** 8 kHz μ-law: one byte per sample. */
export const MULAW_BYTES_PER_MS = MULAW_SAMPLE_RATE / 1000;
/** Twilio's 20 ms payloads are sent to the vendor in binary frames of about this much audio. */
export const DEFAULT_COALESCE_MS = 200;
/** Audio kept while the socket is connecting or reconnecting; the oldest is dropped beyond this. */
export const DEFAULT_PENDING_BUFFER_MS = 10_000;
export const DEFAULT_RECONNECT_INITIAL_MS = 500;
export const DEFAULT_RECONNECT_MAX_MS = 8_000;
/**
 * Consecutive reconnects that never deliver a frame before a call gives up (`unavailable`). The vendor accepts
 * the upgrade and then closes with its code (4030, 1013, …), so an `open` proves nothing: only a `frame` resets
 * the count. Five attempts span about 15 s of backoff.
 */
export const DEFAULT_MAX_RECONNECT_ATTEMPTS = 5;
/**
 * Reconnects after a `busy` close (each at the longest backoff) before the call gives up: about three minutes of
 * waiting for one of the account's concurrent streams to end.
 */
export const DEFAULT_MAX_BUSY_ATTEMPTS = 20;
/**
 * Audio queued inside the socket (accepted by `send` but not yet written to the network) beyond which the
 * connection is treated as stalled and replaced: 30 s of μ-law. Bounds memory whatever the per-call cap is.
 */
export const DEFAULT_STALL_BUFFER_MS = 30_000;
/** How long `close()` waits for the vendor's `done` after the end-of-stream frame. */
export const DEFAULT_CLOSE_GRACE_MS = 1_500;
/** How long new calls skip the vendor after an account-level refusal (bad key, no access, credits, monthly limit). */
export const DEFAULT_COOL_DOWN_MS = 5 * 60 * 1000;
/** `ws` handshake timeout for the default socket factory. */
export const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;

// MARK: close codes (docs.modulate.ai: streaming reference "WebSocket close codes", troubleshooting for 1013)

/**
 * What a close the relay did not ask for means for the call: `finished` — the stream is over; `account` — refused
 * for the whole account, not retried and the detector cools down; `call` — refused for this stream, not retried;
 * `busy` — the vendor has no room right now (the account's concurrency cap, or the service at capacity): retried
 * at the longest backoff for much longer than a broken connection is, because a slot frees when another call's
 * stream ends; `retry` — transient, reconnect with backoff. Codes the vendor does not document (1006 and friends)
 * are `retry`.
 */
export type CloseCodePolicy = "finished" | "account" | "call" | "busy" | "retry";

export const MODULATE_CLOSE_CODES: Readonly<Record<number, { policy: CloseCodePolicy; meaning: string }>> = {
  1000: { policy: "finished", meaning: "normal closure after the done message" },
  1003: { policy: "call", meaning: "invalid query parameters (audio_format, sample_rate or num_channels)" },
  1011: { policy: "retry", meaning: "internal server error" },
  1013: { policy: "busy", meaning: "service temporarily at capacity" },
  4001: { policy: "account", meaning: "the api_key query parameter is missing or invalid" },
  4002: { policy: "call", meaning: "audio could not be decoded or does not match the declared format" },
  4003: { policy: "account", meaning: "the request is not permitted" },
  4004: { policy: "account", meaning: "the API key does not have access to this model" },
  4029: { policy: "account", meaning: "insufficient credits" },
  4030: { policy: "busy", meaning: "concurrent request limit reached" },
  4031: { policy: "account", meaning: "monthly usage limit reached" },
};

export function closeCodePolicy(code: number): CloseCodePolicy {
  return MODULATE_CLOSE_CODES[code]?.policy ?? "retry";
}

/**
 * A refusal at the HTTP upgrade, before any WebSocket exists. The vendor's pages describe refusals as close codes
 * on an accepted socket, and one of them hints at a rejected handshake instead; a gateway in front of the service
 * can also answer the upgrade itself. `ws` reports those as an error "Unexpected server response: <status>"
 * followed by close 1006. Plain HTTP semantics decide: a credential or permission status is the account's problem
 * (no retry, cool-down), a malformed or unknown request will not get better by retrying, 429 means "not now", and
 * everything else (5xx, timeouts) is transient.
 */
export function handshakeStatusPolicy(status: number): CloseCodePolicy {
  if (status === 401 || status === 402 || status === 403) return "account";
  if (status === 429) return "busy";
  if (status >= 400 && status < 500) return "call";
  return "retry";
}

const HANDSHAKE_STATUS = /^Unexpected server response: (\d{3})$/;

/** The HTTP status in a `ws` handshake-refusal message, if that is what the message is. */
export function handshakeStatusOf(message: string): number | undefined {
  const match = HANDSHAKE_STATUS.exec(message.trim());
  return match ? Number(match[1]) : undefined;
}

// MARK: secrets

/**
 * Removes the API key (as given and URL-encoded) and any `api_key=…` query value from a string bound for the log,
 * and caps it at 200 characters. `undefined` for anything that is not a string.
 */
export function scrubModulateSecrets(text: unknown, apiKey: string): string | undefined {
  if (typeof text !== "string") return undefined;
  let out = text;
  for (const secret of new Set([apiKey, encodeURIComponent(apiKey), new URLSearchParams({ k: apiKey }).toString().slice(2)])) {
    if (secret.length > 0) out = out.split(secret).join("[redacted]");
  }
  return out.replace(/api_key=[^&\s"'#]*/gi, "api_key=[redacted]").slice(0, 200);
}

/** The documented connection URL: `api_key`, `audio_format=mulaw`, `sample_rate=8000`, `num_channels=1`. Never log it. */
export function buildVoiceStreamUrl(base: string, apiKey: string): string {
  const url = new URL(base);
  url.searchParams.set("api_key", apiKey);
  url.searchParams.set("audio_format", MODULATE_AUDIO_FORMAT);
  url.searchParams.set("sample_rate", String(MULAW_SAMPLE_RATE));
  url.searchParams.set("num_channels", String(MODULATE_NUM_CHANNELS));
  return url.toString();
}

// MARK: server messages

export type VoiceFrameVerdict = "synthetic" | "non-synthetic" | "no-content";
const FRAME_VERDICTS: readonly string[] = ["synthetic", "non-synthetic", "no-content"];

/** One `frame` message: a verdict for `startMs…endMs` of the stream and the vendor's confidence in that verdict. */
export interface VoiceFrame {
  startMs: number;
  endMs: number;
  verdict: VoiceFrameVerdict;
  /** 0…1, confidence in the STATED verdict — not the probability that the audio is synthetic. */
  confidence: number;
}

export type VoiceServerMessage =
  | { type: "frame"; frame: VoiceFrame }
  | { type: "done"; durationMs: number | undefined; frameCount: number | undefined }
  | { type: "error"; error: string };

/** Lenient parse of one server message; `undefined` for non-JSON, an unknown `type` or a frame missing a field. */
export function parseVoiceMessage(raw: unknown): VoiceServerMessage | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawToString(raw));
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null) return undefined;
  const message = parsed as Record<string, unknown>;
  switch (message["type"]) {
    case "frame": {
      const frame = message["frame"];
      if (typeof frame !== "object" || frame === null) return undefined;
      const fields = frame as Record<string, unknown>;
      const startMs = fields["start_time_ms"];
      const endMs = fields["end_time_ms"];
      const verdict = fields["verdict"];
      const confidence = fields["confidence"];
      if (typeof startMs !== "number" || !Number.isFinite(startMs) || startMs < 0) return undefined;
      if (typeof endMs !== "number" || !Number.isFinite(endMs) || endMs < 0) return undefined;
      if (typeof verdict !== "string" || !FRAME_VERDICTS.includes(verdict)) return undefined;
      if (typeof confidence !== "number" || !Number.isFinite(confidence)) return undefined;
      return {
        type: "frame",
        frame: { startMs, endMs, verdict: verdict as VoiceFrameVerdict, confidence: Math.min(1, Math.max(0, confidence)) },
      };
    }
    case "done":
      return { type: "done", durationMs: finiteNumber(message["duration_ms"]), frameCount: finiteNumber(message["frame_count"]) };
    case "error":
      return { type: "error", error: typeof message["error"] === "string" ? message["error"] : "" };
    default:
      return undefined;
  }
}

function finiteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function rawToString(data: unknown): string {
  if (typeof data === "string") return data;
  if (Buffer.isBuffer(data)) return data.toString("utf8");
  if (Array.isArray(data)) return Buffer.concat(data.map((part) => (Buffer.isBuffer(part) ? part : Buffer.from(part as ArrayBuffer)))).toString("utf8");
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  return String(data);
}

// MARK: frame aggregation

export type VoiceAggregatorConfig = Pick<VoiceDetectionConfig, "windowMs" | "minShare" | "minConfidence">;

/** What the frames so far add up to. The handle adds `unavailable` / `inconclusive` itself. */
export interface VoiceAggregate {
  /** `analyzing` also covers "enough speech, but the recent evidence is mixed" — the check simply goes on. */
  status: "analyzing" | "human" | "synthetic";
  /** Synthetic speech time / all speech time, over the whole call (every `synthetic` frame, whatever its confidence). */
  syntheticShare: number;
  /** Weight-averaged vendor confidence of the frames behind `status` in the decision window; 0 while `analyzing`. */
  confidence: number;
  speechMs: number;
}

interface WindowSegment {
  weightMs: number;
  verdict: "synthetic" | "non-synthetic";
  confidence: number;
}

/** Absorbs floating-point noise in `minShare × windowMs` (weights are whole milliseconds). */
const SHARE_EPSILON_MS = 1e-6;
/** The share of the decision window that must be `non-synthetic` before a voice is reported as human. */
export const HUMAN_MIN_SHARE = 0.5;

/**
 * Turns the vendor's frames into one assessment without assuming a frame geometry — the vendor's pages describe
 * three (4 s frames end to end; a window that grows from zero and then slides, one prediction per second; 192 ms
 * frames). Measured against the live endpoint with μ-law 8 kHz on 2026-11-16: it is the second — 0–500, 0–1500,
 * 0–2500, 0–3500, then 500–4500, 1500–5500, … one reading a second — and a window is `no-content` once its
 * newest part is silent (and for utterances of about two seconds or less), so pauses are not counted as speech.
 * In the same runs the first two readings of one real human voice were `synthetic` at 97 % and 93 %: early
 * readings on telephone audio are not reliable on their own, which is what the window, the share and the
 * two-reading rule are for. Each frame counts as the verdict for the audio it ADDS beyond what earlier frames of the same
 * connection covered: `end − max(start, highest end so far)` milliseconds, ignored when that is not positive.
 * `no-content` frames (silence, classified before inference, always confidence 1.0) advance that mark and are
 * otherwise left out, as the vendor says to do when aggregating.
 *
 * The decision looks at the most recent `windowMs` of SPEECH ("speech" here is analysed stream time that was not
 * `no-content`; with overlapping analysis windows that is not the same as time spent talking). `analyzing` until
 * the call has that much. Then `synthetic` when the window's share of `synthetic` frames at or above
 * `minConfidence` reaches `minShare` AND at least two separate vendor frames back it — one frame, however long
 * and however confident, never decides a call. `human` when `non-synthetic` frames make up at least half of the
 * window (the vendor's own starting point for an overall verdict). Anything in between — mostly `synthetic` but
 * below the confidence bar, or an even mix — stays `analyzing`: the relay does not call a voice human that the
 * vendor did not. `synthetic` is latched for the rest of the call.
 */
export class VoiceFrameAggregator {
  private highWaterMs = 0;
  private speechMs = 0;
  private syntheticMs = 0;
  /** The newest speech, oldest first; trimmed so that dropping the first segment would leave less than `windowMs`. */
  private readonly window: WindowSegment[] = [];
  private windowTotalMs = 0;
  private latched = false;
  private latchedConfidence = 0;
  /** Whether the speech frame before the current one was `synthetic` at or above `minConfidence`. */
  private previousStrong = false;

  constructor(private readonly config: VoiceAggregatorConfig) {}

  /** A new vendor connection counts its timestamps from zero again; the speech already counted stays. */
  resetConnection(): void {
    this.highWaterMs = 0;
  }

  /** Takes one frame; true when it added speech (the assessment may have changed). */
  add(frame: VoiceFrame): boolean {
    const weightMs = frame.endMs - Math.max(frame.startMs, this.highWaterMs);
    if (!(weightMs > 0)) return false;
    this.highWaterMs = frame.endMs;
    if (frame.verdict === "no-content") return false;

    this.speechMs += weightMs;
    if (frame.verdict === "synthetic") this.syntheticMs += weightMs;
    this.window.push({ weightMs, verdict: frame.verdict, confidence: frame.confidence });
    this.windowTotalMs += weightMs;
    while (this.window.length > 1 && this.windowTotalMs - this.window[0]!.weightMs >= this.config.windowMs) {
      this.windowTotalMs -= this.window.shift()!.weightMs;
    }

    const strong = frame.verdict === "synthetic" && frame.confidence >= this.config.minConfidence;
    if (this.speechMs >= this.config.windowMs) {
      const stats = this.windowStats();
      // Two frames: both inside the window, or (a frame as long as the window) this one and the one before it.
      const twoFrames = stats.strongFrames >= 2 || (strong && this.previousStrong);
      if (twoFrames && stats.strongMs + SHARE_EPSILON_MS >= this.config.minShare * this.config.windowMs) {
        this.latched = true;
        this.latchedConfidence = stats.strongMs > 0 ? stats.strongConfidenceMs / stats.strongMs : 0;
      }
    }
    this.previousStrong = strong;
    return true;
  }

  assessment(): VoiceAggregate {
    const syntheticShare = this.speechMs > 0 ? this.syntheticMs / this.speechMs : 0;
    const base = { syntheticShare, speechMs: this.speechMs };
    // Latched: the confidence is that of the last window that met the criterion, not of whatever came after it.
    if (this.latched) return { status: "synthetic", confidence: this.latchedConfidence, ...base };
    if (this.speechMs < this.config.windowMs) return { status: "analyzing", confidence: 0, ...base };
    const stats = this.windowStats();
    if (stats.humanMs + SHARE_EPSILON_MS < HUMAN_MIN_SHARE * this.config.windowMs) return { status: "analyzing", confidence: 0, ...base };
    return { status: "human", confidence: stats.humanConfidenceMs / stats.humanMs, ...base };
  }

  /** Sums over exactly the last `windowMs` of speech: the oldest segment kept may count only in part. */
  private windowStats(): { strongMs: number; strongConfidenceMs: number; strongFrames: number; humanMs: number; humanConfidenceMs: number } {
    let excessMs = Math.max(0, this.windowTotalMs - this.config.windowMs);
    const stats = { strongMs: 0, strongConfidenceMs: 0, strongFrames: 0, humanMs: 0, humanConfidenceMs: 0 };
    for (const segment of this.window) {
      const cutMs = Math.min(excessMs, segment.weightMs);
      excessMs -= cutMs;
      const weightMs = segment.weightMs - cutMs;
      if (weightMs <= 0) continue;
      if (segment.verdict === "non-synthetic") {
        stats.humanMs += weightMs;
        stats.humanConfidenceMs += weightMs * segment.confidence;
      } else if (segment.confidence >= this.config.minConfidence) {
        stats.strongMs += weightMs;
        stats.strongConfidenceMs += weightMs * segment.confidence;
        stats.strongFrames += 1;
      }
      // A `synthetic` frame below `minConfidence` supports neither status.
    }
    return stats;
  }
}

// MARK: socket and options

/** The subset of `ws.WebSocket` the detector uses; tests substitute a fake. */
export interface VoiceSocket {
  on(event: "open", listener: () => void): unknown;
  on(event: "message", listener: (data: unknown, isBinary?: boolean) => void): unknown;
  on(event: "close", listener: (code: number, reason?: unknown) => void): unknown;
  on(event: "error", listener: (error: Error) => void): unknown;
  /** A `Uint8Array` goes out as a binary frame, a string as a text frame (`ws` picks by type). */
  send(data: string | Uint8Array): void;
  close(code?: number, reason?: string): void;
  /** Destroys the socket without a close handshake (`ws` has it; fakes may not). */
  terminate?(): void;
  /** Bytes accepted by `send` and not yet written to the network (`ws` has it; fakes may not). */
  readonly bufferedAmount?: number;
}

/** The URL carries the API key: a factory must not log it. No header carries a credential. */
export type VoiceSocketFactory = (url: string) => VoiceSocket;

/** Diagnostics for the smoke-test script and tests; the relay itself passes none. */
export interface VoiceDetectorObserver {
  /** A connection opened (the first one or a reconnect). */
  opened?(callId: string): void;
  frame?(callId: string, frame: VoiceFrame): void;
  done?(callId: string, summary: { durationMs: number | undefined; frameCount: number | undefined }): void;
  /** A close the relay did not ask for. `detail` is already scrubbed. */
  closed?(callId: string, close: { code: number; policy: CloseCodePolicy; detail: string | undefined }): void;
}

export interface VoiceDetectorOptions {
  config: VoiceDetectionConfig;
  logger: FastifyBaseLogger;
  now?: () => number;
  socketFactory?: VoiceSocketFactory;
  /** The endpoint without its query string (default `MODULATE_VOICE_STREAMING_URL`). */
  url?: string;
  /** Jitter source for the reconnect backoff (default `Math.random`). */
  random?: () => number;
  coalesceMs?: number;
  pendingBufferMs?: number;
  reconnectInitialMs?: number;
  reconnectMaxMs?: number;
  /** Consecutive reconnects without a frame after which the call gives up (`DEFAULT_MAX_RECONNECT_ATTEMPTS`). */
  maxReconnectAttempts?: number;
  /** Reconnects after a `busy` close before the call gives up (`DEFAULT_MAX_BUSY_ATTEMPTS`). */
  maxBusyAttempts?: number;
  /** Audio queued inside the socket beyond which it counts as stalled (`DEFAULT_STALL_BUFFER_MS`). */
  stallBufferMs?: number;
  closeGraceMs?: number;
  coolDownMs?: number;
  observer?: VoiceDetectorObserver;
}

type ResolvedOptions = Required<Omit<VoiceDetectorOptions, "logger" | "url" | "observer">> & { observer: VoiceDetectorObserver | undefined };

/** What a handle needs from the detector that opened it. */
interface HandleOwner {
  /** The full connection URL, key included. */
  readonly url: string;
  scrub(text: unknown): string | undefined;
  coolingDown(): boolean;
  /** An account-level refusal: starts the cool-down (and logs it) unless one is already running. */
  coolDown(code: number, meaning: string | undefined): void;
  forget(handle: ModulateVoiceHandle): void;
}

// MARK: pending audio

/** μ-law waiting to be sent: the coalescing buffer while connected, a bounded backlog while not. */
class PendingAudio {
  private chunks: Buffer[] = [];
  private bytes = 0;
  constructor(private readonly capacity: number) {}

  get length(): number {
    return this.bytes;
  }

  /** Appends a chunk and returns how many of the OLDEST bytes were dropped to stay within the capacity. */
  push(chunk: Buffer): number {
    this.chunks.push(chunk);
    this.bytes += chunk.length;
    let dropped = 0;
    while (this.bytes > this.capacity && this.chunks.length > 1) {
      const oldest = this.chunks.shift()!;
      this.bytes -= oldest.length;
      dropped += oldest.length;
    }
    return dropped;
  }

  take(): Buffer | undefined {
    if (this.bytes === 0) return undefined;
    const all = this.chunks.length === 1 ? this.chunks[0]! : Buffer.concat(this.chunks);
    this.clear();
    return all;
  }

  clear(): void {
    this.chunks = [];
    this.bytes = 0;
  }
}

// MARK: the handle

interface Connection {
  socket: VoiceSocket;
  ready: boolean;
  closedByUs: boolean;
  frames: number;
  /** The vendor's `error` text (scrubbed): it precedes every close other than 1000. */
  serverError: string | undefined;
  /** The socket's own error message (scrubbed), e.g. a refused handshake. */
  socketError: string | undefined;
  /** The HTTP status of an upgrade the server refused, when that is how the connection failed. */
  handshakeStatus: number | undefined;
  /** Set while the handle waits for `done` after the end-of-stream frame; ends that wait. */
  settle: (() => void) | undefined;
}

/**
 * Why a handle stopped: `closed` — `close()` (the call or its media stream ended); `latched` — judged synthetic;
 * `cap` — `maxStreamMs` of audio was sent; `finished` — the vendor closed with 1000 on its own; `unavailable` —
 * a non-retryable close code, the cool-down, or the retry budget ran out; `shutdown` — the detector was closed.
 */
type EndReason = "closed" | "latched" | "cap" | "finished" | "unavailable" | "shutdown";

class ModulateVoiceHandle implements VoiceDetectorHandle {
  private readonly log: FastifyBaseLogger;
  private readonly aggregator: VoiceFrameAggregator;
  private readonly pending: PendingAudio;
  private readonly coalesceBytes: number;
  /** `maxStreamMs` in bytes; 0 = no cap. */
  private readonly maxBytes: number;
  private readonly stallBytes: number;
  private conn: Connection | undefined;
  /** False once the stream was ended for good; audio pushed after that is ignored. */
  private accepting = true;
  private ending: Promise<void> | undefined;
  private finalized = false;
  private resolveFinished!: () => void;
  /** Resolves when the stream was ended for good and its last frames were taken (see `VoiceDetectorHandle`). */
  readonly finished = new Promise<void>((resolve) => {
    this.resolveFinished = resolve;
  });
  private failedAttempts = 0;
  private busyAttempts = 0;
  private reconnectTimer: NodeJS.Timeout | undefined;
  private connections = 0;
  private frames = 0;
  private ignoredMessages = 0;
  private sentBytes = 0;
  private droppedBytes = 0;

  constructor(
    private readonly session: CallSession,
    private readonly options: ResolvedOptions,
    private readonly owner: HandleOwner,
    logger: FastifyBaseLogger,
  ) {
    this.log = logger.child({ callId: session.callId });
    this.aggregator = new VoiceFrameAggregator(options.config);
    this.pending = new PendingAudio(Math.max(1, options.pendingBufferMs) * MULAW_BYTES_PER_MS);
    this.coalesceBytes = Math.max(1, options.coalesceMs) * MULAW_BYTES_PER_MS;
    this.maxBytes = Math.max(0, options.config.maxStreamMs) * MULAW_BYTES_PER_MS;
    this.stallBytes = Math.max(1, options.stallBufferMs) * MULAW_BYTES_PER_MS;
    session.once("ended", () => {
      void this.close();
    });
    // The app shows "analysing" from the first moment of the call, not from the vendor's first frame.
    this.report();
    this.connect();
  }

  /** True once the handle stopped for good (it may do so inside its own constructor). */
  get isFinished(): boolean {
    return this.finalized;
  }

  // MARK: VoiceDetectorHandle

  pushAudio(base64Mulaw: string): void {
    if (!this.accepting) return;
    const bytes = Buffer.from(base64Mulaw, "base64");
    if (bytes.length === 0) return;
    this.droppedBytes += this.pending.push(bytes);
    const conn = this.conn;
    if (!conn?.ready) return;
    const reachesCap = this.maxBytes > 0 && this.sentBytes + this.pending.length >= this.maxBytes;
    if (this.pending.length >= this.coalesceBytes || reachesCap) this.flush(conn);
    this.endAtCap();
  }

  /** Flushes what is pending, signals end of stream, waits briefly for `done`, then closes. Never rejects. */
  close(): Promise<void> {
    return this.end("closed");
  }

  /** Shutdown: no end-of-stream, no wait — the socket is destroyed now. */
  destroy(): void {
    this.accepting = false;
    this.clearReconnect();
    this.pending.clear();
    const conn = this.conn;
    this.conn = undefined;
    if (conn) {
      conn.closedByUs = true;
      conn.ready = false;
      try {
        if (conn.socket.terminate) conn.socket.terminate();
        else conn.socket.close(1001, "shutdown");
      } catch {
        // already gone
      }
      conn.settle?.();
    }
    this.ending ??= Promise.resolve();
    this.finalize("shutdown");
  }

  // MARK: audio

  /** Sends everything pending as one binary frame, never beyond the `maxStreamMs` cap. */
  private flush(conn: Connection): void {
    if ((conn.socket.bufferedAmount ?? 0) > this.stallBytes) {
      this.replaceStalled(conn);
      return;
    }
    let data = this.pending.take();
    if (!data) return;
    if (this.maxBytes > 0 && this.sentBytes + data.length > this.maxBytes) data = data.subarray(0, this.maxBytes - this.sentBytes);
    if (data.length === 0) return;
    try {
      conn.socket.send(data);
      this.sentBytes += data.length;
    } catch (error) {
      this.log.warn({ error: this.owner.scrub(messageOf(error)) }, "calls: voice detector send failed");
    }
  }

  /**
   * The socket accepts audio but is not delivering it: nothing is being analysed and the queue would only grow.
   * The connection is destroyed and the usual retry path opens another; what is pending stays for it.
   */
  private replaceStalled(conn: Connection): void {
    if (this.conn !== conn || !this.accepting) return;
    this.log.warn(
      { queuedMs: Math.round((conn.socket.bufferedAmount ?? 0) / MULAW_BYTES_PER_MS), frames: conn.frames },
      "calls: voice detector socket stalled; reconnecting",
    );
    conn.closedByUs = true;
    conn.ready = false;
    this.conn = undefined;
    try {
      if (conn.socket.terminate) conn.socket.terminate();
      else conn.socket.close(1001, "stalled");
    } catch {
      // already gone
    }
    this.scheduleReconnect("retry");
  }

  private endAtCap(): void {
    if (this.accepting && this.maxBytes > 0 && this.sentBytes >= this.maxBytes) {
      this.log.info({ sentMs: this.sentMs() }, "calls: voice detector reached its per-call audio cap");
      void this.end("cap");
    }
  }

  private sentMs(): number {
    return Math.round(this.sentBytes / MULAW_BYTES_PER_MS);
  }

  // MARK: ending

  /** Stops the stream for good. Idempotent: the first reason wins and every caller gets the same promise. */
  private end(reason: EndReason): Promise<void> {
    if (this.ending) return this.ending;
    this.accepting = false;
    this.clearReconnect();
    const conn = this.conn;
    if (!conn?.ready) {
      // Nothing is streaming: there is no end-of-stream to send and no `done` to wait for. Audio still waiting
      // for a socket is dropped — whoever ended the stream has no use for a verdict on it any more.
      this.pending.clear();
      this.conn = undefined;
      if (conn) this.closeConnection(conn);
      this.ending = Promise.resolve();
      this.finalize(reason);
      return this.ending;
    }
    // Once the voice is judged synthetic the rest of the audio adds nothing; otherwise the tail is part of the call.
    if (reason === "latched") this.pending.clear();
    else this.flush(conn);
    this.ending = this.endOfStream(conn).then(() => {
      this.closeConnection(conn);
      if (this.conn === conn) this.conn = undefined;
      this.finalize(reason);
    });
    return this.ending;
  }

  /** Sends the empty TEXT frame and resolves on `done`, on the socket's close, or after `closeGraceMs`. */
  private endOfStream(conn: Connection): Promise<void> {
    return new Promise((resolve) => {
      const finish = (): void => {
        clearTimeout(timer);
        conn.settle = undefined;
        resolve();
      };
      const timer = setTimeout(finish, this.options.closeGraceMs);
      timer.unref();
      conn.settle = finish;
      try {
        conn.socket.send("");
      } catch {
        finish();
      }
    });
  }

  private finalize(reason: EndReason): void {
    if (this.finalized) return;
    this.finalized = true;
    this.resolveFinished();
    this.owner.forget(this);
    const status = this.aggregator.assessment().status;
    if (reason === "unavailable") {
      if (status !== "synthetic") this.report("unavailable");
    } else if ((reason === "cap" || reason === "finished") && status === "analyzing") {
      // Analysis stopped before the caller had spoken enough. A call that simply ends is settled by the session.
      this.report("inconclusive");
    }
    this.log.info(
      {
        reason,
        connections: this.connections,
        frames: this.frames,
        ignoredMessages: this.ignoredMessages,
        speechMs: this.aggregator.assessment().speechMs,
        sentMs: this.sentMs(),
        droppedMs: Math.round(this.droppedBytes / MULAW_BYTES_PER_MS),
      },
      "calls: voice detector closed",
    );
  }

  /** Reports the aggregate (or a terminal status in its place) to the session, which dedups and keeps `synthetic`. */
  private report(terminal?: "unavailable" | "inconclusive"): void {
    const aggregate = this.aggregator.assessment();
    const update: CallVoiceUpdate = {
      status: terminal ?? aggregate.status,
      syntheticShare: aggregate.syntheticShare,
      confidence: terminal ? 0 : aggregate.confidence,
      speechMs: aggregate.speechMs,
      provider: MODULATE_VOICE_PROVIDER,
    };
    try {
      this.session.setVoice(update);
    } catch (error) {
      // A listener of the session's `voice` event threw; this runs inside a socket callback and must not.
      this.log.error({ errorName: error instanceof Error ? error.name : "unknown" }, "calls: voice assessment could not be delivered");
    }
  }

  // MARK: connection lifecycle

  private connect(): void {
    if (!this.accepting || this.conn) return;
    if (this.owner.coolingDown()) {
      void this.end("unavailable");
      return;
    }
    let socket: VoiceSocket;
    try {
      socket = this.options.socketFactory(this.owner.url);
    } catch (error) {
      this.log.warn({ error: this.owner.scrub(messageOf(error)) }, "calls: voice detector connect failed");
      this.scheduleReconnect("retry");
      return;
    }
    this.connections += 1;
    const conn: Connection = {
      socket,
      ready: false,
      closedByUs: false,
      frames: 0,
      serverError: undefined,
      socketError: undefined,
      handshakeStatus: undefined,
      settle: undefined,
    };
    this.conn = conn;
    socket.on("open", () => this.onOpen(conn));
    socket.on("message", (data, isBinary) => this.onMessage(conn, data, isBinary));
    // Never logged as an object: a `ws` error can carry the request, and the request URL carries the key.
    socket.on("error", (error) => {
      const message = messageOf(error);
      if (!conn.ready) conn.handshakeStatus ??= handshakeStatusOf(message);
      conn.socketError = this.owner.scrub(message);
    });
    socket.on("close", (code, reason) => this.onClose(conn, code, reason));
  }

  private onOpen(conn: Connection): void {
    if (conn.closedByUs || this.conn !== conn) return;
    conn.ready = true;
    this.aggregator.resetConnection();
    this.log.info({ reconnected: this.connections > 1 }, "calls: voice detector connected");
    this.notify(() => this.options.observer?.opened?.(this.session.callId));
    // Whatever arrived while the socket was connecting (bounded; the oldest was dropped beyond the buffer).
    this.flush(conn);
    this.endAtCap();
  }

  private onClose(conn: Connection, code: number, reason: unknown): void {
    conn.ready = false;
    if (conn.closedByUs) {
      conn.settle?.();
      return;
    }
    // An upgrade the server refused never had a close code of its own (`ws` reports 1006): its HTTP status decides.
    const refusedUpgrade = MODULATE_CLOSE_CODES[code] === undefined ? conn.handshakeStatus : undefined;
    const policy = refusedUpgrade !== undefined ? handshakeStatusPolicy(refusedUpgrade) : closeCodePolicy(code);
    const detail = conn.serverError ?? conn.socketError ?? (this.owner.scrub(rawToString(reason ?? "")) || undefined);
    const fields = { code, frames: conn.frames, detail };
    this.notify(() => this.options.observer?.closed?.(this.session.callId, { code, policy, detail }));
    if (policy === "account") {
      const meaning = refusedUpgrade !== undefined ? `HTTP ${refusedUpgrade} at the WebSocket handshake` : MODULATE_CLOSE_CODES[code]?.meaning;
      this.owner.coolDown(refusedUpgrade ?? code, meaning);
    }
    if (conn.settle) {
      // The stream was already ending: whatever the code says, there is nothing left to retry.
      if (policy !== "finished") this.log.warn(fields, "calls: voice detector socket closed while finishing");
      conn.settle();
      return;
    }
    if (this.conn !== conn) return;
    this.conn = undefined;
    if (!this.accepting) return;
    switch (policy) {
      case "finished":
        this.log.info(fields, "calls: voice detector stream ended by the vendor");
        void this.end("finished");
        return;
      case "account":
        // The detector's cool-down line is the warning; this one is per call.
        this.log.info(fields, "calls: voice detector refused for the account; not retried");
        void this.end("unavailable");
        return;
      case "call":
        this.log.warn(fields, "calls: voice detector refused this stream; not retried");
        void this.end("unavailable");
        return;
      case "busy":
        // Info, not warn: with more calls than the account's concurrent streams this is the expected state.
        this.log.info({ ...fields, busyAttempts: this.busyAttempts }, "calls: voice detector has no free stream; waiting for one");
        this.scheduleReconnect("busy");
        return;
      case "retry":
      default:
        this.log.warn({ ...fields, failedAttempts: this.failedAttempts }, "calls: voice detector socket closed; reconnecting");
        this.scheduleReconnect("retry");
        return;
    }
  }

  private scheduleReconnect(kind: "retry" | "busy"): void {
    if (!this.accepting || this.reconnectTimer) return;
    const busy = kind === "busy";
    const attempts = busy ? this.busyAttempts : this.failedAttempts;
    if (attempts >= (busy ? this.options.maxBusyAttempts : this.options.maxReconnectAttempts)) {
      this.log.warn(
        { attempts, busy },
        "calls: voice detector gave up reconnecting; the caller's voice is not checked for the rest of the call",
      );
      void this.end("unavailable");
      return;
    }
    // A broken connection backs off from short to long; a full house is asked again at the long interval only.
    const base = busy ? this.options.reconnectMaxMs : Math.min(this.options.reconnectMaxMs, this.options.reconnectInitialMs * 2 ** this.failedAttempts);
    const jitter = 0.75 + this.options.random() * 0.5;
    const wait = Math.round(base * jitter);
    if (busy) this.busyAttempts += 1;
    else this.failedAttempts += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connect();
    }, wait);
    this.reconnectTimer.unref();
  }

  private clearReconnect(): void {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = undefined;
  }

  private closeConnection(conn: Connection): void {
    conn.closedByUs = true;
    conn.ready = false;
    try {
      conn.socket.close(1000, "done");
    } catch {
      // already closed
    }
  }

  // MARK: server messages

  private onMessage(conn: Connection, data: unknown, isBinary: boolean | undefined): void {
    if (conn.closedByUs || isBinary === true) return;
    const message = parseVoiceMessage(data);
    if (!message) {
      // Not JSON, or a message type this version of the vendor's protocol does not document.
      this.ignoredMessages += 1;
      return;
    }
    switch (message.type) {
      case "frame":
        this.onFrame(conn, message.frame);
        return;
      case "done":
        this.notify(() => this.options.observer?.done?.(this.session.callId, { durationMs: message.durationMs, frameCount: message.frameCount }));
        // All frames are in; the vendor closes next. Unprompted (no end-of-stream sent), its 1000 close follows.
        conn.settle?.();
        return;
      case "error":
        // Logged with the close that follows it (the vendor closes after every error).
        conn.serverError = this.owner.scrub(message.error) || undefined;
        return;
      default:
        return;
    }
  }

  private onFrame(conn: Connection, frame: VoiceFrame): void {
    conn.frames += 1;
    this.frames += 1;
    // A frame is proof the stream works: the next blip gets the full retry budget again.
    this.failedAttempts = 0;
    this.busyAttempts = 0;
    this.notify(() => this.options.observer?.frame?.(this.session.callId, frame));
    if (!this.aggregator.add(frame)) return;
    this.report();
    const aggregate = this.aggregator.assessment();
    if (aggregate.status === "synthetic" && this.accepting) {
      this.log.info(
        { speechMs: aggregate.speechMs, syntheticShare: Number(aggregate.syntheticShare.toFixed(2)), confidence: Number(aggregate.confidence.toFixed(2)) },
        "calls: voice detector judged the caller's voice synthetic; stream ends",
      );
      void this.end("latched");
    }
  }

  /** Observer callbacks run inside socket callbacks: one that throws must not take the process down. */
  private notify(call: () => void): void {
    try {
      call();
    } catch {
      // diagnostics only
    }
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const INERT_HANDLE: VoiceDetectorHandle = {
  pushAudio: () => undefined,
  close: () => Promise.resolve(),
  finished: Promise.resolve(),
};

export function defaultVoiceSocketFactory(url: string): VoiceSocket {
  return new WebSocket(url, { handshakeTimeout: DEFAULT_HANDSHAKE_TIMEOUT_MS });
}

export function createVoiceDetector(options: VoiceDetectorOptions): VoiceDetector {
  const resolved: ResolvedOptions = {
    config: options.config,
    now: options.now ?? Date.now,
    socketFactory: options.socketFactory ?? defaultVoiceSocketFactory,
    random: options.random ?? Math.random,
    coalesceMs: options.coalesceMs ?? DEFAULT_COALESCE_MS,
    pendingBufferMs: options.pendingBufferMs ?? DEFAULT_PENDING_BUFFER_MS,
    reconnectInitialMs: options.reconnectInitialMs ?? DEFAULT_RECONNECT_INITIAL_MS,
    reconnectMaxMs: options.reconnectMaxMs ?? DEFAULT_RECONNECT_MAX_MS,
    maxReconnectAttempts: options.maxReconnectAttempts ?? DEFAULT_MAX_RECONNECT_ATTEMPTS,
    maxBusyAttempts: options.maxBusyAttempts ?? DEFAULT_MAX_BUSY_ATTEMPTS,
    stallBufferMs: options.stallBufferMs ?? DEFAULT_STALL_BUFFER_MS,
    closeGraceMs: options.closeGraceMs ?? DEFAULT_CLOSE_GRACE_MS,
    coolDownMs: options.coolDownMs ?? DEFAULT_COOL_DOWN_MS,
    observer: options.observer,
  };
  const logger = options.logger.child({ module: "calls.voice", provider: MODULATE_VOICE_PROVIDER });
  const handles = new Set<ModulateVoiceHandle>();
  let coolDownUntil = 0;
  let closed = false;

  const owner: HandleOwner = {
    url: buildVoiceStreamUrl(options.url ?? MODULATE_VOICE_STREAMING_URL, resolved.config.apiKey),
    scrub: (text) => scrubModulateSecrets(text, resolved.config.apiKey),
    coolingDown: () => resolved.now() < coolDownUntil,
    coolDown(code, meaning) {
      if (resolved.now() < coolDownUntil) return;
      coolDownUntil = resolved.now() + resolved.coolDownMs;
      // One line per cool-down, however many calls were in flight when the account was refused.
      logger.warn(
        { code, meaning, coolDownSeconds: Math.round(resolved.coolDownMs / 1000) },
        "calls: voice detector refused for the account; calls are not checked for AI voices until the cool-down ends",
      );
    },
    forget: (handle) => {
      handles.delete(handle);
    },
  };

  return {
    open(session: CallSession): VoiceDetectorHandle {
      // Nothing to learn from a call that is over or whose caller was already judged synthetic.
      if (closed || session.isEnded || session.voice?.status === "synthetic") return INERT_HANDLE;
      if (owner.coolingDown()) {
        // No connection, no log line: the cool-down was announced once when it began.
        session.setVoice({ status: "unavailable", syntheticShare: 0, confidence: 0, speechMs: 0, provider: MODULATE_VOICE_PROVIDER });
        return INERT_HANDLE;
      }
      const handle = new ModulateVoiceHandle(session, resolved, owner, logger);
      if (!handle.isFinished) handles.add(handle);
      return handle;
    },
    async close(): Promise<void> {
      closed = true;
      for (const handle of [...handles]) handle.destroy();
      handles.clear();
    },
  };
}

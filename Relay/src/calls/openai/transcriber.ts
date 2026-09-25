import type { FastifyBaseLogger } from "fastify";
import { WebSocket } from "ws";

import type { OpenAIConfig } from "../config.js";
import type { CallSession } from "../session.js";
import { redactNumber, type Speaker, type Transcriber, type TranscriberHandle, type TranscriptSegment } from "../types.js";

/**
 * OpenAI Realtime transcription (docs/research/openaiRealtime.md §1–§5, §7): one WebSocket session per
 * (call, speaker). Twilio's 8 kHz μ-law payloads are appended base64 as-is (`audio/pcmu`), so nothing is
 * decoded for OpenAI — the only decode is the relay's own silence detector, which decides when to commit a
 * turn for models without server VAD (`gpt-live-transcribe`, `gpt-transcribe`, `gpt-realtime-whisper`).
 *
 * Resilience: the socket reconnects with backoff while the handle is open, replaying a 2 s ring buffer of
 * μ-law so a blip costs a fragment rather than the call; sessions rotate proactively before OpenAI's 60-minute
 * limit; `close()` commits what is pending, waits briefly for the last completions and then closes.
 *
 * Every external side effect is injectable: the socket factory (default `new WebSocket(url, { headers })`
 * from `ws`), the clock, and every timing constant. Nothing here logs transcript text.
 */

export const OPENAI_REALTIME_TRANSCRIPTION_URL = "wss://api.openai.com/v1/realtime?intent=transcription";
export const TRANSCRIPTION_PROMPT = "A phone call between two people; transcribe verbatim.";
/** 8 kHz μ-law: one byte per sample. */
export const MULAW_BYTES_PER_MS = 8;
export const RING_BUFFER_MS = 2_000;
export const DEFAULT_RECONNECT_INITIAL_MS = 500;
export const DEFAULT_RECONNECT_MAX_MS = 8_000;
export const DEFAULT_ROTATE_AFTER_MS = 55 * 60 * 1000;
export const DEFAULT_CLOSE_GRACE_MS = 1_500;
/**
 * Consecutive connection attempts that never reach `open` before a track gives up for the rest of the call: a
 * permanent failure (401 bad key, 429 quota, 403) is rejected at the upgrade every time, so the backoff alone
 * would retry every ≤ 8 s for the whole call. Ten attempts span about a minute; a socket that opens resets the count.
 */
export const DEFAULT_MAX_RECONNECT_ATTEMPTS = 10;
/** `ws` handshake timeout for the default socket factory: a stalled connect must not hang a track for the call. */
export const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;

/** The subset of `ws.WebSocket` the transcriber uses; tests substitute a fake. */
export interface TranscriptionSocket {
  on(event: "open", listener: () => void): unknown;
  on(event: "message", listener: (data: unknown) => void): unknown;
  on(event: "close", listener: (code: number, reason?: unknown) => void): unknown;
  on(event: "error", listener: (error: Error) => void): unknown;
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export type TranscriptionSocketFactory = (url: string, headers: Record<string, string>) => TranscriptionSocket;

export interface TranscriberOptions {
  config: OpenAIConfig;
  logger: FastifyBaseLogger;
  socketFactory?: TranscriptionSocketFactory;
  url?: string;
  now?: () => number;
  /** Jitter source for the reconnect backoff (default `Math.random`). */
  random?: () => number;
  reconnectInitialMs?: number;
  reconnectMaxMs?: number;
  /** Consecutive failed connection attempts after which the track stops reconnecting (`DEFAULT_MAX_RECONNECT_ATTEMPTS`). */
  maxReconnectAttempts?: number;
  rotateAfterMs?: number;
  closeGraceMs?: number;
  vad?: Partial<SilenceDetectorConfig>;
}

// MARK: model capabilities (docs/research/openaiRealtime.md §0, §2)

/** Models that reject `turn_detection`; the relay commits turns on silence it measures itself. */
const CLIENT_TURN_MODELS = ["gpt-live-transcribe", "gpt-transcribe", "gpt-realtime-whisper"];
/** Models that take `languages: [...]` instead of the singular `language`. */
const LANGUAGES_ARRAY_MODELS = ["gpt-live-transcribe", "gpt-transcribe"];
/** `prompt` is not supported with `gpt-realtime-whisper`. */
const NO_PROMPT_MODELS = ["gpt-realtime-whisper"];

function matchesModel(model: string, family: readonly string[]): boolean {
  return family.some((name) => model === name || model.startsWith(`${name}-`));
}

export function usesClientTurnDetection(model: string): boolean {
  return matchesModel(model, CLIENT_TURN_MODELS);
}

/** The exact `session.update` for a model (μ-law input, English, verbatim prompt, VAD per capability). */
export function buildSessionUpdate(model: string): Record<string, unknown> {
  const transcription: Record<string, unknown> = { model };
  if (!matchesModel(model, NO_PROMPT_MODELS)) transcription["prompt"] = TRANSCRIPTION_PROMPT;
  if (matchesModel(model, LANGUAGES_ARRAY_MODELS)) transcription["languages"] = ["en"];
  else transcription["language"] = "en";
  const turnDetection = usesClientTurnDetection(model)
    ? null
    : { type: "server_vad", silence_duration_ms: 600, prefix_padding_ms: 300 };
  return {
    type: "session.update",
    session: {
      type: "transcription",
      audio: {
        input: {
          format: { type: "audio/pcmu" },
          transcription,
          turn_detection: turnDetection,
        },
      },
    },
  };
}

// MARK: G.711 μ-law

/** Standard G.711 μ-law → 16-bit linear PCM. */
export const MULAW_TO_LINEAR: Int16Array = (() => {
  const table = new Int16Array(256);
  for (let index = 0; index < 256; index += 1) {
    const value = ~index & 0xff;
    const sign = value & 0x80;
    const exponent = (value >> 4) & 0x07;
    const mantissa = value & 0x0f;
    let sample = (((mantissa << 3) + 0x84) << exponent) - 0x84;
    if (sign) sample = -sample;
    table[index] = sample;
  }
  return table;
})();

export function decodeMulaw(bytes: Uint8Array): Int16Array {
  const out = new Int16Array(bytes.length);
  for (let index = 0; index < bytes.length; index += 1) out[index] = MULAW_TO_LINEAR[bytes[index]!]!;
  return out;
}

// MARK: client-side silence detection

export interface SilenceDetectorConfig {
  frameMs: number;
  /** Commit after this much silence following speech. */
  silenceCommitMs: number;
  /** A turn needs at least this much speech to be worth a commit. */
  minSpeechMs: number;
  /** Commit anyway after this long a turn (continuous speech). */
  maxTurnMs: number;
  /** RMS (16-bit scale) below which a frame is never speech. */
  minSpeechRms: number;
  /** Speech when RMS exceeds the adaptive noise floor by this factor. */
  noiseFactor: number;
  /** Ceiling for the adaptive noise floor (threshold ≤ maxNoiseFloor × noiseFactor), so speech can never be locked out. */
  maxNoiseFloor: number;
  /** Clear a buffer that holds only silence after this long, so it never grows unbounded. */
  silenceClearMs: number;
}

export const DEFAULT_VAD: SilenceDetectorConfig = {
  frameMs: 20,
  silenceCommitMs: 700,
  minSpeechMs: 250,
  maxTurnMs: 8_000,
  minSpeechRms: 300,
  noiseFactor: 3,
  maxNoiseFloor: 700,
  silenceClearMs: 15_000,
};

export type VadDecision = "commit" | "clear";

/**
 * RMS per 20 ms frame against an adaptive threshold; commits after ≥ `silenceCommitMs` of silence following
 * ≥ `minSpeechMs` of speech, or after `maxTurnMs` of continuous speech. Feeds are μ-law bytes in any chunking.
 */
export class SilenceDetector {
  private readonly config: SilenceDetectorConfig;
  private readonly frameBytes: number;
  private carry: number[] = [];
  private noiseFloor = 200;
  private turnStarted = false;
  private speechMs = 0;
  private silenceRunMs = 0;
  private turnMs = 0;
  private silenceOnlyMs = 0;

  constructor(config: Partial<SilenceDetectorConfig> = {}) {
    this.config = { ...DEFAULT_VAD, ...config };
    this.frameBytes = this.config.frameMs * MULAW_BYTES_PER_MS;
  }

  get inTurn(): boolean {
    return this.turnStarted;
  }

  feed(bytes: Uint8Array): VadDecision[] {
    const decisions: VadDecision[] = [];
    const samples = decodeMulaw(bytes);
    for (let index = 0; index < samples.length; index += 1) {
      this.carry.push(samples[index]!);
      if (this.carry.length < this.frameBytes) continue;
      const decision = this.frame(this.carry);
      this.carry = [];
      if (decision) decisions.push(decision);
    }
    return decisions;
  }

  /** Forget the current turn (after a commit or a clear). */
  resetTurn(): void {
    this.turnStarted = false;
    this.speechMs = 0;
    this.silenceRunMs = 0;
    this.turnMs = 0;
    this.silenceOnlyMs = 0;
  }

  private frame(samples: number[]): VadDecision | undefined {
    let energy = 0;
    for (const sample of samples) energy += sample * sample;
    const rms = Math.sqrt(energy / samples.length);
    const threshold = Math.max(this.config.minSpeechRms, this.noiseFloor * this.config.noiseFactor);
    const speech = rms > threshold;
    const { frameMs } = this.config;

    if (speech) {
      if (!this.turnStarted) {
        this.turnStarted = true;
        this.turnMs = 0;
        this.speechMs = 0;
      }
      this.speechMs += frameMs;
      this.silenceRunMs = 0;
      this.turnMs += frameMs;
    } else {
      // Track the room's noise level on quiet frames only.
      this.noiseFloor = Math.min(this.config.maxNoiseFloor, this.noiseFloor * 0.95 + rms * 0.05);
      if (this.turnStarted) {
        this.silenceRunMs += frameMs;
        this.turnMs += frameMs;
      } else {
        this.silenceOnlyMs += frameMs;
      }
    }

    if (this.turnStarted) {
      const enoughSpeech = this.speechMs >= this.config.minSpeechMs;
      if (enoughSpeech && this.silenceRunMs >= this.config.silenceCommitMs) {
        this.resetTurn();
        return "commit";
      }
      if (enoughSpeech && this.turnMs >= this.config.maxTurnMs) {
        this.resetTurn();
        return "commit";
      }
      if (!enoughSpeech && this.silenceRunMs >= this.config.silenceCommitMs) {
        // A click or a cough: fold it back into silence.
        const elapsed = this.turnMs;
        this.resetTurn();
        this.silenceOnlyMs = elapsed;
      }
      return undefined;
    }
    if (this.silenceOnlyMs >= this.config.silenceClearMs) {
      this.silenceOnlyMs = 0;
      return "clear";
    }
    return undefined;
  }
}

// MARK: ring buffer

class MulawRing {
  private chunks: Buffer[] = [];
  private bytes = 0;
  constructor(private readonly capacity: number) {}

  push(chunk: Buffer): void {
    this.chunks.push(chunk);
    this.bytes += chunk.length;
    while (this.bytes > this.capacity && this.chunks.length > 1) {
      const dropped = this.chunks.shift()!;
      this.bytes -= dropped.length;
    }
  }

  get length(): number {
    return this.bytes;
  }

  clear(): void {
    this.chunks = [];
    this.bytes = 0;
  }

  toBase64(): string | undefined {
    if (this.bytes === 0) return undefined;
    return Buffer.concat(this.chunks).toString("base64");
  }
}

// MARK: the handle

interface Connection {
  socket: TranscriptionSocket;
  ready: boolean;
  closedByUs: boolean;
  /** Client-VAD: commits sent minus completions received. */
  pendingCommits: number;
  /** Server-VAD: audio appended since the last completion. */
  awaitingResult: boolean;
  /** Elapsed ms (session clock) at the first append on this socket, for `audio_start_ms` offsets. */
  audioOriginMs: number | undefined;
  /** Turn start (elapsed ms) of every commit sent on this socket that has not yet been answered by `committed`. */
  commitQueue: number[];
  drainTimer: NodeJS.Timeout | undefined;
}

interface RealtimeEvent {
  type?: string;
  item_id?: string;
  delta?: string;
  transcript?: string;
  audio_start_ms?: number;
  error?: { type?: string; code?: string | null; message?: string; param?: string | null };
  session?: { expires_at?: number };
}

class RealtimeTranscriberHandle implements TranscriberHandle {
  private readonly log: FastifyBaseLogger;
  private readonly clientVad: boolean;
  private readonly vad: SilenceDetector;
  private readonly ring = new MulawRing(RING_BUFFER_MS * MULAW_BYTES_PER_MS);
  private readonly partials = new Map<string, string>();
  private readonly itemAtMs = new Map<string, number>();
  private readonly draining = new Set<Connection>();
  private conn: Connection | undefined;
  private open = true;
  /** Set once `maxReconnectAttempts` consecutive attempts failed: audio is dropped and nothing reconnects. */
  private gaveUp = false;
  private closing: Promise<void> | undefined;
  private bytesSinceCommit = 0;
  /** Elapsed ms when the current turn's speech began (client VAD) or its first byte was appended; becomes `atMs`. */
  private turnStartMs: number | undefined;
  private reconnectAttempts = 0;
  private reconnectTimer: NodeJS.Timeout | undefined;
  private rotateTimer: NodeJS.Timeout | undefined;
  private drainWaiter: (() => void) | undefined;
  private segmentsEmitted = 0;

  constructor(
    private readonly session: CallSession,
    private readonly speaker: Speaker,
    private readonly options: Required<
      Pick<
        TranscriberOptions,
        "config" | "now" | "random" | "reconnectInitialMs" | "reconnectMaxMs" | "maxReconnectAttempts" | "rotateAfterMs" | "closeGraceMs" | "url" | "socketFactory"
      >
    >,
    logger: FastifyBaseLogger,
    vad: Partial<SilenceDetectorConfig>,
  ) {
    this.log = logger.child({ callId: session.callId, speaker, caller: redactNumber(session.callerNumber) });
    this.clientVad = usesClientTurnDetection(options.config.transcribeModel);
    this.vad = new SilenceDetector(vad);
    session.once("ended", () => {
      void this.close();
    });
    this.connect();
  }

  // MARK: TranscriberHandle

  pushAudio(base64Mulaw: string): void {
    if (!this.open || this.gaveUp) return;
    const bytes = Buffer.from(base64Mulaw, "base64");
    if (bytes.length === 0) return;
    this.ring.push(bytes);
    const conn = this.conn;
    if (conn?.ready) {
      this.append(conn, base64Mulaw, bytes.length);
    }
    if (this.clientVad) {
      const wasInTurn = this.vad.inTurn;
      const decisions = this.vad.feed(bytes);
      // Speech began inside this payload: stamp the turn here, not at the trailing silence appended after the last commit.
      if (!wasInTurn && this.vad.inTurn) this.turnStartMs = this.session.elapsedMs();
      for (const decision of decisions) {
        if (decision === "commit") this.commit();
        else this.clear();
      }
    }
  }

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.open = false;
    this.clearTimer("reconnect");
    this.clearTimer("rotate");
    this.commit();
    this.closing = this.drain().then(() => {
      for (const conn of this.draining) this.closeConnection(conn);
      this.draining.clear();
      if (this.conn) this.closeConnection(this.conn);
      this.conn = undefined;
      this.log.info({ segments: this.segmentsEmitted }, "calls: transcriber closed");
    });
    return this.closing;
  }

  // MARK: audio

  private append(conn: Connection, base64: string, byteLength: number): void {
    if (conn.audioOriginMs === undefined) conn.audioOriginMs = this.session.elapsedMs();
    if (this.bytesSinceCommit === 0) this.turnStartMs = this.session.elapsedMs();
    this.send(conn, { type: "input_audio_buffer.append", audio: base64 });
    this.bytesSinceCommit += byteLength;
    conn.awaitingResult = true;
  }

  /** Commits the server-side buffer (client-VAD models only) — never when nothing was appended since the last one. */
  private commit(): void {
    const conn = this.conn;
    if (!this.clientVad || !conn?.ready || this.bytesSinceCommit === 0) return;
    this.send(conn, { type: "input_audio_buffer.commit" });
    conn.pendingCommits += 1;
    conn.commitQueue.push(this.turnStartMs ?? this.session.elapsedMs());
    this.bytesSinceCommit = 0;
    this.turnStartMs = undefined;
    this.vad.resetTurn();
  }

  private clear(): void {
    const conn = this.conn;
    if (!conn?.ready || this.bytesSinceCommit === 0) return;
    this.send(conn, { type: "input_audio_buffer.clear" });
    this.bytesSinceCommit = 0;
    this.turnStartMs = undefined;
    conn.awaitingResult = false;
  }

  private send(conn: Connection, event: Record<string, unknown>): void {
    try {
      conn.socket.send(JSON.stringify(event));
    } catch (error) {
      this.log.warn({ err: error, event: event["type"] }, "calls: transcriber send failed");
    }
  }

  // MARK: connection lifecycle

  private connect(): void {
    if (!this.open || this.gaveUp || this.conn) return;
    const headers = { Authorization: `Bearer ${this.options.config.apiKey}` };
    let socket: TranscriptionSocket;
    try {
      socket = this.options.socketFactory(this.options.url, headers);
    } catch (error) {
      this.log.warn({ err: error }, "calls: transcriber connect failed");
      this.scheduleReconnect();
      return;
    }
    const conn: Connection = {
      socket,
      ready: false,
      closedByUs: false,
      pendingCommits: 0,
      awaitingResult: false,
      audioOriginMs: undefined,
      commitQueue: [],
      drainTimer: undefined,
    };
    this.conn = conn;
    socket.on("open", () => this.onOpen(conn));
    socket.on("message", (data) => this.onMessage(conn, data));
    socket.on("error", (error) => {
      this.log.warn({ err: error }, "calls: transcriber socket error");
    });
    socket.on("close", (code) => this.onClose(conn, code));
  }

  private onOpen(conn: Connection): void {
    if (conn.closedByUs) return;
    conn.ready = true;
    const reconnected = this.reconnectAttempts > 0;
    this.reconnectAttempts = 0;
    this.send(conn, buildSessionUpdate(this.options.config.transcribeModel));
    // The ring holds the last 2 s (or everything pushed while the socket was still connecting).
    const replay = this.ring.toBase64();
    if (replay !== undefined && this.open) {
      this.append(conn, replay, this.ring.length);
    }
    this.armRotation(this.options.rotateAfterMs);
    this.log.info({ reconnected, model: this.options.config.transcribeModel, clientVad: this.clientVad }, "calls: transcriber connected");
  }

  private onClose(conn: Connection, code: number): void {
    conn.ready = false;
    if (conn.drainTimer) clearTimeout(conn.drainTimer);
    if (this.draining.delete(conn)) {
      this.notifyDrain();
      return;
    }
    if (this.conn !== conn) return;
    this.conn = undefined;
    this.bytesSinceCommit = 0;
    this.turnStartMs = undefined;
    this.notifyDrain();
    if (!this.open || conn.closedByUs) return;
    this.log.warn({ code, pendingCommits: conn.pendingCommits }, "calls: transcriber socket closed; reconnecting");
    this.scheduleReconnect();
  }

  private scheduleReconnect(): void {
    if (!this.open || this.gaveUp || this.reconnectTimer) return;
    if (this.reconnectAttempts >= this.options.maxReconnectAttempts) {
      this.gaveUp = true;
      this.ring.clear();
      this.log.error(
        { attempts: this.reconnectAttempts },
        "calls: transcriber gave up reconnecting (permanent failure?); this track is not transcribed for the rest of the call",
      );
      return;
    }
    const base = Math.min(this.options.reconnectMaxMs, this.options.reconnectInitialMs * 2 ** this.reconnectAttempts);
    const jitter = 0.75 + this.options.random() * 0.5;
    const wait = Math.round(base * jitter);
    this.reconnectAttempts += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connect();
    }, wait);
    this.reconnectTimer.unref();
  }

  private armRotation(afterMs: number): void {
    this.clearTimer("rotate");
    if (!this.open) return;
    this.rotateTimer = setTimeout(() => {
      this.rotateTimer = undefined;
      this.rotate();
    }, Math.max(1_000, afterMs));
    this.rotateTimer.unref();
  }

  /** Proactive session rotation: commit, keep the old socket for its last completions, open a fresh one. */
  private rotate(): void {
    const old = this.conn;
    if (!this.open || !old) return;
    this.commit();
    old.closedByUs = true;
    this.conn = undefined;
    this.bytesSinceCommit = 0;
    this.turnStartMs = undefined;
    // Planned hand-over: everything so far was committed on the old socket, so the new one must not replay it.
    this.ring.clear();
    this.draining.add(old);
    old.drainTimer = setTimeout(() => {
      old.drainTimer = undefined;
      this.closeConnection(old);
    }, this.options.closeGraceMs);
    old.drainTimer.unref();
    this.log.info({ pendingCommits: old.pendingCommits }, "calls: transcriber rotating session");
    this.connect();
  }

  private closeConnection(conn: Connection): void {
    conn.closedByUs = true;
    conn.ready = false;
    if (conn.drainTimer) {
      clearTimeout(conn.drainTimer);
      conn.drainTimer = undefined;
    }
    try {
      conn.socket.close(1000, "done");
    } catch {
      // already closed
    }
  }

  private clearTimer(which: "reconnect" | "rotate"): void {
    const timer = which === "reconnect" ? this.reconnectTimer : this.rotateTimer;
    if (timer) clearTimeout(timer);
    if (which === "reconnect") this.reconnectTimer = undefined;
    else this.rotateTimer = undefined;
  }

  // MARK: draining

  private outstanding(): boolean {
    const conns = [...this.draining, ...(this.conn ? [this.conn] : [])];
    return conns.some((conn) => conn.ready && (this.clientVad ? conn.pendingCommits > 0 : conn.awaitingResult));
  }

  private notifyDrain(): void {
    if (this.drainWaiter && !this.outstanding()) {
      const waiter = this.drainWaiter;
      this.drainWaiter = undefined;
      waiter();
    }
  }

  /** Resolves when nothing is outstanding or after `closeGraceMs`, whichever comes first. */
  private drain(): Promise<void> {
    if (!this.outstanding()) return Promise.resolve();
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.drainWaiter = undefined;
        resolve();
      }, this.options.closeGraceMs);
      timer.unref();
      this.drainWaiter = () => {
        clearTimeout(timer);
        resolve();
      };
    });
  }

  // MARK: server events

  private onMessage(conn: Connection, data: unknown): void {
    let event: RealtimeEvent;
    try {
      event = JSON.parse(rawToString(data)) as RealtimeEvent;
    } catch {
      this.log.warn("calls: transcriber received a non-JSON frame");
      return;
    }
    switch (event.type) {
      case "conversation.item.input_audio_transcription.delta":
        this.onDelta(event);
        break;
      case "conversation.item.input_audio_transcription.completed":
        this.onCompleted(conn, event);
        break;
      case "conversation.item.input_audio_transcription.failed":
        this.onFailed(conn, event);
        break;
      case "input_audio_buffer.committed": {
        // One `committed` per commit, in order: always consume the queue, even when a delta already stamped the item.
        const turnStart = conn.commitQueue.shift();
        if (typeof event.item_id === "string" && turnStart !== undefined && !this.itemAtMs.has(event.item_id)) {
          this.itemAtMs.set(event.item_id, turnStart);
        }
        break;
      }
      case "input_audio_buffer.speech_started":
        if (typeof event.item_id === "string" && typeof event.audio_start_ms === "number") {
          this.itemAtMs.set(event.item_id, (conn.audioOriginMs ?? 0) + event.audio_start_ms);
        }
        break;
      case "session.created":
        this.onSessionCreated(event);
        break;
      case "error":
        this.log.warn(
          { code: event.error?.code ?? null, errorType: event.error?.type, message: redactApiKeys(event.error?.message) },
          "calls: transcriber error event",
        );
        break;
      default:
        // session.updated, input_audio_buffer.cleared, speech_stopped, rate_limits.updated, …: nothing to do.
        break;
    }
  }

  private onSessionCreated(event: RealtimeEvent): void {
    const expiresAt = event.session?.expires_at;
    if (typeof expiresAt !== "number" || !Number.isFinite(expiresAt)) return;
    // Rotate a minute before OpenAI would end the session, if that is sooner than the fixed rotation.
    const untilExpiry = expiresAt * 1000 - this.options.now() - 60_000;
    if (untilExpiry < this.options.rotateAfterMs) this.armRotation(untilExpiry);
  }

  private segmentId(itemId: string): string {
    return `${this.speaker}-${itemId}`;
  }

  private atMs(itemId: string): number {
    const known = this.itemAtMs.get(itemId);
    if (known !== undefined) return known;
    const at = this.turnStartMs ?? this.session.elapsedMs();
    this.itemAtMs.set(itemId, at);
    return at;
  }

  private onDelta(event: RealtimeEvent): void {
    if (typeof event.item_id !== "string" || typeof event.delta !== "string") return;
    const text = (this.partials.get(event.item_id) ?? "") + event.delta;
    this.partials.set(event.item_id, text);
    if (text.trim().length === 0) return;
    this.emit({ id: this.segmentId(event.item_id), speaker: this.speaker, text, atMs: this.atMs(event.item_id), final: false });
  }

  private onCompleted(conn: Connection, event: RealtimeEvent): void {
    this.settle(conn);
    if (typeof event.item_id !== "string") return;
    const text = typeof event.transcript === "string" ? event.transcript.trim() : "";
    this.partials.delete(event.item_id);
    const atMs = this.atMs(event.item_id);
    this.itemAtMs.delete(event.item_id);
    if (text.length === 0) return;
    this.emit({ id: this.segmentId(event.item_id), speaker: this.speaker, text, atMs, final: true });
  }

  private onFailed(conn: Connection, event: RealtimeEvent): void {
    this.settle(conn);
    if (typeof event.item_id === "string") {
      this.partials.delete(event.item_id);
      this.itemAtMs.delete(event.item_id);
    }
    this.log.warn({ code: event.error?.code ?? null, errorType: event.error?.type }, "calls: transcription item failed");
  }

  private settle(conn: Connection): void {
    if (conn.pendingCommits > 0) conn.pendingCommits -= 1;
    conn.awaitingResult = false;
    this.notifyDrain();
  }

  private emit(segment: TranscriptSegment): void {
    if (segment.final) this.segmentsEmitted += 1;
    this.session.addSegment(segment);
  }
}

/**
 * OpenAI's error text echoes the credential it rejected ("Incorrect API key provided: sk-…", observed with a bad
 * key on 2026-09-23), so anything key-shaped is masked before a server message reaches the log; ≤ 200 chars.
 */
export function redactApiKeys(text: string | undefined): string | undefined {
  return text?.replace(/\bsk-[A-Za-z0-9_-]{2,}/g, "sk-[redacted]").slice(0, 200);
}

function rawToString(data: unknown): string {
  if (typeof data === "string") return data;
  if (Buffer.isBuffer(data)) return data.toString("utf8");
  if (Array.isArray(data)) return Buffer.concat(data.map((part) => (Buffer.isBuffer(part) ? part : Buffer.from(part as ArrayBuffer)))).toString("utf8");
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  return String(data);
}

export function defaultSocketFactory(url: string, headers: Record<string, string>): TranscriptionSocket {
  return new WebSocket(url, { headers, handshakeTimeout: DEFAULT_HANDSHAKE_TIMEOUT_MS });
}

export function createTranscriber(options: TranscriberOptions): Transcriber {
  const resolved = {
    config: options.config,
    now: options.now ?? Date.now,
    random: options.random ?? Math.random,
    reconnectInitialMs: options.reconnectInitialMs ?? DEFAULT_RECONNECT_INITIAL_MS,
    reconnectMaxMs: options.reconnectMaxMs ?? DEFAULT_RECONNECT_MAX_MS,
    maxReconnectAttempts: options.maxReconnectAttempts ?? DEFAULT_MAX_RECONNECT_ATTEMPTS,
    rotateAfterMs: options.rotateAfterMs ?? DEFAULT_ROTATE_AFTER_MS,
    closeGraceMs: options.closeGraceMs ?? DEFAULT_CLOSE_GRACE_MS,
    url: options.url ?? OPENAI_REALTIME_TRANSCRIPTION_URL,
    socketFactory: options.socketFactory ?? defaultSocketFactory,
  };
  const logger = options.logger.child({ module: "calls.transcriber" });
  const vad = options.vad ?? {};
  return {
    open(session: CallSession, speaker: Speaker): TranscriberHandle {
      return new RealtimeTranscriberHandle(session, speaker, resolved, logger, vad);
    },
  };
}

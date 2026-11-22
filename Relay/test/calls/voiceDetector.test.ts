import { EventEmitter } from "node:events";
import type { FastifyBaseLogger } from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { VoiceDetectionConfig } from "../../src/calls/config.js";
import {
  MODULATE_CLOSE_CODES,
  MODULATE_VOICE_PROVIDER,
  MODULATE_VOICE_STREAMING_URL,
  buildVoiceStreamUrl,
  closeCodePolicy,
  handshakeStatusOf,
  handshakeStatusPolicy,
  createVoiceDetector,
  scrubModulateSecrets,
  type VoiceDetectorOptions,
  type VoiceSocket,
} from "../../src/calls/modulate/voiceDetector.js";
import { CallSession } from "../../src/calls/session.js";
import type { CallVoiceAssessment, VoiceDetector, VoiceDetectorHandle } from "../../src/calls/types.js";
import { FakeClock } from "../helpers.js";
import { CALLER_NUMBER, GUARD_NUMBER, MODULATE_TEST_KEY, silentLogger, testVoiceConfig } from "./fakes.js";
import { replyDone, startModulateServer, type FakeModulateServer } from "./modulateServer.js";

/**
 * The Modulate streaming client (src/calls/modulate/voiceDetector.ts) against a fake socket for every protocol
 * and failure path, and once — the last test — with its real default socket factory against an in-process `ws`
 * server speaking the documented protocol. Nothing here reaches the real vendor.
 */

const DOCUMENTED_URL =
  "wss://platform.modulate.ai/api/velma-2-synthetic-voice-detection-streaming" +
  `?api_key=${MODULATE_TEST_KEY}&audio_format=mulaw&sample_rate=8000&num_channels=1`;

// MARK: fakes

class FakeSocket extends EventEmitter implements VoiceSocket {
  /** Binary frames as Buffers, text frames as strings — the distinction `ws` makes by argument type. */
  readonly sent: (string | Buffer)[] = [];
  closed = false;
  closeCode: number | undefined;
  terminated = false;
  /** What `ws` reports as queued inside the socket; tests raise it to simulate a peer that stopped reading. */
  bufferedAmount = 0;
  /** When set, `send` throws it (a socket that died under the client). */
  failSend: Error | undefined;

  constructor(readonly url: string) {
    super();
  }

  send(data: string | Uint8Array): void {
    if (this.failSend) throw this.failSend;
    if (this.closed) throw new Error("socket closed");
    this.sent.push(typeof data === "string" ? data : Buffer.from(data));
  }

  close(code?: number): void {
    if (this.closed) return;
    this.closed = true;
    this.closeCode = code;
    queueMicrotask(() => this.emit("close", code ?? 1005, Buffer.alloc(0)));
  }

  terminate(): void {
    this.terminated = true;
    this.closed = true;
  }

  /** Simulates the server: the upgrade succeeded. */
  open(): void {
    this.emit("open");
  }

  /** Simulates the server: a JSON text message (as `ws` delivers it: a Buffer, `isBinary` false). */
  message(message: Record<string, unknown>): void {
    this.emit("message", Buffer.from(JSON.stringify(message)), false);
  }

  frame(startMs: number, endMs: number, verdict: string, confidence = 0.95): void {
    this.message({ type: "frame", frame: { start_time_ms: startMs, end_time_ms: endMs, verdict, confidence } });
  }

  done(durationMs = 0, frameCount = 0): void {
    this.message({ type: "done", duration_ms: durationMs, frame_count: frameCount });
  }

  /** Simulates the server closing: the documented `error` message first (unless 1000), then the close code. */
  serverClose(code: number, error?: string, reason = ""): void {
    if (error !== undefined) this.message({ type: "error", error });
    this.closed = true;
    this.emit("close", code, Buffer.from(reason));
  }

  /** Simulates a failed handshake as `ws` reports it: `error`, then `close` 1006, never `open`. */
  refuse(error = new Error("Unexpected server response: 503")): void {
    this.emit("error", error);
    this.closed = true;
    this.emit("close", 1006, Buffer.alloc(0));
  }

  binary(): Buffer[] {
    return this.sent.filter((data): data is Buffer => Buffer.isBuffer(data));
  }

  text(): string[] {
    return this.sent.filter((data): data is string => typeof data === "string");
  }

  bytesSent(): number {
    return this.binary().reduce((sum, data) => sum + data.length, 0);
  }
}

interface LogEntry {
  level: string;
  bindings: Record<string, unknown>;
  fields: unknown;
  message: string | undefined;
}

/** A pino-shaped logger that records every call at every level, child bindings included. */
function recordingLogger(): { logger: FastifyBaseLogger; entries: LogEntry[]; text: () => string; at: (level: string, pattern: RegExp) => LogEntry[] } {
  const entries: LogEntry[] = [];
  const make = (bindings: Record<string, unknown>): FastifyBaseLogger => {
    const log =
      (level: string) =>
      (fields: unknown, message?: string): void => {
        entries.push(typeof fields === "string" ? { level, bindings, fields: {}, message: fields } : { level, bindings, fields, message });
      };
    return {
      level: "trace",
      fatal: log("fatal"),
      error: log("error"),
      warn: log("warn"),
      info: log("info"),
      debug: log("debug"),
      trace: log("trace"),
      silent: (): void => undefined,
      child: (extra: Record<string, unknown>) => make({ ...bindings, ...extra }),
    } as unknown as FastifyBaseLogger;
  };
  // Error objects are spelled out (JSON.stringify would hide their message), so a logged Error cannot hide a key.
  const spell = (_key: string, value: unknown): unknown =>
    value instanceof Error ? { name: value.name, message: value.message, stack: value.stack, ...(value as unknown as Record<string, unknown>) } : value;
  return {
    logger: make({}),
    entries,
    text: () => entries.map((entry) => JSON.stringify(entry, spell)).join("\n"),
    at: (level, pattern) => entries.filter((entry) => entry.level === level && pattern.test(entry.message ?? "")),
  };
}

function containsError(value: unknown): boolean {
  if (value instanceof Error) return true;
  if (typeof value !== "object" || value === null) return false;
  return Object.values(value as Record<string, unknown>).some(containsError);
}

// MARK: harness

/** 20 ms of μ-law (one Twilio payload), every byte `index` so the stream's order can be checked. */
function payloadBytes(index: number): Buffer {
  return Buffer.alloc(160, index % 256);
}

function push(handle: VoiceDetectorHandle, count: number, from = 0): Buffer {
  const all: Buffer[] = [];
  for (let index = from; index < from + count; index += 1) {
    const bytes = payloadBytes(index);
    all.push(bytes);
    handle.pushAudio(bytes.toString("base64"));
  }
  return Buffer.concat(all);
}

interface Harness {
  clock: FakeClock;
  detector: VoiceDetector;
  session: CallSession;
  sockets: FakeSocket[];
  /** How many arguments the socket factory was called with, per call. */
  factoryArity: number[];
  /** Every `voice` event of `session`, in order. */
  events: CallVoiceAssessment[];
  newSession(): CallSession;
  open(session?: CallSession): VoiceDetectorHandle;
  latest(): FakeSocket;
}

const detectors: VoiceDetector[] = [];

function harness(options: Partial<VoiceDetectorOptions> = {}, config: Partial<VoiceDetectionConfig> = {}): Harness {
  const clock = new FakeClock();
  const newSession = (): CallSession =>
    new CallSession(
      { deviceId: "device-1", line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: clock.now(), status: "in_progress" },
      clock.now,
    );
  const session = newSession();
  const events: CallVoiceAssessment[] = [];
  session.on("voice", (voice) => events.push(voice));
  const sockets: FakeSocket[] = [];
  const factoryArity: number[] = [];
  const detector = createVoiceDetector({
    config: testVoiceConfig(config),
    logger: silentLogger(),
    socketFactory: (...args: [string]) => {
      factoryArity.push(args.length);
      const socket = new FakeSocket(args[0]);
      sockets.push(socket);
      return socket;
    },
    now: clock.now,
    random: () => 0.5,
    reconnectInitialMs: 1,
    reconnectMaxMs: 4,
    closeGraceMs: 30,
    ...options,
  });
  detectors.push(detector);
  return {
    clock,
    detector,
    session,
    sockets,
    factoryArity,
    events,
    newSession,
    open: (target = session) => detector.open(target),
    latest: () => sockets[sockets.length - 1]!,
  };
}

function tick(ms = 0): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Polls `condition` every millisecond for up to `timeoutMs` (real timers: the backoff runs on them). */
async function until(condition: () => boolean, timeoutMs = 1000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("until: condition not met in time");
    await tick(1);
  }
}

afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(detectors.splice(0).map((detector) => detector.close()));
});

// MARK: tests

describe("handshake", () => {
  it("connects to exactly the documented URL — key and telephony format in the query string, nothing in a header", () => {
    const { open, sockets, factoryArity } = harness();
    open();
    expect(sockets).toHaveLength(1);
    expect(sockets[0]!.url).toBe(DOCUMENTED_URL);
    expect(MODULATE_VOICE_STREAMING_URL).toBe("wss://platform.modulate.ai/api/velma-2-synthetic-voice-detection-streaming");
    // The factory is given the URL and nothing else: there is no headers argument a credential could travel in.
    expect(factoryArity).toEqual([1]);
    expect([...new URL(sockets[0]!.url).searchParams.keys()]).toEqual(["api_key", "audio_format", "sample_rate", "num_channels"]);
  });

  it("percent-encodes a key with reserved characters and keeps an injected endpoint", () => {
    expect(buildVoiceStreamUrl("ws://127.0.0.1:9/api/x", "a b&c=d")).toBe("ws://127.0.0.1:9/api/x?api_key=a+b%26c%3Dd&audio_format=mulaw&sample_rate=8000&num_channels=1");
    const { open, sockets } = harness({ url: "ws://127.0.0.1:9/api/velma-2-synthetic-voice-detection-streaming" });
    open();
    expect(sockets[0]!.url).toBe(`ws://127.0.0.1:9/api/velma-2-synthetic-voice-detection-streaming?api_key=${MODULATE_TEST_KEY}&audio_format=mulaw&sample_rate=8000&num_channels=1`);
  });

  it("reports `analyzing` the moment the handle is opened, before the socket is", () => {
    const { open, session, events, clock } = harness();
    expect(session.voice).toBeUndefined();
    open();
    expect(session.voice).toEqual({ status: "analyzing", syntheticShare: 0, confidence: 0, speechMs: 0, provider: MODULATE_VOICE_PROVIDER, updatedAt: clock.now() });
    expect(MODULATE_VOICE_PROVIDER).toBe("modulate:velma-2-synthetic-voice-detection-streaming");
    expect(events).toHaveLength(1);
  });

  it("opens nothing for a call that is over or whose caller was already judged synthetic", () => {
    const { detector, newSession, sockets } = harness();
    const ended = newSession();
    ended.end("completed");
    detector.open(ended).pushAudio(payloadBytes(1).toString("base64"));
    const judged = newSession();
    judged.setVoice({ status: "synthetic", syntheticShare: 1, confidence: 0.9, speechMs: 6000, provider: MODULATE_VOICE_PROVIDER });
    detector.open(judged);
    expect(sockets).toHaveLength(0);
    expect(ended.voice).toBeUndefined();
    expect(judged.voice?.status).toBe("synthetic");
  });
});

describe("audio", () => {
  it("sends Twilio's μ-law bytes untouched as BINARY frames, coalesced to 200 ms", () => {
    const { open, latest } = harness();
    const handle = open();
    latest().open();
    const first = push(handle, 9);
    // 180 ms so far: nothing has left yet.
    expect(latest().sent).toHaveLength(0);
    const tenth = push(handle, 1, 9);
    expect(latest().sent).toHaveLength(1);
    expect(Buffer.isBuffer(latest().sent[0])).toBe(true);
    expect(latest().binary()[0]!.equals(Buffer.concat([first, tenth]))).toBe(true);
    expect(latest().binary()[0]!.length).toBe(1600);
    push(handle, 25, 10);
    // 500 ms more: two more 200 ms frames, 100 ms still pending.
    expect(latest().binary().map((data) => data.length)).toEqual([1600, 1600, 1600]);
    expect(latest().text()).toEqual([]);
  });

  it("honours the injected coalescing size and ignores empty payloads", () => {
    const { open, latest } = harness({ coalesceMs: 20 });
    const handle = open();
    latest().open();
    handle.pushAudio("");
    push(handle, 3);
    expect(latest().binary().map((data) => data.length)).toEqual([160, 160, 160]);
  });

  it("buffers audio pushed before the socket opens and sends it as one binary frame on open", () => {
    const { open, latest } = harness();
    const handle = open();
    const early = push(handle, 25);
    expect(latest().sent).toHaveLength(0);
    latest().open();
    expect(latest().sent).toHaveLength(1);
    expect(latest().binary()[0]!.equals(early)).toBe(true);
  });

  it("bounds that buffer and drops the OLDEST audio beyond it", () => {
    const { open, latest } = harness({ pendingBufferMs: 100 });
    const handle = open();
    const all = push(handle, 10);
    latest().open();
    // 100 ms = 800 bytes = the newest five payloads.
    expect(latest().binary()).toHaveLength(1);
    expect(latest().binary()[0]!.equals(all.subarray(800))).toBe(true);
  });

  it("keeps ten seconds by default", () => {
    const { open, latest } = harness();
    const handle = open();
    const all = push(handle, 600); // 12 s
    latest().open();
    expect(latest().bytesSent()).toBe(80_000);
    expect(latest().binary()[0]!.equals(all.subarray(all.length - 80_000))).toBe(true);
  });
});

describe("end of stream", () => {
  it("flushes the tail, sends an EMPTY TEXT frame, waits for `done`, then closes with 1000", async () => {
    const { open, latest, session } = harness({ closeGraceMs: 500 });
    const handle = open();
    latest().open();
    const tail = push(handle, 3);
    const closing = handle.close();
    expect(latest().sent).toHaveLength(2);
    expect(latest().binary()[0]!.equals(tail)).toBe(true);
    // The end-of-stream signal is a text frame of length zero — a string, not an empty Buffer.
    expect(latest().sent[1]).toBe("");
    expect(latest().closed).toBe(false);
    // The vendor flushes: its final frames still count.
    latest().frame(0, 6000, "non-synthetic", 0.93);
    expect(session.voice).toMatchObject({ status: "human", speechMs: 6000 });
    latest().done(6000, 1);
    await closing;
    expect(latest().closed).toBe(true);
    expect(latest().closeCode).toBe(1000);
    // Nothing is sent after the end of the stream.
    push(handle, 20, 3);
    expect(latest().sent).toHaveLength(2);
  });

  it("gives up waiting for `done` after the grace period", async () => {
    const { open, latest } = harness({ closeGraceMs: 20 });
    const handle = open();
    latest().open();
    const started = Date.now();
    await handle.close();
    expect(Date.now() - started).toBeLessThan(1000);
    expect(latest().text()).toEqual([""]);
    expect(latest().closed).toBe(true);
  });

  it("the vendor's own close ends the wait as well", async () => {
    const { open, latest } = harness({ closeGraceMs: 5000 });
    const handle = open();
    latest().open();
    const closing = handle.close();
    latest().serverClose(1000);
    await closing;
    expect(latest().text()).toEqual([""]);
  });

  it("sends no end-of-stream on a socket that never opened, is idempotent and never rejects", async () => {
    const { open, latest } = harness();
    const handle = open();
    push(handle, 5);
    await Promise.all([handle.close(), handle.close()]);
    expect(latest().sent).toHaveLength(0);
    expect(latest().closed).toBe(true);
    await expect(handle.close()).resolves.toBeUndefined();
  });

  it("never throws out of close() when the socket does", async () => {
    const { open, latest } = harness();
    const handle = open();
    latest().open();
    push(handle, 3);
    latest().failSend = new Error(`write EPIPE ${DOCUMENTED_URL}`);
    await expect(handle.close()).resolves.toBeUndefined();
  });

  it("closes itself when the session ends; a call that ends while analysing is inconclusive", async () => {
    const { open, latest, session } = harness();
    open();
    latest().open();
    latest().frame(0, 4000, "synthetic", 0.9);
    expect(session.voice?.status).toBe("analyzing");
    session.end("completed");
    expect(latest().text()).toEqual([""]);
    expect(session.voice?.status).toBe("inconclusive");
    latest().done();
    await tick(5);
    expect(latest().closed).toBe(true);
  });
});

describe("frames → the session's assessment", () => {
  it("reports after every frame that adds speech, with the provider and the aggregate numbers", () => {
    const { open, latest, session, events } = harness();
    open();
    latest().open();
    latest().frame(0, 4000, "non-synthetic", 0.94);
    expect(session.voice).toMatchObject({ status: "analyzing", syntheticShare: 0, confidence: 0, speechMs: 4000, provider: MODULATE_VOICE_PROVIDER });
    latest().frame(4000, 8000, "no-content", 1);
    latest().frame(8000, 12000, "non-synthetic", 0.91);
    expect(session.voice).toMatchObject({ status: "human", syntheticShare: 0, speechMs: 8000 });
    expect(session.voice?.confidence).toBeCloseTo((2000 * 0.94 + 4000 * 0.91) / 6000, 10);
    // analyzing (open) → human; the frame that left everything visible unchanged raised no event.
    expect(events.map((voice) => voice.status)).toEqual(["analyzing", "human"]);
  });

  it("ignores malformed JSON, unknown message types, incomplete frames and binary messages", () => {
    const { open, latest, session, sockets } = harness();
    open();
    latest().open();
    latest().emit("message", Buffer.from("not json"), false);
    latest().emit("message", "{", false);
    latest().message({ type: "session.created" });
    latest().message({ type: "frame" });
    latest().message({ type: "frame", frame: { start_time_ms: 0, end_time_ms: 4000, verdict: "maybe", confidence: 1 } });
    latest().emit("message", Buffer.from(JSON.stringify({ type: "frame", frame: { start_time_ms: 0, end_time_ms: 9000, verdict: "synthetic", confidence: 1 } })), true);
    expect(session.voice).toMatchObject({ status: "analyzing", speechMs: 0 });
    expect(latest().closed).toBe(false);
    expect(sockets).toHaveLength(1);
    // …and a well-formed frame after all that still counts.
    latest().frame(0, 4000, "non-synthetic", 0.9);
    expect(session.voice?.speechMs).toBe(4000);
  });

  it("once the voice is judged synthetic it ends the stream gracefully and ignores further audio", async () => {
    const { open, latest, session, events } = harness({ closeGraceMs: 200 });
    const handle = open();
    latest().open();
    push(handle, 15); // 200 ms sent, 100 ms pending
    latest().frame(0, 4000, "synthetic", 0.97);
    expect(latest().text()).toEqual([]);
    latest().frame(4000, 8000, "synthetic", 0.91);
    expect(session.voice).toMatchObject({ status: "synthetic", syntheticShare: 1, speechMs: 8000, detectedAt: expect.any(Number) });
    expect(session.voice?.confidence).toBeCloseTo((2000 * 0.97 + 4000 * 0.91) / 6000, 10);
    // End of stream went out at once; the pending 100 ms was not worth sending.
    expect(latest().sent.map((data) => (typeof data === "string" ? data : data.length))).toEqual([1600, ""]);
    push(handle, 50, 15);
    expect(latest().sent).toHaveLength(2);
    latest().done(8000, 2);
    await tick(5);
    expect(latest().closeCode).toBe(1000);
    // Opened; the first frame moved the share (still analysing); the second completed the window.
    expect(events.map((voice) => [voice.status, voice.syntheticShare])).toEqual([["analyzing", 0], ["analyzing", 1], ["synthetic", 1]]);
    // Later frames cannot take the verdict back.
    await handle.close();
    expect(session.voice?.status).toBe("synthetic");
  });

  it("a listener of the session's voice event that throws does not escape the socket callback", () => {
    const { open, latest, session } = harness();
    open();
    latest().open();
    session.on("voice", () => {
      throw new Error("listener bug");
    });
    expect(() => latest().frame(0, 6000, "non-synthetic", 0.9)).not.toThrow();
    expect(session.voice?.status).toBe("human");
  });
});

describe("maxStreamMs", () => {
  it("sends exactly the cap, ends the stream, ignores the rest and reports inconclusive when still analysing", async () => {
    const { open, latest, session } = harness({}, { maxStreamMs: 1000 });
    const handle = open();
    latest().open();
    const all = push(handle, 60); // 1.2 s
    expect(latest().bytesSent()).toBe(8000);
    expect(Buffer.concat(latest().binary()).equals(all.subarray(0, 8000))).toBe(true);
    expect(latest().sent.at(-1)).toBe("");
    push(handle, 60, 60);
    expect(latest().bytesSent()).toBe(8000);
    // Still analysing while the vendor flushes…
    expect(session.voice?.status).toBe("analyzing");
    latest().frame(0, 1000, "non-synthetic", 0.9);
    latest().done(1000, 1);
    await tick(5);
    // …and inconclusive once it is clear no more frames will come.
    expect(session.voice).toMatchObject({ status: "inconclusive", confidence: 0, speechMs: 1000 });
    expect(latest().closed).toBe(true);
  });

  it("applies the cap to audio buffered before the socket opened", () => {
    const { open, latest } = harness({}, { maxStreamMs: 1000 });
    const handle = open();
    const all = push(handle, 100); // 2 s buffered
    latest().open();
    expect(latest().bytesSent()).toBe(8000);
    expect(latest().binary()[0]!.equals(all.subarray(0, 8000))).toBe(true);
    expect(latest().sent.at(-1)).toBe("");
  });

  it("keeps a verdict reached before the cap", async () => {
    const { open, latest, session } = harness({}, { maxStreamMs: 1000 });
    const handle = open();
    latest().open();
    latest().frame(0, 6000, "non-synthetic", 0.9);
    push(handle, 50);
    latest().done();
    await tick(5);
    expect(session.voice?.status).toBe("human");
  });

  it("0 streams the whole call", () => {
    const { open, latest } = harness({}, { maxStreamMs: 0 });
    const handle = open();
    latest().open();
    push(handle, 1000); // 20 s
    expect(latest().bytesSent()).toBe(160_000);
    expect(latest().text()).toEqual([]);
  });
});

describe("close codes", () => {
  it("knows every documented code's policy, and retries the ones the vendor does not document", () => {
    const policies = Object.fromEntries(Object.entries(MODULATE_CLOSE_CODES).map(([code, entry]) => [code, entry.policy]));
    expect(policies).toEqual({
      1000: "finished",
      1003: "call",
      1011: "retry",
      1013: "busy",
      4001: "account",
      4002: "call",
      4003: "account",
      4004: "account",
      4029: "account",
      4030: "busy",
      4031: "account",
    });
    expect(closeCodePolicy(1006)).toBe("retry");
    expect(closeCodePolicy(1005)).toBe("retry");
    expect(closeCodePolicy(4999)).toBe("retry");
  });

  it("reads a refused upgrade by its HTTP status: credentials cool down, a bad request is final, the rest retries", () => {
    expect(handshakeStatusOf("Unexpected server response: 401")).toBe(401);
    expect(handshakeStatusOf("connect ECONNREFUSED 127.0.0.1:1")).toBeUndefined();
    expect(handshakeStatusOf("Opening handshake has timed out")).toBeUndefined();
    expect([401, 402, 403].map(handshakeStatusPolicy)).toEqual(["account", "account", "account"]);
    expect(handshakeStatusPolicy(429)).toBe("busy");
    expect([400, 404].map(handshakeStatusPolicy)).toEqual(["call", "call"]);
    expect([500, 502, 503, 504].map(handshakeStatusPolicy)).toEqual(["retry", "retry", "retry", "retry"]);
  });

  it.each([401, 403])("an upgrade refused with HTTP %i is the account's problem: one handshake, a cool-down, later calls unchecked", async (status) => {
    const { logger, at } = recordingLogger();
    const { open, sockets, session, newSession } = harness({ logger, coolDownMs: 60_000 });
    open();
    sockets[0]!.refuse(new Error(`Unexpected server response: ${status}`));
    await tick(20);
    expect(sockets).toHaveLength(1);
    expect(session.voice).toMatchObject({ status: "unavailable", confidence: 0 });
    const warnings = at("warn", /refused for the account/);
    expect(warnings).toHaveLength(1);
    expect(JSON.stringify(warnings[0])).toContain(`HTTP ${status} at the WebSocket handshake`);
    // The next call does not even try while the cool-down runs.
    const next = newSession();
    open(next);
    expect(sockets).toHaveLength(1);
    expect(next.voice?.status).toBe("unavailable");
  });

  it("an upgrade refused with HTTP 400 is final for the call but does not cool the detector down", async () => {
    const { open, sockets, session, newSession } = harness();
    open();
    sockets[0]!.refuse(new Error("Unexpected server response: 400"));
    await tick(20);
    expect(sockets).toHaveLength(1);
    expect(session.voice?.status).toBe("unavailable");
    open(newSession());
    expect(sockets).toHaveLength(2);
  });

  it.each([
    [4001, "Invalid API key."],
    [4003, "This request is not permitted."],
    [4004, "This API key does not have access to this model."],
    [4029, "Insufficient credits."],
    [4031, "Monthly usage limit reached."],
  ])("%i (account level) is not retried: unavailable, audio dropped, and the detector cools down", async (code, error) => {
    const { logger, at } = recordingLogger();
    const { open, latest, sockets, session, detector, newSession, clock } = harness({ logger, coolDownMs: 60_000 });
    const handle = open();
    latest().open();
    latest().serverClose(code, error);
    expect(session.voice).toMatchObject({ status: "unavailable", confidence: 0, provider: MODULATE_VOICE_PROVIDER });
    push(handle, 50);
    await tick(20);
    expect(sockets).toHaveLength(1);
    expect(sockets[0]!.sent).toHaveLength(0);

    // During the cool-down a new call is unavailable at once, without a handshake and without another warning.
    for (let call = 0; call < 3; call += 1) {
      const next = newSession();
      const inert = detector.open(next);
      inert.pushAudio(payloadBytes(1).toString("base64"));
      await inert.close();
      expect(next.voice).toMatchObject({ status: "unavailable", syntheticShare: 0, confidence: 0, speechMs: 0, provider: MODULATE_VOICE_PROVIDER });
    }
    expect(sockets).toHaveLength(1);
    const warnings = at("warn", /./);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({ message: expect.stringContaining("cool-down"), fields: { code, coolDownSeconds: 60 } });

    // One millisecond before the end it still holds; then calls connect again.
    clock.advance(59_999);
    detector.open(newSession());
    expect(sockets).toHaveLength(1);
    clock.advance(1);
    const after = newSession();
    detector.open(after);
    expect(sockets).toHaveLength(2);
    expect(after.voice?.status).toBe("analyzing");
  });

  it("one cool-down, one warning — however many calls were in flight — and a new warning for the next cool-down", async () => {
    const { logger, at } = recordingLogger();
    const { detector, newSession, sockets, clock } = harness({ logger, coolDownMs: 1000 });
    const calls = [newSession(), newSession(), newSession()];
    for (const call of calls) detector.open(call);
    for (const socket of sockets) socket.open();
    for (const socket of sockets) socket.serverClose(4029, "Insufficient credits.");
    expect(calls.map((call) => call.voice?.status)).toEqual(["unavailable", "unavailable", "unavailable"]);
    expect(at("warn", /cool-down/)).toHaveLength(1);
    clock.advance(1000);
    detector.open(newSession());
    sockets.at(-1)!.open();
    sockets.at(-1)!.serverClose(4029, "Insufficient credits.");
    expect(at("warn", /cool-down/)).toHaveLength(2);
    expect(at("warn", /./)).toHaveLength(2);
  });

  it("a call waiting to reconnect when the cool-down begins becomes unavailable without another handshake", async () => {
    const { detector, newSession, sockets } = harness({ reconnectInitialMs: 10, reconnectMaxMs: 10 });
    const waiting = newSession();
    detector.open(waiting);
    sockets[0]!.open();
    sockets[0]!.serverClose(1011, "Internal server error");
    const refused = newSession();
    detector.open(refused);
    sockets[1]!.open();
    sockets[1]!.serverClose(4001, "Invalid API key.");
    await until(() => waiting.voice?.status === "unavailable");
    expect(sockets).toHaveLength(2);
  });

  it.each([
    [1003, "Invalid sample_rate=50000. Valid values: [8000, 11025, 16000, 22050, 32000, 44100, 48000, 96000]"],
    [4002, "Audio data does not match the declared audio_format."],
  ])("%i (this stream) is not retried and does not cool the detector down", async (code, error) => {
    const { logger, at } = recordingLogger();
    const { open, latest, sockets, session, detector, newSession } = harness({ logger });
    const handle = open();
    latest().open();
    push(handle, 20);
    latest().serverClose(code, error);
    expect(session.voice?.status).toBe("unavailable");
    push(handle, 20, 20);
    await tick(20);
    expect(sockets).toHaveLength(1);
    expect(at("warn", /not retried/)).toHaveLength(1);
    expect(at("warn", /not retried/)[0]).toMatchObject({ fields: { code, detail: error.slice(0, 200) } });
    // The next call is unaffected.
    const next = newSession();
    detector.open(next);
    expect(sockets).toHaveLength(2);
    expect(next.voice?.status).toBe("analyzing");
  });

  it.each([
    [4030, "Concurrent request limit reached. Please retry after your in-flight requests complete."],
    [1013, undefined],
    [1011, "Internal server error"],
    [1006, undefined],
  ])("%i is retried: a new socket, the same call, still analysing", async (code, error) => {
    const { open, sockets, session } = harness();
    open();
    sockets[0]!.open();
    sockets[0]!.serverClose(code, error);
    await until(() => sockets.length === 2);
    expect(sockets[1]!.url).toBe(DOCUMENTED_URL);
    expect(session.voice?.status).toBe("analyzing");
  });

  it("1000 without having asked for it ends detection for the call: no reconnect, analysing becomes inconclusive", async () => {
    const { open, latest, sockets, session } = harness();
    const handle = open();
    latest().open();
    latest().frame(0, 3000, "non-synthetic", 0.9);
    latest().serverClose(1000);
    expect(session.voice).toMatchObject({ status: "inconclusive", speechMs: 3000 });
    push(handle, 50);
    await tick(20);
    expect(sockets).toHaveLength(1);
  });

  it("a refusal never takes back a synthetic verdict", async () => {
    const { open, latest, session } = harness({ closeGraceMs: 500 });
    const handle = open();
    latest().open();
    latest().frame(0, 3000, "synthetic", 0.95);
    latest().frame(3000, 6000, "synthetic", 0.95);
    expect(session.voice?.status).toBe("synthetic");
    // The stream is ending; the vendor answers with a refusal instead of `done`.
    latest().serverClose(4029, "Insufficient credits.");
    await handle.close();
    expect(session.voice?.status).toBe("synthetic");
  });

  it("a judged-human call whose stream is then refused is reported unavailable (only synthetic is kept)", () => {
    const { open, latest, session } = harness();
    open();
    latest().open();
    latest().frame(0, 6000, "non-synthetic", 0.95);
    expect(session.voice?.status).toBe("human");
    latest().serverClose(4002, "The audio could not be processed. It may be corrupted or in an unsupported format.");
    expect(session.voice).toMatchObject({ status: "unavailable", confidence: 0, speechMs: 6000 });
  });
});

describe("reconnecting", () => {
  it("backs off exponentially with jitter between attempts", () => {
    vi.useFakeTimers();
    const { open, sockets } = harness({ reconnectInitialMs: 1000, reconnectMaxMs: 3000, random: () => 0.5 });
    open();
    sockets[0]!.refuse();
    vi.advanceTimersByTime(999);
    expect(sockets).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(sockets).toHaveLength(2);
    sockets[1]!.refuse();
    vi.advanceTimersByTime(1999);
    expect(sockets).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(sockets).toHaveLength(3);
    // Capped at reconnectMaxMs.
    sockets[2]!.refuse();
    vi.advanceTimersByTime(2999);
    expect(sockets).toHaveLength(3);
    vi.advanceTimersByTime(1);
    expect(sockets).toHaveLength(4);
  });

  it("applies the jitter source: ±25 % around the base delay", () => {
    vi.useFakeTimers();
    const low = harness({ reconnectInitialMs: 1000, reconnectMaxMs: 8000, random: () => 0 });
    low.open();
    low.sockets[0]!.refuse();
    vi.advanceTimersByTime(749);
    expect(low.sockets).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(low.sockets).toHaveLength(2);
    const high = harness({ reconnectInitialMs: 1000, reconnectMaxMs: 8000, random: () => 1 });
    high.open();
    high.sockets[0]!.refuse();
    vi.advanceTimersByTime(1249);
    expect(high.sockets).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(high.sockets).toHaveLength(2);
  });

  it("gives up after maxReconnectAttempts consecutive attempts without a frame: unavailable, one warning, audio dropped", async () => {
    const { logger, at } = recordingLogger();
    const { open, sockets, session } = harness({ logger, maxReconnectAttempts: 3 });
    const handle = open();
    // The vendor accepts the upgrade and then closes with its code, so `open` alone must not reset the budget.
    for (let attempt = 0; attempt < 4; attempt += 1) {
      await until(() => sockets.length === attempt + 1);
      sockets[attempt]!.open();
      sockets[attempt]!.serverClose(1011, "Internal server error");
    }
    await tick(20);
    expect(sockets).toHaveLength(4); // the first connect + 3 reconnects, then no more
    expect(session.voice?.status).toBe("unavailable");
    expect(at("warn", /gave up reconnecting/)).toHaveLength(1);
    expect(at("warn", /reconnecting$/)).toHaveLength(4);
    push(handle, 50);
    await tick(10);
    expect(sockets).toHaveLength(4);
    await handle.close();
  });

  it("waits for a free stream when the vendor is full (4030, 1013): asked again at the long interval, on a budget of its own", async () => {
    vi.useFakeTimers();
    const { logger, at } = recordingLogger();
    const { open, sockets, session } = harness({ logger, reconnectInitialMs: 1000, reconnectMaxMs: 8000, maxReconnectAttempts: 1, maxBusyAttempts: 3, random: () => 0.5 });
    open();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      sockets[attempt]!.open();
      sockets[attempt]!.serverClose(attempt === 1 ? 1013 : 4030, "Concurrent request limit reached. Please retry after your in-flight requests complete.");
      // Not the short first step of the backoff: the long interval straight away.
      vi.advanceTimersByTime(7999);
      expect(sockets).toHaveLength(attempt + 1);
      vi.advanceTimersByTime(1);
      expect(sockets).toHaveLength(attempt + 2);
      expect(session.voice?.status).toBe("analyzing");
    }
    // Far past the budget of a broken connection (1), and not a warning each time.
    expect(at("info", /no free stream/)).toHaveLength(3);
    expect(at("warn", /reconnecting$/)).toHaveLength(0);
    sockets[3]!.open();
    sockets[3]!.serverClose(4030, "Concurrent request limit reached. Please retry after your in-flight requests complete.");
    vi.advanceTimersByTime(20_000);
    expect(sockets).toHaveLength(4);
    expect(session.voice?.status).toBe("unavailable");
    expect(at("warn", /gave up reconnecting/)).toHaveLength(1);
  });

  it("a slot that frees is used: the stream starts and the waiting budget is whole again", async () => {
    const { open, sockets, session } = harness({ maxBusyAttempts: 2 });
    open();
    for (let round = 0; round < 3; round += 1) {
      const busy = sockets.length - 1;
      sockets[busy]!.open();
      sockets[busy]!.serverClose(4030, "Concurrent request limit reached.");
      await until(() => sockets.length === busy + 2);
      sockets[busy + 1]!.open();
      sockets[busy + 1]!.frame(round * 1000, (round + 1) * 1000, "non-synthetic", 0.9);
      sockets[busy + 1]!.serverClose(4030, "Concurrent request limit reached.");
      await until(() => sockets.length === busy + 3);
    }
    expect(session.voice?.status).toBe("analyzing");
  });

  it("replaces a socket that accepts audio without delivering it, so the queue cannot grow without bound", async () => {
    const { logger, at } = recordingLogger();
    const { open, sockets, session } = harness({ logger, stallBufferMs: 1000, coalesceMs: 20 });
    const handle = open();
    sockets[0]!.open();
    push(handle, 5);
    expect(sockets[0]!.binary().length).toBeGreaterThan(0);
    // 1 s of μ-law is 8000 bytes: the socket now reports more than that still unsent.
    sockets[0]!.bufferedAmount = 8001;
    const sentBefore = sockets[0]!.binary().length;
    push(handle, 5);
    expect(sockets[0]!.terminated).toBe(true);
    expect(sockets[0]!.binary()).toHaveLength(sentBefore);
    expect(at("warn", /socket stalled; reconnecting/)).toHaveLength(1);
    await until(() => sockets.length === 2);
    sockets[1]!.open();
    // What was pending went to the new connection.
    expect(sockets[1]!.binary().length).toBeGreaterThan(0);
    expect(session.voice?.status).toBe("analyzing");
    await handle.close();
  });

  it("counts a handshake that fails and a factory that throws as failed attempts too", async () => {
    const sockets: FakeSocket[] = [];
    let calls = 0;
    const { open, session } = harness({
      maxReconnectAttempts: 2,
      socketFactory: (url) => {
        calls += 1;
        if (calls === 2) throw new Error(`Invalid URL: ${url}`);
        const socket = new FakeSocket(url);
        sockets.push(socket);
        return socket;
      },
    });
    open();
    sockets[0]!.refuse();
    await until(() => sockets.length === 2);
    expect(calls).toBe(3);
    sockets[1]!.refuse();
    await until(() => session.voice?.status === "unavailable");
    expect(calls).toBe(3);
  });

  it("a frame resets the budget, so a later blip gets all its attempts again", async () => {
    const { open, sockets, session } = harness({ maxReconnectAttempts: 2 });
    open();
    sockets[0]!.refuse();
    await until(() => sockets.length === 2);
    sockets[1]!.refuse(); // second consecutive failure: none left
    await until(() => sockets.length === 3);
    sockets[2]!.open();
    sockets[2]!.frame(0, 1000, "no-content", 1); // proof the stream works
    sockets[2]!.serverClose(1011, "Internal server error");
    await until(() => sockets.length === 4);
    sockets[3]!.refuse();
    await until(() => sockets.length === 5);
    expect(session.voice?.status).toBe("analyzing");
    sockets[4]!.refuse();
    await until(() => session.voice?.status === "unavailable");
    expect(sockets).toHaveLength(5);
  });

  it("carries the call's speech across a reconnect although the vendor's timestamps start again at zero", async () => {
    const { open, sockets, session } = harness();
    const handle = open();
    sockets[0]!.open();
    sockets[0]!.frame(0, 4000, "synthetic", 0.9);
    expect(session.voice).toMatchObject({ status: "analyzing", speechMs: 4000 });
    sockets[0]!.serverClose(1006);
    // Audio that arrives while reconnecting waits for the new socket.
    const during = push(handle, 30);
    await until(() => sockets.length === 2);
    sockets[1]!.open();
    expect(sockets[1]!.binary()).toHaveLength(1);
    expect(sockets[1]!.binary()[0]!.equals(during)).toBe(true);
    sockets[1]!.frame(0, 4000, "synthetic", 0.9);
    expect(session.voice).toMatchObject({ status: "synthetic", speechMs: 8000, syntheticShare: 1 });
  });

  it("stops reconnecting once closed", async () => {
    const { open, sockets } = harness({ reconnectInitialMs: 5, reconnectMaxMs: 5 });
    const handle = open();
    sockets[0]!.refuse();
    await handle.close();
    await tick(30);
    expect(sockets).toHaveLength(1);
  });
});

describe("shutdown", () => {
  it("detector.close() destroys every socket at once — no end-of-stream, no grace wait — and opens nothing afterwards", async () => {
    const { detector, newSession, sockets } = harness({ closeGraceMs: 60_000 });
    const sessions = [newSession(), newSession(), newSession()];
    const handles = sessions.map((session) => detector.open(session));
    sockets[0]!.open();
    sockets[1]!.open();
    push(handles[0]!, 5);
    // One handle is already waiting for `done` with a minute of grace: shutdown must not wait for it.
    const draining = handles[1]!.close();
    const started = Date.now();
    await detector.close();
    await draining;
    expect(Date.now() - started).toBeLessThan(1000);
    expect(sockets.map((socket) => socket.terminated)).toEqual([true, true, true]);
    expect(sockets[0]!.text()).toEqual([]);
    expect(sockets[2]!.sent).toHaveLength(0);
    // Analysing calls are left for the session's own end to settle; nothing is reported as unavailable.
    expect(sessions.map((session) => session.voice?.status)).toEqual(["analyzing", "analyzing", "analyzing"]);

    push(handles[0]!, 50, 5);
    detector.open(newSession());
    await Promise.all(handles.map((handle) => handle.close()));
    await tick(10);
    expect(sockets).toHaveLength(3);
    await expect(detector.close()).resolves.toBeUndefined();
  });

  it("falls back to close() for a socket without terminate()", async () => {
    const closed: number[] = [];
    const { detector, session } = harness({
      socketFactory: () => ({ on: () => undefined, send: () => undefined, close: (code?: number) => void closed.push(code ?? 0) }),
    });
    detector.open(session);
    await detector.close();
    expect(closed).toEqual([1001]);
  });
});

describe("the API key never reaches the log", () => {
  const ENCODED_KEY = "k/ey+with=odd&chars 7f3a9c1e5b2d";

  it("scrubModulateSecrets removes the key in every spelling and any api_key value, and caps the length", () => {
    expect(scrubModulateSecrets(`Invalid API key: ${MODULATE_TEST_KEY}.`, MODULATE_TEST_KEY)).toBe("Invalid API key: [redacted].");
    expect(scrubModulateSecrets(`GET ${DOCUMENTED_URL} failed`, MODULATE_TEST_KEY)).toBe(
      "GET wss://platform.modulate.ai/api/velma-2-synthetic-voice-detection-streaming?api_key=[redacted]&audio_format=mulaw&sample_rate=8000&num_channels=1 failed",
    );
    // Someone else's key in an api_key= value is masked too.
    expect(scrubModulateSecrets("retry with ?API_KEY=some-other-key&x=1", MODULATE_TEST_KEY)).toBe("retry with ?api_key=[redacted]&x=1");
    const url = buildVoiceStreamUrl(MODULATE_VOICE_STREAMING_URL, ENCODED_KEY);
    for (const text of [url, ENCODED_KEY, encodeURIComponent(ENCODED_KEY), `x ${new URL(url).search} y`]) {
      const scrubbed = scrubModulateSecrets(text, ENCODED_KEY)!;
      expect(scrubbed).not.toContain(ENCODED_KEY);
      expect(scrubbed).not.toContain(encodeURIComponent(ENCODED_KEY));
      expect(scrubbed).not.toContain("7f3a9c1e5b2d");
    }
    expect(scrubModulateSecrets("x".repeat(300), MODULATE_TEST_KEY)).toHaveLength(200);
    expect(scrubModulateSecrets("Insufficient credits.", MODULATE_TEST_KEY)).toBe("Insufficient credits.");
    expect(scrubModulateSecrets(undefined, MODULATE_TEST_KEY)).toBeUndefined();
    expect(scrubModulateSecrets(new Error(MODULATE_TEST_KEY), MODULATE_TEST_KEY)).toBeUndefined();
  });

  it.each([MODULATE_TEST_KEY, ENCODED_KEY])("every failure path with a recording logger: no key, no URL, no Error object (key %#)", async (apiKey) => {
    const { logger, entries, text } = recordingLogger();
    const url = buildVoiceStreamUrl(MODULATE_VOICE_STREAMING_URL, apiKey);
    /** An error as a socket library can produce it: the request URL in the message and on the object. */
    const leaky = (what: string): Error => Object.assign(new Error(`${what}: ${url}`), { url, request: { path: new URL(url).search } });
    let failFactory = false;
    const sockets: FakeSocket[] = [];
    const { detector, newSession, clock } = harness(
      {
        logger,
        coolDownMs: 1000,
        maxReconnectAttempts: 2,
        socketFactory: (target) => {
          if (failFactory) throw leaky("Invalid URL");
          const socket = new FakeSocket(target);
          sockets.push(socket);
          return socket;
        },
      },
      { apiKey, maxStreamMs: 1000 },
    );
    const next = (): { session: CallSession; handle: VoiceDetectorHandle; socket: FakeSocket } => {
      const session = newSession();
      const handle = detector.open(session);
      return { session, handle, socket: sockets.at(-1)! };
    };

    // 1. Every documented close code, each with an error text and a close reason that echo the key and the URL.
    for (const code of Object.keys(MODULATE_CLOSE_CODES).map(Number)) {
      const { socket } = next();
      socket.open();
      socket.emit("error", leaky("socket error"));
      socket.serverClose(code, `Invalid API key '${apiKey}' (api_key=${apiKey}) for ${url}`, `bad key ${apiKey} ${url}`);
      clock.advance(1000); // past any cool-down, so the next call connects
    }
    // 2. A handshake that never opens, and a code the vendor does not document, with only a close reason.
    const refused = next();
    refused.socket.refuse(leaky("Unexpected server response: 401"));
    const odd = next();
    odd.socket.open();
    odd.socket.serverClose(4999, undefined, `go away ${apiKey} ${url}`);
    // 3. Retries until the call gives up, the factory throwing on the way.
    const doomed = next();
    doomed.socket.refuse(leaky("connect ECONNREFUSED"));
    failFactory = true;
    await until(() => doomed.session.voice?.status === "unavailable");
    failFactory = false;
    // 4. A send that throws, on the audio path and on the end-of-stream path.
    const broken = next();
    broken.socket.open();
    broken.socket.failSend = leaky("write EPIPE");
    push(broken.handle, 20);
    await broken.handle.close();
    // 5. The ordinary paths: the cap, a synthetic verdict, a refusal while finishing, shutdown.
    const capped = next();
    capped.socket.open();
    push(capped.handle, 60);
    capped.socket.serverClose(4002, `Audio data does not match the declared audio_format. ${url}`);
    const latched = next();
    latched.socket.open();
    latched.socket.frame(0, 3000, "synthetic", 0.99);
    latched.socket.frame(3000, 6000, "synthetic", 0.99);
    latched.socket.done(6000, 2);
    const live = next();
    live.socket.open();
    clock.advance(1000);
    await tick(20);
    await detector.close();

    const output = text();
    // The paths above really were exercised and logged…
    for (const expected of ["cool-down", "not retried", "reconnecting", "gave up reconnecting", "connect failed", "send failed", "closed while finishing", "judged the caller's voice synthetic", "audio cap", "voice detector closed"]) {
      expect(output).toContain(expected);
    }
    expect(output).toContain("[redacted]");
    // …and none of them carried the key, in any spelling, or the query string, or a raw Error.
    expect(output).not.toContain(apiKey);
    expect(output).not.toContain(encodeURIComponent(apiKey));
    expect(output).not.toContain(new URLSearchParams({ k: apiKey }).toString().slice(2));
    expect(output).not.toContain("7f3a9c1e5b2d");
    expect(output).not.toMatch(/api_key=(?!\[redacted\])/);
    expect(entries.some((entry) => containsError(entry.fields) || containsError(entry.bindings))).toBe(false);
    // What is logged instead: the provider and the call, on every line.
    expect(entries.every((entry) => entry.bindings["provider"] === MODULATE_VOICE_PROVIDER)).toBe(true);
    expect(entries.filter((entry) => entry.bindings["callId"] === undefined).every((entry) => /cool-down/.test(entry.message ?? ""))).toBe(true);
  });
});

describe("against a real WebSocket server speaking the documented protocol (the default socket factory)", () => {
  let server: FakeModulateServer | undefined;
  afterEach(async () => {
    await server?.close();
    server = undefined;
  });

  it("binary audio frames, then a zero-length TEXT frame; frames and done come back and the session is assessed", async () => {
    server = await startModulateServer({
      onEndOfStream: (socket, connection) =>
        replyDone(socket, connection, [
          { start_time_ms: 0, end_time_ms: 4000, verdict: "synthetic", confidence: 0.97 },
          { start_time_ms: 4000, end_time_ms: 8000, verdict: "no-content", confidence: 1 },
          { start_time_ms: 8000, end_time_ms: 12000, verdict: "synthetic", confidence: 0.93 },
        ]),
    });
    const clock = new FakeClock();
    const session = new CallSession(
      { deviceId: "device-1", line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: clock.now(), status: "in_progress" },
      clock.now,
    );
    // No socketFactory: this is `new WebSocket(url)` from `ws`, as in production.
    const detector = createVoiceDetector({ config: testVoiceConfig(), logger: silentLogger(), url: server.url });
    detectors.push(detector);
    const handle = detector.open(session);
    // 8 s pushed before the socket is open (buffered), then 500 ms once it is (coalesced), then the end.
    const early = push(handle, 400);
    await until(() => (server?.connections[0]?.messages.length ?? 0) >= 1, 3000);
    const late = push(handle, 25, 400);
    await handle.close();

    expect(server.connections).toHaveLength(1);
    const connection = server.connections[0]!;
    // The handshake: the documented path and query, and no header that carries the key.
    expect(connection.requestUrl).toBe(`/api/velma-2-synthetic-voice-detection-streaming?api_key=${MODULATE_TEST_KEY}&audio_format=mulaw&sample_rate=8000&num_channels=1`);
    expect(JSON.stringify(connection.headers)).not.toContain(MODULATE_TEST_KEY);
    expect(Object.keys(connection.headers).some((name) => /key|authorization/i.test(name) && name !== "sec-websocket-key")).toBe(false);

    // The stream: only binary frames, carrying exactly the bytes pushed, then one text frame of length zero.
    const last = connection.messages.at(-1)!;
    expect(last.binary).toBe(false);
    expect(last.data.length).toBe(0);
    const audio = connection.messages.slice(0, -1);
    expect(audio.every((message) => message.binary)).toBe(true);
    expect(audio.map((message) => message.data.length)).toEqual([64_000, 1600, 1600, 800]);
    expect(Buffer.concat(audio.map((message) => message.data)).equals(Buffer.concat([early, late]))).toBe(true);

    // The vendor's frames reached the session through the aggregator: 8 s of speech (silence excluded), synthetic.
    expect(session.voice).toMatchObject({ status: "synthetic", syntheticShare: 1, speechMs: 8000, provider: MODULATE_VOICE_PROVIDER });
    expect(session.voice?.confidence).toBeCloseTo((2000 * 0.97 + 4000 * 0.93) / 6000, 10);
  });

  it("a refused connection (error message, then 4001) makes the call unavailable and is not retried", async () => {
    server = await startModulateServer({
      onConnect: (socket) => {
        socket.send(JSON.stringify({ type: "error", error: "Invalid API key." }));
        socket.close(4001);
      },
    });
    const { logger, text, at } = recordingLogger();
    const clock = new FakeClock();
    const session = new CallSession(
      { deviceId: "device-1", line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: clock.now(), status: "in_progress" },
      clock.now,
    );
    const detector = createVoiceDetector({ config: testVoiceConfig(), logger, url: server.url, reconnectInitialMs: 1 });
    detectors.push(detector);
    detector.open(session);
    await until(() => session.voice?.status === "unavailable", 3000);
    await tick(50);
    expect(server.connections).toHaveLength(1);
    expect(at("warn", /cool-down/)).toHaveLength(1);
    expect(at("info", /refused for the account/)[0]).toMatchObject({ fields: { code: 4001, detail: "Invalid API key." } });
    expect(text()).not.toContain(MODULATE_TEST_KEY);
  });

  it("a server that is not there is retried and then given up on, without the key in the log", async () => {
    const { logger, text, at } = recordingLogger();
    const clock = new FakeClock();
    const session = new CallSession(
      { deviceId: "device-1", line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: clock.now(), status: "in_progress" },
      clock.now,
    );
    // Port 9 (discard) on localhost: the connection is refused.
    const detector = createVoiceDetector({
      config: testVoiceConfig(),
      logger,
      url: "ws://127.0.0.1:9/api/velma-2-synthetic-voice-detection-streaming",
      reconnectInitialMs: 1,
      reconnectMaxMs: 2,
      maxReconnectAttempts: 2,
    });
    detectors.push(detector);
    detector.open(session);
    await until(() => session.voice?.status === "unavailable", 5000);
    expect(at("warn", /gave up reconnecting/)).toHaveLength(1);
    expect(text()).not.toContain(MODULATE_TEST_KEY);
    expect(text()).not.toContain("api_key=");
  });
});

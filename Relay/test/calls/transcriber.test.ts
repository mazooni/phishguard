import { EventEmitter } from "node:events";
import type { FastifyBaseLogger } from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_VAD,
  MULAW_TO_LINEAR,
  OPENAI_REALTIME_TRANSCRIPTION_URL,
  SilenceDetector,
  TRANSCRIPTION_PROMPT,
  buildSessionUpdate,
  createTranscriber,
  decodeMulaw,
  usesClientTurnDetection,
  type TranscriberOptions,
  type TranscriptionSocket,
} from "../../src/calls/openai/transcriber.js";
import { CallSession } from "../../src/calls/session.js";
import type { Speaker, TranscriberHandle } from "../../src/calls/types.js";
import { FakeClock } from "../helpers.js";
import { CALLER_NUMBER, GUARD_NUMBER, silentLogger, testOpenAIConfig } from "./fakes.js";
import { redactApiKeys } from "../../src/calls/openai/transcriber.js";

// MARK: fakes

class FakeSocket extends EventEmitter implements TranscriptionSocket {
  readonly sent: string[] = [];
  closed = false;
  closeCode: number | undefined;

  constructor(
    readonly url: string,
    readonly headers: Record<string, string>,
  ) {
    super();
  }

  send(data: string): void {
    if (this.closed) throw new Error("socket closed");
    this.sent.push(data);
  }

  close(code?: number): void {
    if (this.closed) return;
    this.closed = true;
    this.closeCode = code;
    queueMicrotask(() => this.emit("close", code ?? 1005));
  }

  /** Simulates the server: open the socket. */
  open(): void {
    this.emit("open");
  }

  /** Simulates the server: a JSON event frame (as `ws` delivers it, a Buffer). */
  event(event: Record<string, unknown>): void {
    this.emit("message", Buffer.from(JSON.stringify(event)));
  }

  /** Simulates a dropped connection. */
  drop(code = 1006): void {
    this.closed = true;
    this.emit("close", code);
  }

  messages(): Record<string, unknown>[] {
    return this.sent.map((frame) => JSON.parse(frame) as Record<string, unknown>);
  }

  ofType(type: string): Record<string, unknown>[] {
    return this.messages().filter((message) => message["type"] === type);
  }
}

// MARK: μ-law synthesis (standard G.711 encoder, the inverse of the relay's table)

function linearToMulaw(sample: number): number {
  const BIAS = 0x84;
  const CLIP = 32_635;
  let value = Math.max(-32_768, Math.min(32_767, Math.round(sample)));
  const sign = value < 0 ? 0x80 : 0;
  if (value < 0) value = -value;
  if (value > CLIP) value = CLIP;
  value += BIAS;
  let exponent = 7;
  for (let mask = 0x4000; (value & mask) === 0 && exponent > 0; exponent -= 1, mask >>= 1) {
    // find the segment
  }
  const mantissa = (value >> (exponent + 3)) & 0x0f;
  return ~(sign | (exponent << 4) | mantissa) & 0xff;
}

/** `ms` of audio: a 440 Hz tone at the given amplitude, or silence when amplitude is 0. */
function mulaw(ms: number, amplitude: number, phase = 0): Buffer {
  const samples = ms * 8;
  const bytes = Buffer.alloc(samples);
  for (let index = 0; index < samples; index += 1) {
    const value = amplitude === 0 ? 0 : amplitude * Math.sin((2 * Math.PI * 440 * (index + phase)) / 8000);
    bytes[index] = linearToMulaw(value);
  }
  return bytes;
}

/** Feeds `bytes` to a handle in 20 ms Twilio-sized payloads and returns the base64 frames pushed. */
function feed(handle: TranscriberHandle, bytes: Buffer): string[] {
  const frames: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 160) {
    const frame = bytes.subarray(offset, Math.min(bytes.length, offset + 160)).toString("base64");
    frames.push(frame);
    handle.pushAudio(frame);
  }
  return frames;
}

// MARK: harness

interface Harness {
  clock: FakeClock;
  session: CallSession;
  sockets: FakeSocket[];
  handle: TranscriberHandle;
  open(speaker?: Speaker): TranscriberHandle;
  latest(): FakeSocket;
}

const handles: TranscriberHandle[] = [];

function harness(model = "gpt-live-transcribe", options: Partial<TranscriberOptions> = {}, speaker: Speaker = "caller"): Harness {
  const clock = new FakeClock();
  const session = new CallSession(
    { deviceId: "device-1", line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: clock.now() },
    clock.now,
  );
  const sockets: FakeSocket[] = [];
  const transcriber = createTranscriber({
    config: testOpenAIConfig({ transcribeModel: model }),
    logger: silentLogger(),
    socketFactory: (url, headers) => {
      const socket = new FakeSocket(url, headers);
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
  const open = (who: Speaker = speaker): TranscriberHandle => {
    const created = transcriber.open(session, who);
    handles.push(created);
    return created;
  };
  const handle = open(speaker);
  return { clock, session, sockets, handle, open, latest: () => sockets[sockets.length - 1]! };
}

function tick(ms = 0): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Polls `condition` every millisecond for up to `timeoutMs` (real timers: the backoff runs on them). */
async function until(condition: () => boolean, timeoutMs = 500): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("until: condition not met in time");
    await tick(1);
  }
}

/** A pino-shaped logger that records `error` and `warn` messages; `child()` returns itself. */
function recordingLogger(): { logger: FastifyBaseLogger; errors: string[]; warns: string[] } {
  const errors: string[] = [];
  const warns: string[] = [];
  const noop = (): void => undefined;
  const logger = {
    level: "silent",
    fatal: noop,
    error: (_fields: unknown, message?: string): void => {
      errors.push(message ?? "");
    },
    warn: (_fields: unknown, message?: string): void => {
      warns.push(message ?? "");
    },
    info: noop,
    debug: noop,
    trace: noop,
    silent: noop,
    child: () => logger,
  } as unknown as FastifyBaseLogger;
  return { logger, errors, warns };
}

afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
});

// MARK: tests

describe("buildSessionUpdate", () => {
  it("is exactly the transcription session for gpt-live-transcribe (no VAD, languages array, μ-law)", () => {
    expect(buildSessionUpdate("gpt-live-transcribe")).toEqual({
      type: "session.update",
      session: {
        type: "transcription",
        audio: {
          input: {
            format: { type: "audio/pcmu" },
            transcription: { model: "gpt-live-transcribe", prompt: TRANSCRIPTION_PROMPT, languages: ["en"] },
            turn_detection: null,
          },
        },
      },
    });
  });

  it("is exactly the server_vad session for gpt-4o-mini-transcribe (singular language)", () => {
    expect(buildSessionUpdate("gpt-4o-mini-transcribe")).toEqual({
      type: "session.update",
      session: {
        type: "transcription",
        audio: {
          input: {
            format: { type: "audio/pcmu" },
            transcription: { model: "gpt-4o-mini-transcribe", prompt: TRANSCRIPTION_PROMPT, language: "en" },
            turn_detection: { type: "server_vad", silence_duration_ms: 600, prefix_padding_ms: 300 },
          },
        },
      },
    });
  });

  it("omits the prompt for gpt-realtime-whisper and knows which models need client-side turns", () => {
    const update = buildSessionUpdate("gpt-realtime-whisper") as { session: { audio: { input: Record<string, unknown> } } };
    expect(update.session.audio.input["transcription"]).toEqual({ model: "gpt-realtime-whisper", language: "en" });
    expect(update.session.audio.input["turn_detection"]).toBeNull();
    expect(usesClientTurnDetection("gpt-live-transcribe")).toBe(true);
    expect(usesClientTurnDetection("gpt-transcribe")).toBe(true);
    expect(usesClientTurnDetection("gpt-transcribe-2026-09-01")).toBe(true);
    expect(usesClientTurnDetection("gpt-4o-mini-transcribe")).toBe(false);
  });
});

describe("μ-law and the silence detector", () => {
  it("decodes the standard G.711 table (silence is 0xFF, round trip within 3 %)", () => {
    expect(MULAW_TO_LINEAR[0xff]).toBe(0);
    expect(MULAW_TO_LINEAR[0x7f]).toBe(0);
    for (const value of [100, 1000, 8000, 30000, -500, -12000]) {
      const decoded = MULAW_TO_LINEAR[linearToMulaw(value)]!;
      expect(Math.abs(decoded - value)).toBeLessThanOrEqual(Math.abs(value) * 0.03 + 4);
    }
    expect([...decodeMulaw(Buffer.from([0xff, 0xff]))]).toEqual([0, 0]);
  });

  it("commits after 700 ms of silence following speech, and only then", () => {
    const vad = new SilenceDetector();
    expect(vad.feed(mulaw(1000, 8000))).toEqual([]);
    expect(vad.feed(mulaw(680, 0))).toEqual([]);
    expect(vad.feed(mulaw(40, 0))).toEqual(["commit"]);
    expect(vad.feed(mulaw(2000, 0))).toEqual([]);
  });

  it("does not commit a blip shorter than 250 ms of speech", () => {
    const vad = new SilenceDetector();
    expect(vad.feed(mulaw(100, 8000))).toEqual([]);
    expect(vad.feed(mulaw(1000, 0))).toEqual([]);
  });

  it("commits after 8 s of continuous speech and clears a buffer that is only silence", () => {
    const vad = new SilenceDetector();
    expect(vad.feed(mulaw(7980, 8000))).toEqual([]);
    expect(vad.feed(mulaw(40, 8000))).toEqual(["commit"]);
    expect(vad.feed(mulaw(DEFAULT_VAD.silenceClearMs, 0))).toEqual(["clear"]);
  });

  it("caps the adaptive noise floor so a rising line level cannot lock speech out", () => {
    // A staircase of ever-louder "noise": each step sits under the current threshold, so an unbounded floor would
    // climb with it until real speech (amplitude 8000, RMS ≈ 5660) falls under the threshold and is never committed.
    const staircase = (vad: SilenceDetector): string[] => {
      const decisions: string[] = [];
      for (const amplitude of [700, 2000, 5500]) decisions.push(...vad.feed(mulaw(5000, amplitude)));
      decisions.push(...vad.feed(mulaw(1000, 8000)), ...vad.feed(mulaw(720, 0)));
      return decisions;
    };
    expect(staircase(new SilenceDetector({ maxNoiseFloor: 1_000_000 }))).not.toContain("commit");
    expect(staircase(new SilenceDetector())).toContain("commit");
  });

  it("handles payloads that do not align with 20 ms frames", () => {
    const vad = new SilenceDetector();
    const speech = mulaw(1000, 8000);
    for (let offset = 0; offset < speech.length; offset += 77) vad.feed(speech.subarray(offset, offset + 77));
    expect(vad.feed(mulaw(720, 0))).toEqual(["commit"]);
  });
});

describe("connection and session setup", () => {
  it("connects to the transcription intent URL with the bearer header and sends session.update on open", () => {
    const { sockets } = harness();
    expect(sockets).toHaveLength(1);
    const socket = sockets[0]!;
    expect(socket.url).toBe(OPENAI_REALTIME_TRANSCRIPTION_URL);
    expect(socket.headers).toEqual({ Authorization: "Bearer sk-test" });
    expect(socket.sent).toHaveLength(0);
    socket.open();
    expect(socket.messages()[0]).toEqual(buildSessionUpdate("gpt-live-transcribe"));
  });

  it("sends the server_vad session for a VAD-capable model", () => {
    const { latest } = harness("gpt-4o-mini-transcribe");
    latest().open();
    expect(latest().messages()[0]).toEqual(buildSessionUpdate("gpt-4o-mini-transcribe"));
  });
});

describe("audio", () => {
  it("appends each payload untouched once the socket is open", () => {
    const { handle, latest } = harness();
    latest().open();
    const frames = feed(handle, mulaw(60, 8000));
    const appends = latest().ofType("input_audio_buffer.append");
    expect(appends.map((message) => message["audio"])).toEqual(frames);
    expect(appends[0]).toEqual({ type: "input_audio_buffer.append", audio: frames[0] });
  });

  it("buffers audio pushed before the socket opens and replays it as one append", () => {
    const { handle, latest } = harness();
    const bytes = mulaw(200, 8000);
    feed(handle, bytes);
    expect(latest().sent).toHaveLength(0);
    latest().open();
    const appends = latest().ofType("input_audio_buffer.append");
    expect(appends).toHaveLength(1);
    expect(appends[0]?.["audio"]).toBe(bytes.toString("base64"));
  });

  it("commits on measured silence after speech and never commits an empty buffer", () => {
    const { handle, latest } = harness();
    latest().open();
    feed(handle, mulaw(1000, 8000));
    expect(latest().ofType("input_audio_buffer.commit")).toHaveLength(0);
    feed(handle, mulaw(720, 0));
    expect(latest().ofType("input_audio_buffer.commit")).toHaveLength(1);
    // Twenty seconds of silence: no further commit; the silent buffer is cleared instead.
    feed(handle, mulaw(20_000, 0));
    expect(latest().ofType("input_audio_buffer.commit")).toHaveLength(1);
    expect(latest().ofType("input_audio_buffer.clear")).toHaveLength(1);
  });

  it("does not send commits for a server-VAD model", () => {
    const { handle, latest } = harness("gpt-4o-mini-transcribe");
    latest().open();
    feed(handle, mulaw(1000, 8000));
    feed(handle, mulaw(1000, 0));
    expect(latest().ofType("input_audio_buffer.commit")).toHaveLength(0);
    expect(latest().ofType("input_audio_buffer.append").length).toBeGreaterThan(50);
  });

  it("close() without any audio sends no commit", async () => {
    const { handle, latest } = harness();
    latest().open();
    await handle.close();
    expect(latest().ofType("input_audio_buffer.commit")).toHaveLength(0);
    expect(latest().closed).toBe(true);
  });
});

describe("server events → segments", () => {
  it("turns deltas into partials and completed into the final segment, ids prefixed with the speaker", () => {
    const { session, latest, clock } = harness();
    latest().open();
    clock.advance(1500);
    latest().event({ type: "session.created", session: { id: "sess_1" } });
    latest().event({ type: "session.updated", session: {} });
    latest().event({ type: "conversation.item.input_audio_transcription.delta", item_id: "item_001", content_index: 0, delta: "Hello," });
    expect(session.segments).toEqual([{ id: "caller-item_001", speaker: "caller", text: "Hello,", atMs: 1500, final: false }]);
    latest().event({ type: "conversation.item.input_audio_transcription.delta", item_id: "item_001", delta: " grandma" });
    expect(session.segments[0]?.text).toBe("Hello, grandma");
    clock.advance(800);
    latest().event({
      type: "conversation.item.input_audio_transcription.completed",
      item_id: "item_001",
      content_index: 0,
      transcript: "Hello, grandma.",
      usage: { type: "duration", seconds: 2 },
    });
    expect(session.segments).toEqual([{ id: "caller-item_001", speaker: "caller", text: "Hello, grandma.", atMs: 1500, final: true }]);
  });

  it("stamps atMs with the elapsed time when the item's first audio was appended", () => {
    const { session, handle, latest, clock } = harness();
    latest().open();
    clock.advance(4000);
    feed(handle, mulaw(1000, 8000));
    clock.advance(1000);
    feed(handle, mulaw(720, 0));
    clock.advance(500);
    latest().event({ type: "input_audio_buffer.committed", item_id: "item_007", previous_item_id: null });
    latest().event({ type: "conversation.item.input_audio_transcription.completed", item_id: "item_007", transcript: "Hi there" });
    expect(session.segments[0]).toMatchObject({ id: "caller-item_007", atMs: 4000, final: true });
  });

  it("keeps commit → committed pairing when a delta arrives before the commit is acknowledged (live models)", () => {
    const { session, handle, latest, clock } = harness();
    latest().open();
    // Turn A: audio, a delta for its future item while it streams, then the commit and its acknowledgement.
    clock.advance(1000);
    feed(handle, mulaw(1000, 8000));
    latest().event({ type: "conversation.item.input_audio_transcription.delta", item_id: "item_A", delta: "Hel" });
    clock.advance(1000);
    feed(handle, mulaw(720, 0));
    expect(latest().ofType("input_audio_buffer.commit")).toHaveLength(1);
    latest().event({ type: "input_audio_buffer.committed", item_id: "item_A", previous_item_id: null });
    latest().event({ type: "conversation.item.input_audio_transcription.completed", item_id: "item_A", transcript: "Hello" });
    // Turn B: no delta at all; its atMs must come from its own commit, not from turn A's stale queue entry.
    clock.advance(5000);
    feed(handle, mulaw(1000, 8000));
    feed(handle, mulaw(720, 0));
    expect(latest().ofType("input_audio_buffer.commit")).toHaveLength(2);
    latest().event({ type: "input_audio_buffer.committed", item_id: "item_B", previous_item_id: "item_A" });
    latest().event({ type: "conversation.item.input_audio_transcription.completed", item_id: "item_B", transcript: "World" });
    expect(session.segments.map((segment) => [segment.id, segment.atMs, segment.final])).toEqual([
      ["caller-item_A", 1000, true],
      ["caller-item_B", 7000, true],
    ]);
  });

  it("skips empty completions, drops failed items and survives error and junk frames", () => {
    const { session, latest } = harness();
    latest().open();
    latest().event({ type: "conversation.item.input_audio_transcription.completed", item_id: "item_2", transcript: "   " });
    latest().event({ type: "conversation.item.input_audio_transcription.delta", item_id: "item_3", delta: "uh" });
    latest().event({
      type: "conversation.item.input_audio_transcription.failed",
      item_id: "item_3",
      error: { type: "transcription_error", code: "audio_unintelligible", message: "The audio could not be transcribed." },
    });
    latest().event({ type: "error", error: { type: "invalid_request_error", code: "invalid_event", message: "bad", param: null } });
    latest().emit("message", Buffer.from("not json"));
    expect(session.segments.filter((segment) => segment.final)).toHaveLength(0);
    expect(session.segments.map((segment) => segment.id)).toEqual(["caller-item_3"]);
  });

  it("masks an API key echoed in an error event before it reaches the log", () => {
    // Observed with a bad key on 2026-09-23: OpenAI's error text quotes the credential it rejected.
    const lines: string[] = [];
    const noop = (): void => undefined;
    const logger = {
      level: "warn",
      fatal: noop,
      error: noop,
      warn: (obj: unknown, msg?: string): void => {
        lines.push(`${JSON.stringify(obj)} ${msg ?? ""}`);
      },
      info: noop,
      debug: noop,
      trace: noop,
      silent: noop,
      child: () => logger,
    } as unknown as FastifyBaseLogger;
    const { latest } = harness("gpt-live-transcribe", { logger });
    latest().open();
    latest().event({
      type: "error",
      error: { type: "invalid_request_error", code: "invalid_api_key", message: "Incorrect API key provided: sk-fake. You can find your API key at https://platform.openai.com/account/api-keys.", param: null },
    });
    const output = lines.join("\n");
    expect(output).toContain("transcriber error event");
    expect(output).toContain("invalid_api_key");
    expect(output).toContain("sk-[redacted]");
    expect(output).not.toContain("sk-fake");

    expect(redactApiKeys("key sk-proj-AbC_123-xyz ok")).toBe("key sk-[redacted] ok");
    expect(redactApiKeys("no key here")).toBe("no key here");
    expect(redactApiKeys(undefined)).toBeUndefined();
    expect(redactApiKeys("x".repeat(300))).toHaveLength(200);
  });

  it("keeps segment ids unique across the caller and user tracks", () => {
    const { session, open, sockets } = harness();
    open("user");
    for (const socket of sockets) socket.open();
    sockets[0]!.event({ type: "conversation.item.input_audio_transcription.completed", item_id: "item_1", transcript: "caller words" });
    sockets[1]!.event({ type: "conversation.item.input_audio_transcription.completed", item_id: "item_1", transcript: "user words" });
    expect(session.segments.map((segment) => [segment.id, segment.speaker, segment.text])).toEqual([
      ["caller-item_1", "caller", "caller words"],
      ["user-item_1", "user", "user words"],
    ]);
  });

  it("uses speech_started offsets for atMs in server-VAD mode", () => {
    const { session, handle, latest, clock } = harness("gpt-4o-mini-transcribe");
    latest().open();
    clock.advance(10_000);
    feed(handle, mulaw(100, 8000));
    latest().event({ type: "input_audio_buffer.speech_started", item_id: "item_9", audio_start_ms: 2500 });
    latest().event({ type: "conversation.item.input_audio_transcription.completed", item_id: "item_9", transcript: "Yes" });
    expect(session.segments[0]?.atMs).toBe(12_500);
  });
});

describe("resilience", () => {
  it("reconnects after a dropped socket and replays the last two seconds of audio", async () => {
    const { handle, sockets } = harness();
    sockets[0]!.open();
    const early = mulaw(1000, 8000, 0);
    const recent = mulaw(2000, 8000, 8000);
    feed(handle, early);
    feed(handle, recent);
    sockets[0]!.drop();
    await tick(10);
    expect(sockets).toHaveLength(2);
    const replacement = sockets[1]!;
    expect(replacement.sent).toHaveLength(0);
    replacement.open();
    expect(replacement.messages()[0]).toEqual(buildSessionUpdate("gpt-live-transcribe"));
    const appends = replacement.ofType("input_audio_buffer.append");
    expect(appends).toHaveLength(1);
    const replayed = Buffer.from(String(appends[0]?.["audio"]), "base64");
    expect(replayed.length).toBe(16_000);
    expect(replayed.equals(recent)).toBe(true);
    // Later audio streams on the new socket.
    feed(handle, mulaw(20, 8000));
    expect(replacement.ofType("input_audio_buffer.append")).toHaveLength(2);
  });

  it("backs off between reconnect attempts and stops once closed", async () => {
    const { handle, sockets } = harness(undefined, { reconnectInitialMs: 2, reconnectMaxMs: 4 });
    sockets[0]!.drop();
    await tick(15);
    expect(sockets.length).toBeGreaterThanOrEqual(2);
    sockets[sockets.length - 1]!.drop();
    await tick(15);
    const before = sockets.length;
    expect(before).toBeGreaterThanOrEqual(3);
    await handle.close();
    sockets[sockets.length - 1]!.drop();
    await tick(15);
    expect(sockets).toHaveLength(before);
  });

  it("gives up after maxReconnectAttempts consecutive attempts that never open (a 401/429 upgrade), logs once and drops audio", async () => {
    const { logger, errors, warns } = recordingLogger();
    const { handle, sockets } = harness(undefined, { logger, reconnectInitialMs: 1, reconnectMaxMs: 2, maxReconnectAttempts: 3 });
    // The upgrade is refused every time: `ws` emits error + close without ever emitting open.
    for (let attempt = 0; attempt < 4; attempt += 1) {
      await until(() => sockets.length === attempt + 1);
      sockets[attempt]!.drop();
    }
    await tick(20);
    expect(sockets).toHaveLength(4); // the first connect + 3 reconnects, then no more
    expect(errors).toEqual([expect.stringContaining("gave up reconnecting")]);
    expect(warns.filter((message) => message.includes("reconnecting"))).toHaveLength(4);
    handle.pushAudio(mulaw(20, 8000).toString("base64")); // dropped: no socket, no ring buffer growth
    await tick(10);
    expect(sockets).toHaveLength(4);
    await handle.close();
    expect(sockets).toHaveLength(4);
  });

  it("resets the attempt count once a socket opens, so a later blip gets the full budget again", async () => {
    const { logger, errors } = recordingLogger();
    const { sockets } = harness(undefined, { logger, reconnectInitialMs: 1, reconnectMaxMs: 2, maxReconnectAttempts: 2 });
    sockets[0]!.drop();
    await until(() => sockets.length === 2);
    sockets[1]!.drop(); // second consecutive failure: one attempt left
    await until(() => sockets.length === 3);
    sockets[2]!.open(); // success resets the budget
    sockets[2]!.drop();
    await until(() => sockets.length === 4);
    sockets[3]!.drop();
    await until(() => sockets.length === 5);
    sockets[4]!.drop(); // second consecutive failure after the reset: gives up now
    await tick(20);
    expect(sockets).toHaveLength(5);
    expect(errors).toHaveLength(1);
  });

  it("rotates the session proactively: new socket, old one kept briefly for its last completions", async () => {
    const { session, handle, sockets } = harness(undefined, { rotateAfterMs: 1000, closeGraceMs: 20 });
    vi.useFakeTimers();
    sockets[0]!.open();
    feed(handle, mulaw(500, 8000));
    vi.advanceTimersByTime(1100);
    expect(sockets).toHaveLength(2);
    // The pending turn was committed on the old socket, which still delivers its completion.
    expect(sockets[0]!.ofType("input_audio_buffer.commit")).toHaveLength(1);
    sockets[0]!.event({ type: "conversation.item.input_audio_transcription.completed", item_id: "item_x", transcript: "last words" });
    expect(session.segments[0]?.text).toBe("last words");
    vi.advanceTimersByTime(50);
    expect(sockets[0]!.closed).toBe(true);
    sockets[1]!.open();
    expect(sockets[1]!.messages()[0]).toEqual(buildSessionUpdate("gpt-live-transcribe"));
    // Nothing is replayed after a planned rotation (the old socket already had it all); new audio flows on.
    expect(sockets[1]!.ofType("input_audio_buffer.append")).toHaveLength(0);
    feed(handle, mulaw(20, 8000));
    expect(sockets[1]!.ofType("input_audio_buffer.append")).toHaveLength(1);
  });

  it("rotates earlier when session.created announces a nearer expiry", () => {
    const { sockets, clock } = harness();
    vi.useFakeTimers();
    sockets[0]!.open();
    sockets[0]!.event({ type: "session.created", session: { id: "sess", expires_at: Math.floor(clock.now() / 1000) + 62 } });
    vi.advanceTimersByTime(2500);
    expect(sockets).toHaveLength(2);
  });
});

describe("close()", () => {
  it("commits pending audio, waits for the completion, then closes the socket", async () => {
    const { session, handle, latest } = harness(undefined, { closeGraceMs: 500 });
    latest().open();
    feed(handle, mulaw(300, 8000));
    const closing = handle.close();
    expect(latest().ofType("input_audio_buffer.commit")).toHaveLength(1);
    expect(latest().closed).toBe(false);
    latest().event({ type: "conversation.item.input_audio_transcription.completed", item_id: "item_last", transcript: "bye now" });
    await closing;
    expect(latest().closed).toBe(true);
    expect(session.segments.map((segment) => segment.text)).toEqual(["bye now"]);
    handle.pushAudio(mulaw(20, 8000).toString("base64"));
    expect(latest().ofType("input_audio_buffer.append")).toHaveLength(15);
  });

  it("gives up waiting after the grace period", async () => {
    const { handle, latest } = harness(undefined, { closeGraceMs: 20 });
    latest().open();
    feed(handle, mulaw(300, 8000));
    const started = Date.now();
    await handle.close();
    expect(Date.now() - started).toBeLessThan(1000);
    expect(latest().closed).toBe(true);
  });

  it("closes itself when the session ends", async () => {
    const { session, latest } = harness();
    latest().open();
    session.end("completed");
    await tick(5);
    expect(latest().closed).toBe(true);
  });

  it("is idempotent", async () => {
    const { handle, latest } = harness();
    latest().open();
    await Promise.all([handle.close(), handle.close()]);
    expect(latest().closed).toBe(true);
  });
});

/**
 * `npm run calls:voice-check -- <file.wav>` — a live smoke test of AI-voice detection against the REAL Modulate
 * streaming endpoint. The WAV is converted to what a phone call carries (8 kHz μ-law mono, 20 ms payloads: the
 * helpers of src/calls/audio.ts, no ffmpeg) and streamed at real-time pace through the relay's own client and
 * frame aggregator (src/calls/modulate/voiceDetector.ts) — the same code a live call runs, with the thresholds of
 * Relay/.env. Every frame the vendor returns is printed, then the assessment a call would have ended with.
 * A recording sampled above 8 kHz is low-pass filtered first, as the telephone network does before a call reaches
 * Twilio; without that, everything above 4 kHz would fold back into the band and the vendor would be judging
 * audio no call carries.
 *
 *   npm run calls:voice-check -- caller.wav [--channel 0] [--rate 1]
 *
 * Needs MODULATE_API_KEY (Relay/.env; the npm script loads it) and spends Modulate credits. Exits non-zero, with
 * the vendor's close code and what it means, when the stream is refused (bad key, no access to the model, no
 * credits, a rejected audio format, …). Neither the key nor the connection URL is ever printed.
 */

import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import type { FastifyBaseLogger } from "fastify";

import { MULAW_FRAME_MS, MULAW_SAMPLE_RATE, mulawEncode, parseWav, resample, splitFrames } from "../src/calls/audio.js";
import { loadCallsConfig, type VoiceDetectionConfig } from "../src/calls/config.js";
import {
  MODULATE_CLOSE_CODES,
  MODULATE_VOICE_PROVIDER,
  createVoiceDetector,
  type CloseCodePolicy,
  type VoiceSocketFactory,
} from "../src/calls/modulate/voiceDetector.js";
import { CallSession } from "../src/calls/session.js";
import type { CallVoiceAssessment } from "../src/calls/types.js";

export interface VoiceCheckIO {
  /** Arguments after the script name: `<file.wav> [--channel n] [--rate x]`. */
  argv: string[];
  env: NodeJS.ProcessEnv;
  out: (line: string) => void;
  /** Tests only: another endpoint (an in-process server) or socket factory, and a shorter wait for `done`. */
  url?: string;
  socketFactory?: VoiceSocketFactory;
  closeGraceMs?: number;
}

/** How long the script waits for the vendor's `done` after the last audio (the relay itself waits 1.5 s). */
const SCRIPT_CLOSE_GRACE_MS = 15_000;
/** How long the script waits for the connection before it starts the clock on the audio. */
const SCRIPT_CONNECT_WAIT_MS = 30_000;
/** Telephone band edge: the pass band ends here and the filter is well down by 4 kHz (half of 8 kHz). */
const TELEPHONE_CUTOFF_HZ = 3_400;
const TELEPHONE_TRANSITION_HZ = 800;

/**
 * Windowed-sinc (Hamming) low-pass at the telephone band edge, applied before the recording is brought down to
 * 8 kHz. Only for rates above 8 kHz; the cut-off is centred in the transition band so 4 kHz and above are
 * attenuated by the window's full stop-band (about 50 dB).
 */
export function telephoneLowPass(samples: Float32Array, sampleRate: number): Float32Array {
  if (sampleRate <= MULAW_SAMPLE_RATE || samples.length === 0) return samples;
  let taps = Math.ceil((3.3 * sampleRate) / TELEPHONE_TRANSITION_HZ);
  if (taps % 2 === 0) taps += 1;
  const half = (taps - 1) / 2;
  const cutoff = (TELEPHONE_CUTOFF_HZ + TELEPHONE_TRANSITION_HZ / 2) / sampleRate;
  const kernel = new Float64Array(taps);
  let sum = 0;
  for (let i = 0; i < taps; i += 1) {
    const n = i - half;
    const sinc = n === 0 ? 2 * cutoff : Math.sin(2 * Math.PI * cutoff * n) / (Math.PI * n);
    kernel[i] = sinc * (0.54 - 0.46 * Math.cos((2 * Math.PI * i) / (taps - 1)));
    sum += kernel[i]!;
  }
  for (let i = 0; i < taps; i += 1) kernel[i] = kernel[i]! / sum;
  const out = new Float32Array(samples.length);
  for (let i = 0; i < samples.length; i += 1) {
    const from = Math.max(0, i - half);
    const to = Math.min(samples.length - 1, i + half);
    let acc = 0;
    for (let j = from; j <= to; j += 1) acc += samples[j]! * kernel[j - i + half]!;
    out[i] = acc;
  }
  return out;
}
const USAGE =
  "usage: npm run calls:voice-check -- <file.wav> [--channel 0] [--rate 1]\n" +
  "  --channel  which channel of the WAV is the caller (default 0)\n" +
  "  --rate     playback speed, 1 = real time (default 1)\n" +
  "  MODULATE_API_KEY and the CALLS_AI_VOICE_* thresholds are read from Relay/.env.";

interface Args {
  file: string;
  channel: number;
  rate: number;
}

function parseArgs(argv: string[]): Args | string {
  let file: string | undefined;
  const options = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg.startsWith("--")) {
      const value = argv[i + 1];
      if (value === undefined) return `${arg} needs a value`;
      options.set(arg.slice(2), value);
      i += 1;
    } else if (!file) {
      file = arg;
    } else {
      return `unexpected argument ${arg}`;
    }
  }
  if (!file) return "missing <file.wav>";
  const channel = Number(options.get("channel") ?? "0");
  if (!Number.isInteger(channel) || channel < 0) return "--channel must be a channel index (0, 1, …)";
  const rate = Number(options.get("rate") ?? "1");
  if (!Number.isFinite(rate) || rate <= 0 || rate > 50) return "--rate must be between 0 and 50";
  return { file, channel, rate };
}

/** Only the variables voice detection reads, so an unrelated half-configured section cannot stop the check. */
function voiceEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const picked: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(env)) {
    if (name === "MODULATE_API_KEY" || name.startsWith("CALLS_AI_VOICE_")) picked[name] = value;
  }
  return picked;
}

function percent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function describeAssessment(voice: CallVoiceAssessment | undefined): string {
  if (!voice) return "none";
  return `${voice.status} — ${percent(voice.syntheticShare)} of ${voice.speechMs} ms of speech judged synthetic, confidence ${percent(voice.confidence)}`;
}

/** The detector's own log lines (already scrubbed of the key by the detector), printed as they come. */
function printingLogger(out: (line: string) => void): FastifyBaseLogger {
  const noop = (): void => undefined;
  const print =
    (level: string) =>
    (fields: unknown, message?: string): void => {
      const text = typeof fields === "string" ? fields : `${message ?? ""} ${JSON.stringify(fields)}`;
      out(`  [${level}] ${text}`);
    };
  const logger = {
    level: "info",
    fatal: print("error"),
    error: print("error"),
    warn: print("warn"),
    info: print("info"),
    debug: noop,
    trace: noop,
    silent: noop,
    child: () => logger,
  } as unknown as FastifyBaseLogger;
  return logger;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function runVoiceCheck(io: VoiceCheckIO): Promise<number> {
  const args = parseArgs(io.argv);
  if (typeof args === "string") {
    io.out(`error: ${args}\n\n${USAGE}`);
    return 2;
  }
  let config: VoiceDetectionConfig | undefined;
  try {
    config = loadCallsConfig(voiceEnv(io.env)).voice;
  } catch (error) {
    io.out(`error: ${error instanceof Error ? error.message : "invalid configuration"}`);
    return 2;
  }
  if (!config) {
    io.out("error: MODULATE_API_KEY is not set. Put it in Relay/.env (or the environment) and run this again.");
    return 2;
  }
  // Belt and braces: nothing below builds a line from the key, and this makes sure none can carry it anyway.
  const apiKey = config.apiKey;
  const out = (line: string): void => io.out(line.split(apiKey).join("[redacted]"));

  const wav = parseWav(new Uint8Array(await readFile(args.file)));
  const samples = wav.channels[args.channel];
  if (!samples) {
    out(`error: ${args.file} has ${wav.channels.length} channel(s); there is no channel ${args.channel}`);
    return 2;
  }
  // Only what will be streamed is converted: the filter is the slow part on a long wideband recording.
  const wantedSamples = config.maxStreamMs > 0 ? Math.ceil((config.maxStreamMs / 1000) * wav.sampleRate) + wav.sampleRate : samples.length;
  const source = samples.length > wantedSamples ? samples.subarray(0, wantedSamples) : samples;
  const totalMs = Math.ceil((samples.length / wav.sampleRate) * 1000 / MULAW_FRAME_MS) * MULAW_FRAME_MS;
  const payloads = splitFrames(mulawEncode(resample(telephoneLowPass(source, wav.sampleRate), wav.sampleRate, MULAW_SAMPLE_RATE)));
  const capped = config.maxStreamMs > 0 ? Math.min(payloads.length, Math.ceil(config.maxStreamMs / MULAW_FRAME_MS)) : payloads.length;
  out(
    `${args.file}: channel ${args.channel} of ${wav.channels.length} @ ${wav.sampleRate} Hz → ${totalMs / 1000} s of ` +
      `8 kHz μ-law at ${args.rate}× real time`,
  );
  if (capped * MULAW_FRAME_MS < totalMs) {
    out(`note: only the first ${config.maxStreamMs / 1000} s are streamed (CALLS_AI_VOICE_MAX_SECONDS; 0 streams everything)`);
  }
  out(
    `provider ${MODULATE_VOICE_PROVIDER}; decision window ${config.windowMs} ms of speech, ` +
      `synthetic at ≥ ${percent(config.minShare)} of it with frame confidence ≥ ${percent(config.minConfidence)}`,
  );

  // Filled in by the detector's observer callbacks.
  const seen: {
    frames: number;
    opened: boolean;
    done: { durationMs: number | undefined; frameCount: number | undefined } | undefined;
    closes: { code: number; policy: CloseCodePolicy; detail: string | undefined }[];
  } = { frames: 0, opened: false, done: undefined, closes: [] };
  const detector = createVoiceDetector({
    config,
    logger: printingLogger(out),
    closeGraceMs: io.closeGraceMs ?? SCRIPT_CLOSE_GRACE_MS,
    ...(io.url !== undefined ? { url: io.url } : {}),
    ...(io.socketFactory ? { socketFactory: io.socketFactory } : {}),
    observer: {
      opened: () => {
        seen.opened = true;
      },
      frame: (_callId, frame) => {
        seen.frames += 1;
        out(`  ${frame.startMs}-${frame.endMs} ms  ${frame.verdict}  ${percent(frame.confidence)}`);
      },
      done: (_callId, summary) => {
        seen.done = summary;
      },
      closed: (_callId, close) => {
        seen.closes.push(close);
      },
    },
  });

  // A stand-in for the call: the detector reports to it exactly as it does to a live session.
  const session = new CallSession({
    deviceId: "voice-check",
    line: null,
    source: "replay",
    callerNumber: "+15550100199",
    calledNumber: "+15550100100",
    startedAt: Date.now(),
    status: "in_progress",
  });
  session.on("voice", (voice) => out(`  → ${describeAssessment(voice)}`));

  const handle = detector.open(session);
  // A call's audio arrives over minutes, so the relay never has to wait for the handshake; a file played faster
  // than real time could be over before the socket opens. Start the clock once the stream is up (or refused).
  const connectDeadline = Date.now() + SCRIPT_CONNECT_WAIT_MS;
  while (!seen.opened && session.voice?.status !== "unavailable" && Date.now() < connectDeadline) await sleep(10);
  const startedAt = Date.now();
  for (let i = 0; i < capped; i += 1) {
    // Judged synthetic (the relay stops streaming there) or refused: nothing more would be sent.
    const status = session.voice?.status;
    if (status === "synthetic" || status === "unavailable") break;
    const wait = startedAt + (i * MULAW_FRAME_MS) / args.rate - Date.now();
    if (wait > 0) await sleep(wait);
    handle.pushAudio(Buffer.from(payloads[i]!).toString("base64"));
  }
  await handle.close();
  await detector.close();
  // What a call that ended here would be left with: a check still undecided becomes "inconclusive".
  session.end();

  const { done, frames, closes } = seen;
  if (done) out(`done: ${done.durationMs ?? "?"} ms of audio, ${done.frameCount ?? "?"} frames (vendor's count)`);
  out(`final assessment: ${describeAssessment(session.voice)}`);

  const refused = closes.find((close) => close.policy === "account" || close.policy === "call");
  const failed = refused ?? (session.voice?.status === "unavailable" ? closes.at(-1) : undefined);
  if (failed) {
    const meaning = MODULATE_CLOSE_CODES[failed.code]?.meaning ?? "not a code Modulate documents (a dropped or refused connection)";
    out(`error: Modulate closed the stream with code ${failed.code} — ${meaning}${failed.detail ? `: ${failed.detail}` : ""}`);
    return 1;
  }
  if (session.voice?.status === "unavailable") {
    out("error: the Modulate endpoint could not be reached (see the lines above)");
    return 1;
  }
  if (!done && frames === 0) {
    out("error: no frame and no done message arrived from Modulate");
    return 1;
  }
  if (frames === 0) out("note: the vendor returned no frame — is the recording shorter than its minimum, or silent?");
  return 0;
}

const invokedDirectly = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  runVoiceCheck({ argv: process.argv.slice(2), env: process.env, out: (line) => console.log(line) })
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      // A file that cannot be read or is not a WAV. Never the socket: its errors stay inside the detector.
      console.error(`error: ${error instanceof Error ? error.message : "unexpected failure"}`);
      process.exitCode = 1;
    });
}

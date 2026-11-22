import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runVoiceCheck, telephoneLowPass } from "../../scripts/modulate-voice-check.js";
import { encodeWav, resample, synthesizeTone } from "../../src/calls/audio.js";
import { MODULATE_TEST_KEY } from "./fakes.js";
import { refuse, replyDone, startModulateServer, type FakeModulateServer } from "./modulateServer.js";

/**
 * `npm run calls:voice-check` end to end against the in-process server of modulateServer.ts (the real vendor
 * needs a key and credits, which no test has): a WAV becomes 8 kHz μ-law, is streamed through the relay's own
 * client and aggregator, every frame is printed, and a refusal turns into a non-zero exit with its close code.
 */

describe("scripts/modulate-voice-check", () => {
  let dir: string;
  let wav: string;
  let server: FakeModulateServer | undefined;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "pg-voice-check-"));
    wav = join(dir, "caller.wav");
    // Three seconds at 16 kHz, stereo: channel 0 a tone, channel 1 silence.
    const tone = synthesizeTone(440, 3, 16_000);
    writeFileSync(wav, encodeWav({ sampleRate: 16_000, channels: [tone, new Float32Array(tone.length)] }));
  });

  afterEach(async () => {
    await server?.close();
    server = undefined;
    rmSync(dir, { recursive: true, force: true });
  });

  function env(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
    // Half a Twilio section, which the full config loader would reject: the check reads only its own variables.
    return { MODULATE_API_KEY: MODULATE_TEST_KEY, CALLS_AI_VOICE_WINDOW_MS: "2500", TWILIO_NUMBER: "+15551234567", ...overrides };
  }

  it("streams the WAV as μ-law, prints every frame and the final assessment, and exits 0", async () => {
    server = await startModulateServer({
      onEndOfStream: (socket, connection) =>
        replyDone(socket, connection, [
          { start_time_ms: 0, end_time_ms: 1500, verdict: "synthetic", confidence: 0.974 },
          { start_time_ms: 1500, end_time_ms: 2500, verdict: "synthetic", confidence: 0.974 },
          { start_time_ms: 2500, end_time_ms: 3000, verdict: "no-content", confidence: 1 },
        ]),
    });
    const lines: string[] = [];
    const code = await runVoiceCheck({ argv: [wav, "--rate", "50"], env: env(), out: (line) => lines.push(line), url: server.url, closeGraceMs: 3000 });
    const output = lines.join("\n");
    expect(code).toBe(0);

    // What the server received: 3 s of 8 kHz μ-law in binary frames, then the empty text frame.
    const connection = server.connections[0]!;
    expect(connection.requestUrl).toContain("audio_format=mulaw&sample_rate=8000&num_channels=1");
    const audio = connection.messages.filter((message) => message.binary);
    expect(audio.reduce((sum, message) => sum + message.data.length, 0)).toBe(24_000);
    expect(connection.messages.at(-1)).toMatchObject({ binary: false });
    expect(connection.messages.at(-1)!.data.length).toBe(0);
    // A tone is not digital silence (0xFF).
    expect(Buffer.concat(audio.map((message) => message.data)).some((byte) => byte !== 0xff)).toBe(true);

    expect(output).toContain("channel 0 of 2 @ 16000 Hz → 3 s of 8 kHz μ-law at 50× real time");
    expect(output).toContain("  0-1500 ms  synthetic  97%");
    expect(output).toContain("  1500-2500 ms  synthetic  97%");
    expect(output).toContain("  2500-3000 ms  no-content  100%");
    expect(output).toContain("done: 3000 ms of audio, 3 frames");
    expect(output).toContain("final assessment: synthetic — 100% of 2500 ms of speech judged synthetic, confidence 97%");
    expect(output).not.toContain(MODULATE_TEST_KEY);
    expect(output).not.toContain("api_key=");
  });

  it("does not lose the recording when it is played faster than the connection opens", async () => {
    server = await startModulateServer({ handshakeDelayMs: 300 });
    const lines: string[] = [];
    // 3 s at 50× is over in 60 ms; the upgrade takes five times that.
    const code = await runVoiceCheck({ argv: [wav, "--rate", "50"], env: env(), out: (line) => lines.push(line), url: server.url, closeGraceMs: 3000 });
    expect(code).toBe(0);
    const connection = server.connections[0]!;
    expect(connection.messages.filter((message) => message.binary).reduce((sum, message) => sum + message.data.length, 0)).toBe(24_000);
    expect(connection.messages.at(-1)).toMatchObject({ binary: false });
    // No frames came back for a clip this short: a call that ended here would be left "inconclusive".
    expect(lines.join("\n")).toContain("final assessment: inconclusive");
  });

  it("exits 1 after a single handshake when the upgrade itself is refused with HTTP 401", async () => {
    server = await startModulateServer({ rejectUpgradeWith: 401 });
    const lines: string[] = [];
    const code = await runVoiceCheck({ argv: [wav, "--rate", "50"], env: env(), out: (line) => lines.push(line), url: server.url, closeGraceMs: 500 });
    const output = lines.join("\n");
    expect(code).toBe(1);
    expect(server.upgradeAttempts()).toBe(1);
    expect(output).toContain("HTTP 401 at the WebSocket handshake");
    expect(output).toContain("final assessment: unavailable");
    expect(output).not.toContain(MODULATE_TEST_KEY);
    expect(output).not.toContain("api_key=");
  });

  it("band-limits a wideband recording before bringing it down to 8 kHz, as the telephone network does", () => {
    const peak = (samples: Float32Array): number => samples.subarray(800, samples.length - 800).reduce((max, value) => Math.max(max, Math.abs(value)), 0);
    const to8k = (hz: number, rate: number): Float32Array => {
      const tone = synthesizeTone(hz, 1, rate);
      return resample(telephoneLowPass(tone, rate), rate, 8000);
    };
    for (const rate of [16_000, 44_100, 48_000]) {
      const inBand = peak(synthesizeTone(1000, 1, rate));
      // Speech band: untouched (within a few percent).
      expect(peak(to8k(1000, rate)) / inBand).toBeGreaterThan(0.95);
      // 5 kHz would alias to 3 kHz at full level without the filter; with it, it is gone.
      expect(peak(to8k(5000, rate)) / inBand).toBeLessThan(0.02);
    }
    // Telephone-rate audio is passed through as it is.
    const narrow = synthesizeTone(1000, 1, 8000);
    expect(telephoneLowPass(narrow, 8000)).toBe(narrow);
  });

  it("streams the chosen channel and honours the configured cap", async () => {
    server = await startModulateServer();
    const lines: string[] = [];
    const code = await runVoiceCheck({
      argv: [wav, "--channel", "1", "--rate", "50"],
      env: env({ CALLS_AI_VOICE_MAX_SECONDS: "1" }),
      out: (line) => lines.push(line),
      url: server.url,
      closeGraceMs: 3000,
    });
    expect(code).toBe(0);
    const audio = Buffer.concat(server.connections[0]!.messages.filter((message) => message.binary).map((message) => message.data));
    expect(audio.length).toBe(8000);
    // Channel 1 is silence.
    expect(audio.every((byte) => byte === 0xff)).toBe(true);
    const output = lines.join("\n");
    expect(output).toContain("note: only the first 1 s are streamed (CALLS_AI_VOICE_MAX_SECONDS; 0 streams everything)");
    expect(output).toContain("note: the vendor returned no frame");
    expect(output).toContain("final assessment: inconclusive");
  });

  it("exits 1 with the close code and its meaning when the key is refused, without printing the key the vendor echoed", async () => {
    server = await startModulateServer({
      onConnect: (socket) => refuse(socket, 4001, `Invalid API key '${MODULATE_TEST_KEY}' (api_key=${MODULATE_TEST_KEY}).`),
    });
    const lines: string[] = [];
    const code = await runVoiceCheck({ argv: [wav, "--rate", "50"], env: env(), out: (line) => lines.push(line), url: server.url, closeGraceMs: 500 });
    const output = lines.join("\n");
    expect(code).toBe(1);
    // The scrubber masks everything after `api_key=` up to the next separator, closing bracket included.
    expect(output).toContain("error: Modulate closed the stream with code 4001 — the api_key query parameter is missing or invalid: Invalid API key '[redacted]' (api_key=[redacted]");
    expect(output).toContain("final assessment: unavailable");
    expect(output).not.toContain(MODULATE_TEST_KEY);
    expect(server.connections).toHaveLength(1);
  });

  it("exits 1 when the audio is rejected while the stream is finishing (4002)", async () => {
    server = await startModulateServer({
      onEndOfStream: (socket) => refuse(socket, 4002, "Audio data does not match the declared audio_format."),
    });
    const lines: string[] = [];
    const code = await runVoiceCheck({ argv: [wav, "--rate", "50"], env: env(), out: (line) => lines.push(line), url: server.url, closeGraceMs: 3000 });
    expect(code).toBe(1);
    expect(lines.join("\n")).toContain("code 4002 — audio could not be decoded or does not match the declared format: Audio data does not match the declared audio_format.");
  });

  it("exits 2 with a clear message for a missing key, a bad argument, a bad threshold or a missing channel", async () => {
    const run = async (argv: string[], environment: NodeJS.ProcessEnv): Promise<{ code: number; output: string }> => {
      const lines: string[] = [];
      const code = await runVoiceCheck({ argv, env: environment, out: (line) => lines.push(line), url: "ws://127.0.0.1:9/unused" });
      return { code, output: lines.join("\n") };
    };
    expect(await run([wav], {})).toEqual({ code: 2, output: "error: MODULATE_API_KEY is not set. Put it in Relay/.env (or the environment) and run this again." });
    expect((await run([], env())).output).toContain("error: missing <file.wav>");
    expect((await run([wav, "--rate"], env())).output).toContain("--rate needs a value");
    expect((await run([wav, "--rate", "0"], env())).code).toBe(2);
    const threshold = await run([wav], env({ CALLS_AI_VOICE_WINDOW_MS: "1" }));
    expect(threshold).toEqual({ code: 2, output: "error: CALLS_AI_VOICE_WINDOW_MS must be between 2500 and 60000" });
    const channel = await run([wav, "--channel", "5"], env());
    expect(channel.code).toBe(2);
    expect(channel.output).toContain("has 2 channel(s); there is no channel 5");
  });
});

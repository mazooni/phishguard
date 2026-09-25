import { describe, expect, it } from "vitest";

import {
  MULAW_FRAME_BYTES,
  MULAW_SILENCE,
  WavParseError,
  encodeWav,
  mulawDecode,
  mulawDecodeToPcm16,
  mulawEncode,
  mulawEncodePcm16,
  parseWav,
  resample,
  splitFrames,
  synthesizeTone,
} from "../../src/calls/audio.js";

describe("parseWav", () => {
  it("reads a mono 16-bit file", () => {
    const tone = synthesizeTone(440, 0.1, 16_000);
    const parsed = parseWav(encodeWav({ sampleRate: 16_000, channels: [tone] }, "pcm16"));
    expect(parsed.sampleRate).toBe(16_000);
    expect(parsed.channels).toHaveLength(1);
    expect(parsed.channels[0]).toHaveLength(tone.length);
    let maxError = 0;
    for (let i = 0; i < tone.length; i += 1) maxError = Math.max(maxError, Math.abs(parsed.channels[0]![i]! - tone[i]!));
    expect(maxError).toBeLessThan(1 / 32000);
  });

  it("reads a stereo file keeping channel order (0 = caller, 1 = user)", () => {
    const left = synthesizeTone(300, 0.05, 8000, 0.8);
    const right = synthesizeTone(900, 0.05, 8000, 0.2);
    const parsed = parseWav(encodeWav({ sampleRate: 8000, channels: [left, right] }, "pcm16"));
    expect(parsed.channels).toHaveLength(2);
    expect(Math.max(...parsed.channels[0]!)).toBeCloseTo(0.8, 2);
    expect(Math.max(...parsed.channels[1]!)).toBeCloseTo(0.2, 2);
  });

  it("reads 32-bit float, 8-bit and 24-bit files", () => {
    const tone = synthesizeTone(440, 0.02, 44_100, 0.7);
    for (const format of ["float32", "pcm8", "pcm24"] as const) {
      const parsed = parseWav(encodeWav({ sampleRate: 44_100, channels: [tone] }, format));
      expect(parsed.sampleRate).toBe(44_100);
      expect(parsed.channels[0]).toHaveLength(tone.length);
      const tolerance = format === "pcm8" ? 1 / 100 : 1 / 100_000;
      let maxError = 0;
      for (let i = 0; i < tone.length; i += 1) maxError = Math.max(maxError, Math.abs(parsed.channels[0]![i]! - tone[i]!));
      expect(maxError, format).toBeLessThan(tolerance);
    }
  });

  it("rejects files that are not RIFF/WAVE or use an unsupported format", () => {
    expect(() => parseWav(new Uint8Array([1, 2, 3]))).toThrow(WavParseError);
    const bytes = encodeWav({ sampleRate: 8000, channels: [new Float32Array(10)] }, "pcm16");
    new DataView(bytes.buffer).setUint16(20, 0x55, true); // MPEG
    expect(() => parseWav(bytes)).toThrow(/unsupported/);
  });
});

describe("resample", () => {
  it("scales the length by the rate ratio and keeps the waveform", () => {
    const tone = synthesizeTone(440, 0.5, 44_100);
    const out = resample(tone, 44_100, 8000);
    expect(out.length).toBe(Math.round((tone.length * 8000) / 44_100));
    // A 440 Hz tone at 8 kHz still crosses zero ~440 times per second.
    let crossings = 0;
    for (let i = 1; i < out.length; i += 1) if (out[i - 1]! < 0 !== out[i]! < 0) crossings += 1;
    expect(crossings).toBeGreaterThan(400);
    expect(crossings).toBeLessThan(480);
  });

  it("is the identity at equal rates", () => {
    const tone = synthesizeTone(100, 0.01, 8000);
    expect(Array.from(resample(tone, 8000, 8000))).toEqual(Array.from(tone));
  });
});

describe("μ-law", () => {
  it("encodes silence as 0xFF and decodes it back to 0", () => {
    expect(mulawEncodePcm16(0)).toBe(MULAW_SILENCE);
    expect(mulawDecodeToPcm16(MULAW_SILENCE)).toBe(0);
  });

  it("round-trips a synthesised tone within codec tolerance", () => {
    const tone = synthesizeTone(440, 0.1, 8000, 0.6);
    const decoded = mulawDecode(mulawEncode(tone));
    expect(decoded).toHaveLength(tone.length);
    let maxError = 0;
    let energy = 0;
    let noise = 0;
    for (let i = 0; i < tone.length; i += 1) {
      const error = Math.abs(decoded[i]! - tone[i]!);
      maxError = Math.max(maxError, error);
      energy += tone[i]! * tone[i]!;
      noise += error * error;
    }
    // μ-law is logarithmic: relative error ≈ 1/16 per sample; overall SNR well above 30 dB.
    expect(maxError).toBeLessThan(0.05);
    expect(10 * Math.log10(energy / noise)).toBeGreaterThan(30);
  });

  it("clips out-of-range samples instead of wrapping", () => {
    expect(mulawEncodePcm16(40_000)).toBe(mulawEncodePcm16(32_767));
    expect(mulawEncodePcm16(-40_000)).toBe(mulawEncodePcm16(-32_768));
    expect(mulawDecodeToPcm16(mulawEncodePcm16(32_767))).toBeGreaterThan(30_000);
  });
});

describe("splitFrames", () => {
  it("cuts μ-law bytes into 160-byte frames and pads the last one with silence", () => {
    const bytes = new Uint8Array(400).fill(0x12);
    const frames = splitFrames(bytes);
    expect(frames).toHaveLength(3);
    expect(frames.every((frame) => frame.length === MULAW_FRAME_BYTES)).toBe(true);
    expect(frames[2]![79]).toBe(0x12);
    expect(frames[2]![80]).toBe(MULAW_SILENCE);
    expect(splitFrames(new Uint8Array(0))).toHaveLength(0);
  });
});

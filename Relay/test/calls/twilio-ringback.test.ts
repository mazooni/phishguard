import { describe, expect, it } from "vitest";

import {
  RINGBACK_DURATION_SECONDS,
  RINGBACK_SAMPLE_RATE,
  RINGBACK_TONE_SECONDS,
  WAV_HEADER_BYTES,
  ringbackWav,
  synthesiseRingback,
} from "../../src/calls/twilio/ringback.js";

describe("ringback WAV", () => {
  it("is a canonical 8 kHz 16-bit mono PCM RIFF/WAVE file of at least six seconds", () => {
    const wav = ringbackWav();
    expect(wav.toString("ascii", 0, 4)).toBe("RIFF");
    expect(wav.readUInt32LE(4)).toBe(wav.length - 8);
    expect(wav.toString("ascii", 8, 12)).toBe("WAVE");
    expect(wav.toString("ascii", 12, 16)).toBe("fmt ");
    expect(wav.readUInt32LE(16)).toBe(16);
    expect(wav.readUInt16LE(20)).toBe(1); // PCM
    expect(wav.readUInt16LE(22)).toBe(1); // mono
    expect(wav.readUInt32LE(24)).toBe(8000);
    expect(wav.readUInt32LE(28)).toBe(16000); // byte rate
    expect(wav.readUInt16LE(32)).toBe(2); // block align
    expect(wav.readUInt16LE(34)).toBe(16); // bits per sample
    expect(wav.toString("ascii", 36, 40)).toBe("data");
    const dataBytes = wav.readUInt32LE(40);
    expect(dataBytes).toBe(wav.length - WAV_HEADER_BYTES);
    const seconds = dataBytes / 2 / RINGBACK_SAMPLE_RATE;
    expect(seconds).toBeGreaterThanOrEqual(6);
    expect(seconds).toBe(RINGBACK_DURATION_SECONDS);
  });

  it("carries a tone for the first two seconds at a safe level and silence afterwards, and is built once", () => {
    const wav = synthesiseRingback();
    let peak = 0;
    let energy = 0;
    const toneSamples = RINGBACK_SAMPLE_RATE * RINGBACK_TONE_SECONDS;
    for (let i = 0; i < toneSamples; i += 1) {
      const sample = wav.readInt16LE(WAV_HEADER_BYTES + i * 2);
      peak = Math.max(peak, Math.abs(sample));
      energy += Math.abs(sample);
    }
    expect(peak).toBeGreaterThan(3000);
    expect(peak).toBeLessThanOrEqual(Math.round(0.25 * 32767) + 1);
    expect(energy / toneSamples).toBeGreaterThan(1000);
    // First sample starts at zero (fade-in) so the tone does not click.
    expect(Math.abs(wav.readInt16LE(WAV_HEADER_BYTES))).toBeLessThan(50);
    const totalSamples = RINGBACK_SAMPLE_RATE * RINGBACK_DURATION_SECONDS;
    for (let i = toneSamples; i < totalSamples; i += 997) {
      expect(wav.readInt16LE(WAV_HEADER_BYTES + i * 2)).toBe(0);
    }
    expect(ringbackWav()).toBe(ringbackWav());
  });
});

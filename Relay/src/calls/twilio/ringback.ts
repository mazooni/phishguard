/**
 * A synthesised US ringback tone for the conference `waitUrl` (docs/CALLS.md §5.2): the caller hears it while the
 * relay dials the protected phone. 440 + 480 Hz for 2 s, then 4 s of silence, as 8 kHz 16-bit mono PCM WAV — a
 * format Twilio plays without transcoding. Built once and cached; ~96 KB.
 */

export const RINGBACK_SAMPLE_RATE = 8000;
export const RINGBACK_DURATION_SECONDS = 6;
export const RINGBACK_TONE_SECONDS = 2;
export const RINGBACK_FREQUENCIES_HZ = [440, 480] as const;
/** Peak amplitude as a fraction of full scale; loud enough on a handset, never clipping. */
export const RINGBACK_AMPLITUDE = 0.25;
const FADE_SECONDS = 0.02;
export const WAV_HEADER_BYTES = 44;

let cached: Buffer | undefined;

/** The WAV file, synthesised on first use. */
export function ringbackWav(): Buffer {
  cached ??= synthesiseRingback();
  return cached;
}

export function synthesiseRingback(): Buffer {
  const totalSamples = RINGBACK_SAMPLE_RATE * RINGBACK_DURATION_SECONDS;
  const toneSamples = RINGBACK_SAMPLE_RATE * RINGBACK_TONE_SECONDS;
  const fadeSamples = Math.round(RINGBACK_SAMPLE_RATE * FADE_SECONDS);
  const dataBytes = totalSamples * 2;
  const buffer = Buffer.alloc(WAV_HEADER_BYTES + dataBytes);

  buffer.write("RIFF", 0, "ascii");
  buffer.writeUInt32LE(36 + dataBytes, 4);
  buffer.write("WAVE", 8, "ascii");
  buffer.write("fmt ", 12, "ascii");
  buffer.writeUInt32LE(16, 16); // PCM chunk size
  buffer.writeUInt16LE(1, 20); // PCM
  buffer.writeUInt16LE(1, 22); // mono
  buffer.writeUInt32LE(RINGBACK_SAMPLE_RATE, 24);
  buffer.writeUInt32LE(RINGBACK_SAMPLE_RATE * 2, 28); // byte rate
  buffer.writeUInt16LE(2, 32); // block align
  buffer.writeUInt16LE(16, 34); // bits per sample
  buffer.write("data", 36, "ascii");
  buffer.writeUInt32LE(dataBytes, 40);

  const perTone = RINGBACK_AMPLITUDE / RINGBACK_FREQUENCIES_HZ.length;
  for (let i = 0; i < toneSamples; i += 1) {
    const t = i / RINGBACK_SAMPLE_RATE;
    let value = 0;
    for (const hz of RINGBACK_FREQUENCIES_HZ) value += Math.sin(2 * Math.PI * hz * t);
    let envelope = 1;
    if (i < fadeSamples) envelope = i / fadeSamples;
    else if (i >= toneSamples - fadeSamples) envelope = (toneSamples - i) / fadeSamples;
    const sample = Math.round(value * perTone * envelope * 32767);
    buffer.writeInt16LE(Math.max(-32768, Math.min(32767, sample)), WAV_HEADER_BYTES + i * 2);
  }
  // The remaining samples are already zero (silence).
  return buffer;
}

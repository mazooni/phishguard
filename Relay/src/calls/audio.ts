/**
 * Audio helpers for the replay script and tests: PCM WAV parsing, linear resampling and G.711 μ-law coding.
 * Pure functions over typed arrays — no ffmpeg, no native modules. Samples are Float32 in −1…1.
 */

export interface PcmAudio {
  sampleRate: number;
  /** One Float32Array per channel (channel 0 first). */
  channels: Float32Array[];
}

/** Twilio's Media Streams format: 8 kHz μ-law, one 20 ms frame (160 bytes) per message. */
export const MULAW_SAMPLE_RATE = 8000;
export const MULAW_FRAME_BYTES = 160;
export const MULAW_FRAME_MS = 20;
/** μ-law encoding of digital silence. */
export const MULAW_SILENCE = 0xff;

const WAVE_FORMAT_PCM = 1;
const WAVE_FORMAT_IEEE_FLOAT = 3;
const WAVE_FORMAT_EXTENSIBLE = 0xfffe;

export class WavParseError extends Error {
  override readonly name = "WavParseError";
}

/**
 * Parses a RIFF/WAVE file with integer PCM (8, 16, 24 or 32-bit) or 32-bit float samples at any rate and channel
 * count. Extensible headers are resolved through their sub-format. Streaming files whose data chunk size is 0 or
 * 0xFFFFFFFF are read to the end of the buffer.
 */
export function parseWav(input: Uint8Array): PcmAudio {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.byteLength < 12 || ascii(bytes, 0, 4) !== "RIFF" || ascii(bytes, 8, 4) !== "WAVE") {
    throw new WavParseError("not a RIFF/WAVE file");
  }

  let format: number | undefined;
  let channelCount = 0;
  let sampleRate = 0;
  let bitsPerSample = 0;
  let dataOffset = -1;
  let dataLength = 0;

  let offset = 12;
  while (offset + 8 <= bytes.byteLength) {
    const id = ascii(bytes, offset, 4);
    const size = view.getUint32(offset + 4, true);
    const body = offset + 8;
    if (id === "fmt ") {
      if (size < 16) throw new WavParseError("fmt chunk too short");
      format = view.getUint16(body, true);
      channelCount = view.getUint16(body + 2, true);
      sampleRate = view.getUint32(body + 4, true);
      bitsPerSample = view.getUint16(body + 14, true);
      if (format === WAVE_FORMAT_EXTENSIBLE) {
        if (size < 40) throw new WavParseError("extensible fmt chunk too short");
        // The sub-format GUID starts with the two-byte format tag.
        format = view.getUint16(body + 24, true);
      }
    } else if (id === "data") {
      dataOffset = body;
      dataLength = size === 0 || size === 0xffffffff ? bytes.byteLength - body : Math.min(size, bytes.byteLength - body);
      break;
    }
    // Chunks are word-aligned.
    offset = body + size + (size % 2);
  }

  if (format === undefined) throw new WavParseError("missing fmt chunk");
  if (dataOffset < 0) throw new WavParseError("missing data chunk");
  if (channelCount < 1 || sampleRate < 1) throw new WavParseError("invalid channel count or sample rate");
  if (format !== WAVE_FORMAT_PCM && format !== WAVE_FORMAT_IEEE_FLOAT) throw new WavParseError(`unsupported WAV format ${format}`);
  if (format === WAVE_FORMAT_IEEE_FLOAT && bitsPerSample !== 32) throw new WavParseError("float WAV must be 32-bit");
  if (format === WAVE_FORMAT_PCM && ![8, 16, 24, 32].includes(bitsPerSample)) {
    throw new WavParseError(`unsupported PCM bit depth ${bitsPerSample}`);
  }

  const bytesPerSample = bitsPerSample / 8;
  const frameBytes = bytesPerSample * channelCount;
  const frameCount = Math.floor(dataLength / frameBytes);
  const channels = Array.from({ length: channelCount }, () => new Float32Array(frameCount));

  for (let frame = 0; frame < frameCount; frame += 1) {
    const base = dataOffset + frame * frameBytes;
    for (let channel = 0; channel < channelCount; channel += 1) {
      const at = base + channel * bytesPerSample;
      let value: number;
      if (format === WAVE_FORMAT_IEEE_FLOAT) {
        value = view.getFloat32(at, true);
      } else if (bitsPerSample === 8) {
        value = (bytes[at]! - 128) / 128;
      } else if (bitsPerSample === 16) {
        value = view.getInt16(at, true) / 32768;
      } else if (bitsPerSample === 24) {
        const raw = bytes[at]! | (bytes[at + 1]! << 8) | (bytes[at + 2]! << 16);
        value = (raw & 0x800000 ? raw - 0x1000000 : raw) / 8388608;
      } else {
        value = view.getInt32(at, true) / 2147483648;
      }
      channels[channel]![frame] = Math.max(-1, Math.min(1, value));
    }
  }

  return { sampleRate, channels };
}

function ascii(bytes: Uint8Array, offset: number, length: number): string {
  let out = "";
  for (let i = 0; i < length; i += 1) out += String.fromCharCode(bytes[offset + i] ?? 0);
  return out;
}

/** Linear-interpolation resampler; good enough for speech going into a telephony codec. */
export function resample(samples: Float32Array, fromRate: number, toRate: number): Float32Array {
  if (fromRate === toRate || samples.length === 0) return Float32Array.from(samples);
  const outLength = Math.max(1, Math.round((samples.length * toRate) / fromRate));
  const out = new Float32Array(outLength);
  const step = fromRate / toRate;
  const last = samples.length - 1;
  for (let i = 0; i < outLength; i += 1) {
    const position = i * step;
    const index = Math.min(last, Math.floor(position));
    const next = Math.min(last, index + 1);
    const fraction = position - index;
    out[i] = samples[index]! * (1 - fraction) + samples[next]! * fraction;
  }
  return out;
}

// G.711 μ-law (ITU-T G.711), the classic table-driven encoder.
const MULAW_BIAS = 0x84;
const MULAW_CLIP = 32635;
const MULAW_EXPONENT_TABLE = new Uint8Array(256);
for (let i = 0; i < 256; i += 1) {
  MULAW_EXPONENT_TABLE[i] = i === 0 ? 0 : Math.floor(Math.log2(i));
}

/** Encodes one 16-bit linear sample (−32768…32767) to a μ-law byte. */
export function mulawEncodePcm16(pcm: number): number {
  let sample = Math.max(-32768, Math.min(32767, Math.round(pcm)));
  const sign = sample < 0 ? 0x80 : 0;
  if (sign) sample = -sample;
  if (sample > MULAW_CLIP) sample = MULAW_CLIP;
  sample += MULAW_BIAS;
  const exponent = MULAW_EXPONENT_TABLE[(sample >> 7) & 0xff]!;
  const mantissa = (sample >> (exponent + 3)) & 0x0f;
  return ~(sign | (exponent << 4) | mantissa) & 0xff;
}

/** Decodes one μ-law byte to a 16-bit linear sample. */
export function mulawDecodeToPcm16(byte: number): number {
  const value = ~byte & 0xff;
  const sign = value & 0x80;
  const exponent = (value >> 4) & 0x07;
  const mantissa = value & 0x0f;
  let sample = ((mantissa << 3) + MULAW_BIAS) << exponent;
  sample -= MULAW_BIAS;
  return sign ? -sample : sample;
}

/** Float −1…1 samples → μ-law bytes. */
export function mulawEncode(samples: Float32Array): Uint8Array {
  const out = new Uint8Array(samples.length);
  for (let i = 0; i < samples.length; i += 1) out[i] = mulawEncodePcm16(samples[i]! * 32767);
  return out;
}

/** μ-law bytes → Float −1…1 samples. */
export function mulawDecode(bytes: Uint8Array): Float32Array {
  const out = new Float32Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) out[i] = mulawDecodeToPcm16(bytes[i]!) / 32768;
  return out;
}

/** Splits μ-law bytes into Twilio-sized frames; the last frame is padded with silence. */
export function splitFrames(bytes: Uint8Array, frameBytes: number = MULAW_FRAME_BYTES): Uint8Array[] {
  const frames: Uint8Array[] = [];
  for (let offset = 0; offset < bytes.length; offset += frameBytes) {
    const frame = new Uint8Array(frameBytes).fill(MULAW_SILENCE);
    frame.set(bytes.subarray(offset, Math.min(bytes.length, offset + frameBytes)));
    frames.push(frame);
  }
  return frames;
}

/** A sine tone, for tests and synthesised audio. */
export function synthesizeTone(frequencyHz: number, seconds: number, sampleRate: number, amplitude = 0.5): Float32Array {
  const length = Math.round(seconds * sampleRate);
  const out = new Float32Array(length);
  for (let i = 0; i < length; i += 1) out[i] = amplitude * Math.sin((2 * Math.PI * frequencyHz * i) / sampleRate);
  return out;
}

/** Writes a PCM WAV (16-bit or float32) — used by tests to round-trip `parseWav`. */
export function encodeWav(audio: PcmAudio, format: "pcm16" | "pcm8" | "pcm24" | "float32" = "pcm16"): Uint8Array {
  const channelCount = audio.channels.length;
  const frameCount = audio.channels[0]?.length ?? 0;
  const bitsPerSample = format === "pcm8" ? 8 : format === "pcm16" ? 16 : format === "pcm24" ? 24 : 32;
  const bytesPerSample = bitsPerSample / 8;
  const dataLength = frameCount * channelCount * bytesPerSample;
  const bytes = new Uint8Array(44 + dataLength);
  const view = new DataView(bytes.buffer);
  const write = (offset: number, text: string): void => {
    for (let i = 0; i < text.length; i += 1) bytes[offset + i] = text.charCodeAt(i);
  };
  write(0, "RIFF");
  view.setUint32(4, 36 + dataLength, true);
  write(8, "WAVE");
  write(12, "fmt ");
  view.setUint32(16, 16, true);
  view.setUint16(20, format === "float32" ? WAVE_FORMAT_IEEE_FLOAT : WAVE_FORMAT_PCM, true);
  view.setUint16(22, channelCount, true);
  view.setUint32(24, audio.sampleRate, true);
  view.setUint32(28, audio.sampleRate * channelCount * bytesPerSample, true);
  view.setUint16(32, channelCount * bytesPerSample, true);
  view.setUint16(34, bitsPerSample, true);
  write(36, "data");
  view.setUint32(40, dataLength, true);
  let offset = 44;
  for (let frame = 0; frame < frameCount; frame += 1) {
    for (let channel = 0; channel < channelCount; channel += 1) {
      const value = Math.max(-1, Math.min(1, audio.channels[channel]![frame] ?? 0));
      if (format === "float32") {
        view.setFloat32(offset, value, true);
      } else if (format === "pcm8") {
        bytes[offset] = Math.round(value * 127) + 128;
      } else if (format === "pcm16") {
        view.setInt16(offset, Math.round(value * 32767), true);
      } else {
        const raw = Math.round(value * 8388607);
        const unsigned = raw < 0 ? raw + 0x1000000 : raw;
        bytes[offset] = unsigned & 0xff;
        bytes[offset + 1] = (unsigned >> 8) & 0xff;
        bytes[offset + 2] = (unsigned >> 16) & 0xff;
      }
      offset += bytesPerSample;
    }
  }
  return bytes;
}

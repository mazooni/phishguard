import { describe, expect, it } from "vitest";

import { VoiceFrameAggregator, parseVoiceMessage, type VoiceFrame, type VoiceFrameVerdict } from "../../src/calls/modulate/voiceDetector.js";

/**
 * The frame aggregator on its own: Modulate's pages describe three different streaming frame geometries (4 s
 * frames end to end, a growing-then-sliding window with a prediction every second, 192 ms frames), so every
 * rule is exercised on each of them. Defaults of src/calls/config.ts: a 6 s window, 80 % share, 80 % confidence.
 */

const CONFIG = { windowMs: 6000, minShare: 0.8, minConfidence: 0.8 };

function frame(startMs: number, endMs: number, verdict: VoiceFrameVerdict, confidence = 0.9): VoiceFrame {
  return { startMs, endMs, verdict, confidence };
}

function aggregator(overrides: Partial<typeof CONFIG> = {}): VoiceFrameAggregator {
  return new VoiceFrameAggregator({ ...CONFIG, ...overrides });
}

describe("VoiceFrameAggregator: 4 s frames end to end (the documented example output)", () => {
  it("is analysing until the window is full, then judges the last 6 s of speech", () => {
    const agg = aggregator();
    expect(agg.assessment()).toEqual({ status: "analyzing", syntheticShare: 0, confidence: 0, speechMs: 0 });
    expect(agg.add(frame(0, 4000, "synthetic", 0.97))).toBe(true);
    expect(agg.assessment()).toEqual({ status: "analyzing", syntheticShare: 1, confidence: 0, speechMs: 4000 });
    expect(agg.add(frame(4000, 8000, "synthetic", 0.91))).toBe(true);
    const result = agg.assessment();
    expect(result.status).toBe("synthetic");
    expect(result.speechMs).toBe(8000);
    expect(result.syntheticShare).toBe(1);
    // The window is the last 6 s: 2 s of the first frame and all 4 s of the second.
    expect(result.confidence).toBeCloseTo((2000 * 0.97 + 4000 * 0.91) / 6000, 10);
  });

  it("judges natural speech human, with the confidence the vendor had in `non-synthetic`", () => {
    const agg = aggregator();
    agg.add(frame(0, 4000, "non-synthetic", 0.94));
    agg.add(frame(4000, 8000, "non-synthetic", 0.91));
    const result = agg.assessment();
    expect(result.status).toBe("human");
    expect(result.syntheticShare).toBe(0);
    expect(result.confidence).toBeCloseTo((2000 * 0.94 + 4000 * 0.91) / 6000, 10);
  });

  it("the overall share counts every synthetic frame; the decision only the recent window", () => {
    const agg = aggregator();
    agg.add(frame(0, 4000, "synthetic", 0.95));
    agg.add(frame(4000, 8000, "non-synthetic", 0.9));
    agg.add(frame(8000, 12000, "non-synthetic", 0.9));
    const result = agg.assessment();
    expect(result.status).toBe("human");
    expect(result.speechMs).toBe(12000);
    expect(result.syntheticShare).toBeCloseTo(4000 / 12000, 10);
    expect(result.confidence).toBeCloseTo(0.9, 10);
  });
});

describe("VoiceFrameAggregator: a window that grows from zero and then slides, one prediction per second", () => {
  // Minimum audio 2.5 s, then every second; full length 4 s, after which the window slides.
  const SLIDING: [number, number][] = [
    [0, 2500],
    [0, 3500],
    [500, 4500],
    [1500, 5500],
    [2500, 6500],
    [3500, 7500],
  ];

  it("counts each prediction only for the audio it adds, so overlapping windows are not counted twice", () => {
    const agg = aggregator();
    const speech: number[] = [];
    for (const [start, end] of SLIDING) {
      expect(agg.add(frame(start, end, "non-synthetic", 0.9))).toBe(true);
      speech.push(agg.assessment().speechMs);
    }
    // 2.5 s, then one more second each time — the stream's own length, not the 22 s the windows add up to.
    expect(speech).toEqual([2500, 3500, 4500, 5500, 6500, 7500]);
    expect(agg.assessment().status).toBe("human");
  });

  it("latches synthetic on the first prediction that completes 6 s of speech", () => {
    const agg = aggregator();
    const statuses = SLIDING.map(([start, end]) => {
      agg.add(frame(start, end, "synthetic", 0.9));
      return agg.assessment().status;
    });
    expect(statuses).toEqual(["analyzing", "analyzing", "analyzing", "analyzing", "synthetic", "synthetic"]);
    expect(agg.assessment().confidence).toBeCloseTo(0.9, 10);
  });

  it("lets old speech slide out of the decision: a human start followed by a synthetic voice is caught", () => {
    const agg = aggregator();
    agg.add(frame(0, 2500, "non-synthetic", 0.9));
    agg.add(frame(0, 3500, "non-synthetic", 0.9));
    let end = 3500;
    const statuses: string[] = [];
    while (end < 10500) {
      end += 1000;
      agg.add(frame(end - 4000, end, "synthetic", 0.95));
      statuses.push(agg.assessment().status);
    }
    // 3.5 s human then synthetic seconds: at 6.5 s the window is half human (still "human"), at 7.5 s it is
    // two thirds synthetic (neither: the check goes on), at 8.5 s it holds 5 s synthetic of 6 (83 %) and latches.
    expect(statuses).toEqual(["analyzing", "analyzing", "human", "analyzing", "synthetic", "synthetic", "synthetic"]);
    expect(agg.assessment().syntheticShare).toBeCloseTo(7000 / 10500, 10);
  });
});

describe("VoiceFrameAggregator: 192 ms frames", () => {
  it("decides on the frame that completes the window (the 32nd: 6144 ms) and not before", () => {
    const agg = aggregator();
    for (let index = 0; index < 31; index += 1) agg.add(frame(index * 192, (index + 1) * 192, "synthetic", 0.95));
    expect(agg.assessment()).toMatchObject({ status: "analyzing", speechMs: 5952 });
    agg.add(frame(31 * 192, 32 * 192, "synthetic", 0.95));
    expect(agg.assessment()).toMatchObject({ status: "synthetic", speechMs: 6144, syntheticShare: 1 });
    expect(agg.assessment().confidence).toBeCloseTo(0.95, 10);
  });

  it("weights by duration, so many short human frames outweigh a few synthetic ones", () => {
    const agg = aggregator();
    for (let index = 0; index < 40; index += 1) {
      const verdict: VoiceFrameVerdict = index % 4 === 0 ? "synthetic" : "non-synthetic";
      agg.add(frame(index * 192, (index + 1) * 192, verdict, 0.9));
    }
    const result = agg.assessment();
    expect(result.status).toBe("human");
    expect(result.speechMs).toBe(7680);
    expect(result.syntheticShare).toBeCloseTo(0.25, 10);
  });
});

describe("VoiceFrameAggregator: no-content frames", () => {
  it("leaves silence out of the speech total, the share and the decision", () => {
    const agg = aggregator();
    agg.add(frame(0, 4000, "synthetic", 0.9));
    expect(agg.add(frame(4000, 8000, "no-content", 1))).toBe(false);
    expect(agg.add(frame(8000, 12000, "no-content", 1))).toBe(false);
    // Eight seconds of hold time later the caller has still only spoken for four.
    expect(agg.assessment()).toEqual({ status: "analyzing", syntheticShare: 1, confidence: 0, speechMs: 4000 });
    agg.add(frame(12000, 16000, "synthetic", 0.9));
    expect(agg.assessment()).toMatchObject({ status: "synthetic", speechMs: 8000, syntheticShare: 1 });
  });

  it("still advances the high-water mark, so a later overlapping window only counts its new audio", () => {
    const agg = aggregator();
    agg.add(frame(0, 4000, "non-synthetic", 0.9));
    agg.add(frame(4000, 8000, "no-content", 1));
    // A sliding window reaching back into the silence: only 8000…9000 is new.
    expect(agg.add(frame(5000, 9000, "non-synthetic", 0.9))).toBe(true);
    expect(agg.assessment().speechMs).toBe(5000);
  });

  it("a call of pure silence never leaves analysing", () => {
    const agg = aggregator();
    for (let index = 0; index < 20; index += 1) agg.add(frame(index * 4000, (index + 1) * 4000, "no-content", 1));
    expect(agg.assessment()).toEqual({ status: "analyzing", syntheticShare: 0, confidence: 0, speechMs: 0 });
  });
});

describe("VoiceFrameAggregator: the latch", () => {
  it("keeps synthetic for the rest of the call, with the confidence of the window that met the criterion", () => {
    const agg = aggregator();
    agg.add(frame(0, 4000, "synthetic", 0.96));
    agg.add(frame(4000, 8000, "synthetic", 0.96));
    expect(agg.assessment().status).toBe("synthetic");
    for (let start = 8000; start < 40000; start += 4000) agg.add(frame(start, start + 4000, "non-synthetic", 0.99));
    const result = agg.assessment();
    expect(result.status).toBe("synthetic");
    expect(result.confidence).toBeCloseTo(0.96, 10);
    // The share is still the honest overall number.
    expect(result.syntheticShare).toBeCloseTo(8000 / 40000, 10);
    expect(result.speechMs).toBe(40000);
  });

  it("refreshes the confidence when a later window meets the criterion again", () => {
    const agg = aggregator();
    agg.add(frame(0, 3000, "synthetic", 0.85));
    agg.add(frame(3000, 6000, "synthetic", 0.85));
    expect(agg.assessment().confidence).toBeCloseTo(0.85, 10);
    agg.add(frame(6000, 12000, "synthetic", 0.99));
    expect(agg.assessment().confidence).toBeCloseTo(0.99, 10);
  });
});

describe("VoiceFrameAggregator: window and threshold boundaries", () => {
  it("needs exactly windowMs of speech: one millisecond less is still analysing", () => {
    const short = aggregator();
    short.add(frame(0, 3000, "synthetic", 0.99));
    short.add(frame(3000, 5999, "synthetic", 0.99));
    expect(short.assessment().status).toBe("analyzing");
    const exact = aggregator();
    exact.add(frame(0, 3000, "synthetic", 0.99));
    exact.add(frame(3000, 6000, "synthetic", 0.99));
    expect(exact.assessment().status).toBe("synthetic");
  });

  it("needs the share to reach minShare: 4800 of 6000 ms is synthetic, 4799 is not — and is not human either", () => {
    const at = aggregator();
    at.add(frame(0, 1200, "non-synthetic", 0.9));
    at.add(frame(1200, 3600, "synthetic", 0.9));
    at.add(frame(3600, 6000, "synthetic", 0.9));
    expect(at.assessment().status).toBe("synthetic");
    const below = aggregator();
    below.add(frame(0, 1201, "non-synthetic", 0.9));
    below.add(frame(1201, 3600, "synthetic", 0.9));
    below.add(frame(3600, 6000, "synthetic", 0.9));
    // A fifth of the window says human: nowhere near enough to reassure anyone. The check goes on.
    expect(below.assessment()).toEqual({ status: "analyzing", syntheticShare: 4799 / 6000, confidence: 0, speechMs: 6000 });
  });

  it("reports human only when at least half of the window is `non-synthetic`", () => {
    const half = aggregator();
    half.add(frame(0, 3000, "synthetic", 0.9));
    half.add(frame(3000, 6000, "non-synthetic", 0.92));
    expect(half.assessment().status).toBe("human");
    expect(half.assessment().confidence).toBeCloseTo(0.92, 10);
    const less = aggregator();
    less.add(frame(0, 3001, "synthetic", 0.9));
    less.add(frame(3001, 6000, "non-synthetic", 0.92));
    expect(less.assessment().status).toBe("analyzing");
  });

  it("never calls a voice human that the vendor called synthetic in every frame, however unsure it was", () => {
    const agg = aggregator();
    for (let start = 0; start < 40000; start += 4000) {
      agg.add(frame(start, start + 4000, "synthetic", 0.79));
      expect(agg.assessment().status).toBe("analyzing");
    }
    expect(agg.assessment()).toEqual({ status: "analyzing", syntheticShare: 1, confidence: 0, speechMs: 40000 });
  });

  it("one frame never decides a call, whatever the window and the share are set to", () => {
    // A window no longer than one documented 4 s frame: the first strong frame fills it alone and must not latch.
    const narrow = aggregator({ windowMs: 4000 });
    narrow.add(frame(0, 4000, "synthetic", 0.99));
    expect(narrow.assessment().status).toBe("analyzing");
    narrow.add(frame(4000, 8000, "synthetic", 0.99));
    expect(narrow.assessment().status).toBe("synthetic");
    // A low share: one synthetic frame after a human one is 67 % of the window, and still one frame.
    const lax = aggregator({ minShare: 0.65 });
    lax.add(frame(0, 4000, "non-synthetic", 0.9));
    lax.add(frame(4000, 8000, "synthetic", 0.99));
    expect(lax.assessment().status).toBe("analyzing");
    lax.add(frame(8000, 12000, "synthetic", 0.99));
    expect(lax.assessment().status).toBe("synthetic");
    // A single frame as long as the window: the next strong one makes two.
    const long = aggregator();
    long.add(frame(0, 6000, "synthetic", 0.99));
    expect(long.assessment().status).toBe("analyzing");
    long.add(frame(6000, 12000, "non-synthetic", 0.9));
    long.add(frame(12000, 18000, "synthetic", 0.99));
    expect(long.assessment().status).toBe("analyzing");
    long.add(frame(18000, 24000, "synthetic", 0.99));
    expect(long.assessment().status).toBe("synthetic");
  });

  it("is not thrown by floating point at a fractional share (55 % of 6000 ms is 3300.0000000000005)", () => {
    const agg = aggregator({ minShare: 0.55 });
    agg.add(frame(0, 2700, "non-synthetic", 0.9));
    agg.add(frame(2700, 4350, "synthetic", 0.9));
    agg.add(frame(4350, 6000, "synthetic", 0.9));
    expect(agg.assessment().status).toBe("synthetic");
    const below = aggregator({ minShare: 0.55 });
    below.add(frame(0, 2701, "non-synthetic", 0.9));
    below.add(frame(2701, 4350, "synthetic", 0.9));
    below.add(frame(4350, 6000, "synthetic", 0.9));
    expect(below.assessment().status).toBe("analyzing");
  });

  it("counts a synthetic frame only at or above minConfidence", () => {
    const at = aggregator();
    at.add(frame(0, 3000, "synthetic", 0.8));
    at.add(frame(3000, 6000, "synthetic", 0.8));
    expect(at.assessment().status).toBe("synthetic");
    expect(at.assessment().confidence).toBeCloseTo(0.8, 10);
    const below = aggregator();
    below.add(frame(0, 3000, "synthetic", 0.79));
    below.add(frame(3000, 6000, "synthetic", 0.79));
    // Not confident enough to call it synthetic — and no frame says "human" either: the check goes on.
    expect(below.assessment()).toEqual({ status: "analyzing", syntheticShare: 1, confidence: 0, speechMs: 6000 });
  });

  it("confidence is the vendor's confidence in the stated verdict: a confident `non-synthetic` never counts towards synthetic", () => {
    const agg = aggregator();
    agg.add(frame(0, 6000, "non-synthetic", 0.99));
    expect(agg.assessment()).toMatchObject({ status: "human", syntheticShare: 0, speechMs: 6000 });
    expect(agg.assessment().confidence).toBeCloseTo(0.99, 10);
  });

  it("honours a 100 % share and a longer window", () => {
    const agg = aggregator({ windowMs: 10000, minShare: 1 });
    agg.add(frame(0, 4000, "synthetic", 0.9));
    agg.add(frame(4000, 8000, "synthetic", 0.9));
    expect(agg.assessment().status).toBe("analyzing");
    agg.add(frame(8000, 8192, "non-synthetic", 0.9));
    agg.add(frame(8192, 12000, "synthetic", 0.9));
    expect(agg.assessment().status).toBe("analyzing");
    // Ten seconds of unbroken synthetic speech after the blip.
    agg.add(frame(12000, 18192, "synthetic", 0.9));
    expect(agg.assessment().status).toBe("synthetic");
  });
});

describe("VoiceFrameAggregator: readings recorded from the live endpoint (μ-law 8 kHz, 2026-11-16)", () => {
  type Recorded = [number, number, "s" | "n" | "-", number];
  const VERDICT = { s: "synthetic", n: "non-synthetic", "-": "no-content" } as const;
  function play(recorded: Recorded[], overrides: Partial<typeof CONFIG> = {}): { statuses: string[]; agg: VoiceFrameAggregator } {
    const agg = aggregator(overrides);
    const statuses = recorded.map(([start, end, verdict, confidence]) => {
      agg.add(frame(start, end, VERDICT[verdict], confidence));
      return agg.assessment().status;
    });
    return { statuses, agg };
  }

  // A text-to-speech voice reading a script without pauses.
  const SYNTHETIC: Recorded[] = [
    [0, 500, "-", 1], [0, 1500, "s", 0.98], [0, 2500, "s", 0.97], [0, 3500, "s", 0.97],
    [500, 4500, "s", 0.97], [1500, 5500, "s", 0.97], [2500, 6500, "s", 0.97],
  ];
  // Another text-to-speech voice in the shape of a conversation: it speaks, listens for three seconds, speaks.
  const SYNTHETIC_WITH_PAUSES: Recorded[] = [
    [0, 500, "-", 1], [0, 1500, "-", 1], [0, 2500, "s", 0.96], [0, 3500, "s", 0.96], [500, 4500, "s", 0.96],
    [1500, 5500, "s", 0.97], [2500, 6500, "-", 1], [3500, 7500, "-", 1], [4500, 8500, "-", 1],
    [5500, 9500, "s", 0.97], [6500, 10500, "s", 0.97],
  ];
  // Two seconds of synthetic speech, then nothing: the vendor stops giving verdicts once the newest part is silent.
  const SHORT_THEN_SILENCE: Recorded[] = [
    [0, 500, "-", 1], [0, 1500, "s", 0.98], [0, 2500, "s", 0.97], [0, 3500, "s", 0.97], [500, 4500, "-", 1],
    [1500, 5500, "-", 1], [2500, 6500, "-", 1], [3500, 7500, "-", 1], [4500, 8500, "-", 1], [5500, 9500, "-", 1],
  ];
  // A real person (a public-domain recording). The first two readings came back `synthetic` at 97 % and 93 %.
  const HUMAN_WITH_A_FALSE_START: Recorded[] = [
    [0, 500, "-", 1], [0, 1500, "-", 1], [0, 2500, "s", 0.97], [0, 3500, "s", 0.93], [500, 4500, "s", 0.61],
    [1500, 5500, "n", 0.76], [2500, 6500, "n", 0.93], [3500, 7500, "n", 0.91], [4500, 8500, "n", 0.92],
    [5500, 9500, "n", 0.93], [6500, 10500, "n", 0.91], [7500, 11500, "n", 0.93], [8500, 12500, "-", 1],
    [9500, 13500, "-", 1], [10500, 14500, "n", 0.85], [11500, 15500, "s", 0.54], [12500, 16500, "n", 0.83],
    [13500, 17500, "-", 1], [14500, 18500, "-", 1], [15500, 19500, "-", 1], [16500, 20500, "n", 0.85],
    [17500, 21500, "n", 0.76], [18500, 22500, "n", 0.75], [19500, 23500, "n", 0.93], [20500, 24500, "-", 1],
    [21500, 25500, "n", 0.94],
  ];

  it("flags an uninterrupted synthetic voice 6.5 s into the stream", () => {
    const { statuses, agg } = play(SYNTHETIC);
    expect(statuses).toEqual(["analyzing", "analyzing", "analyzing", "analyzing", "analyzing", "analyzing", "synthetic"]);
    expect(agg.assessment()).toMatchObject({ speechMs: 6000, syntheticShare: 1 });
    expect(agg.assessment().confidence).toBeCloseTo(0.97, 2);
  });

  it("flags a synthetic voice across its pauses: the silence between two utterances is not speech", () => {
    const { statuses, agg } = play(SYNTHETIC_WITH_PAUSES);
    expect(statuses.indexOf("synthetic")).toBe(SYNTHETIC_WITH_PAUSES.length - 1); // 10.5 s into the stream
    expect(agg.assessment().speechMs).toBe(6000);
  });

  it("does not decide a call on two seconds of speech followed by silence", () => {
    const { statuses, agg } = play(SHORT_THEN_SILENCE);
    expect(new Set(statuses)).toEqual(new Set(["analyzing"]));
    expect(agg.assessment().speechMs).toBe(3000);
  });

  it("never flags the real person whose first readings were a confident `synthetic`, and ends on `human`", () => {
    const { statuses, agg } = play(HUMAN_WITH_A_FALSE_START);
    expect(statuses).not.toContain("synthetic");
    expect(statuses.at(-1)).toBe("human");
    // Honest about what the vendor said: three of the early readings were `synthetic`, and the share shows it.
    expect(agg.assessment().syntheticShare).toBeGreaterThan(0.15);
  });

  it("the same person IS flagged at the loosest thresholds the configuration accepts: why the defaults are not those", () => {
    const { statuses } = play(HUMAN_WITH_A_FALSE_START, { windowMs: 2500, minShare: 0.5, minConfidence: 0.5 });
    expect(statuses).toContain("synthetic");
  });
});

describe("VoiceFrameAggregator: frames that add nothing, and reconnects", () => {
  it("ignores repeated, out-of-order and inverted frames", () => {
    const agg = aggregator();
    agg.add(frame(0, 4000, "non-synthetic", 0.9));
    const before = agg.assessment();
    expect(agg.add(frame(0, 4000, "synthetic", 0.99))).toBe(false);
    expect(agg.add(frame(1000, 3000, "synthetic", 0.99))).toBe(false);
    expect(agg.add(frame(9000, 8000, "synthetic", 0.99))).toBe(false);
    expect(agg.assessment()).toEqual(before);
    // The inverted frame did not move the mark: the next real frame counts in full.
    agg.add(frame(4000, 8000, "non-synthetic", 0.9));
    expect(agg.assessment().speechMs).toBe(8000);
  });

  it("counts a frame that starts after a gap from its own start", () => {
    const agg = aggregator();
    agg.add(frame(0, 2000, "non-synthetic", 0.9));
    agg.add(frame(5000, 7000, "non-synthetic", 0.9));
    expect(agg.assessment().speechMs).toBe(4000);
  });

  it("a new connection restarts the vendor's timestamps: the mark is reset, the speech already counted stays", () => {
    const stale = aggregator();
    stale.add(frame(0, 4000, "synthetic", 0.9));
    // Without the reset, the new connection's first frame would look like a repeat.
    expect(stale.add(frame(0, 4000, "synthetic", 0.9))).toBe(false);

    const agg = aggregator();
    agg.add(frame(0, 4000, "synthetic", 0.9));
    agg.resetConnection();
    expect(agg.add(frame(0, 4000, "synthetic", 0.9))).toBe(true);
    expect(agg.assessment()).toMatchObject({ status: "synthetic", speechMs: 8000, syntheticShare: 1 });
  });
});

describe("parseVoiceMessage", () => {
  it("parses the three documented messages", () => {
    expect(parseVoiceMessage('{"type":"frame","frame":{"start_time_ms":0,"end_time_ms":4000,"verdict":"synthetic","confidence":0.9732}}')).toEqual({
      type: "frame",
      frame: { startMs: 0, endMs: 4000, verdict: "synthetic", confidence: 0.9732 },
    });
    expect(parseVoiceMessage(Buffer.from('{"type":"done","duration_ms":12500,"frame_count":10}'))).toEqual({ type: "done", durationMs: 12500, frameCount: 10 });
    expect(parseVoiceMessage('{"type":"error","error":"Insufficient credits."}')).toEqual({ type: "error", error: "Insufficient credits." });
    for (const verdict of ["synthetic", "non-synthetic", "no-content"]) {
      expect(parseVoiceMessage(JSON.stringify({ type: "frame", frame: { start_time_ms: 1, end_time_ms: 2, verdict, confidence: 1 } }))).toMatchObject({
        frame: { verdict },
      });
    }
  });

  it("is lenient: junk, unknown types and incomplete frames are undefined, never an exception", () => {
    expect(parseVoiceMessage("not json")).toBeUndefined();
    expect(parseVoiceMessage("")).toBeUndefined();
    expect(parseVoiceMessage("42")).toBeUndefined();
    expect(parseVoiceMessage("null")).toBeUndefined();
    expect(parseVoiceMessage('{"type":"partial_frame"}')).toBeUndefined();
    expect(parseVoiceMessage('{"type":"frame"}')).toBeUndefined();
    expect(parseVoiceMessage('{"type":"frame","frame":{"start_time_ms":0,"end_time_ms":4000,"verdict":"robot","confidence":0.9}}')).toBeUndefined();
    expect(parseVoiceMessage('{"type":"frame","frame":{"start_time_ms":"0","end_time_ms":4000,"verdict":"synthetic","confidence":0.9}}')).toBeUndefined();
    expect(parseVoiceMessage('{"type":"frame","frame":{"start_time_ms":0,"end_time_ms":4000,"verdict":"synthetic"}}')).toBeUndefined();
    expect(parseVoiceMessage('{"type":"frame","frame":{"start_time_ms":-5,"end_time_ms":4000,"verdict":"synthetic","confidence":0.9}}')).toBeUndefined();
    expect(parseVoiceMessage([Buffer.from('{"type":"done"'), Buffer.from("}")])).toEqual({ type: "done", durationMs: undefined, frameCount: undefined });
    expect(parseVoiceMessage('{"type":"error"}')).toEqual({ type: "error", error: "" });
    // An out-of-range confidence is clamped rather than trusted.
    expect(parseVoiceMessage('{"type":"frame","frame":{"start_time_ms":0,"end_time_ms":1,"verdict":"synthetic","confidence":1.7}}')).toMatchObject({
      frame: { confidence: 1 },
    });
  });
});

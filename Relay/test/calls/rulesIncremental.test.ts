import { describe, expect, it } from "vitest";

import { ScamDetector } from "../../src/calls/scoring/detector.js";
import { TranscriptAnalyzer, analyzeTranscript } from "../../src/calls/scoring/rules.js";
import { CallSession, MAX_SEGMENTS } from "../../src/calls/session.js";
import type { Speaker, TranscriptSegment } from "../../src/calls/types.js";
import { FakeClock } from "../helpers.js";
import { CALLER_NUMBER, GUARD_NUMBER, silentLogger, testCallsConfig } from "./fakes.js";

/**
 * The incremental rules analyzer must answer exactly like the one-shot `analyzeTranscript` while doing the regex
 * work once per segment (docs/CALLS.md §6.1, open finding "O(n²) re-analysis per segment").
 */

const SCRIPT: [Speaker, string][] = [
  ["user", "hello who is this"],
  ["caller", "this is the fraud department at your bank there has been unusual activity"],
  ["user", "should i go and buy gift cards for you"],
  ["caller", "yes go buy apple gift cards and read me the numbers on the back"],
  ["caller", "and do not tell anyone about this it is confidential"],
  ["user", "my code is 123456"],
  ["caller", "we will never ask you for your password"],
  ["user", "okay it says the code is 654321 and my pin is 9876"],
  ["caller", "you have to do it right now within the hour"],
  ["user", "let me call my daughter first"],
];

const FILLER = [
  "hello there is this margaret speaking",
  "yes this is she who is calling please",
  "i am calling about your account there has been some unusual activity we noticed",
  "oh dear what kind of activity are you talking about",
  "well we need you to verify a few things first can you confirm your address",
  "sure it is the same as always on the street by the park",
  "thank you and now the weather has been lovely this week has it not",
  "yes we went to the garden center on tuesday and bought some tulips",
];

function segment(id: string, speaker: Speaker, text: string, final = true): TranscriptSegment {
  return { id, speaker, text, atMs: 0, final };
}

function filler(count: number): TranscriptSegment[] {
  const segments: TranscriptSegment[] = [];
  for (let index = 0; index < count; index += 1) {
    segments.push(segment(`f-${index}`, index % 2 ? "user" : "caller", FILLER[index % FILLER.length]!));
  }
  return segments;
}

describe("TranscriptAnalyzer", () => {
  it("answers exactly like analyzeTranscript on a growing transcript (caller-over-user precedence, first occurrence, protective advice, user-only signals)", () => {
    const analyzer = new TranscriptAnalyzer();
    const segments: TranscriptSegment[] = [];
    SCRIPT.forEach(([speaker, text], index) => {
      segments.push(segment(`s-${index}`, speaker, text));
      expect(analyzer.analyze(segments)).toEqual(analyzeTranscript(segments));
    });
    const last = analyzer.analyze(segments);
    expect(last.signals.map((signal) => signal.id)).toContain("call.gift_cards");
    expect(last.signals.find((signal) => signal.id === "call.gift_cards")?.speaker).toBe("caller"); // the caller's line beat the user's earlier one
    expect(last.signals.find((signal) => signal.id === "call.user_sharing_sensitive")?.segmentId).toBe("s-5"); // first occurrence stands
    expect(analyzer.cachedCount).toBe(SCRIPT.length);
  });

  it("ignores partials, re-analyses a final whose text or speaker changed, and forgets segments that left the window", () => {
    const analyzer = new TranscriptAnalyzer();
    const partial = segment("p-1", "caller", "go buy apple gift cards", false);
    expect(analyzer.analyze([partial])).toEqual({ signals: [], score: 0 });
    expect(analyzer.cachedCount).toBe(0);

    const benign = segment("p-1", "caller", "how is the garden doing");
    expect(analyzer.analyze([benign]).signals).toEqual([]);
    const changed = segment("p-1", "caller", "go buy apple gift cards and read me the numbers");
    expect(analyzer.analyze([changed]).signals.map((signal) => signal.id)).toEqual(["call.gift_cards"]);
    const asUser = { ...changed, speaker: "user" as const };
    expect(analyzer.analyze([asUser]).signals[0]?.speaker).toBe("user");
    expect(analyzer.analyze([asUser])).toEqual(analyzeTranscript([asUser]));

    // The session window drops the oldest finals beyond MAX_SEGMENTS: a signal on a dropped line disappears, as in the one-shot form.
    const many = [changed, ...filler(MAX_SEGMENTS)];
    expect(analyzer.analyze(many).signals.map((signal) => signal.id)).toEqual(["call.gift_cards"]);
    expect(analyzer.cachedCount).toBe(MAX_SEGMENTS + 1);
    const windowed = many.slice(1);
    expect(analyzer.analyze(windowed)).toEqual(analyzeTranscript(windowed));
    expect(analyzer.analyze(windowed).signals).toEqual([]);
    expect(analyzer.cachedCount).toBe(MAX_SEGMENTS);
  });

  it("2000 finals: replaying the whole call costs about one full pass, not two thousand", () => {
    const segments = filler(1990).concat(SCRIPT.map(([speaker, text], index) => segment(`s-${index}`, speaker, text)));
    expect(segments).toHaveLength(2000);
    const analyzer = new TranscriptAnalyzer();
    let last = analyzer.analyze([]);
    const startedIncremental = performance.now();
    for (let count = 1; count <= segments.length; count += 1) last = analyzer.analyze(segments.slice(0, count));
    const incrementalMs = performance.now() - startedIncremental;
    const startedFull = performance.now();
    const full = analyzeTranscript(segments);
    const fullPassMs = performance.now() - startedFull;

    expect(last).toEqual(full);
    expect(full.signals.length).toBeGreaterThanOrEqual(4);
    expect(analyzer.cachedCount).toBe(2000);
    // Measured 2026-09-23 on an Apple Silicon Mac: one full pass over 2000 finals ≈ 11 ms, so the previous
    // re-analysis on every final cost ≈ 11 s per call; the incremental replay of all 2000 finals runs in
    // well under a second (≈ 100–200 ms). The bound below is loose enough for a slow CI machine.
    expect(incrementalMs).toBeLessThan(2_000);
    expect(incrementalMs).toBeLessThan(fullPassMs * 400);
    console.info(`[rules] 2000 finals incrementally: ${incrementalMs.toFixed(0)} ms; one full pass: ${fullPassMs.toFixed(1)} ms`);
  });

  it("the detector stays responsive over a 2000-segment call without a scorer", async () => {
    const clock = new FakeClock();
    const detector = new ScamDetector({ scorer: undefined, config: testCallsConfig(), logger: silentLogger(), now: clock.now });
    const session = new CallSession(
      { deviceId: "device-1", line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: clock.now() },
      clock.now,
    );
    detector.attach(session);
    const started = performance.now();
    for (const item of filler(1990)) session.addSegment(item);
    SCRIPT.forEach(([speaker, text], index) => session.addSegment(segment(`s-${index}`, speaker, text)));
    const elapsedMs = performance.now() - started;
    expect(session.segments).toHaveLength(2000);
    expect(session.verdict?.level).toBe("high");
    expect(session.verdict?.reasons.map((reason) => reason.id)).toEqual(analyzeTranscript(session.segments).signals.map((signal) => signal.id).slice(0, 8));
    expect(elapsedMs).toBeLessThan(2_000);
    await detector.close();
  });
});

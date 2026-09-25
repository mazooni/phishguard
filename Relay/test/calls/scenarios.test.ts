import { describe, expect, it } from "vitest";

import { DEMO_SCENARIOS, isDemoScenarioId, scenarioDurationMs, scriptForScenario } from "../../src/calls/demo/scenarios.js";
import { DEMO_SCENARIO_IDS, isE164 } from "../../src/calls/types.js";

/** The vocabulary docs/CALLS.md §6.1 rules key on; the benign scenario must not trip any of it. */
const SCAM_KEYWORDS = [
  /gift\s*card/i,
  /wire\s*transfer|bitcoin|crypto/i,
  /safe\s*account|secure\s*account/i,
  /remote\s*access|connect to your computer|windows key/i,
  /\b(irs|social security|medicare|warrant|arrest(ed)?|sheriff|police)\b/i,
  /\b(grandchild|grandson|granddaughter|jail|bail|hospital|accident)\b/i,
  /don'?t tell|do not tell|don'?t hang up|do not hang up|stay on the line|keep me on the line|confidential/i,
  /\b(urgent|immediately|right now|within the hour|last chance|before tonight|before five)\b/i,
  /\b(one[- ]time code|read me the (code|digits)|password|pin\b|date of birth)/i,
  /\b(prize|lottery|sweepstakes|winner)\b/i,
  /\b(virus|your computer|microsoft|refund|hackers?)\b/i,
  /\b(fraud department|from your bank|government)\b/i,
  /\b(pay(ment)?|fee|dollars|money|transfer)\b/i,
];

describe("demo scenarios", () => {
  it("defines every scenario id with a fictional caller number and a title", () => {
    for (const id of DEMO_SCENARIO_IDS) {
      const scenario = DEMO_SCENARIOS[id];
      expect(scenario.id).toBe(id);
      expect(scenario.title.length).toBeGreaterThan(3);
      expect(scenario.summaryForDocs.length).toBeGreaterThan(10);
      expect(isE164(scenario.callerNumber)).toBe(true);
      // North American fictional range: 555-01xx.
      expect(scenario.callerNumber).toMatch(/^\+1\d{3}55501\d{2}$/);
    }
    expect(isDemoScenarioId("grandparent")).toBe(true);
    expect(isDemoScenarioId("nope")).toBe(false);
  });

  it("keeps every scenario between 6 and 18 lines, alternating speakers, with a caller opening", () => {
    for (const id of DEMO_SCENARIO_IDS) {
      const { lines } = DEMO_SCENARIOS[id];
      expect(lines.length, id).toBeGreaterThanOrEqual(6);
      expect(lines.length, id).toBeLessThanOrEqual(18);
      expect(lines[0]!.speaker).toBe("caller");
      expect(lines[0]!.pauseMs).toBe(0);
      for (let i = 1; i < lines.length; i += 1) {
        expect(lines[i]!.speaker, `${id} line ${i}`).not.toBe(lines[i - 1]!.speaker);
        expect(lines[i]!.pauseMs).toBeGreaterThan(0);
        expect(lines[i]!.text.trim().length).toBeGreaterThan(0);
      }
      expect(scenarioDurationMs(DEMO_SCENARIOS[id])).toBeGreaterThan(10_000);
    }
  });

  it("puts scam vocabulary in every scam scenario's caller lines and none in the benign one", () => {
    for (const id of DEMO_SCENARIO_IDS) {
      const callerText = DEMO_SCENARIOS[id].lines.filter((line) => line.speaker === "caller").map((line) => line.text).join("\n");
      const hits = SCAM_KEYWORDS.filter((pattern) => pattern.test(callerText));
      if (id === "benign") {
        const allText = DEMO_SCENARIOS[id].lines.map((line) => line.text).join("\n");
        expect(SCAM_KEYWORDS.filter((pattern) => pattern.test(allText))).toEqual([]);
      } else {
        expect(hits.length, id).toBeGreaterThanOrEqual(3);
      }
    }
  });

  it("derives the Twilio test-call script from the caller lines with answer pauses of 2–12 s", () => {
    for (const id of DEMO_SCENARIO_IDS) {
      const script = scriptForScenario(id);
      const callerLines = DEMO_SCENARIOS[id].lines.filter((line) => line.speaker === "caller");
      expect(script.lines.map((line) => line.text)).toEqual(callerLines.map((line) => line.text));
      for (const line of script.lines) {
        expect(Number.isInteger(line.pauseSeconds)).toBe(true);
        expect(line.pauseSeconds).toBeGreaterThanOrEqual(2);
        expect(line.pauseSeconds).toBeLessThanOrEqual(12);
      }
    }
    // Grandparent: the first caller line waits for the 2200 ms answer plus the 1800 ms pause before line 3 → 4 s.
    expect(scriptForScenario("grandparent").lines[0]!.pauseSeconds).toBe(4);
  });
});

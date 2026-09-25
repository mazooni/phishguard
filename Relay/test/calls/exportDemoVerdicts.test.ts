import { describe, expect, it } from "vitest";

import {
  EXPORT_UPDATED_AT,
  recordAllScenarios,
  recordScenario,
  renderExport,
  scenarioSegments,
  swiftScenario,
  swiftString,
  type DemoVerdictExport,
} from "../../scripts/export-demo-verdicts.js";
import { DEMO_SCENARIOS, scenarioDurationMs } from "../../src/calls/demo/scenarios.js";
import { fuseVerdict } from "../../src/calls/scoring/fusion.js";
import { analyzeTranscript } from "../../src/calls/scoring/rules.js";
import { DEMO_SCENARIO_IDS, riskLevelRank } from "../../src/calls/types.js";

/**
 * `npm run calls:export-demo-verdicts` records the rule engine's verdict for each scripted call so the app's
 * offline demo (docs/CALLS.md §7.4) carries real output. The export must be reproducible and must say what the
 * demo path says: every scam scenario at least `medium` on rules alone, the neighbour `safe`.
 */
describe("scripts/export-demo-verdicts", () => {
  it("is deterministic: two runs produce identical recordings and identical text", () => {
    const first = recordAllScenarios();
    const second = recordAllScenarios();
    expect(second).toEqual(first);
    expect(renderExport(second)).toBe(renderExport(first));
    expect(first.map((recording) => recording.export.scenario)).toEqual([...DEMO_SCENARIO_IDS]);
  });

  it("flags every scam scenario at medium or above and leaves the benign one safe", () => {
    for (const recording of recordAllScenarios()) {
      const { scenario, verdict } = recording.export;
      if (scenario === "benign") {
        expect(verdict.level).toBe("safe");
        expect(verdict.category).toBe("safe");
        expect(verdict.summary).toBe("No signs of a scam so far.");
      } else {
        expect(riskLevelRank(verdict.level), scenario).toBeGreaterThanOrEqual(riskLevelRank("medium"));
        expect(verdict.category, scenario).not.toBe("safe");
        expect(verdict.reasons.length, scenario).toBeGreaterThan(0);
        expect(verdict.reasons.some((reason) => reason.severity === "high"), scenario).toBe(true);
      }
    }
  });

  it("exports the scenario's number and rounded-up duration with a rules-only verdict and no sequence", () => {
    for (const recording of recordAllScenarios()) {
      const entry = recording.export;
      const scenario = DEMO_SCENARIOS[entry.scenario];
      expect(entry.callerNumber).toBe(scenario.callerNumber);
      expect(entry.durationSeconds).toBe(Math.ceil(scenarioDurationMs(scenario) / 1000));
      expect(entry.durationSeconds * 1000).toBeGreaterThanOrEqual(scenarioDurationMs(scenario));
      expect(Object.keys(entry.verdict)).not.toContain("sequence");
      expect(entry.verdict.modelIdentifier).toBeUndefined();
      expect(entry.verdict.modelRiskScore).toBeUndefined();
      expect(entry.verdict.heuristicScore).toBe(entry.verdict.confidence);
      expect(entry.verdict.updatedAt).toBe(EXPORT_UPDATED_AT);
      expect(entry.verdict.reasons.every((reason) => reason.source === "heuristic" && reason.id.startsWith("call."))).toBe(true);
      expect(entry.verdict.reasons.length).toBeLessThanOrEqual(8);
      expect(recording.title).toBe(scenario.title);
      // The detector emits at least the first verdict and at most one per final segment.
      expect(recording.sequence).toBeGreaterThanOrEqual(1);
      expect(recording.sequence).toBeLessThanOrEqual(scenario.lines.length);
    }
  });

  it("records what the detector's last evaluation would hold: the rules over the whole transcript, no model", () => {
    for (const id of DEMO_SCENARIO_IDS) {
      const scenario = DEMO_SCENARIOS[id];
      const segments = scenarioSegments(scenario);
      expect(segments.map((segment) => segment.id)).toEqual(scenario.lines.map((_, index) => `demo-${index + 1}`));
      expect(segments.every((segment) => segment.final)).toBe(true);
      expect(segments.at(-1)?.atMs).toBe(scenarioDurationMs(scenario));
      const expected = fuseVerdict({ rules: analyzeTranscript(segments), model: undefined, now: EXPORT_UPDATED_AT });
      expect(recordScenario(scenario).export.verdict).toEqual(expected);
    }
  });

  it("prints the JSON objects first, then a Swift snippet in DemoCalls.swift's shape", () => {
    const recordings = recordAllScenarios();
    const text = renderExport(recordings);
    const [jsonText, swiftText] = text.split("\n\n// Swift — App/PhishGuard/Features/Support/DemoCalls.swift\n\n");
    const parsed = JSON.parse(jsonText!) as DemoVerdictExport[];
    expect(parsed).toEqual(recordings.map((recording) => recording.export));
    for (const recording of recordings) {
      const id = recording.export.scenario;
      expect(swiftText).toContain(`    static let ${id} = Scenario(\n        id: .${id},`);
      expect(swiftText).toContain(`            sequence: ${recording.sequence},`);
    }
    // Swift literal for a reason title with a straight quote in it.
    const irs = swiftScenario(recordings.find((recording) => recording.export.scenario === "irs")!);
    expect(irs).toContain('title: "Says to move money to a \\"safe account\\""');
    expect(irs).not.toContain("modelIdentifier");
  });

  it("escapes Swift string literals", () => {
    expect(swiftString('say "hi"\\now\n')).toBe('"say \\"hi\\"\\\\now\\n"');
    expect(swiftString("curly “quotes” and ’apostrophes’ stay")).toBe('"curly “quotes” and ’apostrophes’ stay"');
  });
});

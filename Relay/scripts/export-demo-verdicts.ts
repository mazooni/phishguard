import { pathToFileURL } from "node:url";

import { DEMO_SCENARIOS, scenarioDurationMs, type DemoScenario } from "../src/calls/demo/scenarios.js";
import { fuseVerdict } from "../src/calls/scoring/fusion.js";
import { analyzeTranscript } from "../src/calls/scoring/rules.js";
import { DEMO_SCENARIO_IDS, type CallVerdict, type DemoScenarioId, type TranscriptSegment } from "../src/calls/types.js";

/**
 * `npm run calls:export-demo-verdicts` — records what the rule engine says about each scripted demo call, for the
 * app's offline demo (docs/CALLS.md §7.4: "a bundled scenario with the rule engine's recorded verdict").
 *
 * Every scenario's lines are fed through `analyzeTranscript` + `fuseVerdict` exactly as `ScamDetector` does for a
 * rules-only call (no model, so `modelRiskScore`/`modelIdentifier` are absent): the segments are the ones
 * `DemoCallRunner` emits (`demo-N`, scripted offsets), the rules re-run over the whole transcript on every final
 * segment, and a verdict counts as emitted only when the detector's signature (level, confidence to 2 dp, reason
 * ids, summary) changes — that count is the `sequence` the session would have stored. The final verdict is what
 * the relay would persist for the call. `updatedAt` is the detector's wall clock and is fixed at 0 here so the
 * export is byte-for-byte reproducible.
 *
 * Prints, for every `DemoScenarioId`, a JSON object `{scenario, callerNumber, durationSeconds, verdict}` (the
 * verdict without `sequence`), then the same as Swift in the shape `App/PhishGuard/Features/Support/DemoCalls.swift`
 * uses. Re-run after any change to `scoring/rules.ts`, `scoring/fusion.ts` or `demo/scenarios.ts` and paste the
 * Swift into `DemoCalls.swift` verbatim.
 */

export interface DemoVerdictExport {
  scenario: DemoScenarioId;
  callerNumber: string;
  /** The scenario's total scripted duration, rounded up to whole seconds. */
  durationSeconds: number;
  verdict: Omit<CallVerdict, "sequence">;
}

export interface DemoVerdictRecording {
  export: DemoVerdictExport;
  /** Number of verdicts `ScamDetector` would have handed to `session.setVerdict`, i.e. the final `sequence`. */
  sequence: number;
  title: string;
  summaryForDocs: string;
}

/** `updatedAt` of every exported verdict: the detector's clock, pinned for reproducibility. */
export const EXPORT_UPDATED_AT = 0;

/** The final segments `DemoCallRunner` would feed the session at speed 1 (ids and offsets included). */
export function scenarioSegments(scenario: DemoScenario): TranscriptSegment[] {
  let at = 0;
  return scenario.lines.map((line, index) => {
    at += line.pauseMs;
    return { id: `demo-${index + 1}`, speaker: line.speaker, text: line.text, atMs: at, final: true };
  });
}

/** `ScamDetector.evaluate`'s hysteresis key. */
function signature(verdict: Omit<CallVerdict, "sequence">): string {
  return [verdict.level, verdict.confidence.toFixed(2), verdict.reasons.map((reason) => reason.id).join(","), verdict.summary].join("|");
}

export function recordScenario(scenario: DemoScenario): DemoVerdictRecording {
  const segments = scenarioSegments(scenario);
  let lastSignature: string | undefined;
  let sequence = 0;
  let verdict: Omit<CallVerdict, "sequence"> | undefined;
  for (let count = 1; count <= segments.length; count += 1) {
    const rules = analyzeTranscript(segments.slice(0, count));
    verdict = fuseVerdict({ rules, model: undefined, now: EXPORT_UPDATED_AT });
    const key = signature(verdict);
    if (key === lastSignature) continue;
    lastSignature = key;
    sequence += 1;
  }
  if (!verdict) throw new Error(`scenario ${scenario.id} has no lines`);
  return {
    export: {
      scenario: scenario.id,
      callerNumber: scenario.callerNumber,
      durationSeconds: Math.ceil(scenarioDurationMs(scenario) / 1000),
      verdict,
    },
    sequence,
    title: scenario.title,
    summaryForDocs: scenario.summaryForDocs,
  };
}

export function recordAllScenarios(): DemoVerdictRecording[] {
  return DEMO_SCENARIO_IDS.map((id) => recordScenario(DEMO_SCENARIOS[id]));
}

// MARK: Swift rendering

/** A Swift string literal body: backslash, double quote and control characters escaped; everything else as is. */
export function swiftString(text: string): string {
  let out = "";
  for (const char of text) {
    switch (char) {
      case "\\":
        out += "\\\\";
        break;
      case '"':
        out += '\\"';
        break;
      case "\n":
        out += "\\n";
        break;
      case "\r":
        out += "\\r";
        break;
      case "\t":
        out += "\\t";
        break;
      case "\0":
        out += "\\0";
        break;
      default:
        out += char;
    }
  }
  return `"${out}"`;
}

/** Shortest round-trip decimal; Swift parses it to the same double. */
function swiftNumber(value: number): string {
  if (!Number.isFinite(value)) throw new Error(`not a finite number: ${value}`);
  return String(value);
}

export function swiftScenario(recording: DemoVerdictRecording): string {
  const { export: entry, sequence } = recording;
  const verdict = entry.verdict;
  const lines: string[] = [];
  lines.push(`    /// ${recording.summaryForDocs}`);
  lines.push(`    static let ${entry.scenario} = Scenario(`);
  lines.push(`        id: .${entry.scenario},`);
  lines.push(`        title: ${swiftString(recording.title)},`);
  lines.push(`        callerNumber: ${swiftString(entry.callerNumber)},`);
  lines.push(`        durationSeconds: ${entry.durationSeconds},`);
  lines.push(`        verdict: CallVerdict(`);
  lines.push(`            sequence: ${sequence},`);
  lines.push(`            category: .${verdict.category},`);
  lines.push(`            confidence: ${swiftNumber(verdict.confidence)},`);
  lines.push(`            level: .${verdict.level},`);
  if (verdict.reasons.length === 0) {
    lines.push(`            reasons: [],`);
  } else {
    lines.push(`            reasons: [`);
    for (const reason of verdict.reasons) {
      lines.push(`                CallReason(id: ${swiftString(reason.id)}, title: ${swiftString(reason.title)},`);
      lines.push(`                           detail: ${swiftString(reason.detail)},`);
      lines.push(`                           severity: .${reason.severity}, source: .${reason.source}),`);
    }
    lines.push(`            ],`);
  }
  lines.push(`            summary: ${swiftString(verdict.summary)},`);
  lines.push(`            recommendedAction: ${swiftString(verdict.recommendedAction)},`);
  lines.push(`            heuristicScore: ${swiftNumber(verdict.heuristicScore)},`);
  if (verdict.modelRiskScore !== undefined) lines.push(`            modelRiskScore: ${swiftNumber(verdict.modelRiskScore)},`);
  if (verdict.modelIdentifier !== undefined) lines.push(`            modelIdentifier: ${swiftString(verdict.modelIdentifier)},`);
  lines.push(`            updatedAt: ${verdict.updatedAt}`);
  lines.push(`        )`);
  lines.push(`    )`);
  return lines.join("\n");
}

/** What the CLI prints: the JSON objects (one array), then the Swift snippet. */
export function renderExport(recordings: readonly DemoVerdictRecording[]): string {
  const json = JSON.stringify(
    recordings.map((recording) => recording.export),
    null,
    2,
  );
  const swift = recordings.map(swiftScenario).join("\n\n");
  return `${json}\n\n// Swift — App/PhishGuard/Features/Support/DemoCalls.swift\n\n${swift}\n`;
}

const invokedDirectly = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  process.stdout.write(renderExport(recordAllScenarios()));
}

import { describe, expect, it } from "vitest";

import type { ModelScoringResult } from "../../src/calls/openai/scorer.js";
import {
  AGREEMENT_BONUS,
  derivedCategory,
  fusedReasons,
  fuseVerdict,
  generatedSummary,
  severityForRiskScore,
} from "../../src/calls/scoring/fusion.js";
import { SIGNAL_CATALOG, saturatingScore, type CallSignal, type RulesResult } from "../../src/calls/scoring/rules.js";
import { riskLevelRank, type CallSeverity } from "../../src/calls/types.js";
import { benignResult, scamResult } from "./fakes.js";

const NOW = 1_760_000_000_000;

function signal(id: string, overrides: Partial<CallSignal> = {}): CallSignal {
  const definition = SIGNAL_CATALOG.get(id);
  return {
    id,
    title: definition?.title ?? id,
    description: definition?.description ?? id,
    severity: definition?.severity ?? "medium",
    weight: definition?.weight ?? 0.3,
    detail: `Caller said: “${id}”`,
    speaker: "caller",
    segmentId: "caller-1",
    ...overrides,
  };
}

function rules(...signals: CallSignal[]): RulesResult {
  return { signals, score: saturatingScore(signals.map((entry) => entry.weight)) };
}

function withScore(score: number, ...signals: CallSignal[]): RulesResult {
  return { signals, score };
}

function model(overrides: Partial<ModelScoringResult>): ModelScoringResult {
  return scamResult(overrides);
}

const GIFT = signal("call.gift_cards");
const URGENCY = signal("call.urgency");
const OTP = signal("call.otp_or_credentials");
const ERRAND = signal("call.gift_card_errand");
const SECRECY = signal("call.secrecy");
const FAMILY = signal("call.family_emergency");

describe("fuseVerdict — confidence", () => {
  it("is the rule score alone when there is no model", () => {
    const verdict = fuseVerdict({ rules: withScore(0.8, GIFT), now: NOW });
    expect(verdict.confidence).toBeCloseTo(0.8, 9);
    expect(verdict.level).toBe("high");
    expect(verdict.heuristicScore).toBeCloseTo(0.8, 9);
    expect(verdict.modelRiskScore).toBeUndefined();
    expect(verdict.modelIdentifier).toBeUndefined();
    expect(verdict.updatedAt).toBe(NOW);
  });

  it("lets the model raise the alert alone: rules 0 + model 90 → high", () => {
    const verdict = fuseVerdict({ rules: rules(), model: model({ riskScore: 90 }), now: NOW });
    expect(verdict.confidence).toBeCloseTo(0.9, 9);
    expect(verdict.level).toBe("high");
    expect(verdict.category).toBe("scam");
    expect(verdict.modelRiskScore).toBe(90);
    expect(verdict.modelIdentifier).toBe("openai:gpt-6-luna");
  });

  it("lets the rules raise the alert alone: rules 0.8 + model safe → high", () => {
    const verdict = fuseVerdict({ rules: withScore(0.8, GIFT), model: benignResult(), now: NOW });
    expect(verdict.confidence).toBeCloseTo(0.8, 9);
    expect(verdict.level).toBe("high");
    expect(verdict.modelRiskScore).toBe(5);
  });

  it("adds the agreement bonus only with isScam, riskScore ≥ 50 and a high-severity rule signal", () => {
    const agreeing = fuseVerdict({ rules: withScore(0.7, GIFT), model: model({ riskScore: 70, isScam: true }), now: NOW });
    expect(agreeing.confidence).toBeCloseTo(0.7 + AGREEMENT_BONUS, 9);
    expect(agreeing.level).toBe("high");

    const mediumOnly = fuseVerdict({ rules: withScore(0.7, URGENCY), model: model({ riskScore: 70, isScam: true }), now: NOW });
    expect(mediumOnly.confidence).toBeCloseTo(0.7, 9);

    const weakModel = fuseVerdict({ rules: withScore(0.7, GIFT), model: model({ riskScore: 45, isScam: true }), now: NOW });
    expect(weakModel.confidence).toBeCloseTo(0.7, 9);

    const notScam = fuseVerdict({ rules: withScore(0.7, GIFT), model: model({ riskScore: 70, isScam: false }), now: NOW });
    expect(notScam.confidence).toBeCloseTo(0.7, 9);
  });

  it("clamps to 1", () => {
    const verdict = fuseVerdict({ rules: withScore(0.95, GIFT), model: model({ riskScore: 98 }), now: NOW });
    expect(verdict.confidence).toBe(1);
  });

  it("applies the PhishCore thresholds", () => {
    const at = (riskScore: number) => fuseVerdict({ rules: rules(), model: model({ riskScore, isScam: riskScore >= 50 }), now: NOW }).level;
    expect(at(29)).toBe("safe");
    expect(at(30)).toBe("low");
    expect(at(50)).toBe("medium");
    expect(at(75)).toBe("high");
  });
});

/** The errand tier of the gift-card signal (docs/CALLS.md §6.1): low, 0.15, never an alert on its own. */
describe("fuseVerdict — a gift-card errand", () => {
  it("alone leaves the verdict safe with the errand as its one reason", () => {
    const verdict = fuseVerdict({ rules: rules(ERRAND), now: NOW });
    expect(ERRAND.severity).toBe("low");
    expect(verdict.confidence).toBeCloseTo(0.15, 9);
    expect(verdict.level).toBe("safe");
    expect(verdict.category).toBe("safe");
    expect(verdict.summary).toBe("No signs of a scam so far.");
    expect(verdict.recommendedAction).toBe("Nothing suspicious so far.");
    expect(verdict.reasons.map((reason) => [reason.id, reason.severity, reason.source])).toEqual([["call.gift_card_errand", "low", "heuristic"]]);
  });

  it("with urgency stays below medium", () => {
    const verdict = fuseVerdict({ rules: rules(URGENCY, ERRAND), now: NOW });
    expect(verdict.confidence).toBeCloseTo(1 - 0.75 * 0.85, 9);
    expect(verdict.level).toBe("low");
    expect(riskLevelRank(verdict.level)).toBeLessThan(riskLevelRank("medium"));
    expect(verdict.recommendedAction).toBe("Be careful: do not share codes or card details.");
  });

  it("with secrecy and a family emergency reaches high through the other signals, as before", () => {
    const withErrand = fuseVerdict({ rules: rules(FAMILY, SECRECY, ERRAND), now: NOW });
    const without = fuseVerdict({ rules: rules(FAMILY, SECRECY), now: NOW });
    expect(without.level).toBe("high");
    expect(withErrand.level).toBe("high");
    expect(withErrand.category).toBe("scam");
    expect(withErrand.confidence).toBeGreaterThan(without.confidence);
    expect(withErrand.reasons.map((reason) => reason.id)).toEqual(["call.family_emergency", "call.secrecy", "call.gift_card_errand"]);
  });

  it("is not the high-severity rule signal the agreement bonus needs", () => {
    const verdict = fuseVerdict({ rules: withScore(0.7, ERRAND), model: model({ riskScore: 70, isScam: true }), now: NOW });
    expect(verdict.confidence).toBeCloseTo(0.7, 9);
  });
});

describe("fuseVerdict — category", () => {
  it("takes the model's category when present, not safe, at confidence ≥ 0.5", () => {
    expect(fuseVerdict({ rules: rules(), model: model({ riskScore: 80, category: "phishing" }), now: NOW }).category).toBe("phishing");
    expect(fuseVerdict({ rules: rules(), model: model({ riskScore: 60, category: "spam", isScam: false }), now: NOW }).category).toBe("spam");
  });

  it("derives the category from the signals when the model says safe or is unsure", () => {
    expect(fuseVerdict({ rules: withScore(0.8, GIFT), model: benignResult(), now: NOW }).category).toBe("scam");
    expect(fuseVerdict({ rules: withScore(0.4, OTP), model: model({ riskScore: 40, category: "phishing" }), now: NOW }).category).toBe("phishing");
    expect(fuseVerdict({ rules: withScore(0.4, URGENCY), now: NOW }).category).toBe("scam");
  });

  it("never labels a flagged verdict safe and always labels a safe one safe", () => {
    expect(derivedCategory([URGENCY], "low")).toBe("scam");
    expect(derivedCategory([OTP], "medium")).toBe("phishing");
    expect(derivedCategory([OTP, GIFT], "high")).toBe("scam");
    expect(derivedCategory([GIFT], "safe")).toBe("safe");
    expect(fuseVerdict({ rules: rules(), model: benignResult(), now: NOW }).category).toBe("safe");
  });
});

describe("fuseVerdict — reasons", () => {
  it("tags rule signals as heuristic and model reasons as model, ordered by severity", () => {
    const verdict = fuseVerdict({
      rules: rules(URGENCY, GIFT),
      model: model({ riskScore: 60, reasons: [{ title: "Pretends to be a grandchild", detail: "Says they are in jail." }] }),
      now: NOW,
    });
    expect(verdict.reasons.map((reason) => [reason.id, reason.source, reason.severity])).toEqual([
      ["call.gift_cards", "heuristic", "high"],
      ["call.urgency", "heuristic", "medium"],
      ["model.reason.0", "model", "medium"],
    ]);
    expect(verdict.reasons[0]?.detail).toBe(GIFT.detail);
  });

  it("drops a model reason whose normalised title repeats a rule and keeps the rule", () => {
    const reasons = fusedReasons([GIFT], model({ riskScore: 90, reasons: [{ title: "  asks for GIFT cards! ", detail: "model detail" }] }));
    expect(reasons).toHaveLength(1);
    expect(reasons[0]?.source).toBe("heuristic");
  });

  it("caps at 8 reasons, 6 of them from the model, and trims details to 300 characters", () => {
    const signals = ["call.gift_cards", "call.secrecy", "call.urgency"].map((id) => signal(id));
    const modelReasons = Array.from({ length: 9 }, (_, index) => ({ title: `Model finding ${index}`, detail: "x".repeat(400) }));
    const reasons = fusedReasons(signals, model({ riskScore: 90, reasons: modelReasons }));
    expect(reasons).toHaveLength(8);
    // Severity first: the two high rule signals and six high model reasons outrank the medium urgency rule.
    expect(reasons.filter((reason) => reason.source === "model")).toHaveLength(6);
    expect(reasons.map((reason) => reason.id)).not.toContain("call.urgency");
    const many = fusedReasons([], model({ riskScore: 90, reasons: modelReasons }));
    expect(many).toHaveLength(6);
    for (const reason of many) expect(reason.detail.length).toBeLessThanOrEqual(300);
  });

  it("maps the model risk score to a reason severity", () => {
    const expected: [number, CallSeverity][] = [
      [10, "info"],
      [30, "low"],
      [50, "medium"],
      [75, "high"],
    ];
    for (const [score, severity] of expected) expect(severityForRiskScore(score)).toBe(severity);
  });
});

describe("fuseVerdict — summary and action", () => {
  it("uses the model summary and action when present", () => {
    const verdict = fuseVerdict({ rules: rules(GIFT), model: model({ riskScore: 90 }), now: NOW });
    expect(verdict.summary).toBe(scamResult().summary);
    expect(verdict.recommendedAction).toBe(scamResult().recommendedAction);
  });

  it("generates a sentence from the top signals without a model or with a blank model summary", () => {
    const rulesOnly = fuseVerdict({ rules: rules(URGENCY, GIFT), now: NOW });
    expect(rulesOnly.summary).toBe("This call looks like a scam: Asks for gift cards; Creates urgency.");
    const blank = fuseVerdict({ rules: rules(GIFT), model: model({ riskScore: 90, summary: "   " }), now: NOW });
    expect(blank.summary).toBe("This call looks like a scam: Asks for gift cards.");
    expect(generatedSummary("safe", "safe", [])).toBe("No signs of a scam so far.");
    expect(generatedSummary("medium", "phishing", [OTP])).toContain("codes or passwords");
    expect(generatedSummary("low", "scam", [])).toBe("This call looks like a scam (low risk).");
  });

  it("falls back to per-level actions and bounds the model's", () => {
    expect(fuseVerdict({ rules: rules(), now: NOW }).recommendedAction).toBe("Nothing suspicious so far.");
    expect(fuseVerdict({ rules: withScore(0.35, URGENCY), now: NOW }).recommendedAction).toBe("Be careful: do not share codes or card details.");
    expect(fuseVerdict({ rules: withScore(0.6, GIFT), now: NOW }).recommendedAction).toBe(
      "Hang up and call the organisation back on a number you trust.",
    );
    expect(fuseVerdict({ rules: withScore(0.9, GIFT), now: NOW }).recommendedAction).toBe(
      "Hang up and call the organisation back on a number you trust.",
    );
    const long = fuseVerdict({ rules: rules(), model: model({ riskScore: 90, recommendedAction: "y".repeat(400) }), now: NOW });
    expect(long.recommendedAction.length).toBeLessThanOrEqual(200);
    const longSummary = fuseVerdict({ rules: rules(), model: model({ riskScore: 90, summary: "z".repeat(800) }), now: NOW });
    expect(longSummary.summary.length).toBeLessThanOrEqual(500);
  });
});

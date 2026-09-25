import { MAX_MODEL_REASONS, type ModelScoringResult } from "../openai/scorer.js";
import {
  MAX_REASON_DETAIL_CHARS,
  MAX_RECOMMENDED_ACTION_CHARS,
  MAX_SUMMARY_CHARS,
  MAX_VERDICT_REASONS,
  clamp01,
  riskLevelForConfidence,
  riskLevelRank,
  severityRank,
  truncate,
  type CallCategory,
  type CallReason,
  type CallRiskLevel,
  type CallSeverity,
  type CallVerdict,
} from "../types.js";
import type { CallSignal, RulesResult } from "./rules.js";

/**
 * Fuses the rule signals with the latest model answer (docs/CALLS.md §6.2), mirroring PhishCore's
 * `VerdictEngine`: the rules and the model are two independent detectors, so the confidence is the *maximum*
 * of the two — either may raise the alert on its own and neither may veto the other. A small agreement bonus
 * applies only when both are independently elevated: the model says scam with riskScore ≥ 50 and the rules
 * hold at least one high-severity signal. An absent model leaves the verdict rules-only.
 */

export const AGREEMENT_BONUS = 0.1;
export const AGREEMENT_MODEL_SCORE = 50;
export const MAX_REASON_TITLE_CHARS = 100;

export interface FusionInput {
  rules: RulesResult;
  /** The last successful model answer, if any. */
  model?: ModelScoringResult | undefined;
  /** ms since epoch, becomes `updatedAt`. */
  now: number;
}

/** Signal ids that mean "they are after your codes or passwords" rather than money. */
const PHISHING_SIGNAL_IDS: ReadonlySet<string> = new Set(["call.otp_or_credentials", "call.user_sharing_sensitive"]);

const DEFAULT_ACTIONS: Readonly<Record<CallRiskLevel, string>> = {
  safe: "Nothing suspicious so far.",
  low: "Be careful: do not share codes or card details.",
  medium: "Hang up and call the organisation back on a number you trust.",
  high: "Hang up and call the organisation back on a number you trust.",
};

export function fuseVerdict(input: FusionInput): Omit<CallVerdict, "sequence"> {
  const { rules, model } = input;
  const heuristicScore = clamp01(rules.score);
  const hasHighSignal = rules.signals.some((signal) => signal.severity === "high");

  let confidence = heuristicScore;
  if (model) {
    const modelScore = clamp01(model.riskScore / 100);
    confidence = Math.max(heuristicScore, modelScore);
    if (model.isScam && model.riskScore >= AGREEMENT_MODEL_SCORE && hasHighSignal) {
      confidence = clamp01(confidence + AGREEMENT_BONUS);
    }
  }

  const level = riskLevelForConfidence(confidence);
  const category = fusedCategory(rules.signals, model, confidence, level);
  const reasons = fusedReasons(rules.signals, model);

  // The model's prose is shown only when the model stands behind the level shown. When the rules alone put the
  // call higher than the model did, a summary or action that plays the call down — what a caller gets by
  // addressing the model through the transcript — must not be what the person reads; the generated text is.
  const speaking = model && modelStandsBehind(model, heuristicScore) ? model : undefined;
  const modelSummary = speaking ? speaking.summary.trim() : "";
  const summary = modelSummary ? truncate(modelSummary, MAX_SUMMARY_CHARS) : generatedSummary(level, category, rules.signals);
  const modelAction = speaking ? speaking.recommendedAction.trim() : "";
  const recommendedAction = modelAction ? truncate(modelAction, MAX_RECOMMENDED_ACTION_CHARS) : DEFAULT_ACTIONS[level];

  const verdict: Omit<CallVerdict, "sequence"> = {
    category,
    confidence,
    level,
    reasons,
    summary,
    recommendedAction,
    heuristicScore,
    updatedAt: input.now,
  };
  if (model) {
    verdict.modelRiskScore = model.riskScore;
    verdict.modelIdentifier = model.modelIdentifier;
  }
  return verdict;
}

/** True when the model's own level is at least the rules' level: it set, or matched, the level the verdict shows. */
export function modelStandsBehind(model: ModelScoringResult, heuristicScore: number): boolean {
  const modelLevel = riskLevelForConfidence(clamp01(model.riskScore / 100));
  return riskLevelRank(modelLevel) >= riskLevelRank(riskLevelForConfidence(clamp01(heuristicScore)));
}

/**
 * The model's category when it gave one, not `safe`, and the fused confidence reaches medium; otherwise derived
 * from the signal ids. A verdict whose level is not `safe` never carries category `safe`.
 */
export function fusedCategory(
  signals: readonly CallSignal[],
  model: ModelScoringResult | undefined,
  confidence: number,
  level: CallRiskLevel,
): CallCategory {
  if (model && model.category !== "safe" && confidence >= 0.5) return model.category;
  return derivedCategory(signals, level);
}

export function derivedCategory(signals: readonly CallSignal[], level: CallRiskLevel): CallCategory {
  if (level === "safe") return "safe";
  const ids = signals.filter((signal) => signal.weight > 0).map((signal) => signal.id);
  const phishing = ids.some((id) => PHISHING_SIGNAL_IDS.has(id));
  const other = ids.some((id) => !PHISHING_SIGNAL_IDS.has(id));
  // Money-shaped evidence outranks a code request; a call that is *only* after codes is phishing.
  if (phishing && !other) return "phishing";
  return "scam";
}

/** riskScore → severity for model reasons, as `VerdictEngine.severity(forRiskScore:)`. */
export function severityForRiskScore(riskScore: number): CallSeverity {
  if (riskScore >= 75) return "high";
  if (riskScore >= 50) return "medium";
  if (riskScore >= 30) return "low";
  return "info";
}

function normalizeTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim();
}

/**
 * Rule signals as heuristic reasons, then the model's as model reasons; a model reason whose title matches a
 * rule's (normalised) is dropped so the rule's quoted evidence is what the person sees. Stable sort by severity
 * descending, at most `MAX_VERDICT_REASONS`.
 */
export function fusedReasons(signals: readonly CallSignal[], model: ModelScoringResult | undefined): CallReason[] {
  const reasons: CallReason[] = [];
  const seen = new Set<string>();
  for (const signal of signals) {
    const title = truncate(signal.title, MAX_REASON_TITLE_CHARS);
    seen.add(normalizeTitle(title));
    reasons.push({
      id: signal.id,
      title,
      detail: truncate(signal.detail, MAX_REASON_DETAIL_CHARS),
      severity: signal.severity,
      source: "heuristic",
    });
  }
  if (model) {
    const severity = severityForRiskScore(model.riskScore);
    let index = 0;
    for (const reason of model.reasons.slice(0, MAX_MODEL_REASONS)) {
      const title = truncate(reason.title, MAX_REASON_TITLE_CHARS);
      const detail = truncate(reason.detail, MAX_REASON_DETAIL_CHARS);
      if (!title) continue;
      const key = normalizeTitle(title);
      if (seen.has(key)) continue;
      seen.add(key);
      reasons.push({ id: `model.reason.${index}`, title, detail: detail || title, severity, source: "model" });
      index += 1;
    }
  }
  return reasons
    .map((reason, offset) => ({ reason, offset }))
    .sort((a, b) => severityRank(b.reason.severity) - severityRank(a.reason.severity) || a.offset - b.offset)
    .map((entry) => entry.reason)
    .slice(0, MAX_VERDICT_REASONS);
}

function summaryPhrase(category: CallCategory): string {
  switch (category) {
    case "phishing":
      return "like an attempt to get your codes or passwords";
    case "scam":
      return "like a scam";
    case "spam":
      return "like an unwanted sales call";
    case "safe":
      return "suspicious";
  }
}

/** A sentence from the top signals when the model gave no summary (or is absent). */
export function generatedSummary(level: CallRiskLevel, category: CallCategory, signals: readonly CallSignal[]): string {
  if (level === "safe") return "No signs of a scam so far.";
  const top = [...signals]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.weight - a.weight)
    .slice(0, 2)
    .map((signal) => signal.title);
  const what = summaryPhrase(category);
  if (top.length === 0) return `This call looks ${what} (${level} risk).`;
  return `This call looks ${what}: ${top.join("; ")}.`;
}

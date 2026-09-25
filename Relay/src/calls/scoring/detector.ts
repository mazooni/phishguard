import type { FastifyBaseLogger } from "fastify";

import type { CallsConfig } from "../config.js";
import { ModelScoringError, type ModelScorer, type ModelScoringInput, type ModelScoringResult } from "../openai/scorer.js";
import type { CallSession } from "../session.js";
import { redactNumber, type SessionObserver, type TranscriptSegment } from "../types.js";
import { fuseVerdict } from "./fusion.js";
import { TranscriptAnalyzer, type RulesResult } from "./rules.js";

/**
 * Cadence and hysteresis (docs/CALLS.md §6.3). Rules run synchronously on every *final* segment and are fused
 * with the last model answer; `session.setVerdict` fires only when something the person would notice changed
 * (level, confidence to 2 dp, reason ids, summary). The model runs when there is new final text since its last
 * call, at most once per `modelMinIntervalMs` (trailing timer), one request in flight per session, never on
 * fewer than `MIN_TRANSCRIPT_CHARS` of transcript, and once more at call end for the final summary. A failed
 * or refused model pass keeps the previous model answer; no scorer means rules-only verdicts.
 *
 * All timing reads the injected `now()`; scheduling uses `setTimeout` with unref'd, cancellable timers.
 */

export interface ScamDetectorOptions {
  scorer: ModelScorer | undefined;
  config: CallsConfig;
  logger: FastifyBaseLogger;
  now: () => number;
}

export const MIN_TRANSCRIPT_CHARS = 40;
export const FINAL_PASS_CAP_MS = 10_000;

interface InFlight {
  controller: AbortController;
  done: Promise<void>;
}

interface SessionState {
  session: CallSession;
  /** Per-segment regex cache: each final is matched once, however long the call runs. */
  analyzer: TranscriptAnalyzer;
  rules: RulesResult;
  model: ModelScoringResult | undefined;
  /** New final text since the last model call started. */
  dirty: boolean;
  inFlight: InFlight | undefined;
  timer: NodeJS.Timeout | undefined;
  lastModelStartedAt: number | undefined;
  lastSignature: string | undefined;
  ended: boolean;
  modelPasses: number;
  onSegment: (segment: TranscriptSegment) => void;
  onEnded: () => void;
}

export class ScamDetector implements SessionObserver {
  private readonly scorer: ModelScorer | undefined;
  private readonly config: CallsConfig;
  private readonly log: FastifyBaseLogger;
  private readonly now: () => number;
  private readonly states = new Map<string, SessionState>();
  private readonly finalPasses = new Set<Promise<void>>();
  private closed = false;

  constructor(options: ScamDetectorOptions) {
    this.scorer = options.scorer;
    this.config = options.config;
    this.log = options.logger.child({ module: "calls.detector" });
    this.now = options.now;
  }

  /** Sessions currently followed (tests). */
  get attachedCount(): number {
    return this.states.size;
  }

  attach(session: CallSession): void {
    if (this.closed || session.isEnded || this.states.has(session.callId)) return;
    const state: SessionState = {
      session,
      analyzer: new TranscriptAnalyzer(),
      rules: { signals: [], score: 0 },
      model: undefined,
      dirty: false,
      inFlight: undefined,
      timer: undefined,
      lastModelStartedAt: undefined,
      lastSignature: undefined,
      ended: false,
      modelPasses: 0,
      onSegment: (segment) => this.onSegment(state, segment),
      onEnded: () => this.onEnded(state),
    };
    this.states.set(session.callId, state);
    session.on("segment", state.onSegment);
    session.once("ended", state.onEnded);
  }

  /** Aborts every in-flight request, clears timers and forgets every session. */
  async close(): Promise<void> {
    this.closed = true;
    const pending: Promise<void>[] = [...this.finalPasses];
    for (const state of this.states.values()) {
      this.clearTimer(state);
      state.ended = true;
      state.session.off("segment", state.onSegment);
      state.session.off("ended", state.onEnded);
      if (state.inFlight) {
        state.inFlight.controller.abort();
        pending.push(state.inFlight.done);
      }
    }
    this.states.clear();
    await Promise.allSettled(pending);
  }

  // MARK: rules on every final segment

  private onSegment(state: SessionState, segment: TranscriptSegment): void {
    if (!segment.final || state.ended) return;
    state.rules = state.analyzer.analyze(state.session.segments);
    this.evaluate(state);
    state.dirty = true;
    this.scheduleModel(state);
  }

  private evaluate(state: SessionState): void {
    const verdict = fuseVerdict({ rules: state.rules, model: state.model, now: this.now() });
    const signature = [
      verdict.level,
      verdict.confidence.toFixed(2),
      verdict.reasons.map((reason) => reason.id).join(","),
      verdict.summary,
    ].join("|");
    if (signature === state.lastSignature) return;
    state.lastSignature = signature;
    const stored = state.session.setVerdict(verdict);
    this.log.info(
      {
        callId: state.session.callId,
        caller: redactNumber(state.session.callerNumber),
        sequence: stored.sequence,
        level: stored.level,
        confidence: Number(stored.confidence.toFixed(2)),
        category: stored.category,
        signals: state.rules.signals.map((signal) => signal.id),
        model: stored.modelRiskScore ?? null,
      },
      "calls: verdict",
    );
  }

  // MARK: model cadence

  private scheduleModel(state: SessionState): void {
    if (!this.scorer || state.ended || !state.dirty || state.inFlight || state.timer) return;
    if (state.session.finalTranscriptChars() < MIN_TRANSCRIPT_CHARS) return;
    const wait =
      state.lastModelStartedAt === undefined ? 0 : Math.max(0, state.lastModelStartedAt + this.config.modelMinIntervalMs - this.now());
    if (wait === 0) {
      this.runModel(state);
      return;
    }
    state.timer = setTimeout(() => {
      state.timer = undefined;
      if (state.ended || state.inFlight || !state.dirty) return;
      this.runModel(state);
    }, wait);
    state.timer.unref();
  }

  private runModel(state: SessionState): InFlight | undefined {
    const scorer = this.scorer;
    if (!scorer || state.inFlight) return undefined;
    state.dirty = false;
    state.lastModelStartedAt = this.now();
    state.modelPasses += 1;
    const controller = new AbortController();
    const session = state.session;
    const input: ModelScoringInput = {
      callerNumber: session.callerNumber,
      elapsedSeconds: Math.round(session.elapsedMs() / 1000),
      transcript: session.transcriptText(this.config.modelTranscriptChars),
      signalIds: state.rules.signals.map((signal) => signal.id),
      lineId: session.line?.lineId,
    };
    // `new Promise` turns a synchronous throw from a scorer into a rejection: nothing may escape into the
    // session's `segment` emitter (the transcriber's WebSocket handler) or leave the final pass unsettled.
    const done = new Promise<ModelScoringResult>((resolve) => resolve(scorer.score(input, controller.signal)))
      .then(
        (result) => {
          state.model = result;
          state.rules = state.analyzer.analyze(session.segments);
          this.evaluate(state);
        },
        (error: unknown) => {
          const level = controller.signal.aborted ? "debug" : "warn";
          if (error instanceof ModelScoringError) {
            // Fields only: a ModelScoringError's message is a fixed string; never serialise the full error chain.
            this.log[level](
              { callId: session.callId, kind: error.kind, status: error.status, retried: error.retried, message: error.message },
              "calls: model pass skipped",
            );
          } else {
            this.log[level]({ callId: session.callId, kind: "unknown", err: controller.signal.aborted ? undefined : error }, "calls: model pass skipped");
          }
        },
      )
      .finally(() => {
        if (state.inFlight?.controller === controller) state.inFlight = undefined;
        if (!state.ended) this.scheduleModel(state);
      });
    const inFlight: InFlight = { controller, done };
    state.inFlight = inFlight;
    return inFlight;
  }

  // MARK: call end

  private onEnded(state: SessionState): void {
    state.ended = true;
    this.clearTimer(state);
    state.session.off("segment", state.onSegment);
    const pass = this.finalPass(state).finally(() => {
      this.finalPasses.delete(pass);
      if (this.states.get(state.session.callId) === state) this.states.delete(state.session.callId);
    });
    this.finalPasses.add(pass);
  }

  /** One last model pass over any unscored text so the persisted record carries the final summary. */
  private async finalPass(state: SessionState): Promise<void> {
    if (!this.scorer || this.closed) return;
    const deadline = this.now() + FINAL_PASS_CAP_MS;
    if (state.inFlight) await this.awaitCapped(state.inFlight, deadline);
    if (this.closed) return;
    if (state.dirty && state.session.finalTranscriptChars() >= MIN_TRANSCRIPT_CHARS) {
      const inFlight = this.runModel(state);
      if (inFlight) await this.awaitCapped(inFlight, deadline);
    }
  }

  private async awaitCapped(inFlight: InFlight, deadline: number): Promise<void> {
    const remaining = Math.max(0, deadline - this.now());
    let timer: NodeJS.Timeout | undefined;
    const cap = new Promise<void>((resolve) => {
      timer = setTimeout(() => {
        inFlight.controller.abort();
        resolve();
      }, remaining);
      timer.unref();
    });
    await Promise.race([inFlight.done, cap]);
    if (timer) clearTimeout(timer);
  }

  private clearTimer(state: SessionState): void {
    if (state.timer) clearTimeout(state.timer);
    state.timer = undefined;
  }
}

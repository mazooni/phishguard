import type { FastifyBaseLogger } from "fastify";

import type { CallSession, CallSessionManager } from "../session.js";
import type { CallLine, DemoScenarioId, TranscriptSegment } from "../types.js";
import { DEMO_SCENARIOS } from "./scenarios.js";

/**
 * Feeds a scripted scenario into a `demo` session at conversational pace (docs/CALLS.md §7.1): every line arrives
 * first as a partial (the first half of its words) and ~400 ms later as the final segment; the session completes
 * 1.5 s after the last line. `speed` scales every interval. Everything downstream — rules, model, push, live feed,
 * history — is the real code, because the runner only calls `sessions.create` and `session.addSegment`.
 */

export interface DemoCallRunnerOptions {
  sessions: CallSessionManager;
  logger: FastifyBaseLogger;
  now: () => number;
}

export interface DemoCallStart {
  deviceId: string;
  line: CallLine | null;
  scenario: DemoScenarioId;
  /** 0.25…4; default 1. */
  speed?: number | undefined;
}

/** The "protected number" of a demo call for a device without a line. */
export const DEMO_CALLED_NUMBER = "+15550100000";
export const MIN_DEMO_SPEED = 0.25;
export const MAX_DEMO_SPEED = 4;
const PARTIAL_TO_FINAL_MS = 400;
const END_AFTER_LAST_LINE_MS = 1500;
/** Lines this short are not worth a partial. */
const MIN_WORDS_FOR_PARTIAL = 3;

export class DemoCallRunner {
  private readonly runs = new Map<string, Set<NodeJS.Timeout>>();

  constructor(private readonly options: DemoCallRunnerOptions) {}

  get activeRuns(): number {
    return this.runs.size;
  }

  start(input: DemoCallStart): CallSession {
    const scenario = DEMO_SCENARIOS[input.scenario];
    const speed = clampSpeed(input.speed ?? 1);
    const session = this.options.sessions.create({
      deviceId: input.deviceId,
      line: input.line,
      source: "demo",
      callerNumber: scenario.callerNumber,
      calledNumber: input.line?.phoneNumber ?? DEMO_CALLED_NUMBER,
      startedAt: this.options.now(),
      status: "in_progress",
    });
    const timers = new Set<NodeJS.Timeout>();
    this.runs.set(session.callId, timers);
    const cancel = (): void => {
      for (const timer of timers) clearTimeout(timer);
      timers.clear();
      this.runs.delete(session.callId);
    };
    session.once("ended", cancel);

    const schedule = (delayMs: number, task: () => void): void => {
      const timer = setTimeout(() => {
        timers.delete(timer);
        if (session.isEnded) return;
        try {
          task();
        } catch (error) {
          this.options.logger.error({ err: error, callId: session.callId }, "demo: step failed");
        }
      }, Math.max(0, Math.round(delayMs)));
      timer.unref();
      timers.add(timer);
    };

    let at = 0;
    scenario.lines.forEach((line, index) => {
      at += line.pauseMs / speed;
      const id = `demo-${index + 1}`;
      const words = line.text.split(/\s+/).filter((word) => word.length > 0);
      const finalAt = at + PARTIAL_TO_FINAL_MS / speed;
      if (words.length >= MIN_WORDS_FOR_PARTIAL) {
        const partialText = words.slice(0, Math.ceil(words.length / 2)).join(" ");
        const partial: TranscriptSegment = { id, speaker: line.speaker, text: partialText, atMs: Math.round(at), final: false };
        schedule(at, () => session.addSegment(partial));
      }
      const final: TranscriptSegment = { id, speaker: line.speaker, text: line.text, atMs: Math.round(at), final: true };
      schedule(finalAt, () => session.addSegment(final));
      at = finalAt;
    });
    schedule(at + END_AFTER_LAST_LINE_MS / speed, () => session.end("completed"));

    this.options.logger.info(
      { callId: session.callId, deviceId: input.deviceId, scenario: scenario.id, speed, lines: scenario.lines.length },
      "demo: call started",
    );
    return session;
  }

  /** Cancels every pending step; the sessions themselves are ended by the manager's `close()`. */
  close(): void {
    for (const timers of this.runs.values()) {
      for (const timer of timers) clearTimeout(timer);
    }
    this.runs.clear();
  }
}

export function clampSpeed(speed: number): number {
  if (!Number.isFinite(speed)) return 1;
  return Math.min(MAX_DEMO_SPEED, Math.max(MIN_DEMO_SPEED, speed));
}

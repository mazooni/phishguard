import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DEMO_CALLED_NUMBER, DemoCallRunner, clampSpeed } from "../../src/calls/demo/runner.js";
import { DEMO_SCENARIOS } from "../../src/calls/demo/scenarios.js";
import { CallSessionManager } from "../../src/calls/session.js";
import type { CallLine, CallRecord, TranscriptSegment } from "../../src/calls/types.js";
import { DEVICE_ID, FakeClock } from "../helpers.js";
import { GUARD_NUMBER, PROTECTED_NUMBER, silentLogger } from "./fakes.js";

const LINE: CallLine = {
  lineId: "line-1",
  deviceId: DEVICE_ID,
  guardNumber: GUARD_NUMBER,
  phoneNumber: PROTECTED_NUMBER,
  minimumLevel: "medium",
  spokenWarning: true,
  createdAt: 0,
  updatedAt: 0,
};

describe("DemoCallRunner", () => {
  let clock: FakeClock;
  let sessions: CallSessionManager;
  let runner: DemoCallRunner;
  let records: CallRecord[];

  beforeEach(() => {
    vi.useFakeTimers();
    clock = new FakeClock();
    records = [];
    sessions = new CallSessionManager({ store: { upsertCall: (record) => records.push(record) }, retainEndedMs: 60_000, now: clock.now });
    runner = new DemoCallRunner({ sessions, logger: silentLogger(), now: clock.now });
  });

  afterEach(() => {
    runner.close();
    sessions.close();
    vi.useRealTimers();
  });

  it("creates a demo session with the scenario's caller and the line's number, in progress immediately", () => {
    const session = runner.start({ deviceId: DEVICE_ID, line: LINE, scenario: "grandparent" });
    expect(session.source).toBe("demo");
    expect(session.status).toBe("in_progress");
    expect(session.callerNumber).toBe(DEMO_SCENARIOS.grandparent.callerNumber);
    expect(session.calledNumber).toBe(PROTECTED_NUMBER);
    expect(session.line).toBe(LINE);
    expect(session.startedAt).toBe(clock.now());
    expect(sessions.get(session.callId)).toBe(session);
    expect(records[0]?.status).toBe("in_progress");

    const noLine = runner.start({ deviceId: DEVICE_ID, line: null, scenario: "benign" });
    expect(noLine.calledNumber).toBe(DEMO_CALLED_NUMBER);
    expect(runner.activeRuns).toBe(2);
  });

  it("feeds every line as a partial (first half of the words) then the final ~400 ms later, in order, then completes", () => {
    const scenario = DEMO_SCENARIOS.benign;
    const session = runner.start({ deviceId: DEVICE_ID, line: null, scenario: "benign" });
    const seen: TranscriptSegment[] = [];
    session.on("segment", (segment) => seen.push({ ...segment }));

    vi.advanceTimersByTime(0);
    expect(seen).toHaveLength(1);
    const firstWords = scenario.lines[0]!.text.split(/\s+/);
    expect(seen[0]).toMatchObject({ id: "demo-1", speaker: "caller", final: false, atMs: 0, text: firstWords.slice(0, Math.ceil(firstWords.length / 2)).join(" ") });
    vi.advanceTimersByTime(399);
    expect(seen).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(seen).toHaveLength(2);
    expect(seen[1]).toMatchObject({ id: "demo-1", final: true, text: scenario.lines[0]!.text });
    expect(session.segments).toHaveLength(1);

    // Second line: its pause starts after the first final.
    vi.advanceTimersByTime(scenario.lines[1]!.pauseMs - 1);
    expect(seen).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(seen).toHaveLength(3);
    expect(seen[2]).toMatchObject({ id: "demo-2", speaker: "user", final: false, atMs: 400 + scenario.lines[1]!.pauseMs });

    vi.runAllTimers();
    const finals = seen.filter((segment) => segment.final);
    expect(finals.map((segment) => segment.text)).toEqual(scenario.lines.map((line) => line.text));
    expect(finals.map((segment) => segment.speaker)).toEqual(scenario.lines.map((line) => line.speaker));
    for (let i = 1; i < seen.length; i += 1) expect(seen[i]!.atMs).toBeGreaterThanOrEqual(seen[i - 1]!.atMs);
    expect(session.isEnded).toBe(true);
    expect(session.status).toBe("completed");
    expect(session.transcriptText()).toContain("Caller: Hi Margaret");
    expect(runner.activeRuns).toBe(0);
  });

  it("scales every interval by speed and clamps speed to 0.25–4", () => {
    expect(clampSpeed(10)).toBe(4);
    expect(clampSpeed(0)).toBe(0.25);
    expect(clampSpeed(Number.NaN)).toBe(1);
    const scenario = DEMO_SCENARIOS.prize;
    const session = runner.start({ deviceId: DEVICE_ID, line: null, scenario: "prize", speed: 2 });
    const seen: TranscriptSegment[] = [];
    session.on("segment", (segment) => seen.push(segment));
    vi.advanceTimersByTime(200);
    expect(seen).toHaveLength(2);
    expect(seen[1]!.final).toBe(true);
    vi.advanceTimersByTime(scenario.lines[1]!.pauseMs / 2);
    expect(seen).toHaveLength(3);
    const total = scenario.lines.reduce((sum, line) => sum + line.pauseMs + 400, 0) / 2 + 1500 / 2;
    vi.advanceTimersByTime(total);
    expect(session.isEnded).toBe(true);
  });

  it("stops feeding when the session ends early, and close() cancels every run", () => {
    const early = runner.start({ deviceId: DEVICE_ID, line: null, scenario: "irs" });
    vi.advanceTimersByTime(500);
    expect(early.segments).toHaveLength(1);
    early.end("canceled");
    expect(runner.activeRuns).toBe(0);
    vi.runAllTimers();
    expect(early.segments).toHaveLength(1);
    expect(early.status).toBe("canceled");

    const cancelled = runner.start({ deviceId: DEVICE_ID, line: null, scenario: "bankFraud" });
    runner.close();
    vi.runAllTimers();
    expect(cancelled.segments).toHaveLength(0);
    expect(cancelled.isEnded).toBe(false);
  });
});

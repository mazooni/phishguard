import { afterEach, describe, expect, it } from "vitest";

import { ModelScoringError } from "../../src/calls/openai/scorer.js";
import { MIN_TRANSCRIPT_CHARS, ScamDetector } from "../../src/calls/scoring/detector.js";
import { CallSession } from "../../src/calls/session.js";
import type { CallVerdict, Speaker } from "../../src/calls/types.js";
import { FakeClock, closeTestApp, createCallsTestApp, registerDevice } from "../helpers.js";
import { CALLER_NUMBER, FakeScorer, GUARD_NUMBER, benignResult, scamResult, silentLogger, testCallsConfig } from "./fakes.js";

const INTERVAL_MS = 80;

interface Harness {
  clock: FakeClock;
  scorer: FakeScorer;
  detector: ScamDetector;
  session: CallSession;
  verdicts: CallVerdict[];
  say(speaker: Speaker, text: string, final?: boolean): void;
}

const detectors: ScamDetector[] = [];

function harness(options: { scorer?: FakeScorer | undefined; withScorer?: boolean } = {}): Harness {
  const clock = new FakeClock();
  const scorer = options.scorer ?? new FakeScorer();
  const detector = new ScamDetector({
    scorer: options.withScorer === false ? undefined : scorer,
    config: testCallsConfig({ modelMinIntervalMs: INTERVAL_MS, modelTranscriptChars: 6000 }),
    logger: silentLogger(),
    now: clock.now,
  });
  detectors.push(detector);
  const session = new CallSession(
    { deviceId: "device-1", line: null, source: "twilio", callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: clock.now() },
    clock.now,
  );
  const verdicts: CallVerdict[] = [];
  session.on("verdict", (verdict) => verdicts.push(verdict));
  detector.attach(session);
  let counter = 0;
  return {
    clock,
    scorer,
    detector,
    session,
    verdicts,
    say(speaker, text, final = true) {
      counter += 1;
      session.addSegment({ id: `${speaker}-${counter}`, speaker, text, atMs: clock.now() - session.startedAt, final });
    },
  };
}

function tick(ms = 0): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const LONG_SCAM = "Grandma it's me, I'm in trouble, I need you to buy gift cards right now and don't tell anyone.";
const LONG_BENIGN = "Hi Margaret, this is the pharmacy, your prescription is ready for pickup any time this week.";

afterEach(async () => {
  await Promise.all(detectors.splice(0).map((detector) => detector.close()));
});

describe("ScamDetector — rules", () => {
  it("emits a rules-only verdict on the first final segment and ignores partials", () => {
    const { say, verdicts, session } = harness({ withScorer: false });
    say("caller", "hello there, is this Margaret?", false);
    expect(verdicts).toHaveLength(0);
    say("caller", "hello there, is this Margaret?");
    expect(verdicts).toHaveLength(1);
    expect(verdicts[0]).toMatchObject({ sequence: 1, level: "safe", confidence: 0, heuristicScore: 0, category: "safe" });
    expect(verdicts[0]?.modelIdentifier).toBeUndefined();
    expect(session.verdict).toBe(verdicts[0]);

    say("caller", "go buy gift cards and read me the numbers");
    expect(verdicts).toHaveLength(2);
    expect(verdicts[1]).toMatchObject({ sequence: 2, level: "medium", category: "scam" });
    expect(verdicts[1]?.reasons.map((reason) => reason.id)).toEqual(["call.gift_cards"]);
    expect(verdicts[1]?.reasons[0]?.detail).toContain("Caller said:");
  });

  it("does not re-emit when nothing the person would notice changed", () => {
    const { say, verdicts } = harness({ withScorer: false });
    say("caller", "hello there");
    say("user", "hi, who is this?");
    say("caller", "just checking in");
    expect(verdicts).toHaveLength(1);
    say("caller", "you need to do it right now");
    expect(verdicts).toHaveLength(2);
    say("caller", "immediately, please");
    expect(verdicts).toHaveLength(2);
  });

  it("attaches once per session and ignores ended sessions", () => {
    const { detector, session, say, verdicts, clock } = harness({ withScorer: false });
    detector.attach(session);
    say("caller", "hello");
    expect(verdicts).toHaveLength(1);
    const ended = new CallSession(
      { deviceId: "device-1", line: null, source: "demo", callerNumber: CALLER_NUMBER, calledNumber: GUARD_NUMBER, startedAt: clock.now() },
      clock.now,
    );
    ended.end();
    detector.attach(ended);
    expect(detector.attachedCount).toBe(1);
  });
});

describe("ScamDetector — model cadence", () => {
  it("does not call the model under 40 characters of final transcript", async () => {
    const { say, scorer } = harness();
    say("caller", "hello Margaret");
    await tick();
    expect(scorer.inputs).toHaveLength(0);
    expect("hello Margaret".length).toBeLessThan(MIN_TRANSCRIPT_CHARS);
  });

  it("calls the model with the transcript window, the rule signal ids and the metadata", async () => {
    const { say, scorer, session, clock } = harness();
    clock.advance(42_000);
    say("caller", LONG_SCAM);
    await tick();
    expect(scorer.inputs).toHaveLength(1);
    expect(scorer.inputs[0]).toEqual({
      callerNumber: CALLER_NUMBER,
      elapsedSeconds: 42,
      transcript: session.transcriptText(6000),
      signalIds: expect.arrayContaining(["call.gift_cards", "call.secrecy", "call.family_emergency"]),
      lineId: undefined,
    });
    expect(scorer.inputs[0]?.transcript).toBe(`Caller: ${LONG_SCAM}`);
  });

  it("fuses the model answer and emits the new verdict", async () => {
    const { say, scorer, verdicts } = harness();
    scorer.respond = () => scamResult();
    say("caller", LONG_BENIGN);
    expect(verdicts).toHaveLength(1);
    expect(verdicts[0]?.level).toBe("safe");
    await tick();
    expect(verdicts).toHaveLength(2);
    expect(verdicts[1]).toMatchObject({ level: "high", modelRiskScore: 92, modelIdentifier: "openai:gpt-6-luna", category: "scam" });
    expect(verdicts[1]?.summary).toBe(scamResult().summary);
  });

  it("does not emit when the model answer changes nothing visible", async () => {
    const { say, scorer, verdicts } = harness();
    // riskScore 0 keeps the rounded confidence at 0.00 and the generated summary; only the identifier would differ.
    scorer.respond = () => benignResult({ riskScore: 0, summary: "", recommendedAction: "" });
    say("caller", LONG_BENIGN);
    await tick();
    expect(scorer.inputs).toHaveLength(1);
    expect(verdicts).toHaveLength(1);
  });

  it("respects the minimum interval with a trailing timer", async () => {
    const { say, scorer } = harness();
    say("caller", LONG_BENIGN);
    await tick();
    expect(scorer.inputs).toHaveLength(1);
    say("caller", "and we also wanted to ask about your flu shot appointment");
    say("caller", "it is due this month");
    await tick(10);
    expect(scorer.inputs).toHaveLength(1);
    await tick(INTERVAL_MS + 20);
    expect(scorer.inputs).toHaveLength(2);
    expect(scorer.inputs[1]?.transcript).toContain("flu shot");
    expect(scorer.inputs[1]?.transcript).toContain("due this month");
  });

  it("skips the model when no new final text arrived since the last call", async () => {
    const { say, scorer, clock } = harness();
    say("caller", LONG_BENIGN);
    await tick();
    clock.advance(INTERVAL_MS * 2);
    await tick(INTERVAL_MS + 20);
    expect(scorer.inputs).toHaveLength(1);
  });

  it("keeps one request in flight per session and catches up afterwards", async () => {
    const { say, scorer, clock } = harness();
    let release!: () => void;
    scorer.gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    say("caller", LONG_BENIGN);
    say("caller", "we are open until eight tonight if that helps you at all");
    say("caller", "and the copay is twelve dollars");
    await tick(10);
    expect(scorer.inputs).toHaveLength(1);
    scorer.gate = undefined;
    clock.advance(INTERVAL_MS);
    release();
    await tick(10);
    expect(scorer.inputs).toHaveLength(2);
    expect(scorer.inputs[1]?.transcript).toContain("twelve dollars");
  });

  it("keeps the previous model result when a pass fails", async () => {
    const { say, scorer, verdicts, clock } = harness();
    scorer.respond = () => scamResult();
    say("caller", LONG_BENIGN);
    await tick();
    expect(verdicts.at(-1)).toMatchObject({ level: "high", modelRiskScore: 92 });
    scorer.respond = () => {
      throw new ModelScoringError("refusal", "model refused");
    };
    clock.advance(INTERVAL_MS);
    say("caller", "please bring your insurance card when you come");
    await tick(10);
    expect(scorer.inputs).toHaveLength(2);
    expect(verdicts.at(-1)).toMatchObject({ level: "high", modelRiskScore: 92 });
    expect(verdicts).toHaveLength(2);
  });

  it("works rules-only without a scorer", () => {
    const { say, verdicts, scorer } = harness({ withScorer: false });
    say("caller", LONG_SCAM);
    expect(verdicts[0]?.level).toBe("high");
    expect(verdicts[0]?.modelIdentifier).toBeUndefined();
    expect(scorer.inputs).toHaveLength(0);
  });
});

describe("ScamDetector — call end and close", () => {
  it("runs one last model pass over unscored text when the call ends and then detaches", async () => {
    const { say, scorer, verdicts, session, detector } = harness();
    say("caller", LONG_BENIGN);
    await tick();
    expect(scorer.inputs).toHaveLength(1);
    scorer.respond = () => scamResult({ summary: "Final summary." });
    say("caller", "actually, read me the verification code we just texted you");
    session.end("completed");
    await tick(10);
    expect(scorer.inputs).toHaveLength(2);
    expect(scorer.inputs[1]?.transcript).toContain("verification code");
    expect(verdicts.at(-1)).toMatchObject({ level: "high", summary: "Final summary." });
    expect(session.verdict?.summary).toBe("Final summary.");
    expect(detector.attachedCount).toBe(0);
  });

  it("does not run a final pass when everything was already scored", async () => {
    const { say, scorer, session, detector } = harness();
    say("caller", LONG_BENIGN);
    await tick();
    session.end("completed");
    await tick(5);
    expect(scorer.inputs).toHaveLength(1);
    expect(detector.attachedCount).toBe(0);
  });

  it("close() aborts the in-flight request, clears timers and forgets the sessions", async () => {
    const { say, scorer, verdicts, detector, session } = harness();
    let release!: () => void;
    scorer.gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    scorer.respond = () => scamResult();
    say("caller", LONG_BENIGN);
    say("caller", "we are open until eight tonight if that helps at all");
    await tick(5);
    expect(scorer.inputs).toHaveLength(1);
    const closing = detector.close();
    release();
    await closing;
    await tick(INTERVAL_MS + 20);
    expect(scorer.inputs).toHaveLength(1);
    expect(verdicts).toHaveLength(1);
    expect(verdicts[0]?.level).toBe("safe");
    expect(detector.attachedCount).toBe(0);
    say("caller", LONG_SCAM);
    expect(verdicts).toHaveLength(1);
    expect(session.verdict?.level).toBe("safe");
  });
});

describe("ScamDetector — wired through registerCalls", () => {
  it("scores a session created on the manager with the injected fake scorer and persists the verdict", async () => {
    const ctx = await createCallsTestApp();
    try {
      await registerDevice(ctx.app);
      ctx.scorer.respond = () => scamResult();
      const session = ctx.app.callGuard.sessions.create({
        deviceId: "6F9619FF-8B86-D011-B42D-00C04FC964FF",
        line: null,
        source: "demo",
        callerNumber: CALLER_NUMBER,
        calledNumber: GUARD_NUMBER,
        startedAt: ctx.clock.now(),
      });
      session.addSegment({ id: "caller-1", speaker: "caller", text: LONG_SCAM, atMs: 0, final: true });
      await tick(10);
      expect(ctx.scorer.inputs).toHaveLength(1);
      const record = ctx.db.findCall(session.callId);
      expect(record?.verdict).toMatchObject({ level: "high", modelRiskScore: 92, modelIdentifier: "openai:gpt-6-luna" });
      expect(record?.verdict?.reasons.map((reason) => reason.id)).toContain("call.gift_cards");
    } finally {
      await closeTestApp(ctx);
    }
  });
});

import type { FastifyBaseLogger } from "fastify";

import type { CallsConfig, OpenAIConfig, TwilioConfig } from "../../src/calls/config.js";
import { DEFAULT_SCORING_MODEL, DEFAULT_SPOKEN_WARNING, DEFAULT_TRANSCRIBE_MODEL } from "../../src/calls/config.js";
import type { ModelScorer, ModelScoringInput, ModelScoringResult } from "../../src/calls/openai/scorer.js";
import type { CallSession } from "../../src/calls/session.js";
import type { TwilioAccountType, TwilioClient } from "../../src/calls/twilio/client.js";
import type { Speaker, Transcriber, TranscriberHandle, TranscriptSegment } from "../../src/calls/types.js";

/**
 * Shared fakes for Call Guard tests (docs/CALLS.md). Every external service the module talks to — Twilio REST,
 * OpenAI Realtime transcription, the OpenAI scorer — has a recording fake here so route, detector and alert
 * tests never touch the network. Test files under test/calls/ import these; add new fakes here rather than
 * editing test/helpers.ts.
 */

export const TWILIO_ACCOUNT_SID = "AC" + "0123456789abcdef".repeat(2);
export const TWILIO_AUTH_TOKEN = "twilio-auth-token-for-tests-0123";
export const GUARD_NUMBER = "+15550100001";
export const PROTECTED_NUMBER = "+15550100002";
export const CALLER_NUMBER = "+15550100003";

export function testTwilioConfig(overrides: Partial<TwilioConfig> = {}): TwilioConfig {
  return { accountSid: TWILIO_ACCOUNT_SID, authToken: TWILIO_AUTH_TOKEN, number: GUARD_NUMBER, ...overrides };
}

export function testOpenAIConfig(overrides: Partial<OpenAIConfig> = {}): OpenAIConfig {
  return { apiKey: "sk-test", transcribeModel: DEFAULT_TRANSCRIBE_MODEL, scoringModel: DEFAULT_SCORING_MODEL, ...overrides };
}

/** A Call Guard config with Twilio and OpenAI "configured" (the fakes stand in for both). */
export function testCallsConfig(overrides: Partial<CallsConfig> = {}): CallsConfig {
  return {
    twilio: testTwilioConfig(),
    openai: testOpenAIConfig(),
    transcribeTracks: "both",
    transcriptionSource: "openai",
    modelMinIntervalMs: 250,
    modelTranscriptChars: 6000,
    defaultMinimumLevel: "medium",
    spokenWarningText: DEFAULT_SPOKEN_WARNING,
    retainEndedMs: 60_000,
    retentionDays: 30,
    demoEnabled: true,
    consoleEnabled: true,
    ...overrides,
  };
}

/** Records every REST call; `validateSignature` accepts everything unless `rejectSignatures` is set. */
export class FakeTwilioClient implements TwilioClient {
  readonly dialed: { callId: string; sid: string }[] = [];
  readonly testCalls: { callId: string; scenario: string; sid: string }[] = [];
  readonly spoken: { callId: string; text: string }[] = [];
  readonly hungUp: string[] = [];
  readonly signatureChecks: { signature: string | undefined; url: string; params: Record<string, string> }[] = [];
  /** `redirectCall` requests: the caller-leg TwiML replacements (e.g. "could not reach"). */
  readonly redirected: { callSid: string; twiml: string }[] = [];
  /** `endCall` requests. */
  readonly endedCalls: string[] = [];
  rejectSignatures = false;
  failDial: Error | undefined;
  /** What `fetchAccountType` answers (the auto transcription source depends on it). */
  accountType: TwilioAccountType = "Full";
  accountTypeFetches = 0;
  private counter = 0;

  async dialProtectedUser(session: CallSession): Promise<string> {
    if (this.failDial) throw this.failDial;
    const sid = `CAuser${String(++this.counter).padStart(4, "0")}`;
    this.dialed.push({ callId: session.callId, sid });
    return sid;
  }

  async placeTestCall(session: CallSession, scenarioId: string): Promise<string> {
    if (this.failDial) throw this.failDial;
    const sid = `CAtest${String(++this.counter).padStart(4, "0")}`;
    this.testCalls.push({ callId: session.callId, scenario: scenarioId, sid });
    return sid;
  }

  async speakToUser(session: CallSession, text: string): Promise<boolean> {
    this.spoken.push({ callId: session.callId, text });
    return true;
  }

  async hangUp(session: CallSession): Promise<boolean> {
    this.hungUp.push(session.callId);
    return true;
  }

  validateSignature(signature: string | undefined, url: string, params: Record<string, string>): boolean {
    this.signatureChecks.push({ signature, url, params });
    return !this.rejectSignatures;
  }

  async fetchAccountType(): Promise<TwilioAccountType> {
    this.accountTypeFetches += 1;
    return this.accountType;
  }

  async redirectCall(callSid: string, twiml: string): Promise<boolean> {
    this.redirected.push({ callSid, twiml });
    return true;
  }

  async endCall(callSid: string): Promise<boolean> {
    this.endedCalls.push(callSid);
    return true;
  }

  announcementText(session: CallSession): string | undefined {
    return this.spoken.filter((entry) => entry.callId === session.callId).at(-1)?.text;
  }
}

/** A transcriber whose handles record audio and let the test inject transcript segments. */
export class FakeTranscriber implements Transcriber {
  readonly handles: FakeTranscriberHandle[] = [];

  open(session: CallSession, speaker: Speaker): TranscriberHandle {
    const handle = new FakeTranscriberHandle(session, speaker);
    this.handles.push(handle);
    return handle;
  }

  handle(speaker: Speaker, callId?: string): FakeTranscriberHandle | undefined {
    return this.handles.find((h) => h.speaker === speaker && (callId === undefined || h.session.callId === callId));
  }
}

export class FakeTranscriberHandle implements TranscriberHandle {
  readonly audio: string[] = [];
  closed = false;
  private counter = 0;

  constructor(
    readonly session: CallSession,
    readonly speaker: Speaker,
  ) {}

  pushAudio(base64Mulaw: string): void {
    this.audio.push(base64Mulaw);
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  /** What the real transcriber would do when OpenAI reports a (partial or final) transcript. */
  emit(text: string, final = true, atMs = this.session.elapsedMs()): TranscriptSegment {
    const segment: TranscriptSegment = { id: `${this.speaker}-${++this.counter}`, speaker: this.speaker, text, atMs, final };
    this.session.addSegment(segment);
    return segment;
  }
}

/** Answers with a scripted result (default: a benign 5) and records every input. */
export class FakeScorer implements ModelScorer {
  readonly inputs: ModelScoringInput[] = [];
  respond: (input: ModelScoringInput) => ModelScoringResult | Promise<ModelScoringResult> = () => benignResult();
  /** Optional gate to hold a request open (concurrency tests). */
  gate: Promise<void> | undefined;

  async score(input: ModelScoringInput, signal?: AbortSignal): Promise<ModelScoringResult> {
    this.inputs.push(input);
    if (this.gate) await this.gate;
    if (signal?.aborted) throw new Error("aborted");
    return this.respond(input);
  }
}

export function benignResult(overrides: Partial<ModelScoringResult> = {}): ModelScoringResult {
  return {
    riskScore: 5,
    category: "safe",
    isScam: false,
    summary: "An ordinary call.",
    reasons: [],
    recommendedAction: "No action needed.",
    callerClaims: "",
    modelIdentifier: `openai:${DEFAULT_SCORING_MODEL}`,
    ...overrides,
  };
}

export function scamResult(overrides: Partial<ModelScoringResult> = {}): ModelScoringResult {
  return {
    riskScore: 92,
    category: "scam",
    isScam: true,
    summary: "The caller pretends to be a grandchild in trouble and asks for gift cards.",
    reasons: [
      { title: "Claims to be a grandchild in trouble", detail: "Says they were arrested and need bail money." },
      { title: "Asks for gift cards", detail: "Wants payment in Apple gift cards read over the phone." },
    ],
    recommendedAction: "Hang up and call your grandchild directly on their usual number.",
    callerClaims: "Grandchild arrested after an accident",
    modelIdentifier: `openai:${DEFAULT_SCORING_MODEL}`,
    ...overrides,
  };
}

/** A pino-shaped logger that swallows everything (Fastify's `logger: false` provides one per app; this is for unit tests). */
export function silentLogger(): FastifyBaseLogger {
  const noop = (): void => undefined;
  const logger = {
    level: "silent",
    fatal: noop,
    error: noop,
    warn: noop,
    info: noop,
    debug: noop,
    trace: noop,
    silent: noop,
    child: () => logger,
  } as unknown as FastifyBaseLogger;
  return logger;
}

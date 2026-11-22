import type { FastifyBaseLogger } from "fastify";

import type { CallsConfig, OpenAIConfig, TwilioConfig, VoiceDetectionConfig } from "../../src/calls/config.js";
import {
  DEFAULT_AI_VOICE_MAX_SECONDS,
  DEFAULT_AI_VOICE_MIN_CONFIDENCE_PERCENT,
  DEFAULT_AI_VOICE_MIN_SHARE_PERCENT,
  DEFAULT_AI_VOICE_WARNING,
  DEFAULT_AI_VOICE_WINDOW_MS,
  DEFAULT_SCORING_MODEL,
  DEFAULT_SPOKEN_WARNING,
  DEFAULT_TRANSCRIBE_MODEL,
} from "../../src/calls/config.js";
import { MODULATE_VOICE_PROVIDER } from "../../src/calls/modulate/voiceDetector.js";
import type { ModelScorer, ModelScoringInput, ModelScoringResult } from "../../src/calls/openai/scorer.js";
import type { CallSession } from "../../src/calls/session.js";
import type { TwilioAccountType, TwilioClient } from "../../src/calls/twilio/client.js";
import type {
  AnnouncementSlot,
  CallVoiceAssessment,
  CallVoiceUpdate,
  Speaker,
  Transcriber,
  TranscriberHandle,
  TranscriptSegment,
  VoiceDetector,
  VoiceDetectorHandle,
  VoiceStatus,
} from "../../src/calls/types.js";

/**
 * Shared fakes for Call Guard tests (docs/CALLS.md). Every external service the module talks to — Twilio REST,
 * OpenAI Realtime transcription, the OpenAI scorer, Modulate voice detection — has a recording fake here so
 * route, detector and alert tests never touch the network. Test files under test/calls/ import these; add new fakes here rather than
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

/** Not a real key: distinctive enough that a test can assert it never reaches a log line. */
export const MODULATE_TEST_KEY = "mdl-test-key-7f3a9c1e5b2d";

/** The AI-voice section as `MODULATE_API_KEY` alone would configure it (the defaults of src/calls/config.ts). */
export function testVoiceConfig(overrides: Partial<VoiceDetectionConfig> = {}): VoiceDetectionConfig {
  return {
    apiKey: MODULATE_TEST_KEY,
    windowMs: DEFAULT_AI_VOICE_WINDOW_MS,
    minShare: DEFAULT_AI_VOICE_MIN_SHARE_PERCENT / 100,
    minConfidence: DEFAULT_AI_VOICE_MIN_CONFIDENCE_PERCENT / 100,
    maxStreamMs: DEFAULT_AI_VOICE_MAX_SECONDS * 1000,
    spokenWarning: true,
    warningText: DEFAULT_AI_VOICE_WARNING,
    ...overrides,
  };
}

/** A Call Guard config with Twilio and OpenAI "configured" (the fakes stand in for both). */
export function testCallsConfig(overrides: Partial<CallsConfig> = {}): CallsConfig {
  return {
    twilio: testTwilioConfig(),
    openai: testOpenAIConfig(),
    voice: undefined,
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
  /** `speakToUser(…, "voice")` requests: the AI-voice announcements, kept apart from the scam warnings in `spoken`. */
  readonly voiceSpoken: { callId: string; text: string }[] = [];
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

  async speakToUser(session: CallSession, text: string, slot: AnnouncementSlot = "scam"): Promise<boolean> {
    if (slot === "voice") {
      // Like the real client: a test call's TwiML is never replaced for the AI-voice warning.
      if (session.source === "test-call") return false;
      this.voiceSpoken.push({ callId: session.callId, text });
      return true;
    }
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

  /** `stopStream` requests: `[callSid, streamSid]`. */
  readonly stoppedStreams: [string, string][] = [];

  async stopStream(callSid: string, streamSid: string): Promise<boolean> {
    this.stoppedStreams.push([callSid, streamSid]);
    return true;
  }

  async endCall(callSid: string): Promise<boolean> {
    this.endedCalls.push(callSid);
    return true;
  }

  announcementText(session: CallSession, slot: AnnouncementSlot = "scam"): string | undefined {
    const requests = slot === "voice" ? this.voiceSpoken : this.spoken;
    return requests.filter((entry) => entry.callId === session.callId).at(-1)?.text;
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

/**
 * A voice detector whose handles record the caller audio they are given and let the test report an assessment.
 * Like the real one, a handle reports `analyzing` the moment it is opened. Opt-in: `createCallsTestApp` only
 * injects one when asked (or when the test's config has a `voice` section), so no other test sees voice events.
 */
export class FakeVoiceDetector implements VoiceDetector {
  readonly handles: FakeVoiceDetectorHandle[] = [];
  closed = false;

  open(session: CallSession): VoiceDetectorHandle {
    const handle = new FakeVoiceDetectorHandle(session);
    this.handles.push(handle);
    handle.report("analyzing", { syntheticShare: 0, confidence: 0, speechMs: 0 });
    return handle;
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const handle of this.handles) handle.closed = true;
  }

  /** The most recent handle for a call (a second media stream opens a second one). */
  handle(callId?: string): FakeVoiceDetectorHandle | undefined {
    return this.handles.filter((h) => callId === undefined || h.session.callId === callId).at(-1);
  }

  /** Every base64 payload pushed for a call, across its handles, in order. */
  audioFor(callId: string): string[] {
    return this.handles.filter((h) => h.session.callId === callId).flatMap((h) => h.audio);
  }
}

export class FakeVoiceDetectorHandle implements VoiceDetectorHandle {
  readonly audio: string[] = [];
  closed = false;
  /** Ends the handle the way the real one does after a latch, the cap or a refusal. */
  finish!: () => void;
  readonly finished = new Promise<void>((resolve) => {
    this.finish = resolve;
  });

  constructor(readonly session: CallSession) {}

  pushAudio(base64Mulaw: string): void {
    this.audio.push(base64Mulaw);
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  /** What the real detector does when the vendor's frames add up to (or change) an assessment. */
  report(status: VoiceStatus, overrides: Partial<CallVoiceUpdate> = {}): CallVoiceAssessment | undefined {
    const decided = status === "human" || status === "synthetic";
    return this.session.setVoice({
      status,
      syntheticShare: status === "synthetic" ? 1 : 0,
      confidence: decided ? 0.95 : 0,
      speechMs: decided ? DEFAULT_AI_VOICE_WINDOW_MS : 0,
      provider: MODULATE_VOICE_PROVIDER,
      ...overrides,
    });
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

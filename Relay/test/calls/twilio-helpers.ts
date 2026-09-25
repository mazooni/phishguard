import { randomUUID } from "node:crypto";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";

import type { CallSession } from "../../src/calls/session.js";
import type { AlertLevel, CallLine } from "../../src/calls/types.js";
import { DEVICE_ID, registerDevice, type CallsTestContext } from "../helpers.js";
import { CALLER_NUMBER, GUARD_NUMBER, PROTECTED_NUMBER, TWILIO_ACCOUNT_SID } from "./fakes.js";

/** Helpers shared by the Twilio call-path tests (webhook forms, sessions, draining async work). */

export const CALLER_SID = "CA" + "a".repeat(32);
export const USER_SID = "CA" + "b".repeat(32);
export const TEST_SID = "CA" + "d".repeat(32);
export const CONFERENCE_SID = "CF" + "c".repeat(32);
export const TEST_SIGNATURE = "dGVzdC1zaWduYXR1cmU=";

/** Registers the test device and its protected line (the guard number is the fake Twilio number). */
export async function registerLine(
  ctx: CallsTestContext,
  overrides: Partial<{ phoneNumber: string; spokenWarning: boolean; minimumLevel: AlertLevel }> = {},
): Promise<CallLine> {
  const registered = await registerDevice(ctx.app);
  if (registered.statusCode >= 300) throw new Error(`device registration failed: ${registered.statusCode}`);
  const { line } = ctx.db.upsertCallLine(
    {
      lineId: randomUUID(),
      deviceId: DEVICE_ID,
      guardNumber: GUARD_NUMBER,
      phoneNumber: overrides.phoneNumber ?? PROTECTED_NUMBER,
      minimumLevel: overrides.minimumLevel ?? "medium",
      spokenWarning: overrides.spokenWarning ?? true,
    },
    ctx.clock.now(),
  );
  return line;
}

/** A Twilio-style form POST (`application/x-www-form-urlencoded`) with a signature header the fake accepts. */
export function postForm(
  app: FastifyInstance,
  url: string,
  form: Record<string, string>,
  headers: Record<string, string> = {},
): Promise<LightMyRequestResponse> {
  return app.inject({
    method: "POST",
    url,
    headers: { "content-type": "application/x-www-form-urlencoded", "x-twilio-signature": TEST_SIGNATURE, ...headers },
    payload: new URLSearchParams(form).toString(),
  });
}

export function voiceForm(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    CallSid: CALLER_SID,
    AccountSid: TWILIO_ACCOUNT_SID,
    From: CALLER_NUMBER,
    To: GUARD_NUMBER,
    CallStatus: "ringing",
    Direction: "inbound",
    ApiVersion: "2010-04-01",
    ...overrides,
  };
}

/** Lets promise chains started by a webhook (the async dial, handle closes) run to completion. */
export async function settle(turns = 4): Promise<void> {
  for (let i = 0; i < turns; i += 1) await new Promise<void>((resolve) => setImmediate(resolve));
}

/** Polls until `check` passes (for work that finishes on another socket). */
export async function waitFor(check: () => boolean, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!check()) {
    if (Date.now() > deadline) throw new Error("waitFor: condition not met in time");
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
}

/** Places an inbound call through the voice webhook and drains the async dial. */
export async function inboundCall(
  ctx: CallsTestContext,
  overrides: Record<string, string> = {},
): Promise<{ response: LightMyRequestResponse; session: CallSession }> {
  const before = new Set(ctx.app.callGuard.sessions.all().map((session) => session.callId));
  const response = await postForm(ctx.app, "/v1/calls/twilio/voice", voiceForm(overrides));
  await settle();
  const session = ctx.app.callGuard.sessions.all().find((candidate) => !before.has(candidate.callId));
  if (!session) throw new Error(`no session was created (status ${response.statusCode})`);
  return { response, session };
}

/** `?callID=…&token=…[&extra]` for a session's callback URLs. */
export function tokenQuery(session: Pick<CallSession, "callId" | "mediaToken">, extra: Record<string, string> = {}): string {
  return new URLSearchParams({ callID: session.callId, token: session.mediaToken, ...extra }).toString();
}

export function statusForm(callSid: string, callStatus: string, overrides: Record<string, string> = {}): Record<string, string> {
  return { CallSid: callSid, AccountSid: TWILIO_ACCOUNT_SID, CallStatus: callStatus, From: GUARD_NUMBER, To: PROTECTED_NUMBER, ...overrides };
}

export function conferenceForm(event: string, overrides: Record<string, string> = {}): Record<string, string> {
  return {
    ConferenceSid: CONFERENCE_SID,
    FriendlyName: "cg-test",
    AccountSid: TWILIO_ACCOUNT_SID,
    StatusCallbackEvent: event,
    SequenceNumber: "1",
    Timestamp: "Tue, 23 Sep 2026 10:00:00 +0000",
    ...overrides,
  };
}

export function transcriptionForm(
  track: string,
  transcript: string,
  final: boolean,
  sequence: number,
  overrides: Record<string, string> = {},
): Record<string, string> {
  return {
    TranscriptionEvent: "transcription-content",
    TranscriptionSid: "GT" + "e".repeat(32),
    CallSid: CALLER_SID,
    AccountSid: TWILIO_ACCOUNT_SID,
    Timestamp: "2026-09-23T10:00:00.000Z",
    SequenceId: String(sequence),
    Track: track,
    Final: final ? "true" : "false",
    LanguageCode: "en-US",
    TranscriptionData: JSON.stringify({ transcript, confidence: 0.91 }),
    ...overrides,
  };
}

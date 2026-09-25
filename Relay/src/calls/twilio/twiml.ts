import twilio from "twilio";
import type VoiceResponse from "twilio/lib/twiml/VoiceResponse.js";

import type { CallSession } from "../session.js";
import type { CallSource, Speaker } from "../types.js";

/**
 * Pure TwiML builders for the Call Guard call path (docs/CALLS.md §5.2, §7.2; docs/research/twilio.md §1, §2,
 * §4, §7). Every function returns an XML string and touches nothing else, so the exact attributes can be
 * asserted in tests. The `twilio` SDK is CommonJS: only its default import works in ESM.
 */

const { VoiceResponse: Response } = twilio.twiml;

// The SDK keeps these unions private to its namespace; derive them from the attribute interfaces.
type SayVoice = NonNullable<VoiceResponse.SayAttributes["voice"]>;
type ConferenceEvent = NonNullable<VoiceResponse.ConferenceAttributes["statusCallbackEvent"]>[number];
type StreamTrack = NonNullable<VoiceResponse.StreamAttributes["track"]>;
type TranscriptionTrack = NonNullable<VoiceResponse.TranscriptionAttributes["track"]>;

/** The transcription source a session actually uses (config `auto` has been resolved by then). */
export type ResolvedTranscriptionSource = "twilio" | "openai";

/** A scripted "scammer" for a test call: caller lines spoken by Twilio with a pause after each for the person to answer. */
export interface TestCallScript {
  lines: { text: string; pauseSeconds: number }[];
}

export const WARNING_VOICE: SayVoice = "Polly.Joanna-Neural";
export const SCAMMER_VOICE: SayVoice = "Polly.Matthew-Neural";
export const CALLER_PARTICIPANT_LABEL = "caller";
export const CONFERENCE_STATUS_EVENTS: readonly ConferenceEvent[] = ["start", "end", "join", "leave"];
export const TEST_CALL_GOODBYE = "This was a PhishGuard test call. Nothing you said was recorded. Goodbye.";
export const NOT_SET_UP_MESSAGE = "This number is not set up for call protection. Goodbye.";
export const LOOP_GUARD_MESSAGE = "This call cannot be forwarded to the number it came from. Goodbye.";
export const COULD_NOT_REACH_MESSAGE = "Sorry, we could not reach them right now. Please try again later. Goodbye.";

/** Built-in script used when no scenario provider is wired (docs/CALLS.md §7.2 "grandparent"). */
export const DEFAULT_TEST_CALL_SCRIPT: TestCallScript = {
  lines: [
    { text: "Hi Grandma, it's me. I'm in trouble and I really need your help right now.", pauseSeconds: 4 },
    {
      text: "I had a car accident and I'm at the police station. Please don't tell Mom or Dad, they would be so upset.",
      pauseSeconds: 4,
    },
    {
      text: "The lawyer says I need three thousand dollars for bail today. Can you go to the store, buy gift cards and read me the numbers on the back?",
      pauseSeconds: 5,
    },
    { text: "Please hurry, I don't have much time. Stay on the phone with me while you get them.", pauseSeconds: 4 },
  ],
};

export function conferenceNameFor(callId: string): string {
  return `cg-${callId}`;
}

/** `PUBLIC_BASE_URL/v1/calls/twilio/<route>?callID=…&token=…[&extra]` — every relay callback carries the session token. */
export function callbackUrl(
  publicBaseUrl: string,
  route: string,
  session: Pick<CallSession, "callId" | "mediaToken">,
  extra: Record<string, string> = {},
): string {
  const params = new URLSearchParams({ callID: session.callId, token: session.mediaToken, ...extra });
  return `${trimSlash(publicBaseUrl)}/v1/calls/twilio/${route}?${params.toString()}`;
}

/** The Media Streams endpoint: `wss://…/v1/calls/twilio/media/<mediaToken>` (no query string — Twilio forbids one). */
export function mediaStreamUrl(publicBaseUrl: string, session: Pick<CallSession, "mediaToken">): string {
  return `${toWebSocketBase(publicBaseUrl)}/v1/calls/twilio/media/${session.mediaToken}`;
}

export function ringbackUrl(publicBaseUrl: string): string {
  return `${trimSlash(publicBaseUrl)}/v1/calls/twilio/ringback.wav`;
}

/**
 * Which speaker each Twilio track carries. On an inbound call the stream is on the caller's leg: `inbound` is
 * the caller, `outbound` is what the caller hears (ringback, then the protected person). A test call is an
 * outbound call to the protected phone, so the tracks are the other way round: `inbound` is the person,
 * `outbound` is Twilio's scripted "scammer".
 */
export function trackSpeakers(source: CallSource): { inbound: Speaker; outbound: Speaker } {
  return source === "test-call" ? { inbound: "user", outbound: "caller" } : { inbound: "caller", outbound: "user" };
}

/** Maps a track name (`inbound`, `outbound_track`, …) or one of our labels (`caller`, `user`) to a speaker. */
export function speakerForTrack(source: CallSource, track: string | undefined): Speaker | undefined {
  if (!track) return undefined;
  const name = track.toLowerCase();
  if (name === "caller" || name === "user") return name;
  const speakers = trackSpeakers(source);
  if (name === "inbound" || name === "inbound_track") return speakers.inbound;
  if (name === "outbound" || name === "outbound_track") return speakers.outbound;
  return undefined;
}

export interface ForkInput {
  session: CallSession;
  source: ResolvedTranscriptionSource;
  publicBaseUrl: string;
  transcribeTracks: "both" | "caller";
}

/** The `<Start>` block: a Media Streams fork (source `openai`) or Twilio's own `<Transcription>` (source `twilio`). */
function addFork(response: VoiceResponse, input: ForkInput): void {
  const { session, publicBaseUrl } = input;
  const start = response.start();
  if (input.source === "openai") {
    const stream = start.stream({
      url: mediaStreamUrl(publicBaseUrl, session),
      track: streamTrack(session.source, input.transcribeTracks),
      statusCallback: callbackUrl(publicBaseUrl, "stream", session),
      statusCallbackMethod: "POST",
    });
    stream.parameter({ name: "callID", value: session.callId });
    return;
  }
  const speakers = trackSpeakers(session.source);
  start.transcription({
    name: conferenceNameFor(session.callId),
    statusCallbackUrl: callbackUrl(publicBaseUrl, "transcription", session),
    statusCallbackMethod: "POST",
    track: transcriptionTrack(session.source, input.transcribeTracks),
    partialResults: true,
    inboundTrackLabel: speakers.inbound,
    outboundTrackLabel: speakers.outbound,
  });
}

function streamTrack(source: CallSource, tracks: "both" | "caller"): StreamTrack {
  if (tracks === "both") return "both_tracks";
  return trackSpeakers(source).inbound === "caller" ? "inbound_track" : "outbound_track";
}

function transcriptionTrack(source: CallSource, tracks: "both" | "caller"): TranscriptionTrack {
  if (tracks === "both") return "both_tracks";
  return trackSpeakers(source).inbound === "caller" ? "inbound_track" : "outbound_track";
}

/**
 * The inbound voice webhook answer: fork the audio, then park the caller in the session's conference (muted, hearing
 * ringback) until the relay dials the protected phone in through the Participants API (docs/CALLS.md §2 decision 1).
 */
export function inboundCallTwiml(input: ForkInput): string {
  const { session, publicBaseUrl } = input;
  const response = new Response();
  addFork(response, input);
  const dial = response.dial();
  dial.conference(
    {
      startConferenceOnEnter: false,
      endConferenceOnExit: true,
      beep: "false",
      waitUrl: ringbackUrl(publicBaseUrl),
      waitMethod: "GET",
      statusCallback: callbackUrl(publicBaseUrl, "conference", session),
      statusCallbackMethod: "POST",
      statusCallbackEvent: [...CONFERENCE_STATUS_EVENTS],
      participantLabel: CALLER_PARTICIPANT_LABEL,
    },
    conferenceNameFor(session.callId),
  );
  // Without this Twilio would re-render the document once the conference ends (docs/research/twilio.md §3.3).
  response.hangup();
  return response.toString();
}

/** The test call (docs/CALLS.md §7.2): fork, then the scripted caller lines with pauses, a goodbye and a hang-up. */
export function testCallTwiml(input: ForkInput & { script: TestCallScript }): string {
  const response = new Response();
  addFork(response, input);
  for (const line of input.script.lines) {
    response.say({ voice: SCAMMER_VOICE }, line.text);
    const pause = Math.min(30, Math.max(1, Math.round(line.pauseSeconds)));
    response.pause({ length: pause });
  }
  response.say({ voice: WARNING_VOICE }, TEST_CALL_GOODBYE);
  response.hangup();
  return response.toString();
}

/** The spoken warning, played to the protected person only (participant `AnnounceUrl`) or as a test call's new TwiML. */
export function announceTwiml(text: string): string {
  const response = new Response();
  response.say({ voice: WARNING_VOICE }, text);
  return response.toString();
}

export function notSetUpTwiml(): string {
  return sayAndHangUp(NOT_SET_UP_MESSAGE);
}

export function loopGuardTwiml(): string {
  return sayAndHangUp(LOOP_GUARD_MESSAGE);
}

export function couldNotReachTwiml(): string {
  return sayAndHangUp(COULD_NOT_REACH_MESSAGE);
}

function sayAndHangUp(message: string): string {
  const response = new Response();
  response.say({ voice: WARNING_VOICE }, message);
  response.hangup();
  return response.toString();
}

function trimSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

function toWebSocketBase(publicBaseUrl: string): string {
  const base = trimSlash(publicBaseUrl);
  if (base.startsWith("https://")) return `wss://${base.slice("https://".length)}`;
  if (base.startsWith("http://")) return `ws://${base.slice("http://".length)}`;
  return base;
}

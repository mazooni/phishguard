import type { FastifyBaseLogger } from "fastify";

import type { CallSession } from "../session.js";
import type { Speaker, TranscriptSegment } from "../types.js";
import { speakerForTrack } from "./twiml.js";

/**
 * Turns Twilio `<Transcription>` status callbacks into transcript segments (docs/CALLS.md §5.2; docs/research/
 * twilio.md §7). Only sessions whose `transcriptionSource` is `twilio` take content; everything else is logged.
 *
 * Callback fields: `TranscriptionEvent` (`transcription-started|-content|-stopped|-error`), `Track`
 * (`inbound_track` | `outbound_track`, or the label we configured), `Final` (`true`/`false`), `SequenceId`,
 * `TranscriptionData` (JSON `{transcript, confidence}`), `Stability` (partials). Partials of one utterance share
 * a segment id until the final replaces it; the next partial starts a new id. Transcript text is never logged.
 */

export type TranscriptionOutcome = "segment" | "ignored" | "started" | "stopped" | "error";

export interface TranscriptionWebhookOptions {
  logger: FastifyBaseLogger;
  now: () => number;
}

interface TrackState {
  counter: number;
  /** The id of the utterance currently being built (partials); cleared by its final. */
  currentId: string | undefined;
  lastSequence: number;
}

export class TranscriptionWebhook {
  private readonly tracks = new WeakMap<CallSession, Map<Speaker, TrackState>>();
  private readonly logger: FastifyBaseLogger;
  private readonly now: () => number;

  constructor(options: TranscriptionWebhookOptions) {
    this.logger = options.logger;
    this.now = options.now;
  }

  handle(session: CallSession, body: Record<string, string>): TranscriptionOutcome {
    const event = body["TranscriptionEvent"] ?? "";
    switch (event) {
      case "transcription-started":
        this.logger.info({ callId: session.callId }, "calls: twilio transcription started");
        return "started";
      case "transcription-stopped":
        // The call status callbacks end the session; a stopped transcription on its own means nothing.
        this.logger.info({ callId: session.callId }, "calls: twilio transcription stopped");
        return "stopped";
      case "transcription-error":
        this.logger.warn({ callId: session.callId, track: body["Track"] }, "calls: twilio transcription error");
        return "error";
      case "transcription-content":
        return this.content(session, body);
      default:
        this.logger.debug({ callId: session.callId, event }, "calls: unknown transcription event");
        return "ignored";
    }
  }

  private content(session: CallSession, body: Record<string, string>): TranscriptionOutcome {
    if (session.transcriptionSource !== "twilio") {
      this.logger.debug({ callId: session.callId }, "calls: transcription content for a session Twilio does not transcribe");
      return "ignored";
    }
    if (session.isEnded) return "ignored";
    const speaker = speakerForTrack(session.source, body["Track"]);
    if (!speaker) {
      this.logger.debug({ callId: session.callId }, "calls: transcription content with an unknown track");
      return "ignored";
    }
    const text = parseTranscript(body["TranscriptionData"]);
    if (!text) return "ignored";
    const final = (body["Final"] ?? "").toLowerCase() === "true";
    const sequence = Number.parseInt(body["SequenceId"] ?? "", 10);

    const state = this.track(session, speaker);
    if (!final && Number.isFinite(sequence) && sequence < state.lastSequence) return "ignored"; // a late partial
    if (Number.isFinite(sequence)) state.lastSequence = Math.max(state.lastSequence, sequence);

    const id = state.currentId ?? `${speaker}-tw-${++state.counter}`;
    const segment: TranscriptSegment = { id, speaker, text, atMs: session.elapsedMs(this.now()), final };
    session.addSegment(segment);
    state.currentId = final ? undefined : id;
    return "segment";
  }

  private track(session: CallSession, speaker: Speaker): TrackState {
    let perSpeaker = this.tracks.get(session);
    if (!perSpeaker) {
      perSpeaker = new Map();
      this.tracks.set(session, perSpeaker);
    }
    let state = perSpeaker.get(speaker);
    if (!state) {
      state = { counter: 0, currentId: undefined, lastSequence: -1 };
      perSpeaker.set(speaker, state);
    }
    return state;
  }
}

/** `TranscriptionData` is a JSON string `{"transcript": "...", "confidence": 0.9}`; anything else yields no text. */
export function parseTranscript(data: string | undefined): string | undefined {
  if (!data) return undefined;
  try {
    const parsed: unknown = JSON.parse(data);
    if (typeof parsed !== "object" || parsed === null) return undefined;
    const transcript = (parsed as Record<string, unknown>)["transcript"];
    if (typeof transcript !== "string") return undefined;
    const trimmed = transcript.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  } catch {
    return undefined;
  }
}

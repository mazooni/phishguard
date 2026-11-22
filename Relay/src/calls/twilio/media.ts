import type { FastifyBaseLogger } from "fastify";

import type { CallSession } from "../session.js";
import type { Speaker, Transcriber, TranscriberHandle, VoiceDetector, VoiceDetectorHandle } from "../types.js";
import { speakerForTrack } from "./twiml.js";

/**
 * One Twilio Media Streams connection (docs/CALLS.md §5.2; docs/research/twilio.md §1.3). Twilio sends JSON text
 * frames: `connected`, `start` (tracks, `customParameters.callID`), `media` (`track`, base64 μ-law `payload`),
 * `mark`, `dtmf`, `stop`. Unknown events are ignored. Audio is forwarded frame by frame to one transcriber handle
 * per track — nothing is buffered here — and the outbound track of an inbound call is dropped until the
 * protected person has joined (before that it is only the ringback the caller hears).
 *
 * With a voice detector, the CALLER's track is also fed to one voice handle per stream, whoever transcribes the
 * call (it is the only consumer of the caller-only stream a Twilio-transcribed call gets). The protected
 * person's track never reaches it.
 */

export interface MediaStart {
  streamSid?: string;
  callSid?: string;
  tracks?: string[];
  customParameters?: Record<string, string>;
}

export type TwilioMediaMessage =
  | { event: "connected" }
  | { event: "start"; start: MediaStart }
  | { event: "media"; track: string; payload: string }
  | { event: "mark" }
  | { event: "dtmf" }
  | { event: "stop" }
  | { event: "other"; name: string };

/** Lenient parse of one frame; `undefined` for non-JSON or a frame without an `event`. */
export function parseMediaMessage(raw: unknown): TwilioMediaMessage | undefined {
  let text: string;
  if (typeof raw === "string") text = raw;
  else if (Buffer.isBuffer(raw)) text = raw.toString("utf8");
  else if (Array.isArray(raw)) text = Buffer.concat(raw as Buffer[]).toString("utf8");
  else if (raw instanceof ArrayBuffer) text = Buffer.from(raw).toString("utf8");
  else return undefined;

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null) return undefined;
  const message = parsed as Record<string, unknown>;
  const event = message["event"];
  if (typeof event !== "string") return undefined;

  switch (event) {
    case "connected":
    case "mark":
    case "dtmf":
    case "stop":
      return { event };
    case "start": {
      const start = typeof message["start"] === "object" && message["start"] !== null ? (message["start"] as Record<string, unknown>) : {};
      const result: MediaStart = {};
      if (typeof start["streamSid"] === "string") result.streamSid = start["streamSid"];
      if (typeof start["callSid"] === "string") result.callSid = start["callSid"];
      if (Array.isArray(start["tracks"])) result.tracks = start["tracks"].filter((t): t is string => typeof t === "string");
      const custom = start["customParameters"];
      if (typeof custom === "object" && custom !== null) {
        const params: Record<string, string> = {};
        for (const [key, value] of Object.entries(custom as Record<string, unknown>)) if (typeof value === "string") params[key] = value;
        result.customParameters = params;
      }
      return { event: "start", start: result };
    }
    case "media": {
      const media = typeof message["media"] === "object" && message["media"] !== null ? (message["media"] as Record<string, unknown>) : {};
      const track = media["track"];
      const payload = media["payload"];
      if (typeof track !== "string" || typeof payload !== "string") return { event: "other", name: "media-invalid" };
      return { event: "media", track, payload };
    }
    default:
      return { event: "other", name: event };
  }
}

/** The subset of `ws.WebSocket` the connection uses, so unit tests can pass a stub. */
export interface MediaSocket {
  on(event: "message", listener: (data: unknown) => void): unknown;
  on(event: "close", listener: () => void): unknown;
  on(event: "error", listener: (error: Error) => void): unknown;
  close(code?: number, reason?: string): void;
  /** Destroys the socket without a close handshake (`ws` has it; stubs may not). */
  terminate?(): void;
}

export interface MediaConnectionOptions {
  session: CallSession;
  transcriber: Transcriber | undefined;
  transcribeTracks: "both" | "caller";
  logger: FastifyBaseLogger;
  /** AI-voice detection on the caller's track; absent (no `MODULATE_API_KEY`) changes nothing here. */
  voiceDetector?: VoiceDetector | undefined;
  /**
   * Stops this stream at Twilio (`TwilioClient.stopStream`). Used only for a stream that feeds nothing but the
   * voice detector, once the detector has finished with the call; absent for replays and tests without Twilio.
   */
  stopStream?: ((callSid: string, streamSid: string) => Promise<boolean>) | undefined;
}

/** `forwarded` and `dropped` count the transcriber path only; audio for the voice detector is not counted. */
export interface MediaStats {
  frames: number;
  forwarded: number;
  dropped: number;
  invalid: number;
}

/** Close code for a stream whose `start` names another call (RFC 6455 "policy violation"). */
export const CLOSE_POLICY_VIOLATION = 1008;

export class MediaConnection {
  readonly stats: MediaStats = { frames: 0, forwarded: 0, dropped: 0, invalid: 0 };
  private readonly handles = new Map<Speaker, TranscriberHandle>();
  /** The caller's audio into the voice detector; opened on `start` when the stream carries the caller's track. */
  private voiceHandle: VoiceDetectorHandle | undefined;
  private readonly session: CallSession;
  private readonly transcriber: Transcriber | undefined;
  private readonly voiceDetector: VoiceDetector | undefined;
  private readonly stopStream: ((callSid: string, streamSid: string) => Promise<boolean>) | undefined;
  /** Twilio's identifiers for this stream, from its `start` message. */
  private twilioStream: { callSid: string; streamSid: string } | undefined;
  private readonly transcribeTracks: "both" | "caller";
  private readonly logger: FastifyBaseLogger;
  private started = false;
  private closed = false;
  private readonly onEnded = (): void => this.close(1000, "call ended");

  constructor(
    private readonly socket: MediaSocket,
    options: MediaConnectionOptions,
  ) {
    this.session = options.session;
    this.transcriber = options.transcriber;
    this.transcribeTracks = options.transcribeTracks;
    this.logger = options.logger;
    this.voiceDetector = options.voiceDetector;
    this.stopStream = options.stopStream;
  }

  get isClosed(): boolean {
    return this.closed;
  }

  /** Attaches the socket listeners (synchronously, as @fastify/websocket requires) and follows the session's end. */
  attach(): void {
    this.socket.on("message", (data) => this.handleMessage(data));
    this.socket.on("close", () => this.close());
    this.socket.on("error", (error) => {
      this.logger.warn({ err: error, callId: this.session.callId }, "calls: media stream socket error");
      this.close();
    });
    if (this.session.isEnded) {
      this.close(1000, "call ended");
      return;
    }
    this.session.once("ended", this.onEnded);
  }

  handleMessage(raw: unknown): void {
    if (this.closed) return;
    this.stats.frames += 1;
    const message = parseMediaMessage(raw);
    if (!message) {
      this.stats.invalid += 1;
      return;
    }
    switch (message.event) {
      case "connected":
        return;
      case "start":
        this.start(message.start);
        return;
      case "media":
        this.media(message.track, message.payload);
        return;
      case "stop":
        this.logger.info({ callId: this.session.callId, ...this.stats }, "calls: media stream stopped");
        this.close(1000, "stream stopped");
        return;
      case "mark":
      case "dtmf":
      case "other":
        return;
      default:
        return;
    }
  }

  private start(start: MediaStart): void {
    if (this.started) return;
    const callId = start.customParameters?.["callID"];
    if (callId !== this.session.callId) {
      this.logger.warn({ callId: this.session.callId }, "calls: media stream started for another call; closing");
      this.close(CLOSE_POLICY_VIOLATION, "callID mismatch");
      return;
    }
    this.started = true;
    if (start.callSid && start.streamSid) this.twilioStream = { callSid: start.callSid, streamSid: start.streamSid };
    const tracks = start.tracks && start.tracks.length > 0 ? start.tracks : ["inbound", "outbound"];
    this.openVoice(tracks);
    if (this.session.transcriptionSource === "twilio") {
      // With a voice handle this is the caller-only stream added for it; nothing here is for a transcriber.
      if (!this.voiceHandle) this.logger.warn({ callId: this.session.callId }, "calls: media stream on a session Twilio transcribes; audio ignored");
      return;
    }
    if (!this.transcriber) {
      if (!this.voiceHandle) this.logger.warn({ callId: this.session.callId }, "calls: media stream without a transcriber; audio ignored");
      return;
    }
    for (const track of tracks) {
      const speaker = speakerForTrack(this.session.source, track);
      if (!speaker || this.handles.has(speaker)) continue;
      if (speaker === "user" && this.transcribeTracks === "caller") continue;
      this.handles.set(speaker, this.transcriber.open(this.session, speaker));
    }
    this.logger.info(
      { callId: this.session.callId, tracks: tracks.length, transcribing: [...this.handles.keys()] },
      "calls: media stream started",
    );
  }

  /** One voice handle for the caller's track (a test call swaps the tracks, hence `speakerForTrack`). */
  private openVoice(tracks: string[]): void {
    if (!this.voiceDetector || this.voiceHandle) return;
    if (!tracks.some((track) => speakerForTrack(this.session.source, track) === "caller")) return;
    try {
      this.voiceHandle = this.voiceDetector.open(this.session);
    } catch (error) {
      // Voice detection is an extra: failing to start it must never cost the call its transcription.
      this.logger.warn(
        { errorName: error instanceof Error ? error.name : "unknown", callId: this.session.callId },
        "calls: voice detector could not be opened",
      );
      return;
    }
    this.logger.info({ callId: this.session.callId }, "calls: media stream feeds the voice detector with the caller's track");
    const handle = this.voiceHandle;
    // Deferred past `start()`, which opens the transcriber handles after this: only then is it known whether the
    // stream serves anything else.
    void handle.finished?.then(() => this.voiceFinished(handle));
  }

  /**
   * The detector is done with this call. A stream that exists for it alone (the caller-only fork added to a call
   * Twilio transcribes) would otherwise run, unused, until the call ends: ask Twilio to stop it. Twilio then sends
   * `stop` and closes the socket, which is the ordinary end of a stream. A stream that also feeds a transcriber is
   * left alone, and so is everything when Twilio cannot be asked.
   */
  private voiceFinished(handle: VoiceDetectorHandle): void {
    if (this.closed || this.voiceHandle !== handle || this.handles.size > 0) return;
    if (!this.stopStream || !this.twilioStream || this.session.isEnded) return;
    const { callSid, streamSid } = this.twilioStream;
    this.logger.info({ callId: this.session.callId }, "calls: voice detector finished; stopping its media stream");
    this.stopStream(callSid, streamSid).catch(() => false);
  }

  private media(track: string, payload: string): void {
    if (!this.started) {
      this.stats.dropped += 1;
      return;
    }
    const speaker = speakerForTrack(this.session.source, track);
    // Independent of the transcriber below. Only ever the caller: the protected person's voice is not analysed.
    if (speaker === "caller") this.voiceHandle?.pushAudio(payload);
    const handle = speaker ? this.handles.get(speaker) : undefined;
    if (!speaker || !handle || this.shouldDrop(speaker)) {
      this.stats.dropped += 1;
      return;
    }
    handle.pushAudio(payload);
    this.stats.forwarded += 1;
  }

  /** On an inbound call the outbound track is ringback until the protected person joins. */
  private shouldDrop(speaker: Speaker): boolean {
    return this.session.source === "twilio" && speaker === "user" && this.session.status !== "in_progress";
  }

  /** Shutdown: releases the handles and destroys the socket without waiting for the peer's close frame. */
  terminate(): void {
    this.close(1001, "server shutting down");
    try {
      this.socket.terminate?.();
    } catch {
      // Already gone.
    }
  }

  close(code = 1000, reason = ""): void {
    if (this.closed) return;
    this.closed = true;
    this.session.off("ended", this.onEnded);
    for (const [speaker, handle] of this.handles) {
      handle.close().catch((error: unknown) => {
        this.logger.warn({ err: error, callId: this.session.callId, speaker }, "calls: transcriber handle close failed");
      });
    }
    this.handles.clear();
    if (this.voiceHandle) {
      this.voiceHandle.close().catch((error: unknown) => {
        // Fields only: a vendor error object can carry its connection URL.
        this.logger.warn(
          { errorName: error instanceof Error ? error.name : "unknown", callId: this.session.callId },
          "calls: voice detector handle close failed",
        );
      });
      this.voiceHandle = undefined;
    }
    try {
      this.socket.close(code, reason);
    } catch {
      // Already closed.
    }
  }
}

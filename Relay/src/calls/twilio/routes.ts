import type { FastifyBaseLogger, FastifyInstance, FastifyReply } from "fastify";

import type { RelayConfig } from "../../config.js";
import type { RelayDb } from "../../db.js";
import type { CallsConfig } from "../config.js";
import type { CallSession, CallSessionInit, CallSessionManager } from "../session.js";
import { redactNumber, type CallStatus, type Transcriber } from "../types.js";
import { twilioErrorFields, type TwilioClient } from "./client.js";
import { MediaConnection } from "./media.js";
import { ringbackWav } from "./ringback.js";
import {
  findSessionByMediaToken,
  formParams,
  lookupSessionFromQuery,
  publicUrlFor,
  queryParams,
  sessionTokenGuard,
  signatureHeader,
  twilioSignatureGuard,
  websocketUrlFor,
} from "./signature.js";
import { TranscriptionWebhook } from "./transcription.js";
import { ensureWebPlugins } from "../websocket.js";
import {
  DEFAULT_TEST_CALL_SCRIPT,
  announceTwiml,
  conferenceNameFor,
  couldNotReachTwiml,
  inboundCallTwiml,
  loopGuardTwiml,
  notSetUpTwiml,
  testCallTwiml,
  type ResolvedTranscriptionSource,
  type TestCallScript,
} from "./twiml.js";

/**
 * The Twilio webhooks and the Media Streams WebSocket (docs/CALLS.md §5.2). Every POST is signature-checked
 * against the public URL; every per-call route also checks the session token in its query string. Routes log at
 * `warn` and above only, so Fastify's request log never prints a URL that carries a session token; the handlers
 * emit their own structured lines (numbers redacted, never transcript text).
 */

export interface TwilioRoutesOptions {
  config: RelayConfig;
  calls: CallsConfig;
  db: RelayDb;
  sessions: CallSessionManager;
  twilio: TwilioClient | undefined;
  transcriber: Transcriber | undefined;
  logger: FastifyBaseLogger;
  now: () => number;
  /** Supplies a test call's scripted lines by scenario id; the built-in "grandparent" script when absent or unknown. */
  testCallScript?: (scenarioId: string) => TestCallScript | undefined;
}

const WEBHOOK_BODY_LIMIT = 64 * 1024;
/** Twilio media frames are a few hundred bytes; anything near this is not Twilio. */
/** Twilio abandons a voice webhook after a few seconds (5 s on a trial account), so the account lookup that picks the transcription source is capped. */
export const ACCOUNT_TYPE_DEADLINE_MS = 2500;
export { ensureWebPlugins };

type Leg = "caller" | "user" | "test";

/** `work`'s value, or `fallback` once `ms` have passed or `work` rejected. The timer never keeps the process alive. */
export function withinDeadline<T>(work: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(fallback), ms);
    timer.unref();
    work.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        clearTimeout(timer);
        resolve(fallback);
      },
    );
  });
}

/** Twilio `CallStatus` → `CallStatus` for the terminal values; `undefined` for the transitional ones. */
export function endedStatusFor(twilioStatus: string | undefined): CallStatus | undefined {
  switch (twilioStatus) {
    case "completed":
      return "completed";
    case "busy":
      return "busy";
    case "failed":
      return "failed";
    case "no-answer":
      return "no_answer";
    case "canceled":
      return "canceled";
    default:
      return undefined;
  }
}

export function registerTwilioRoutes(app: FastifyInstance, options: TwilioRoutesOptions): void {
  ensureWebPlugins(app);
  const { config, calls, db, sessions, transcriber, now } = options;
  const log = options.logger.child({ module: "calls.twilio" });
  // The Media Streams socket is also the replay script's input (docs/CALLS.md §4 `replay`), so it exists whenever
  // Call Guard is on; without a Twilio client the handshake signature is simply never checked.
  registerMediaRoute(app, {
    sessions,
    twilio: options.twilio,
    transcriber,
    transcribeTracks: calls.transcribeTracks,
    publicBaseUrl: config.publicBaseUrl,
    log,
  });
  if (!options.twilio) {
    log.info("calls: Twilio not configured; webhook routes are off");
    return;
  }
  // A typed const so the hoisted helper functions below see a definite client.
  const twilio: TwilioClient = options.twilio;
  const transcription = new TranscriptionWebhook({ logger: log, now });
  const publicBaseUrl = config.publicBaseUrl;
  /** The one Media Streams connection per call; a second one for the same call supersedes it (no doubled transcriber handles). */
  const mediaConnections = new Map<string, MediaConnection>();
  // Shutdown: destroy the media sockets before Fastify waits for the HTTP server to drain, so a peer that never
  // answers the close handshake cannot hold `app.close()` (and the persistence behind it) for ws's 30 s timeout.
  app.addHook("preClose", async () => {
    for (const connection of mediaConnections.values()) connection.terminate();
    mediaConnections.clear();
  });

  async function resolveTranscriptionSource(): Promise<ResolvedTranscriptionSource> {
    const configured = calls.transcriptionSource;
    if (configured === "twilio" || configured === "openai") return configured;
    if (!calls.openai || !transcriber) return "twilio";
    // Media Streams are blocked on Trial accounts; when the type cannot be fetched, Twilio's transcription is the
    // choice that works on every account.
    const type = await withinDeadline(twilio.fetchAccountType(), ACCOUNT_TYPE_DEADLINE_MS, "unknown");
    return type === "Full" ? "openai" : "twilio";
  }

  if (calls.transcriptionSource === "auto") {
    void twilio.fetchAccountType().then((type) => {
      log.info({ accountType: type }, "calls: twilio account type resolved");
      if (type === "Trial") log.warn("calls: Trial account — <Stream> is blocked, using Twilio transcription; calls only to verified numbers");
    });
  }

  function sendTwiml(reply: FastifyReply, xml: string): FastifyReply {
    return reply.code(200).type("text/xml; charset=utf-8").send(xml);
  }

  /** Work started from a webhook after its reply: a rejection is logged, never left unhandled. */
  function background(work: Promise<unknown>, context: string, callId: string): void {
    work.catch((error: unknown) => log.error({ err: error, context, callId }, "calls: background work failed"));
  }

  /** Tells the caller the protected phone could not be reached and ends the session. */
  async function failCall(session: CallSession, status: CallStatus): Promise<void> {
    if (session.isEnded) return;
    if (session.twilioCallSid) await twilio.redirectCall(session.twilioCallSid, couldNotReachTwiml());
    session.end(status);
  }

  /** Runs after the voice webhook's TwiML has been sent: dials the protected phone into the conference. */
  async function dialUser(session: CallSession): Promise<void> {
    if (session.isEnded) return;
    try {
      const sid = await twilio.dialProtectedUser(session);
      session.userCallSid ??= sid;
      sessions.index(session, sid);
      if (session.isEnded) void twilio.endCall(sid); // the caller hung up while we were dialling
    } catch (error) {
      log.error({ reason: twilioErrorFields(error), callId: session.callId }, "calls: could not dial the protected phone");
      await failCall(session, "failed");
    }
  }

  function applyCallStatus(session: CallSession, leg: Leg, twilioStatus: string | undefined, callSid: string | undefined): void {
    // Late callbacks (the legs Twilio tears down after "could not reach", a hang-up already reported) change nothing.
    if (session.isEnded) return;
    const ended = endedStatusFor(twilioStatus);
    switch (leg) {
      case "user": {
        if (callSid) {
          session.userCallSid ??= callSid;
          sessions.index(session, callSid);
        }
        if (twilioStatus === "initiated" || twilioStatus === "ringing") {
          if (session.status === "ringing") session.setStatus("connecting");
        } else if (twilioStatus === "in-progress") {
          session.setStatus("in_progress");
        } else if (ended) {
          if (session.status === "in_progress") session.end(ended);
          else background(failCall(session, ended === "completed" ? "no_answer" : ended), "fail-call", session.callId); // never joined
        }
        return;
      }
      case "test": {
        if (callSid) {
          session.twilioCallSid ??= callSid;
          sessions.index(session, callSid);
        }
        if (twilioStatus === "in-progress") session.setStatus("in_progress");
        else if (ended) session.end(ended);
        return;
      }
      case "caller":
      default: {
        if (!ended) return;
        const wasConnected = session.status === "in_progress";
        session.end(ended);
        // The caller gave up while the protected phone was still ringing: stop that leg.
        if (!wasConnected && session.userCallSid) void twilio.endCall(session.userCallSid);
        return;
      }
    }
  }

  void app.register(async (scoped) => {
    scoped.decorateRequest("twilioSession", null);
    const signature = twilioSignatureGuard({ twilio, publicBaseUrl });
    const token = sessionTokenGuard({ sessions });
    const webhook = { bodyLimit: WEBHOOK_BODY_LIMIT, logLevel: "warn" as const };
    const perCall = { ...webhook, preHandler: [signature, token] };

    // Inbound call to the guard number.
    scoped.post("/v1/calls/twilio/voice", { ...webhook, preHandler: [signature] }, async (request, reply) => {
      const body = formParams(request.body);
      const callSid = body["CallSid"];
      const from = body["From"] ?? "";
      const to = body["To"] ?? "";
      const line = to ? db.findCallLineByGuardNumber(to) : undefined;
      if (!line) {
        log.warn({ to: redactNumber(to) }, "calls: inbound call to a number with no line");
        return sendTwiml(reply, notSetUpTwiml());
      }
      const forwardedFrom = body["ForwardedFrom"];
      if (from === line.phoneNumber || from === line.guardNumber || (forwardedFrom !== undefined && forwardedFrom === line.phoneNumber)) {
        log.warn({ lineId: line.lineId, from: redactNumber(from) }, "calls: loop guard — call from the protected number itself");
        return sendTwiml(reply, loopGuardTwiml());
      }
      const source = await resolveTranscriptionSource();
      const init: CallSessionInit = {
        deviceId: line.deviceId,
        line,
        source: "twilio",
        callerNumber: from || "unknown",
        calledNumber: to,
        startedAt: now(),
        status: "ringing",
        transcriptionSource: source,
      };
      if (callSid) init.twilioCallSid = callSid;
      const session = sessions.create(init);
      session.conferenceName = conferenceNameFor(session.callId);
      log.info({ callId: session.callId, deviceId: line.deviceId, from: redactNumber(from), transcription: source }, "calls: inbound call");
      // Dial the protected phone only once Twilio has our TwiML (the conference must exist before the user joins).
      // `reply.then` runs these inside a stream callback: nothing here may throw.
      reply.then(
        () => {
          background(dialUser(session), "dial", session.callId);
        },
        (error) => {
          log.warn({ err: error, callId: session.callId }, "calls: voice webhook response failed; call abandoned");
          try {
            session.end("failed");
          } catch (endError) {
            log.error({ err: endError, callId: session.callId }, "calls: could not end the abandoned session");
          }
        },
      );
      return sendTwiml(reply, inboundCallTwiml({ session, source, publicBaseUrl, transcribeTracks: calls.transcribeTracks }));
    });

    // Call status callbacks for the caller leg (from the number's status callback or our own URL), the user leg and test calls.
    scoped.post("/v1/calls/twilio/status", { ...webhook, preHandler: [signature] }, async (request, reply) => {
      const body = formParams(request.body);
      const query = queryParams(request.query);
      let session: CallSession | undefined;
      if (query["callID"]) {
        const lookup = lookupSessionFromQuery(sessions, request.query);
        if ("error" in lookup) return reply.code(lookup.status).send({ error: lookup.error });
        session = lookup.session;
      } else if (body["CallSid"]) {
        session = sessions.byTwilioSid(body["CallSid"]);
      }
      if (!session) return reply.code(204).send();
      const leg: Leg = query["leg"] === "user" || query["leg"] === "test" ? query["leg"] : "caller";
      log.info({ callId: session.callId, leg, status: body["CallStatus"] }, "calls: call status");
      applyCallStatus(session, leg, body["CallStatus"], body["CallSid"]);
      return reply.code(204).send();
    });

    // Conference status callbacks (set by the caller's <Conference>).
    scoped.post("/v1/calls/twilio/conference", perCall, async (request, reply) => {
      const session = request.twilioSession!;
      const body = formParams(request.body);
      const event = body["StatusCallbackEvent"];
      const conferenceSid = body["ConferenceSid"];
      if (conferenceSid) session.conferenceSid ??= conferenceSid;
      log.info({ callId: session.callId, event, participant: body["ParticipantLabel"] }, "calls: conference event");
      switch (event) {
        case "participant-join":
          if (body["ParticipantLabel"] === "user") {
            const callSid = body["CallSid"];
            if (callSid) {
              session.userCallSid ??= callSid;
              sessions.index(session, callSid);
            }
            session.setStatus("in_progress");
          }
          break;
        case "conference-end": {
          if (session.isEnded) break; // a repeated or late callback
          const wasConnected = session.status === "in_progress";
          session.end("completed");
          // The caller left while the protected phone was still ringing: stop that leg rather than let it ring into
          // an empty conference (the caller-leg status path does the same).
          if (!wasConnected && session.userCallSid) void twilio.endCall(session.userCallSid);
          break;
        }
        default:
          break;
      }
      return reply.code(204).send();
    });

    // Twilio <Transcription> status callbacks.
    scoped.post("/v1/calls/twilio/transcription", perCall, async (request, reply) => {
      transcription.handle(request.twilioSession!, formParams(request.body));
      return reply.code(204).send();
    });

    // <Stream> status callbacks: only ever logged (error 31920 diagnostics).
    scoped.post("/v1/calls/twilio/stream", perCall, async (request, reply) => {
      const session = request.twilioSession!;
      const body = formParams(request.body);
      const event = body["StreamEvent"];
      if (event === "stream-error") log.warn({ callId: session.callId, error: body["StreamError"]?.slice(0, 200) }, "calls: media stream error");
      else log.info({ callId: session.callId, event }, "calls: media stream event");
      return reply.code(204).send();
    });

    // The conference waitUrl: public and cacheable.
    scoped.get(
      "/v1/calls/twilio/ringback.wav",
      {
        logLevel: "warn",
        onSend: async (_request, reply, payload) => {
          reply.header("cache-control", "public, max-age=86400");
          return payload;
        },
      },
      async (_request, reply) => reply.type("audio/wav").send(ringbackWav()),
    );

    // Participant AnnounceUrl: the spoken warning for the user leg.
    scoped.post("/v1/calls/twilio/announce", perCall, async (request, reply) => {
      const session = request.twilioSession!;
      const text = twilio.announcementText(session) ?? calls.spokenWarningText;
      log.info({ callId: session.callId }, "calls: announcing the warning");
      return sendTwiml(reply, announceTwiml(text));
    });

    // TwiML for a test call (docs/CALLS.md §7.2).
    scoped.post("/v1/calls/twilio/test-call", perCall, async (request, reply) => {
      const session = request.twilioSession!;
      const scenario = queryParams(request.query)["scenario"] ?? "grandparent";
      const script = options.testCallScript?.(scenario) ?? DEFAULT_TEST_CALL_SCRIPT;
      const source = session.transcriptionSource ?? (await resolveTranscriptionSource());
      session.transcriptionSource ??= source;
      log.info({ callId: session.callId, scenario, transcription: source }, "calls: test call answered");
      return sendTwiml(reply, testCallTwiml({ session, source, publicBaseUrl, transcribeTracks: calls.transcribeTracks, script }));
    });

  });
}

interface MediaRouteOptions {
  sessions: CallSessionManager;
  twilio: TwilioClient | undefined;
  transcriber: Transcriber | undefined;
  transcribeTracks: "both" | "caller";
  publicBaseUrl: string;
  log: FastifyBaseLogger;
}

/**
 * Media Streams WebSocket (source `openai`; docs/CALLS.md §5.2). The path token must belong to a live session
 * before the upgrade happens. Registered with or without Twilio: `npm run calls:replay` feeds it Twilio-shaped
 * frames for a `replay` session, which needs only OpenAI.
 */
function registerMediaRoute(app: FastifyInstance, options: MediaRouteOptions): void {
  const { sessions, twilio, transcriber, transcribeTracks, publicBaseUrl, log } = options;
  // One live media connection per call: a second connection for the same token supersedes the first (its
  // transcriber handles are released), so a Twilio reconnect never doubles the OpenAI sessions.
  const mediaConnections = new Map<string, MediaConnection>();
  void app.register(async (scoped) => {
    scoped.get<{ Params: { mediaToken: string } }>(
      "/v1/calls/twilio/media/:mediaToken",
      {
        websocket: true,
        logLevel: "warn",
        preValidation: async (request, reply) => {
          const session = findSessionByMediaToken(sessions, request.params.mediaToken);
          if (!session) return reply.code(404).send({ error: "not_found" });
          // Settled on a real call (2026-09-24): Twilio signs the `wss://` URL exactly as written in the TwiML
          // (`handshakeSignature: "wss"`, docs/CALLS.md §12). A Twilio-sourced session therefore REQUIRES a valid
          // signature over the wss URL (its trailing-slash and https forms are accepted too, per the SDK's own
          // leniency); a replay session has no Twilio behind it and is authenticated by its media token alone.
          const sig = signatureHeader(request);
          let variant = "absent";
          if (sig) {
            if (!twilio) {
              variant = "unchecked";
            } else {
              const wsUrl = websocketUrlFor(publicBaseUrl, request.url);
              if (twilio.validateSignature(sig, wsUrl, {})) variant = "wss";
              else if (twilio.validateSignature(sig, `${wsUrl}/`, {})) variant = "wss-trailing-slash";
              else if (twilio.validateSignature(sig, publicUrlFor(publicBaseUrl, request.url), {})) variant = "https";
              else variant = "invalid";
            }
          }
          const fromTwilio = session.source === "twilio" || session.source === "test-call";
          const accepted = variant === "wss" || variant === "wss-trailing-slash" || variant === "https";
          if (fromTwilio && twilio && !accepted) {
            log.warn({ callId: session.callId, handshakeSignature: variant }, "calls: media stream handshake rejected");
            return reply.code(403).send({ error: "bad_signature" });
          }
          log.info({ callId: session.callId, handshakeSignature: variant }, "calls: media stream handshake");
          return undefined;
        },
      },
      (socket, request) => {
        // Looked up again rather than carried on the request: the session may have ended before the upgrade.
        const session = findSessionByMediaToken(sessions, request.params.mediaToken);
        if (!session) {
          socket.close(1008, "unknown session");
          return;
        }
        const previous = mediaConnections.get(session.callId);
        if (previous && !previous.isClosed) {
          log.warn({ callId: session.callId }, "calls: a second media stream for the call; the first one is closed");
          previous.close(1000, "superseded");
        }
        const connection = new MediaConnection(socket, {
          session,
          transcriber,
          transcribeTracks,
          logger: log,
        });
        mediaConnections.set(session.callId, connection);
        socket.on("close", () => {
          if (mediaConnections.get(session.callId) === connection) mediaConnections.delete(session.callId);
        });
        connection.attach();
      },
    );
  });
}

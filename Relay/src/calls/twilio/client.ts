import type { FastifyBaseLogger } from "fastify";
import twilio from "twilio";
import type { CallContextUpdateOptions, CallListInstanceCreateOptions } from "twilio/lib/rest/api/v2010/account/call.js";
import type { ConferenceContextUpdateOptions } from "twilio/lib/rest/api/v2010/account/conference.js";
import type {
  ParticipantContextUpdateOptions,
  ParticipantListInstanceCreateOptions,
} from "twilio/lib/rest/api/v2010/account/conference/participant.js";

import type { TwilioConfig } from "../config.js";
import type { CallSession } from "../session.js";
import { redactNumber, type VoiceControl } from "../types.js";
import { announceTwiml, callbackUrl, conferenceNameFor } from "./twiml.js";

/**
 * The relay's view of Twilio (docs/CALLS.md §3, §5.2; docs/research/twilio.md §2.3, §3.2, §4). Wraps the `twilio`
 * SDK behind a six-operation port (`TwilioRest`) so tests inject a recording fake; `createTwilioClient` adds the
 * Call Guard semantics on top: which conference/participant to address, which URLs Twilio must call back, and
 * the account type that decides the transcription source. Never logs a phone number in full.
 */

export type TwilioAccountType = "Trial" | "Full" | "unknown";

export interface TwilioClient extends VoiceControl {
  /** Dials the protected phone into the session's conference. Resolves the user leg's CallSid. */
  dialProtectedUser(session: CallSession): Promise<string>;
  /** Places the scripted test call (docs/CALLS.md §7.2). Resolves the CallSid. */
  placeTestCall(session: CallSession, scenarioId: string): Promise<string>;
  /** Validates `X-Twilio-Signature` for a webhook (`url` is PUBLIC_BASE_URL + path + query). */
  validateSignature(signature: string | undefined, url: string, params: Record<string, string>): boolean;
  /** `Trial` or `Full` from the Accounts API, cached after the first success; `unknown` while it cannot be fetched. */
  fetchAccountType(): Promise<TwilioAccountType>;
  /** Replaces a live call's TwiML (tells the caller the protected phone could not be reached). */
  redirectCall(callSid: string, twiml: string): Promise<boolean>;
  /** Ends one call leg (`status: completed`). */
  endCall(callSid: string): Promise<boolean>;
  /** The text the last `speakToUser` asked to be spoken on this session — what the announce webhook plays. */
  announcementText(session: CallSession): string | undefined;
}

/** The REST operations the client needs, as a port: the SDK behind it in production, a recording fake in tests. */
export interface TwilioRest {
  createParticipant(conference: string, params: ParticipantListInstanceCreateOptions): Promise<{ callSid: string }>;
  updateParticipant(conference: string, participant: string, params: ParticipantContextUpdateOptions): Promise<unknown>;
  updateConference(conferenceSid: string, params: ConferenceContextUpdateOptions): Promise<unknown>;
  /** The SID of the in-progress conference with this friendly name, if any (Participant *update* needs a SID). */
  findConferenceSid(friendlyName: string): Promise<string | undefined>;
  createCall(params: CallListInstanceCreateOptions): Promise<{ sid: string }>;
  updateCall(callSid: string, params: CallContextUpdateOptions): Promise<unknown>;
  /** The account's `type` property (`Trial` | `Full`). */
  fetchAccountType(): Promise<string>;
}

export interface TwilioClientOptions {
  config: TwilioConfig;
  publicBaseUrl: string;
  logger: FastifyBaseLogger;
  /** Defaults to the twilio SDK; tests pass a fake. */
  rest?: TwilioRest;
}

/** How long the protected phone rings before Twilio gives up (Participants API `Timeout`, 5–600). */
export const USER_LEG_TIMEOUT_SECONDS = 25;
export const USER_PARTICIPANT_LABEL = "user";
export const LEG_STATUS_EVENTS: readonly string[] = ["initiated", "ringing", "answered", "completed"];
/** Announcement texts are kept per session at most this long; a call never lasts longer. */
const ANNOUNCEMENT_TTL_MS = 60 * 60 * 1000;
/** A digit run long enough to be a phone number (7+ digits, separators allowed); shorter runs (error codes, HTTP statuses) stay readable. */
const PHONE_LIKE = /\+?\d(?:[\s().-]*\d){6,}/g;

export interface TwilioErrorFields {
  message: string;
  code?: number;
  status?: number;
}

/**
 * What a failed Twilio request may contribute to a log line. Never the raw error: a `RestException` message such
 * as "The number +1555… is unverified" (error 21219, the usual trial-account failure) carries the protected
 * person's full number, and pino's `err` serializer would print it again in the stack.
 */
export function twilioErrorFields(error: unknown): TwilioErrorFields {
  const record = typeof error === "object" && error !== null ? (error as Record<string, unknown>) : {};
  const raw = error instanceof Error ? error.message : typeof error === "string" ? error : "request failed";
  const fields: TwilioErrorFields = { message: raw.replace(PHONE_LIKE, (match) => redactNumber(match)) };
  if (typeof record["code"] === "number") fields.code = record["code"];
  if (typeof record["status"] === "number") fields.status = record["status"];
  return fields;
}

/** The SDK behind the port. Only this function touches `twilio(...)`. */
export function sdkRest(config: TwilioConfig): TwilioRest {
  const client = twilio(config.accountSid, config.authToken);
  return {
    createParticipant: (conference, params) => client.conferences(conference).participants.create(params),
    updateParticipant: (conference, participant, params) =>
      client.conferences(conference).participants(participant).update(params),
    updateConference: (conferenceSid, params) => client.conferences(conferenceSid).update(params),
    findConferenceSid: async (friendlyName) => {
      const [conference] = await client.conferences.list({ friendlyName, status: "in-progress", limit: 1 });
      return conference?.sid;
    },
    createCall: (params) => client.calls.create(params),
    updateCall: (callSid, params) => client.calls(callSid).update(params),
    fetchAccountType: async () => (await client.api.v2010.accounts(config.accountSid).fetch()).type,
  };
}

export function createTwilioClient(options: TwilioClientOptions): TwilioClient {
  const { config, publicBaseUrl, logger } = options;
  const rest = options.rest ?? sdkRest(config);
  const announcements = new Map<string, { text: string; at: number }>();
  let accountType: TwilioAccountType = "unknown";
  let accountFetch: Promise<TwilioAccountType> | undefined;

  function rememberAnnouncement(callId: string, text: string): void {
    const now = Date.now();
    for (const [key, value] of announcements) if (now - value.at > ANNOUNCEMENT_TTL_MS) announcements.delete(key);
    announcements.set(callId, { text, at: now });
  }

  const client: TwilioClient = {
    async dialProtectedUser(session) {
      const line = session.line;
      if (!line) throw new Error("twilio: session has no line to dial");
      const conference = session.conferenceName ?? conferenceNameFor(session.callId);
      const participant = await rest.createParticipant(conference, {
        from: config.number,
        to: line.phoneNumber,
        label: USER_PARTICIPANT_LABEL,
        startConferenceOnEnter: true,
        endConferenceOnExit: true,
        beep: "false",
        timeout: USER_LEG_TIMEOUT_SECONDS,
        statusCallback: callbackUrl(publicBaseUrl, "status", session, { leg: "user" }),
        statusCallbackMethod: "POST",
        statusCallbackEvent: [...LEG_STATUS_EVENTS],
      });
      logger.info({ callId: session.callId, to: redactNumber(line.phoneNumber) }, "twilio: user leg dialled");
      return participant.callSid;
    },

    async placeTestCall(session, scenarioId) {
      const line = session.line;
      if (!line) throw new Error("twilio: session has no line to call");
      const call = await rest.createCall({
        to: line.phoneNumber,
        from: config.number,
        url: callbackUrl(publicBaseUrl, "test-call", session, { scenario: scenarioId }),
        method: "POST",
        statusCallback: callbackUrl(publicBaseUrl, "status", session, { leg: "test" }),
        statusCallbackMethod: "POST",
        statusCallbackEvent: [...LEG_STATUS_EVENTS],
        timeout: USER_LEG_TIMEOUT_SECONDS,
      });
      logger.info({ callId: session.callId, scenario: scenarioId, to: redactNumber(line.phoneNumber) }, "twilio: test call placed");
      return call.sid;
    },

    async speakToUser(session, text) {
      try {
        if (session.source === "test-call") {
          if (!session.twilioCallSid) return false;
          // Replacing the call's TwiML ends the scripted "scammer" and plays the warning (docs/CALLS.md §5.2).
          await rest.updateCall(session.twilioCallSid, { twiml: announceTwiml(text) });
          logger.info({ callId: session.callId }, "twilio: warning spoken on test call");
          return true;
        }
        if (session.source !== "twilio") return false;
        // docs/research/twilio.md §2.3 verifies friendly names for Participant *create* only, and the user leg
        // can report `answered` before `conference-start` delivers the SID: resolve it by name when missing.
        if (!session.conferenceSid && session.conferenceName) {
          session.conferenceSid = await rest.findConferenceSid(session.conferenceName);
        }
        const conference = session.conferenceSid ?? session.conferenceName;
        if (!conference) return false;
        rememberAnnouncement(session.callId, text);
        await rest.updateParticipant(conference, session.userCallSid ?? USER_PARTICIPANT_LABEL, {
          announceUrl: callbackUrl(publicBaseUrl, "announce", session),
          announceMethod: "POST",
        });
        logger.info({ callId: session.callId }, "twilio: warning announced to the user leg");
        return true;
      } catch (error) {
        logger.error({ reason: twilioErrorFields(error), callId: session.callId }, "twilio: could not speak to the user");
        return false;
      }
    },

    async hangUp(session) {
      try {
        if (session.conferenceSid) {
          await rest.updateConference(session.conferenceSid, { status: "completed" });
          return true;
        }
        if (session.twilioCallSid) {
          await rest.updateCall(session.twilioCallSid, { status: "completed" });
          return true;
        }
        return false;
      } catch (error) {
        logger.error({ reason: twilioErrorFields(error), callId: session.callId }, "twilio: could not hang up");
        return false;
      }
    },

    validateSignature(signature, url, params) {
      if (!signature) return false;
      return twilio.validateRequest(config.authToken, signature, url, params);
    },

    async fetchAccountType() {
      if (accountType !== "unknown") return accountType;
      accountFetch ??= rest
        .fetchAccountType()
        .then((type) => {
          accountType = type === "Trial" ? "Trial" : type === "Full" ? "Full" : "unknown";
          if (accountType === "unknown") logger.warn({ type }, "twilio: unexpected account type");
          return accountType;
        })
        .catch((error: unknown) => {
          logger.warn({ reason: twilioErrorFields(error) }, "twilio: could not fetch the account type");
          return "unknown" as const;
        })
        .finally(() => {
          accountFetch = undefined;
        });
      return accountFetch;
    },

    async redirectCall(callSid, twiml) {
      try {
        await rest.updateCall(callSid, { twiml });
        return true;
      } catch (error) {
        logger.error({ reason: twilioErrorFields(error) }, "twilio: could not redirect the call");
        return false;
      }
    },

    async endCall(callSid) {
      try {
        await rest.updateCall(callSid, { status: "completed" });
        return true;
      } catch (error) {
        logger.error({ reason: twilioErrorFields(error) }, "twilio: could not end the call");
        return false;
      }
    },

    announcementText(session) {
      return announcements.get(session.callId)?.text;
    },
  };
  return client;
}

import type { FastifyRequest, preHandlerAsyncHookHandler } from "fastify";

import { constantTimeEqual } from "../../auth.js";
import type { CallSession, CallSessionManager } from "../session.js";
import type { TwilioClient } from "./client.js";

/**
 * Request guards for the Twilio webhooks (docs/CALLS.md §5.2; docs/research/twilio.md §1.4, §3.2).
 *
 * `X-Twilio-Signature` is an HMAC over the *public* URL Twilio was given plus the sorted form fields, so the
 * URL is reconstructed from `PUBLIC_BASE_URL` + the raw request URL (query string included) rather than inferred
 * from proxy headers. The per-session `token` in the query string is a second, independent check: it proves the
 * URL was issued by this relay for that call, and is compared in constant time.
 */

declare module "fastify" {
  interface FastifyRequest {
    /** Set by `sessionTokenGuard` (and the media route's preValidation) once the session token has been verified. */
    twilioSession: CallSession | null;
  }
}

export interface SignatureGuardOptions {
  twilio: Pick<TwilioClient, "validateSignature">;
  publicBaseUrl: string;
}

export interface TokenGuardOptions {
  sessions: CallSessionManager;
}

/** `PUBLIC_BASE_URL` + the raw request URL (path and query as Twilio sent them). */
export function publicUrlFor(publicBaseUrl: string, requestUrl: string): string {
  return `${publicBaseUrl.replace(/\/+$/, "")}${requestUrl}`;
}

/** The `wss://` form of the public URL — what Twilio signs on a Media Streams handshake (community-verified). */
export function websocketUrlFor(publicBaseUrl: string, requestUrl: string): string {
  const url = publicUrlFor(publicBaseUrl, requestUrl);
  if (url.startsWith("https://")) return `wss://${url.slice("https://".length)}`;
  if (url.startsWith("http://")) return `ws://${url.slice("http://".length)}`;
  return url;
}

export function signatureHeader(request: FastifyRequest): string | undefined {
  const value = request.headers["x-twilio-signature"];
  return Array.isArray(value) ? value[0] : value;
}

/** The parsed form body as the flat string map the signature algorithm expects. */
export function formParams(body: unknown): Record<string, string> {
  const params: Record<string, string> = {};
  if (typeof body !== "object" || body === null) return params;
  for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
    if (typeof value === "string") params[key] = value;
    else if (typeof value === "number" || typeof value === "boolean") params[key] = String(value);
    else if (Array.isArray(value)) params[key] = value.map(String).join(",");
  }
  return params;
}

/** The query string as a flat string map (repeated keys keep their first value). */
export function queryParams(query: unknown): Record<string, string> {
  return formParams(query);
}

/** `preHandler` (runs after body parsing): 403 `bad_signature` unless the request is authentically Twilio's. */
export function twilioSignatureGuard(options: SignatureGuardOptions): preHandlerAsyncHookHandler {
  return async (request, reply) => {
    const url = publicUrlFor(options.publicBaseUrl, request.url);
    const valid = options.twilio.validateSignature(signatureHeader(request), url, formParams(request.body));
    if (!valid) {
      // The route pattern, never `request.url`: the query string carries the session token.
      request.log.warn({ route: request.routeOptions.url }, "twilio: bad webhook signature");
      return reply.code(403).send({ error: "bad_signature" });
    }
    return undefined;
  };
}

export type SessionLookup = { session: CallSession } | { status: 403 | 404; error: "bad_token" | "not_found" };

/** Resolves `?callID=…&token=…` to a retained session, or the error the caller should answer with. */
export function lookupSessionFromQuery(sessions: CallSessionManager, query: unknown): SessionLookup {
  const params = queryParams(query);
  const callId = params["callID"];
  const token = params["token"];
  if (!callId) return { status: 404, error: "not_found" };
  const session = sessions.get(callId);
  if (!session) return { status: 404, error: "not_found" };
  if (!token || !constantTimeEqual(token, session.mediaToken)) return { status: 403, error: "bad_token" };
  return { session };
}

/** `preHandler`: 404 for an unknown `callID`, 403 `bad_token` for a wrong token, else `request.twilioSession` is set. */
export function sessionTokenGuard(options: TokenGuardOptions): preHandlerAsyncHookHandler {
  return async (request, reply) => {
    const lookup = lookupSessionFromQuery(options.sessions, request.query);
    if ("error" in lookup) return reply.code(lookup.status).send({ error: lookup.error });
    request.twilioSession = lookup.session;
    return undefined;
  };
}

/** The live session whose Media Streams path token this is (compared in constant time). */
export function findSessionByMediaToken(sessions: CallSessionManager, token: string | undefined): CallSession | undefined {
  if (!token) return undefined;
  for (const session of sessions.active()) {
    if (constantTimeEqual(token, session.mediaToken)) return session;
  }
  return undefined;
}

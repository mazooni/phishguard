import type { FastifyInstance } from "fastify";
import { OAuth2Client } from "google-auth-library";

import { deriveAccountKey } from "../accountKey.js";
import { constantTimeEqual, parseBearer, unauthorized } from "../auth.js";
import type { PushDispatcher } from "../push.js";

/**
 * `POST /v1/gmail/pubsub` — Google Cloud Pub/Sub push endpoint for Gmail `users.watch` notifications.
 *
 * Authentication: Pub/Sub sends `Authorization: Bearer <OIDC JWT>`; the JWT signature, `exp`, `iss` and `aud`
 * are checked by `OAuth2Client.verifyIdToken`, then `email` must equal the push service account and
 * `email_verified` must be true (Google's documented requirement).
 *
 * The message data is `{ "emailAddress": "...", "historyId": "..." }`. The address is hashed into the
 * accountKey immediately and never logged or stored; the device does the actual `history.list`.
 */

export interface IdTokenClaims {
  email?: string | undefined;
  email_verified?: boolean | undefined;
}

export interface TokenVerifier {
  /** Resolves with the claims of a valid token for `audience`; rejects otherwise. */
  verifyIdToken(idToken: string, audience: string): Promise<IdTokenClaims>;
}

export function createGoogleTokenVerifier(): TokenVerifier {
  const client = new OAuth2Client();
  return {
    async verifyIdToken(idToken, audience) {
      const ticket = await client.verifyIdToken({ idToken, audience });
      const payload = ticket.getPayload();
      if (!payload) throw new Error("ID token has no payload");
      return { email: payload.email, email_verified: payload.email_verified };
    },
  };
}

export interface GmailRoutesOptions {
  dispatcher: PushDispatcher;
  verifier: TokenVerifier;
  audience: string;
  serviceAccountEmail: string;
  relaySalt: string;
}

interface GmailNotification {
  emailAddress: string;
  historyId: string;
}

interface Envelope {
  messageId?: string | undefined;
  subscription?: string | undefined;
  notification?: GmailNotification | undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Decodes the Pub/Sub push envelope; `notification` is undefined when the data is not a Gmail watch event. */
export function decodeEnvelope(body: unknown): Envelope {
  if (!isRecord(body) || !isRecord(body["message"])) return {};
  const message = body["message"];
  const envelope: Envelope = {
    messageId: typeof message["messageId"] === "string" ? message["messageId"] : undefined,
    subscription: typeof body["subscription"] === "string" ? body["subscription"] : undefined,
  };
  const data = message["data"];
  if (typeof data !== "string") return envelope;
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(data, "base64").toString("utf8"));
  } catch {
    return envelope;
  }
  if (!isRecord(parsed)) return envelope;
  const emailAddress = parsed["emailAddress"];
  const historyId = parsed["historyId"];
  if (typeof emailAddress !== "string" || emailAddress.trim().length === 0) return envelope;
  if (typeof historyId !== "string" && typeof historyId !== "number") return envelope;
  envelope.notification = { emailAddress, historyId: String(historyId) };
  return envelope;
}

/**
 * google-auth-library error messages can quote parts of the presented token (e.g. "Can't parse token envelope:
 * <fragment>"), so only a coarse category is ever logged.
 */
export function classifyVerifyError(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  if (/audience|recipient/i.test(message)) return "audience_mismatch";
  if (/too late|expired/i.test(message)) return "expired";
  if (/too early/i.test(message)) return "not_yet_valid";
  if (/signature/i.test(message)) return "bad_signature";
  if (/issuer/i.test(message)) return "bad_issuer";
  if (/certificate|cert/i.test(message)) return "certificate_error";
  if (/segments|parse|envelope|malformed|json/i.test(message)) return "malformed";
  return "invalid";
}

const PUBSUB_BODY_LIMIT = 64 * 1024;

export default async function gmailRoutes(app: FastifyInstance, options: GmailRoutesOptions): Promise<void> {
  const { dispatcher, verifier, audience, relaySalt } = options;
  const serviceAccountEmail = options.serviceAccountEmail.toLowerCase();

  app.post("/v1/gmail/pubsub", { bodyLimit: PUBSUB_BODY_LIMIT }, async (request, reply) => {
    const idToken = parseBearer(request.headers.authorization);
    if (idToken === undefined) return unauthorized(reply);

    let claims: IdTokenClaims;
    try {
      claims = await verifier.verifyIdToken(idToken, audience);
    } catch (error) {
      request.log.warn({ reason: classifyVerifyError(error) }, "pubsub: token rejected");
      return unauthorized(reply, "invalid_token");
    }
    if (
      claims.email_verified !== true ||
      typeof claims.email !== "string" ||
      !constantTimeEqual(claims.email.toLowerCase(), serviceAccountEmail)
    ) {
      request.log.warn("pubsub: token is not from the configured push service account");
      return reply.code(403).send({ error: "forbidden" });
    }

    // From here on always ack (204): Pub/Sub would otherwise redeliver, and nothing below is retryable.
    const envelope = decodeEnvelope(request.body);
    if (!envelope.notification) {
      request.log.warn({ messageId: envelope.messageId }, "pubsub: message is not a Gmail watch notification; acknowledged");
      return reply.code(204).send();
    }

    const accountKey = deriveAccountKey(envelope.notification.emailAddress, relaySalt);
    const decision = dispatcher.request({ accountKey, provider: "gmail" });
    request.log.info({ messageId: envelope.messageId, accountKey: accountKey.slice(0, 12), decision }, "pubsub: doorbell");
    return reply.code(204).send();
  });
}

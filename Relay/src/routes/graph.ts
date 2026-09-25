import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { constantTimeEqual, sha256Hex } from "../auth.js";
import type { RelayDb } from "../db.js";
import type { DispatchRequest, PushDispatcher } from "../push.js";

/**
 * Microsoft Graph change-notification webhook.
 *
 *   POST /v1/graph/notifications?validationToken=...  → 200 text/plain with the (already URL-decoded) token
 *   POST /v1/graph/notifications  { value: [ { subscriptionId, clientState, changeType, ... } ] } → 202
 *   POST /v1/graph/lifecycle      { value: [ { subscriptionId, clientState, lifecycleEvent } ] }  → 202
 *
 * Every item is matched to a subscription the app registered (`POST /v1/devices/graph-subscriptions`) and its
 * `clientState` is compared in constant time against the registered hash; mismatches are dropped. Graph wants a
 * 2xx within 3 seconds, so the handler only does SQLite lookups and hands the push to the dispatcher.
 */

export interface GraphRoutesOptions {
  db: RelayDb;
  dispatcher: PushDispatcher;
}

interface GraphQuery {
  validationToken?: string;
}

const GRAPH_BODY_LIMIT = 256 * 1024;
const MAX_ITEMS_PER_POST = 500;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function extractItems(body: unknown): Record<string, unknown>[] | undefined {
  if (!isRecord(body)) return undefined;
  const value = body["value"];
  if (!Array.isArray(value)) return undefined;
  return value.filter(isRecord).slice(0, MAX_ITEMS_PER_POST);
}

export default async function graphRoutes(app: FastifyInstance, options: GraphRoutesOptions): Promise<void> {
  const { db, dispatcher } = options;

  const handler = async (
    request: FastifyRequest<{ Querystring: GraphQuery }>,
    reply: FastifyReply,
  ): Promise<FastifyReply> => {
    const validationToken = request.query.validationToken;
    if (typeof validationToken === "string" && validationToken.length > 0) {
      // Fastify's query parser has already URL-decoded the token; Graph requires the plain text back.
      request.log.info("graph: validation handshake");
      return reply.code(200).type("text/plain; charset=utf-8").send(validationToken);
    }

    const items = extractItems(request.body);
    if (!items) return reply.code(400).send({ error: "bad_request" });

    let accepted = 0;
    let unknown = 0;
    let rejected = 0;
    for (const item of items) {
      const subscriptionId = item["subscriptionId"];
      const clientState = item["clientState"];
      if (typeof subscriptionId !== "string" || subscriptionId.length === 0) {
        rejected += 1;
        continue;
      }
      const subscription = db.findGraphSubscription(subscriptionId);
      if (!subscription) {
        unknown += 1;
        continue;
      }
      if (typeof clientState !== "string" || !constantTimeEqual(sha256Hex(clientState), subscription.clientStateHash)) {
        rejected += 1;
        request.log.warn({ subscriptionId }, "graph: clientState mismatch; notification dropped");
        continue;
      }
      const dispatch: DispatchRequest = { accountKey: subscription.accountKey, provider: "microsoft" };
      const lifecycleEvent = item["lifecycleEvent"];
      if (typeof lifecycleEvent === "string" && lifecycleEvent.length > 0 && lifecycleEvent.length <= 64) {
        dispatch.extra = { lifecycleEvent };
      }
      dispatcher.request(dispatch);
      accepted += 1;
    }
    request.log.info({ items: items.length, accepted, unknown, rejected }, "graph: notifications");
    return reply.code(202).send();
  };

  const routeOptions = { bodyLimit: GRAPH_BODY_LIMIT };
  app.post<{ Querystring: GraphQuery }>("/v1/graph/notifications", routeOptions, handler);
  app.post<{ Querystring: GraphQuery }>("/v1/graph/lifecycle", routeOptions, handler);
}

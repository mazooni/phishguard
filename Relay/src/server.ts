import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest, type FastifyServerOptions } from "fastify";

import type { PushSender } from "./apns.js";
import { registerCalls, type CallsDependencies } from "./calls/index.js";
import type { RelayConfig } from "./config.js";
import type { RelayDb } from "./db.js";
import { PushDispatcher } from "./push.js";
import deviceRoutes from "./routes/devices.js";
import gmailRoutes, { type TokenVerifier } from "./routes/gmail.js";
import graphRoutes from "./routes/graph.js";
import healthRoutes from "./routes/health.js";

export interface BuildAppOptions {
  config: RelayConfig;
  db: RelayDb;
  pushSender: PushSender;
  tokenVerifier: TokenVerifier;
  /** Overrides the pino configuration (tests pass `false`). */
  logger?: FastifyServerOptions["logger"];
  /** Call Guard collaborators (fakes in tests). Only read when `config.calls` is set. */
  calls?: Partial<CallsDependencies>;
}

declare module "fastify" {
  interface FastifyInstance {
    dispatcher: PushDispatcher;
  }
}

const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "x-permitted-cross-domain-policies": "none",
};

/** Header values that must never reach the logs, whichever serializer ends up emitting them. */
const REDACTED_PATHS = [
  "req.headers.authorization",
  'req.headers["x-api-key"]',
  "headers.authorization",
  'headers["x-api-key"]',
  "authorization",
];

/**
 * Secrets also travel in URLs: the operator console takes `?key=<RELAY_API_KEY>` (docs/CALLS.md §5.3) and the
 * Twilio callbacks carry a per-session `?token=` and `/media/<mediaToken>` (§5.2). Fastify logs every request's
 * URL at `info`, so the request serializer masks those values the way `redact` masks the headers above.
 */
const SECRET_QUERY_PARAMS: ReadonlySet<string> = new Set(["key", "token", "apikey", "api_key", "api-key"]);
const MEDIA_TOKEN_PATH = /^(\/v1\/calls\/twilio\/media\/)[^/?#]+/;

export function redactRequestUrl(url: string | undefined): string | undefined {
  if (url === undefined) return undefined;
  const queryAt = url.indexOf("?");
  const path = (queryAt < 0 ? url : url.slice(0, queryAt)).replace(MEDIA_TOKEN_PATH, "$1[redacted]");
  if (queryAt < 0) return path;
  const query = url
    .slice(queryAt + 1)
    .split("&")
    .map((pair) => {
      const eq = pair.indexOf("=");
      const name = eq < 0 ? pair : pair.slice(0, eq);
      return SECRET_QUERY_PARAMS.has(name.toLowerCase()) ? `${name}=[redacted]` : pair;
    })
    .join("&");
  return `${path}?${query}`;
}

/** Fastify's default `req` serializer with the URL redacted. */
const REQUEST_LOG_SERIALIZERS = {
  req(request: FastifyRequest): Record<string, unknown> {
    return {
      method: request.method,
      url: redactRequestUrl(request.url),
      version: request.headers["accept-version"],
      host: request.host,
      remoteAddress: request.ip,
      remotePort: request.socket?.remotePort,
    };
  },
};

type LoggerOptions = NonNullable<FastifyServerOptions["logger"]>;

function loggerOptions(config: RelayConfig, override: LoggerOptions | undefined): LoggerOptions {
  if (override === undefined) {
    return { level: config.logLevel, redact: { paths: REDACTED_PATHS, censor: "[redacted]" }, serializers: REQUEST_LOG_SERIALIZERS };
  }
  if (typeof override === "boolean") return override;
  return { ...override, serializers: { ...REQUEST_LOG_SERIALIZERS, ...(override.serializers ?? {}) } };
}

function describeError(error: unknown): { status: number; code: string | undefined; message: string } {
  const record = typeof error === "object" && error !== null ? (error as Record<string, unknown>) : {};
  const rawStatus = record["statusCode"];
  const status = typeof rawStatus === "number" && rawStatus >= 400 && rawStatus <= 599 ? rawStatus : 500;
  const code = typeof record["code"] === "string" ? record["code"] : undefined;
  const message = error instanceof Error ? error.message : "request failed";
  return { status, code, message };
}

export function buildApp(options: BuildAppOptions): FastifyInstance {
  const { config, db, pushSender, tokenVerifier } = options;

  const app = Fastify({
    logger: loggerOptions(config, options.logger),
    // Webhook bodies are small; the device routes tighten this further per route.
    bodyLimit: 256 * 1024,
    // Fly.io terminates TLS and forwards the client address in X-Forwarded-For.
    trustProxy: true,
    requestTimeout: 30_000,
  });

  app.decorateRequest("device", null);

  const dispatcher = new PushDispatcher({
    db,
    sender: pushSender,
    debounceMs: config.debounceSeconds * 1000,
    logger: app.log,
  });
  app.decorate("dispatcher", dispatcher);

  app.addHook("onSend", async (_request, reply, payload) => {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) reply.header(name, value);
    return payload;
  });

  app.setNotFoundHandler(async (_request, reply) => reply.code(404).send({ error: "not_found" }));

  app.setErrorHandler((error: unknown, request, reply) => {
    const { status, code, message } = describeError(error);
    if (status >= 500) {
      request.log.error({ err: error }, "unhandled error");
      return reply.code(500).send({ error: "internal" });
    }
    // Validation / body-parser / payload-size errors: Fastify's messages name fields, never values.
    request.log.info({ code, status }, "request rejected");
    return reply.code(status).send({ error: code ?? "bad_request", message });
  });

  app.register(healthRoutes);
  app.register(deviceRoutes, { db, apiKey: config.relayApiKey, bundleId: config.bundleId });
  if (config.pubsub) {
    app.register(gmailRoutes, {
      dispatcher,
      verifier: tokenVerifier,
      audience: config.pubsub.audience,
      serviceAccountEmail: config.pubsub.serviceAccountEmail,
      relaySalt: config.relaySalt,
    });
  } else {
    app.post("/v1/gmail/pubsub", async (_request, reply) => reply.code(503).send({ error: "gmail_not_configured" }));
  }
  app.register(graphRoutes, { db, dispatcher });

  let closeCalls: (() => Promise<void>) | undefined;
  if (!config.calls) {
    // docs/CALLS.md §5.1: the app must be able to tell "Call Guard is off on this relay" from "unknown route".
    const off = async (_request: unknown, reply: FastifyReply): Promise<FastifyReply> =>
      reply.code(503).send({ error: "calls_not_configured" });
    for (const url of ["/v1/devices/call-line", "/v1/devices/calls", "/v1/devices/calls/*", "/v1/calls/*"]) {
      app.all(url, off);
    }
  }
  if (config.calls) {
    const calls = registerCalls(app, {
      config,
      calls: config.calls,
      db,
      pushSender,
      ...(options.calls ?? {}),
    });
    closeCalls = calls.close;
  }

  app.addHook("onClose", async () => {
    dispatcher.close();
    await dispatcher.drain();
    if (closeCalls) await closeCalls();
    await pushSender.close();
  });

  return app;
}

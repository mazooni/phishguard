import formbody from "@fastify/formbody";
import websocket from "@fastify/websocket";
import type { FastifyInstance } from "fastify";

/**
 * Registers `@fastify/formbody` (Twilio posts form-encoded webhooks) and `@fastify/websocket` exactly once, at
 * the root instance, before any Call Guard route plugin runs. Both are `fastify-plugin` wrapped, so a second
 * registration anywhere would add a second `upgrade` listener and a duplicate `websocketServer` decorator.
 * `hasPlugin` only reports a plugin after it has *loaded*, and every Call Guard module registers its routes
 * synchronously before `ready()`, so a guard on `hasPlugin` alone would still queue a second registration;
 * the synchronous decorator markers close that gap. Routes that need the plugins must be registered inside a
 * scoped plugin, which runs after these have loaded.
 */
export const FORMBODY_MARK = "callsFormbodyRegistered";
export const WEBSOCKET_MARK = "callsWebsocketRegistered";

/** Twilio media frames and live-feed pings are tiny; a larger frame is either a bug or an attack. */
export const MAX_PAYLOAD_BYTES = 64 * 1024;

export function ensureWebPlugins(app: FastifyInstance): void {
  if (!app.hasPlugin("@fastify/formbody") && !app.hasDecorator(FORMBODY_MARK)) {
    app.decorate(FORMBODY_MARK, true);
    void app.register(formbody);
  }
  if (!app.hasPlugin("@fastify/websocket") && !app.hasDecorator("websocketServer") && !app.hasDecorator(WEBSOCKET_MARK)) {
    app.decorate(WEBSOCKET_MARK, true);
    void app.register(websocket, { options: { maxPayload: MAX_PAYLOAD_BYTES } });
  }
}

/** Kept for the modules that only need the WebSocket half; same idempotent registration. */
export const ensureWebSocketPlugin = ensureWebPlugins;

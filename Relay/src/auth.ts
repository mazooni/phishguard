import { createHash, timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest, preHandlerAsyncHookHandler } from "fastify";

import type { DeviceRow, RelayDb } from "./db.js";

/** sha256 of `input`, lowercase hex. */
export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/**
 * Constant-time string comparison. Both sides are hashed first so the comparison never short-circuits on
 * length and never touches the raw secret bytes with a variable-time operation.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const left = createHash("sha256").update(a, "utf8").digest();
  const right = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(left, right) && a.length === b.length;
}

export function parseBearer(header: string | string[] | undefined): string | undefined {
  if (typeof header !== "string") return undefined;
  const match = /^Bearer\s+(\S+)\s*$/i.exec(header);
  return match?.[1];
}

/** Device secrets are random strings generated on the device (the app uses 64 hex characters). */
export function isPlausibleDeviceSecret(secret: string): boolean {
  return secret.length >= 32 && secret.length <= 512 && /^[\x21-\x7e]+$/.test(secret);
}

function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

export function unauthorized(reply: FastifyReply, error = "unauthorized"): FastifyReply {
  return reply.code(401).header("www-authenticate", 'Bearer realm="phishguard-relay"').send({ error });
}

/** `X-API-Key` check shared by every device route (the two webhook routes are exempt). */
export function apiKeyGuard(expectedApiKey: string): preHandlerAsyncHookHandler {
  return async (request, reply) => {
    const presented = headerValue(request.headers["x-api-key"]);
    if (presented === undefined || !constantTimeEqual(presented, expectedApiKey)) {
      return unauthorized(reply, "invalid_api_key");
    }
    return undefined;
  };
}

declare module "fastify" {
  interface FastifyRequest {
    /** Set by `deviceAuthGuard` once the bearer secret has been verified. */
    device: DeviceRow | null;
  }
}

/**
 * Resolves the calling device from `Authorization: Bearer <deviceSecret>`: the sha256 of the presented secret
 * locates the row, and the stored hash is then compared in constant time. Does not create devices — that is
 * `POST /v1/devices`' job.
 */
export function deviceAuthGuard(db: RelayDb): preHandlerAsyncHookHandler {
  return async (request, reply) => {
    const device = authenticateDevice(request, db);
    if (!device) return unauthorized(reply);
    request.device = device;
    db.touchDevice(device.deviceId, Date.now());
    return undefined;
  };
}

export function authenticateDevice(request: FastifyRequest, db: RelayDb): DeviceRow | undefined {
  const secret = parseBearer(request.headers.authorization);
  if (secret === undefined || !isPlausibleDeviceSecret(secret)) return undefined;
  const secretHash = sha256Hex(secret);
  const device = db.findDeviceBySecretHash(secretHash);
  if (!device || !constantTimeEqual(device.secretHash, secretHash)) return undefined;
  return device;
}

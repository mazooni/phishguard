import type { FastifyInstance } from "fastify";

import { ACCOUNT_KEY_PATTERN } from "../accountKey.js";
import {
  apiKeyGuard,
  constantTimeEqual,
  deviceAuthGuard,
  isPlausibleDeviceSecret,
  parseBearer,
  sha256Hex,
  unauthorized,
} from "../auth.js";
import type { ApnsEnvironment } from "../config.js";
import { PROVIDERS, type Provider, type RelayDb } from "../db.js";

/**
 * Device routes (all require `X-API-Key` and `Authorization: Bearer <deviceSecret>`).
 *
 *   POST   /v1/devices                      {deviceID, apnsToken?, environment, bundleID}  — upsert; creates on first use;
 *                                           `bundleID` must equal the configured APNS_BUNDLE_ID (else 400 bundle_id_mismatch).
 *                                           `apnsToken` is optional: a build without the push entitlement (free Apple
 *                                           team, Simulator) still registers so Call Guard's device routes work; an
 *                                           update without a token keeps the one already stored.
 *   POST   /v1/devices/accounts             {accountKey, provider}
 *   DELETE /v1/devices/accounts/:accountKey
 *   POST   /v1/devices/graph-subscriptions  {subscriptionID, accountKey, clientState}
 *   DELETE /v1/devices
 */

export interface DeviceRoutesOptions {
  db: RelayDb;
  apiKey: string;
  /** The configured `APNS_BUNDLE_ID`; the only `bundleID` a device may register with. */
  bundleId: string;
}

interface RegisterBody {
  deviceID: string;
  apnsToken?: string;
  environment: ApnsEnvironment;
  bundleID: string;
}

interface AccountBody {
  accountKey: string;
  provider: Provider;
}

interface GraphSubscriptionBody {
  subscriptionID: string;
  accountKey: string;
  clientState: string;
}

interface AccountParams {
  accountKey: string;
}

const DEVICE_BODY_LIMIT = 16 * 1024;

const registerSchema = {
  type: "object",
  required: ["deviceID", "environment", "bundleID"],
  properties: {
    deviceID: { type: "string", minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9._:-]+$" },
    // APNs tokens are variable length hex; never hard-code their size.
    apnsToken: { type: "string", minLength: 16, maxLength: 512, pattern: "^[0-9a-fA-F]+$" },
    environment: { type: "string", enum: ["sandbox", "production"] },
    bundleID: { type: "string", minLength: 1, maxLength: 256, pattern: "^[A-Za-z0-9.-]+$" },
  },
} as const;

const accountSchema = {
  type: "object",
  required: ["accountKey", "provider"],
  properties: {
    accountKey: { type: "string", pattern: ACCOUNT_KEY_PATTERN },
    provider: { type: "string", enum: [...PROVIDERS] },
  },
} as const;

const graphSubscriptionSchema = {
  type: "object",
  required: ["subscriptionID", "accountKey", "clientState"],
  properties: {
    subscriptionID: { type: "string", minLength: 1, maxLength: 256 },
    accountKey: { type: "string", pattern: ACCOUNT_KEY_PATTERN },
    // Graph caps clientState at 128 characters.
    clientState: { type: "string", minLength: 16, maxLength: 128 },
  },
} as const;

const accountParamsSchema = {
  type: "object",
  required: ["accountKey"],
  properties: { accountKey: { type: "string", pattern: ACCOUNT_KEY_PATTERN } },
} as const;

export default async function deviceRoutes(app: FastifyInstance, options: DeviceRoutesOptions): Promise<void> {
  const { db } = options;
  app.addHook("onRequest", apiKeyGuard(options.apiKey));

  app.post<{ Body: RegisterBody }>(
    "/v1/devices",
    { schema: { body: registerSchema }, bodyLimit: DEVICE_BODY_LIMIT },
    async (request, reply) => {
      const secret = parseBearer(request.headers.authorization);
      if (secret === undefined || !isPlausibleDeviceSecret(secret)) return unauthorized(reply);
      const secretHash = sha256Hex(secret);
      const now = Date.now();
      const { deviceID, environment, bundleID } = request.body;
      const apnsToken = request.body.apnsToken?.toLowerCase() ?? null;
      if (bundleID !== options.bundleId) {
        // Bundle ids are not secrets; naming the offending one is what an operator needs to fix the config.
        request.log.warn({ deviceId: deviceID, bundleId: bundleID }, "device rejected: bundleID is not APNS_BUNDLE_ID");
        return reply.code(400).send({ error: "bundle_id_mismatch" });
      }

      const existing = db.findDevice(deviceID);
      if (existing) {
        if (!constantTimeEqual(existing.secretHash, secretHash)) return unauthorized(reply);
        db.updateDevice({ deviceId: deviceID, apnsToken, environment, bundleId: bundleID }, now);
        request.log.info({ deviceId: deviceID, environment, hasToken: apnsToken !== null }, "device updated");
        return reply.code(200).send({ deviceID, created: false });
      }

      if (db.findDeviceBySecretHash(secretHash)) {
        // The same secret cannot identify two devices; the app would have to generate a new one.
        return reply.code(409).send({ error: "secret_in_use" });
      }
      db.createDevice({ deviceId: deviceID, secretHash, apnsToken, environment, bundleId: bundleID }, now);
      request.log.info({ deviceId: deviceID, environment, hasToken: apnsToken !== null }, "device created");
      return reply.code(201).send({ deviceID, created: true });
    },
  );

  // Everything below needs an already-registered device.
  await app.register(async (scoped) => {
    scoped.addHook("onRequest", deviceAuthGuard(db));

    scoped.post<{ Body: AccountBody }>(
      "/v1/devices/accounts",
      { schema: { body: accountSchema }, bodyLimit: DEVICE_BODY_LIMIT },
      async (request, reply) => {
        const device = request.device!;
        db.addDeviceAccount(device.deviceId, request.body.accountKey, request.body.provider, Date.now());
        request.log.info({ deviceId: device.deviceId, provider: request.body.provider }, "account registered");
        return reply.code(204).send();
      },
    );

    scoped.delete<{ Params: AccountParams }>(
      "/v1/devices/accounts/:accountKey",
      { schema: { params: accountParamsSchema } },
      async (request, reply) => {
        const device = request.device!;
        const removed = db.removeDeviceAccount(device.deviceId, request.params.accountKey);
        request.log.info({ deviceId: device.deviceId, removed }, "account unregistered");
        return reply.code(204).send();
      },
    );

    scoped.post<{ Body: GraphSubscriptionBody }>(
      "/v1/devices/graph-subscriptions",
      { schema: { body: graphSubscriptionSchema }, bodyLimit: DEVICE_BODY_LIMIT },
      async (request, reply) => {
        const device = request.device!;
        db.upsertGraphSubscription(
          {
            subscriptionId: request.body.subscriptionID,
            accountKey: request.body.accountKey,
            clientStateHash: sha256Hex(request.body.clientState),
            deviceId: device.deviceId,
          },
          Date.now(),
        );
        request.log.info({ deviceId: device.deviceId, subscriptionId: request.body.subscriptionID }, "graph subscription registered");
        return reply.code(204).send();
      },
    );

    scoped.delete("/v1/devices", async (request, reply) => {
      const device = request.device!;
      db.deleteDevice(device.deviceId);
      request.log.info({ deviceId: device.deviceId }, "device deleted");
      return reply.code(204).send();
    });
  });
}

import { join } from "node:path";

import { createApnsSender, createNoopPushSender } from "./apns.js";
import { ConfigError, loadConfig } from "./config.js";
import { RelayDb } from "./db.js";
import { createGoogleTokenVerifier } from "./routes/gmail.js";
import { buildApp } from "./server.js";

let config;
try {
  config = loadConfig();
} catch (error) {
  // ConfigError messages name variables, never values.
  process.stderr.write(`phishguard-relay: ${error instanceof ConfigError ? error.message : String(error)}\n`);
  process.exit(1);
}

const db = RelayDb.open(join(config.dataDir, "relay.sqlite"));
const pushSender = config.apns ? createApnsSender({ config: config.apns }) : createNoopPushSender();
const app = buildApp({ config, db, pushSender, tokenVerifier: createGoogleTokenVerifier() });
if (!config.apns) app.log.warn("APNs is not configured (no APNS_KEY_P8_BASE64 / APNS_KEY_PATH): pushes will be skipped");
if (!config.pubsub) app.log.warn("Pub/Sub is not configured (no PUBSUB_SERVICE_ACCOUNT_EMAIL): POST /v1/gmail/pubsub answers 503");

let shuttingDown = false;
async function shutdown(signal: NodeJS.Signals): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  app.log.info({ signal }, "shutting down");
  try {
    await app.close();
    db.close();
    process.exit(0);
  } catch (error) {
    app.log.error({ err: error }, "shutdown failed");
    process.exit(1);
  }
}
process.on("SIGTERM", (signal) => void shutdown(signal));
process.on("SIGINT", (signal) => void shutdown(signal));

try {
  await app.listen({ port: config.port, host: config.host });
  app.log.info(
    {
      publicBaseUrl: config.publicBaseUrl,
      pubsubAudience: config.pubsub?.audience ?? null,
      apnsConfigured: config.apns !== undefined,
      bundleId: config.bundleId,
      callsEnabled: config.calls !== undefined,
      debounceSeconds: config.debounceSeconds,
    },
    "phishguard-relay ready",
  );
} catch (error) {
  app.log.error({ err: error }, "failed to start");
  db.close();
  process.exit(1);
}

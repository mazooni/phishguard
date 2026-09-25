import { readFileSync } from "node:fs";

import { CallsConfigError, isCallsEnabled, loadCallsConfig, type CallsConfig } from "./calls/config.js";

/**
 * Relay configuration. Every value comes from the environment (Fly secrets in production, `.env` locally).
 * Error messages name the offending variable but never echo its value.
 */

export type ApnsEnvironment = "sandbox" | "production";

export interface ApnsConfig {
  keyId: string;
  teamId: string;
  /** PEM contents of the `.p8` key (never logged, never written to disk by the relay). */
  signingKey: Buffer;
  /** The `apns-topic` of every push (the app's bundle identifier); `POST /v1/devices` rejects any other `bundleID`. */
  bundleId: string;
}

export interface PubSubConfig {
  /** Must equal the `--push-auth-token-audience` of the Pub/Sub push subscription. */
  audience: string;
  /** Must equal the `--push-auth-service-account` of the Pub/Sub push subscription. */
  serviceAccountEmail: string;
}

export interface RelayConfig {
  port: number;
  host: string;
  publicBaseUrl: string;
  relayApiKey: string;
  relaySalt: string;
  dataDir: string;
  /** Undefined when no APNs key is configured: devices still register, pushes are logged and skipped. */
  apns: ApnsConfig | undefined;
  /** Undefined when Pub/Sub is not configured: `POST /v1/gmail/pubsub` answers 503. */
  pubsub: PubSubConfig | undefined;
  /** The `apns-topic` (the app's bundle id); required even without an APNs key because device registration checks it. */
  bundleId: string;
  /** Call Guard (docs/CALLS.md); undefined unless `CALLS_ENABLED=true`. */
  calls: CallsConfig | undefined;
  debounceSeconds: number;
  logLevel: LogLevel;
}

export const LOG_LEVELS = ["fatal", "error", "warn", "info", "debug", "trace", "silent"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

export class ConfigError extends Error {
  override readonly name = "ConfigError";
}

const MIN_SECRET_LENGTH = 16;

function read(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const raw = env[name];
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}

function requireVar(env: NodeJS.ProcessEnv, name: string): string {
  const value = read(env, name);
  if (value === undefined) throw new ConfigError(`Missing required environment variable ${name}`);
  return value;
}

function requireSecret(env: NodeJS.ProcessEnv, name: string): string {
  const value = requireVar(env, name);
  if (value.length < MIN_SECRET_LENGTH) {
    throw new ConfigError(`${name} must be at least ${MIN_SECRET_LENGTH} characters`);
  }
  return value;
}

function readInteger(env: NodeJS.ProcessEnv, name: string, fallback: number, min: number, max: number): number {
  const raw = read(env, name);
  if (raw === undefined) return fallback;
  if (!/^\d+$/.test(raw)) throw new ConfigError(`${name} must be an integer`);
  const value = Number.parseInt(raw, 10);
  if (value < min || value > max) throw new ConfigError(`${name} must be between ${min} and ${max}`);
  return value;
}

function readBaseUrl(env: NodeJS.ProcessEnv, name: string): string {
  const raw = requireVar(env, name);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError(`${name} must be an absolute URL`);
  }
  const isLocal = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocal)) {
    throw new ConfigError(`${name} must use https (http is only allowed for localhost)`);
  }
  if (url.search || url.hash) throw new ConfigError(`${name} must not contain a query string or fragment`);
  return raw.replace(/\/+$/, "");
}

/** Undefined when neither `APNS_KEY_P8_BASE64` nor `APNS_KEY_PATH` is set (APNs is optional). */
function readSigningKey(env: NodeJS.ProcessEnv): Buffer | undefined {
  const base64 = read(env, "APNS_KEY_P8_BASE64");
  const path = read(env, "APNS_KEY_PATH");
  if (base64 && path) throw new ConfigError("Set only one of APNS_KEY_P8_BASE64 or APNS_KEY_PATH");
  let key: Buffer;
  if (base64) {
    key = Buffer.from(base64, "base64");
  } else if (path) {
    try {
      key = readFileSync(path);
    } catch {
      throw new ConfigError("APNS_KEY_PATH could not be read");
    }
  } else {
    return undefined;
  }
  if (!key.toString("utf8").includes("PRIVATE KEY")) {
    throw new ConfigError("APNs signing key does not look like a PEM .p8 private key");
  }
  return key;
}

/**
 * APNs is configured when a signing key is present; `APNS_KEY_ID` and `APNS_TEAM_ID` are then required.
 * Without a key the relay runs, registers devices and skips pushes (Call Guard's console and spoken warning
 * still work), which is what a developer without a paid Apple team needs.
 */
function readApns(env: NodeJS.ProcessEnv, bundleId: string): ApnsConfig | undefined {
  const signingKey = readSigningKey(env);
  const keyId = read(env, "APNS_KEY_ID");
  const teamId = read(env, "APNS_TEAM_ID");
  if (!signingKey) {
    if (keyId || teamId) throw new ConfigError("APNS_KEY_ID / APNS_TEAM_ID are set but no APNS_KEY_P8_BASE64 or APNS_KEY_PATH");
    return undefined;
  }
  if (!keyId) throw new ConfigError("Missing required environment variable APNS_KEY_ID");
  if (!teamId) throw new ConfigError("Missing required environment variable APNS_TEAM_ID");
  return { keyId, teamId, signingKey, bundleId };
}

/** Pub/Sub is configured when `PUBSUB_SERVICE_ACCOUNT_EMAIL` is set. */
function readPubSub(env: NodeJS.ProcessEnv, publicBaseUrl: string): PubSubConfig | undefined {
  const raw = read(env, "PUBSUB_SERVICE_ACCOUNT_EMAIL");
  if (raw === undefined) {
    if (read(env, "PUBSUB_AUDIENCE")) throw new ConfigError("PUBSUB_AUDIENCE is set but PUBSUB_SERVICE_ACCOUNT_EMAIL is not");
    return undefined;
  }
  const serviceAccountEmail = raw.toLowerCase();
  if (!serviceAccountEmail.includes("@")) throw new ConfigError("PUBSUB_SERVICE_ACCOUNT_EMAIL must be an email address");
  return {
    audience: read(env, "PUBSUB_AUDIENCE") ?? `${publicBaseUrl}/v1/gmail/pubsub`,
    serviceAccountEmail,
  };
}

function readCalls(env: NodeJS.ProcessEnv): CallsConfig | undefined {
  try {
    if (!isCallsEnabled(env)) return undefined;
    return loadCallsConfig(env);
  } catch (error) {
    if (error instanceof CallsConfigError) throw new ConfigError(error.message);
    throw error;
  }
}

function readLogLevel(env: NodeJS.ProcessEnv): LogLevel {
  const raw = read(env, "LOG_LEVEL") ?? "info";
  if (!(LOG_LEVELS as readonly string[]).includes(raw)) {
    throw new ConfigError(`LOG_LEVEL must be one of ${LOG_LEVELS.join(", ")}`);
  }
  return raw as LogLevel;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): RelayConfig {
  const publicBaseUrl = readBaseUrl(env, "PUBLIC_BASE_URL");
  const bundleId = requireVar(env, "APNS_BUNDLE_ID");
  if (!/^[A-Za-z0-9.-]+$/.test(bundleId)) throw new ConfigError("APNS_BUNDLE_ID is not a valid bundle identifier");

  return {
    port: readInteger(env, "PORT", 8080, 1, 65535),
    host: read(env, "HOST") ?? "0.0.0.0",
    publicBaseUrl,
    relayApiKey: requireSecret(env, "RELAY_API_KEY"),
    relaySalt: requireSecret(env, "RELAY_SALT"),
    dataDir: read(env, "DATA_DIR") ?? "./data",
    apns: readApns(env, bundleId),
    pubsub: readPubSub(env, publicBaseUrl),
    bundleId,
    calls: readCalls(env),
    debounceSeconds: readInteger(env, "DEBOUNCE_SECONDS", 10, 0, 3600),
    logLevel: readLogLevel(env),
  };
}

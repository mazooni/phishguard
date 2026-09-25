import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";

/**
 * The operator's first steps (Relay/README.md "Run locally", docs/CALLS.md §11): `cp .env.example .env`, fill the two
 * secrets, and — for Call Guard — set CALLS_ENABLED=true. Both must boot as they are, and every npm script that
 * reads configuration must load `.env` (the production entry point in the Dockerfile runs `node dist/index.js`
 * directly and gets its variables from `fly secrets`, so the flag must be the `-if-exists` one).
 */

const relayDir = join(dirname(fileURLToPath(import.meta.url)), "..");

/** `KEY=VALUE` lines the way `node --env-file` reads them (comments and blank lines skipped; no inline comments). */
function parseEnvFile(path: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const raw of readFileSync(path, "utf8").split("\n")) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    expect(eq, `not a KEY=VALUE line: ${line}`).toBeGreaterThan(0);
    env[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  return env;
}

const SECRETS = { RELAY_API_KEY: "9f1c2b7e4d5a6c8b0e1f2a3b4c5d6e7f", RELAY_SALT: "0a1b2c3d4e5f60718293a4b5c6d7e8f9" };

describe(".env.example", () => {
  it("boots as copied once the two secrets are filled (Call Guard off, nothing else configured)", () => {
    const config = loadConfig({ ...parseEnvFile(join(relayDir, ".env.example")), ...SECRETS });
    expect(config.calls).toBeUndefined();
    expect(config.apns).toBeUndefined();
    expect(config.pubsub).toBeUndefined();
    expect(config.publicBaseUrl).toBe("http://localhost:8080");
    expect(config.bundleId).toBe("com.mazooni.PhishGuard");
  });

  it("boots as a demo-only Call Guard relay with just CALLS_ENABLED=true added (no Twilio, OpenAI or APNs)", () => {
    const config = loadConfig({ ...parseEnvFile(join(relayDir, ".env.example")), ...SECRETS, CALLS_ENABLED: "true" });
    expect(config.calls).toBeDefined();
    expect(config.calls?.twilio).toBeUndefined();
    expect(config.calls?.openai).toBeUndefined();
    expect(config.calls?.demoEnabled).toBe(true);
    expect(config.calls?.consoleEnabled).toBe(true);
    expect(config.apns).toBeUndefined();
    expect(config.pubsub).toBeUndefined();
  });

  it("names every Call Guard variable of docs/CALLS.md §9", () => {
    const text = readFileSync(join(relayDir, ".env.example"), "utf8");
    for (const name of [
      "CALLS_ENABLED",
      "TWILIO_ACCOUNT_SID",
      "TWILIO_AUTH_TOKEN",
      "TWILIO_NUMBER",
      "OPENAI_API_KEY",
      "OPENAI_TRANSCRIBE_MODEL",
      "OPENAI_SCORING_MODEL",
      "CALLS_TRANSCRIPTION_SOURCE",
      "CALLS_TRANSCRIBE_TRACKS",
      "CALLS_MODEL_MIN_INTERVAL_MS",
      "CALLS_MODEL_TRANSCRIPT_CHARS",
      "CALLS_SPOKEN_WARNING_TEXT",
      "CALLS_RETAIN_ENDED_MINUTES",
      "CALLS_RETENTION_DAYS",
      "CALLS_DEMO_ENABLED",
      "CALLS_CONSOLE_ENABLED",
    ]) {
      expect(text, name).toMatch(new RegExp(`^#? ?${name}=`, "m"));
    }
  });
});

describe("package.json scripts", () => {
  it("load .env for every entry point that reads configuration", () => {
    const { scripts } = JSON.parse(readFileSync(join(relayDir, "package.json"), "utf8")) as { scripts: Record<string, string> };
    for (const name of ["dev", "start", "calls:setup", "calls:replay"]) {
      expect(scripts[name], name).toContain("--env-file-if-exists=.env");
    }
    expect(scripts["build"]).toBe("tsc -p tsconfig.build.json");
  });
});

import { describe, expect, it } from "vitest";

import { TRIAL_CAVEATS, describeSetupFailure, runTwilioSetup, type SetupClient, type SetupNumber } from "../../scripts/twilio-setup.js";
import { API_KEY, BUNDLE_ID, RELAY_SALT } from "../helpers.js";
import { GUARD_NUMBER, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN } from "./fakes.js";

function env(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    PUBLIC_BASE_URL: "https://abc.ngrok.app",
    RELAY_API_KEY: API_KEY,
    RELAY_SALT,
    APNS_BUNDLE_ID: BUNDLE_ID,
    CALLS_ENABLED: "true",
    TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN,
    TWILIO_NUMBER: GUARD_NUMBER,
    OPENAI_API_KEY: "sk-test",
    ...overrides,
  };
}

class FakeSetupClient implements SetupClient {
  readonly updates: unknown[] = [];
  readonly listed: string[] = [];
  numbers: string[] = [GUARD_NUMBER];
  type = "Full";
  async listNumbers(phoneNumber: string): Promise<SetupNumber[]> {
    this.listed.push(phoneNumber);
    return this.numbers
      .filter((number) => number === phoneNumber)
      .map((number) => ({
        sid: "PN" + "1".repeat(32),
        phoneNumber: number,
        update: async (params: unknown) => {
          this.updates.push(params);
          return {};
        },
      }));
  }
  async fetchAccount() {
    return { type: this.type, friendlyName: "PhishGuard", status: "active" };
  }
}

describe("scripts/twilio-setup", () => {
  it("points the guard number's voice webhook and status callback at PUBLIC_BASE_URL and reports a Full account", async () => {
    const client = new FakeSetupClient();
    const lines: string[] = [];
    const code = await runTwilioSetup({ env: env(), client, out: (line) => lines.push(line) });
    expect(code).toBe(0);
    expect(client.listed).toEqual([GUARD_NUMBER]);
    expect(client.updates).toEqual([
      {
        voiceUrl: "https://abc.ngrok.app/v1/calls/twilio/voice",
        voiceMethod: "POST",
        statusCallback: "https://abc.ngrok.app/v1/calls/twilio/status?leg=caller",
        statusCallbackMethod: "POST",
      },
    ]);
    const output = lines.join("\n");
    expect(output).toContain("type Full");
    expect(output).toContain("Transcription source: auto → openai");
    expect(output).not.toContain("Trial account caveats");
    expect(output).not.toContain(TWILIO_AUTH_TOKEN);
  });

  it("prints the trial caveats and the twilio transcription fallback on a Trial account", async () => {
    const client = new FakeSetupClient();
    client.type = "Trial";
    const lines: string[] = [];
    const code = await runTwilioSetup({ env: env({ PUBLIC_BASE_URL: "http://localhost:8080" }), client, out: (line) => lines.push(line) });
    expect(code).toBe(0);
    const output = lines.join("\n");
    expect(output).toContain("type Trial");
    expect(output).toContain("Transcription source: auto → twilio");
    expect(output).toContain("Trial account caveats");
    for (const caveat of TRIAL_CAVEATS) expect(output).toContain(caveat);
    expect(output).toContain("Warning: PUBLIC_BASE_URL is http://localhost:8080");
  });

  it("fails clearly when Call Guard is not configured, the config is invalid, or the number is not on the account", async () => {
    const off: string[] = [];
    expect(await runTwilioSetup({ env: env({ CALLS_ENABLED: "false" }), client: new FakeSetupClient(), out: (l) => off.push(l) })).toBe(1);
    expect(off.join("\n")).toContain("CALLS_ENABLED=true");

    const invalid: string[] = [];
    expect(await runTwilioSetup({ env: env({ TWILIO_NUMBER: "555-0100" }), client: new FakeSetupClient(), out: (l) => invalid.push(l) })).toBe(1);
    expect(invalid.join("\n")).toContain("Configuration error: TWILIO_NUMBER must be an E.164 number");

    const missing = new FakeSetupClient();
    missing.numbers = ["+15550109999"];
    const notFound: string[] = [];
    expect(await runTwilioSetup({ env: env(), client: missing, out: (l) => notFound.push(l) })).toBe(1);
    expect(notFound.join("\n")).toContain(`No incoming phone number ${GUARD_NUMBER}`);
    expect(missing.updates).toHaveLength(0);
  });

  it("explains rejected credentials and an unreachable API, and never prints the auth token", async () => {
    // What the SDK throws for fake credentials (observed 2026-09-23: "auth account AC… does not exist", 401 / 20003).
    const rejected = new FakeSetupClient();
    rejected.listNumbers = async () => {
      throw Object.assign(new Error(`auth account ${TWILIO_ACCOUNT_SID} does not exist`), { code: 20003, status: 401 });
    };
    const lines: string[] = [];
    expect(await runTwilioSetup({ env: env(), client: rejected, out: (l) => lines.push(l) })).toBe(1);
    const output = lines.join("\n");
    expect(output).toContain("Twilio refused the request (HTTP 401, error 20003): auth account");
    expect(output).toContain("Check TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN in Relay/.env");
    expect(output).not.toContain(TWILIO_AUTH_TOKEN);

    const offline = new FakeSetupClient();
    offline.listNumbers = async () => {
      throw Object.assign(new Error("getaddrinfo ENOTFOUND api.twilio.com"), { code: "ENOTFOUND" });
    };
    const off: string[] = [];
    expect(await runTwilioSetup({ env: env(), client: offline, out: (l) => off.push(l) })).toBe(1);
    expect(off.join("\n")).toContain("could not be reached");

    expect(describeSetupFailure(Object.assign(new Error("Resource not found"), { code: 20404, status: 404 }))).toContain("Check TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_NUMBER");
  });
});

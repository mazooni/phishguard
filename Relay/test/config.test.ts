import { describe, expect, it } from "vitest";

import {
  DEFAULT_AI_VOICE_MAX_SECONDS,
  DEFAULT_AI_VOICE_MIN_CONFIDENCE_PERCENT,
  DEFAULT_AI_VOICE_MIN_SHARE_PERCENT,
  DEFAULT_AI_VOICE_WARNING,
  DEFAULT_AI_VOICE_WINDOW_MS,
  loadCallsConfig,
} from "../src/calls/config.js";
import { ConfigError, loadConfig } from "../src/config.js";
import { FAKE_P8 } from "./helpers.js";

const SECRET_VALUE = "sup3r-secret-value-that-must-not-leak";

function baseEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    PUBLIC_BASE_URL: "https://relay.example.net/",
    RELAY_API_KEY: SECRET_VALUE,
    RELAY_SALT: "another-long-random-salt-value",
    APNS_KEY_ID: "ABC123DEFG",
    APNS_TEAM_ID: "TEAM123456",
    APNS_KEY_P8_BASE64: Buffer.from(FAKE_P8).toString("base64"),
    APNS_BUNDLE_ID: "com.mazooni.PhishGuard",
    PUBSUB_SERVICE_ACCOUNT_EMAIL: "Push@Example-Project.iam.gserviceaccount.com",
    ...overrides,
  };
}

describe("loadConfig", () => {
  it("loads a complete environment with defaults applied", () => {
    const config = loadConfig(baseEnv());
    expect(config.port).toBe(8080);
    expect(config.host).toBe("0.0.0.0");
    expect(config.publicBaseUrl).toBe("https://relay.example.net");
    expect(config.pubsub?.audience).toBe("https://relay.example.net/v1/gmail/pubsub");
    expect(config.pubsub?.serviceAccountEmail).toBe("push@example-project.iam.gserviceaccount.com");
    expect(config.bundleId).toBe("com.mazooni.PhishGuard");
    expect(config.calls).toBeUndefined();
    expect(config.debounceSeconds).toBe(10);
    expect(config.logLevel).toBe("info");
    expect(config.dataDir).toBe("./data");
    expect(config.apns?.signingKey.toString("utf8")).toBe(FAKE_P8);
  });

  it("honours explicit PUBSUB_AUDIENCE, PORT, DEBOUNCE_SECONDS, DATA_DIR and LOG_LEVEL", () => {
    const config = loadConfig(
      baseEnv({
        PUBSUB_AUDIENCE: "custom-audience",
        PORT: "9090",
        DEBOUNCE_SECONDS: "0",
        DATA_DIR: "/data",
        LOG_LEVEL: "debug",
      }),
    );
    expect(config.pubsub?.audience).toBe("custom-audience");
    expect(config.port).toBe(9090);
    expect(config.debounceSeconds).toBe(0);
    expect(config.dataDir).toBe("/data");
    expect(config.logLevel).toBe("debug");
  });

  it("names the missing variable without echoing any value", () => {
    const env = baseEnv({ RELAY_SALT: undefined });
    expect(() => loadConfig(env)).toThrow(ConfigError);
    try {
      loadConfig(env);
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain("RELAY_SALT");
      expect(message).not.toContain(SECRET_VALUE);
    }
  });

  it("rejects short secrets", () => {
    expect(() => loadConfig(baseEnv({ RELAY_API_KEY: "short" }))).toThrow(/RELAY_API_KEY/);
  });

  it("accepts at most one APNs key source and validates it", () => {
    expect(() => loadConfig(baseEnv({ APNS_KEY_PATH: "/nonexistent/AuthKey.p8" }))).toThrow(/only one of/);
    expect(() => loadConfig(baseEnv({ APNS_KEY_P8_BASE64: Buffer.from("not a key").toString("base64") }))).toThrow(
      /PEM/,
    );
  });

  it("runs without APNs when no key is given, but rejects a dangling key id", () => {
    const withoutKey = loadConfig(baseEnv({ APNS_KEY_P8_BASE64: undefined, APNS_KEY_ID: undefined, APNS_TEAM_ID: undefined }));
    expect(withoutKey.apns).toBeUndefined();
    expect(withoutKey.bundleId).toBe("com.mazooni.PhishGuard");
    expect(() => loadConfig(baseEnv({ APNS_KEY_P8_BASE64: undefined }))).toThrow(/APNS_KEY_ID \/ APNS_TEAM_ID/);
    expect(() => loadConfig(baseEnv({ APNS_KEY_ID: undefined }))).toThrow(/APNS_KEY_ID/);
    expect(() => loadConfig(baseEnv({ APNS_BUNDLE_ID: undefined }))).toThrow(/APNS_BUNDLE_ID/);
  });

  it("runs without Pub/Sub when no service account is given, but rejects a dangling audience", () => {
    const withoutPubSub = loadConfig(baseEnv({ PUBSUB_SERVICE_ACCOUNT_EMAIL: undefined }));
    expect(withoutPubSub.pubsub).toBeUndefined();
    expect(() => loadConfig(baseEnv({ PUBSUB_SERVICE_ACCOUNT_EMAIL: undefined, PUBSUB_AUDIENCE: "x" }))).toThrow(/PUBSUB_AUDIENCE/);
    expect(() => loadConfig(baseEnv({ PUBSUB_SERVICE_ACCOUNT_EMAIL: "not-an-email" }))).toThrow(/email address/);
  });

  it("reads the Call Guard section only when CALLS_ENABLED is true", () => {
    expect(loadConfig(baseEnv({ TWILIO_NUMBER: "+15551234567" })).calls).toBeUndefined();
    const enabled = loadConfig(
      baseEnv({
        CALLS_ENABLED: "true",
        TWILIO_ACCOUNT_SID: "AC" + "0".repeat(32),
        TWILIO_AUTH_TOKEN: "twilio-auth-token",
        TWILIO_NUMBER: "+15551234567",
        OPENAI_API_KEY: "sk-test",
        CALLS_ALERT_MIN_LEVEL: "high",
      }),
    );
    expect(enabled.calls?.twilio?.number).toBe("+15551234567");
    expect(enabled.calls?.openai?.apiKey).toBe("sk-test");
    expect(enabled.calls?.defaultMinimumLevel).toBe("high");
    expect(enabled.calls?.demoEnabled).toBe(true);
    expect(() => loadConfig(baseEnv({ CALLS_ENABLED: "true", TWILIO_NUMBER: "+15551234567" }))).toThrow(/TWILIO_ACCOUNT_SID/);
    expect(() => loadConfig(baseEnv({ CALLS_ENABLED: "true", CALLS_ALERT_MIN_LEVEL: "safe" }))).toThrow(/CALLS_ALERT_MIN_LEVEL/);
    expect(() => loadConfig(baseEnv({ CALLS_ENABLED: "maybe" }))).toThrow(/CALLS_ENABLED/);
    const bare = loadConfig(baseEnv({ CALLS_ENABLED: "true" }));
    expect(bare.calls?.twilio).toBeUndefined();
    expect(bare.calls?.openai).toBeUndefined();
  });

  it("rejects non-https base URLs except localhost", () => {
    expect(() => loadConfig(baseEnv({ PUBLIC_BASE_URL: "http://relay.example.net" }))).toThrow(/https/);
    expect(loadConfig(baseEnv({ PUBLIC_BASE_URL: "http://localhost:8080" })).publicBaseUrl).toBe("http://localhost:8080");
    expect(() => loadConfig(baseEnv({ PUBLIC_BASE_URL: "nonsense" }))).toThrow(/absolute URL/);
  });

  it("validates numeric ranges and log levels", () => {
    expect(() => loadConfig(baseEnv({ DEBOUNCE_SECONDS: "abc" }))).toThrow(/integer/);
    expect(() => loadConfig(baseEnv({ DEBOUNCE_SECONDS: "99999" }))).toThrow(/between/);
    expect(() => loadConfig(baseEnv({ PORT: "0" }))).toThrow(/between/);
    expect(() => loadConfig(baseEnv({ LOG_LEVEL: "loud" }))).toThrow(/LOG_LEVEL/);
  });
});

describe("AI-voice detection config (MODULATE_API_KEY and CALLS_AI_VOICE_*)", () => {
  const MODULATE_KEY = "mdl-secret-key-that-must-not-leak";

  function voiceEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
    return baseEnv({ CALLS_ENABLED: "true", MODULATE_API_KEY: MODULATE_KEY, ...overrides });
  }

  it("is absent without MODULATE_API_KEY — whatever the other variables say, valid or not", () => {
    expect(loadConfig(baseEnv({ CALLS_ENABLED: "true" })).calls?.voice).toBeUndefined();
    expect(loadConfig(baseEnv({ CALLS_ENABLED: "true", MODULATE_API_KEY: "   " })).calls?.voice).toBeUndefined();
    const ignored = loadConfig(
      baseEnv({
        CALLS_ENABLED: "true",
        CALLS_AI_VOICE_WINDOW_MS: "1",
        CALLS_AI_VOICE_MIN_SHARE_PERCENT: "abc",
        CALLS_AI_VOICE_MIN_CONFIDENCE_PERCENT: "0",
        CALLS_AI_VOICE_MAX_SECONDS: "-1",
        CALLS_AI_VOICE_SPOKEN_WARNING: "maybe",
        CALLS_AI_VOICE_WARNING_TEXT: "unused",
      }),
    );
    expect(ignored.calls?.voice).toBeUndefined();
    // …and the key alone does not turn Call Guard on.
    expect(loadConfig(baseEnv({ MODULATE_API_KEY: MODULATE_KEY })).calls).toBeUndefined();
  });

  it("the key alone gives the documented defaults", () => {
    expect(loadConfig(voiceEnv()).calls?.voice).toEqual({
      apiKey: MODULATE_KEY,
      windowMs: 6000,
      minShare: 0.8,
      minConfidence: 0.8,
      maxStreamMs: 180_000,
      spokenWarning: true,
      warningText: DEFAULT_AI_VOICE_WARNING,
    });
    expect([DEFAULT_AI_VOICE_WINDOW_MS, DEFAULT_AI_VOICE_MIN_SHARE_PERCENT, DEFAULT_AI_VOICE_MIN_CONFIDENCE_PERCENT, DEFAULT_AI_VOICE_MAX_SECONDS]).toEqual([6000, 80, 80, 180]);
    expect(DEFAULT_AI_VOICE_WARNING).toMatch(/A\.I\. generated/);
    // Independent of Twilio and OpenAI: the section does not need either.
    const alone = loadCallsConfig({ MODULATE_API_KEY: ` ${MODULATE_KEY} ` });
    expect(alone.voice?.apiKey).toBe(MODULATE_KEY);
    expect(alone.twilio).toBeUndefined();
    expect(alone.openai).toBeUndefined();
  });

  it("reads every variable", () => {
    const voice = loadConfig(
      voiceEnv({
        CALLS_AI_VOICE_WINDOW_MS: "10000",
        CALLS_AI_VOICE_MIN_SHARE_PERCENT: "65",
        CALLS_AI_VOICE_MIN_CONFIDENCE_PERCENT: "90",
        CALLS_AI_VOICE_MAX_SECONDS: "60",
        CALLS_AI_VOICE_SPOKEN_WARNING: "false",
        CALLS_AI_VOICE_WARNING_TEXT: "  Careful: this may be a cloned voice.  ",
      }),
    ).calls?.voice;
    expect(voice).toEqual({
      apiKey: MODULATE_KEY,
      windowMs: 10_000,
      minShare: 0.65,
      minConfidence: 0.9,
      maxStreamMs: 60_000,
      spokenWarning: false,
      warningText: "Careful: this may be a cloned voice.",
    });
  });

  it.each([
    ["CALLS_AI_VOICE_WINDOW_MS", 2500, 60_000],
    ["CALLS_AI_VOICE_MIN_SHARE_PERCENT", 50, 100],
    ["CALLS_AI_VOICE_MIN_CONFIDENCE_PERCENT", 50, 100],
    ["CALLS_AI_VOICE_MAX_SECONDS", 0, 14_400],
  ])("%s accepts %i…%i and nothing outside, naming the variable", (name, min, max) => {
    expect(() => loadConfig(voiceEnv({ [name]: String(min) }))).not.toThrow();
    expect(() => loadConfig(voiceEnv({ [name]: String(max) }))).not.toThrow();
    expect(() => loadConfig(voiceEnv({ [name]: String(max + 1) }))).toThrow(new RegExp(`${name} must be between ${min} and ${max}`));
    if (min > 0) expect(() => loadConfig(voiceEnv({ [name]: String(min - 1) }))).toThrow(new RegExp(`${name} must be between`));
    for (const junk of ["-1", "1.5", "ten", "6e3"]) {
      expect(() => loadConfig(voiceEnv({ [name]: junk }))).toThrow(new RegExp(`${name} must be an integer`));
    }
    expect(() => loadConfig(voiceEnv({ [name]: String(max + 1) }))).toThrow(ConfigError);
  });

  it("converts the bounds: percentages to fractions, seconds to milliseconds, 0 seconds to no cap", () => {
    const low = loadConfig(
      voiceEnv({ CALLS_AI_VOICE_WINDOW_MS: "2500", CALLS_AI_VOICE_MIN_SHARE_PERCENT: "50", CALLS_AI_VOICE_MIN_CONFIDENCE_PERCENT: "50", CALLS_AI_VOICE_MAX_SECONDS: "0" }),
    ).calls?.voice;
    expect(low).toMatchObject({ windowMs: 2500, minShare: 0.5, minConfidence: 0.5, maxStreamMs: 0 });
    const high = loadConfig(
      voiceEnv({ CALLS_AI_VOICE_WINDOW_MS: "60000", CALLS_AI_VOICE_MIN_SHARE_PERCENT: "100", CALLS_AI_VOICE_MIN_CONFIDENCE_PERCENT: "100", CALLS_AI_VOICE_MAX_SECONDS: "14400" }),
    ).calls?.voice;
    expect(high).toMatchObject({ windowMs: 60_000, minShare: 1, minConfidence: 1, maxStreamMs: 14_400_000 });
  });

  it("CALLS_AI_VOICE_SPOKEN_WARNING is a boolean, and an empty warning text falls back to the default", () => {
    for (const [raw, expected] of [["true", true], ["1", true], ["on", true], ["false", false], ["0", false], ["No", false]] as const) {
      expect(loadConfig(voiceEnv({ CALLS_AI_VOICE_SPOKEN_WARNING: raw })).calls?.voice?.spokenWarning).toBe(expected);
    }
    expect(() => loadConfig(voiceEnv({ CALLS_AI_VOICE_SPOKEN_WARNING: "maybe" }))).toThrow(/CALLS_AI_VOICE_SPOKEN_WARNING must be true or false/);
    expect(loadConfig(voiceEnv({ CALLS_AI_VOICE_WARNING_TEXT: "   " })).calls?.voice?.warningText).toBe(DEFAULT_AI_VOICE_WARNING);
  });

  it("never echoes the key in a configuration error", () => {
    try {
      loadConfig(voiceEnv({ CALLS_AI_VOICE_WINDOW_MS: "1" }));
      throw new Error("expected a ConfigError");
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      expect((error as Error).message).toContain("CALLS_AI_VOICE_WINDOW_MS");
      expect((error as Error).message).not.toContain(MODULATE_KEY);
    }
  });

  it("leaves the rest of the Call Guard section exactly as it is without the key", () => {
    const env = { CALLS_ENABLED: "true", TWILIO_ACCOUNT_SID: "AC" + "0".repeat(32), TWILIO_AUTH_TOKEN: "twilio-auth-token", TWILIO_NUMBER: "+15551234567", OPENAI_API_KEY: "sk-test" };
    const without = loadConfig(baseEnv(env)).calls!;
    const withKey = loadConfig(baseEnv({ ...env, MODULATE_API_KEY: MODULATE_KEY })).calls!;
    expect({ ...withKey, voice: undefined }).toEqual(without);
    expect(without.voice).toBeUndefined();
  });
});

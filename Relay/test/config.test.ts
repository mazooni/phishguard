import { describe, expect, it } from "vitest";

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

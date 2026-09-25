import type { FastifyBaseLogger } from "fastify";
import { describe, expect, it } from "vitest";
import twilio from "twilio";

import { CallSession } from "../../src/calls/session.js";
import {
  LEG_STATUS_EVENTS,
  USER_LEG_TIMEOUT_SECONDS,
  createTwilioClient,
  twilioErrorFields,
  type TwilioRest,
} from "../../src/calls/twilio/client.js";
import type { CallLine, CallSource } from "../../src/calls/types.js";
import { CALLER_NUMBER, GUARD_NUMBER, PROTECTED_NUMBER, TWILIO_AUTH_TOKEN, silentLogger, testTwilioConfig } from "./fakes.js";

const BASE = "https://relay.test";

type Call = { op: string; args: unknown[] };

/** Records every port call; each operation can be scripted to throw. */
class FakeRest implements TwilioRest {
  readonly calls: Call[] = [];
  accountType = "Full";
  fail: Partial<Record<keyof TwilioRest, Error>> = {};
  private record(op: keyof TwilioRest, ...args: unknown[]): void {
    this.calls.push({ op, args });
    const error = this.fail[op];
    if (error) throw error;
  }
  async createParticipant(conference: string, params: unknown) {
    this.record("createParticipant", conference, params);
    return { callSid: "CA" + "u".repeat(32) };
  }
  async updateParticipant(conference: string, participant: string, params: unknown) {
    this.record("updateParticipant", conference, participant, params);
    return {};
  }
  async updateConference(sid: string, params: unknown) {
    this.record("updateConference", sid, params);
    return {};
  }
  /** What `conferences.list({friendlyName, status: "in-progress"})` answers; undefined = no such conference. */
  resolvedConferenceSid: string | undefined = "CF" + "r".repeat(32);
  async findConferenceSid(friendlyName: string) {
    this.record("findConferenceSid", friendlyName);
    return this.resolvedConferenceSid;
  }
  async createCall(params: unknown) {
    this.record("createCall", params);
    return { sid: "CA" + "t".repeat(32) };
  }
  async updateCall(sid: string, params: unknown) {
    this.record("updateCall", sid, params);
    return {};
  }
  async fetchAccountType() {
    this.record("fetchAccountType");
    return this.accountType;
  }
}

const line: CallLine = {
  lineId: "line-1",
  deviceId: "device-1",
  guardNumber: GUARD_NUMBER,
  phoneNumber: PROTECTED_NUMBER,
  minimumLevel: "medium",
  spokenWarning: true,
  createdAt: 1,
  updatedAt: 1,
};

function session(source: CallSource = "twilio", withLine = true): CallSession {
  const s = new CallSession({
    deviceId: "device-1",
    line: withLine ? line : null,
    source,
    callerNumber: CALLER_NUMBER,
    calledNumber: GUARD_NUMBER,
    startedAt: 1_760_000_000_000,
    twilioCallSid: "CA" + "c".repeat(32),
  });
  s.conferenceName = `cg-${s.callId}`;
  return s;
}

function make(rest = new FakeRest()) {
  return { rest, client: createTwilioClient({ config: testTwilioConfig(), publicBaseUrl: BASE, logger: silentLogger(), rest }) };
}

/** A logger that keeps every line (serialised like pino would) so a test can assert what never reaches the logs. */
function recordingLogger(): { logger: FastifyBaseLogger; lines: string[] } {
  const lines: string[] = [];
  const write = (...args: unknown[]): void => {
    lines.push(JSON.stringify(args));
  };
  const logger = {
    level: "trace",
    fatal: write,
    error: write,
    warn: write,
    info: write,
    debug: write,
    trace: write,
    silent: () => undefined,
    child: () => logger,
  } as unknown as FastifyBaseLogger;
  return { logger, lines };
}

/** Twilio's RestException for error 21219, the usual trial-account failure — its message carries the dialled number. */
function unverifiedNumberError(number: string): Error {
  return Object.assign(new Error(`The number ${number} is unverified. Trial accounts cannot make calls to unverified numbers.`), {
    code: 21219,
    status: 400,
    moreInfo: "https://www.twilio.com/docs/errors/21219",
  });
}

describe("createTwilioClient", () => {
  it("dialProtectedUser creates the user participant on the conference friendly name with the contract's parameters", async () => {
    const { rest, client } = make();
    const s = session();
    await expect(client.dialProtectedUser(s)).resolves.toBe("CA" + "u".repeat(32));
    expect(rest.calls).toEqual([
      {
        op: "createParticipant",
        args: [
          `cg-${s.callId}`,
          {
            from: GUARD_NUMBER,
            to: PROTECTED_NUMBER,
            label: "user",
            startConferenceOnEnter: true,
            endConferenceOnExit: true,
            beep: "false",
            timeout: USER_LEG_TIMEOUT_SECONDS,
            statusCallback: `${BASE}/v1/calls/twilio/status?callID=${s.callId}&token=${s.mediaToken}&leg=user`,
            statusCallbackMethod: "POST",
            statusCallbackEvent: ["initiated", "ringing", "answered", "completed"],
          },
        ],
      },
    ]);
    expect(USER_LEG_TIMEOUT_SECONDS).toBe(25);
    expect(LEG_STATUS_EVENTS).toEqual(["initiated", "ringing", "answered", "completed"]);
    await expect(client.dialProtectedUser(session("twilio", false))).rejects.toThrow(/no line/);
  });

  it("placeTestCall calls the protected number from the guard number with the test-call TwiML URL and a test-leg status callback", async () => {
    const { rest, client } = make();
    const s = session("test-call");
    await expect(client.placeTestCall(s, "irs")).resolves.toBe("CA" + "t".repeat(32));
    expect(rest.calls[0]).toEqual({
      op: "createCall",
      args: [
        {
          to: PROTECTED_NUMBER,
          from: GUARD_NUMBER,
          url: `${BASE}/v1/calls/twilio/test-call?callID=${s.callId}&token=${s.mediaToken}&scenario=irs`,
          method: "POST",
          statusCallback: `${BASE}/v1/calls/twilio/status?callID=${s.callId}&token=${s.mediaToken}&leg=test`,
          statusCallbackMethod: "POST",
          statusCallbackEvent: ["initiated", "ringing", "answered", "completed"],
          timeout: USER_LEG_TIMEOUT_SECONDS,
        },
      ],
    });
  });

  it("speakToUser on a conference call announces to the user participant (SID when known, label otherwise) and remembers the text", async () => {
    const rest = new FakeRest();
    rest.resolvedConferenceSid = undefined; // conference-start not seen and nothing listed: fall back to the name
    const { client } = make(rest);
    const s = session();
    await expect(client.speakToUser(s, "Hang up now.")).resolves.toBe(true);
    expect(rest.calls[0]).toEqual({ op: "findConferenceSid", args: [`cg-${s.callId}`] });
    expect(rest.calls[1]).toEqual({
      op: "updateParticipant",
      args: [`cg-${s.callId}`, "user", { announceUrl: `${BASE}/v1/calls/twilio/announce?callID=${s.callId}&token=${s.mediaToken}`, announceMethod: "POST" }],
    });
    expect(client.announcementText(s)).toBe("Hang up now.");
    rest.calls.length = 0;

    s.conferenceSid = "CF" + "1".repeat(32);
    s.userCallSid = "CA" + "u".repeat(32);
    await client.speakToUser(s, "Second warning.");
    expect(rest.calls[0]!.op).toBe("updateParticipant");
    expect(rest.calls[0]!.args.slice(0, 2)).toEqual(["CF" + "1".repeat(32), "CA" + "u".repeat(32)]);
    expect(client.announcementText(s)).toBe("Second warning.");
    expect(client.announcementText(session())).toBeUndefined();
  });

  it("speakToUser on a test call replaces the call's TwiML with the announcement; demo sessions get false without a REST call", async () => {
    const { rest, client } = make();
    const test = session("test-call");
    await expect(client.speakToUser(test, "Warning.")).resolves.toBe(true);
    expect(rest.calls).toEqual([
      { op: "updateCall", args: [test.twilioCallSid, { twiml: expect.stringContaining('<Say voice="Polly.Joanna-Neural">Warning.</Say>') }] },
    ]);
    await expect(client.speakToUser(session("demo"), "Warning.")).resolves.toBe(false);
    const noSid = session("test-call");
    noSid.twilioCallSid = undefined;
    await expect(client.speakToUser(noSid, "Warning.")).resolves.toBe(false);
    expect(rest.calls).toHaveLength(1);
  });

  it("speakToUser and hangUp answer false when Twilio rejects the request", async () => {
    const rest = new FakeRest();
    rest.fail = { updateParticipant: new Error("20404"), updateConference: new Error("20404") };
    const { client } = make(rest);
    const s = session();
    s.conferenceSid = "CF" + "2".repeat(32);
    await expect(client.speakToUser(s, "x")).resolves.toBe(false);
    await expect(client.hangUp(s)).resolves.toBe(false);
  });

  it("hangUp ends the conference when its SID is known, else the caller's call, else nothing", async () => {
    const { rest, client } = make();
    const s = session();
    await expect(client.hangUp(s)).resolves.toBe(true);
    expect(rest.calls[0]).toEqual({ op: "updateCall", args: [s.twilioCallSid, { status: "completed" }] });
    s.conferenceSid = "CF" + "3".repeat(32);
    await expect(client.hangUp(s)).resolves.toBe(true);
    expect(rest.calls[1]).toEqual({ op: "updateConference", args: ["CF" + "3".repeat(32), { status: "completed" }] });
    const bare = session("demo");
    bare.twilioCallSid = undefined;
    await expect(client.hangUp(bare)).resolves.toBe(false);
    expect(rest.calls).toHaveLength(2);
  });

  it("redirectCall and endCall update the call, and report failure as false", async () => {
    const { rest, client } = make();
    await expect(client.redirectCall("CA1", "<Response/>")).resolves.toBe(true);
    await expect(client.endCall("CA2")).resolves.toBe(true);
    expect(rest.calls).toEqual([
      { op: "updateCall", args: ["CA1", { twiml: "<Response/>" }] },
      { op: "updateCall", args: ["CA2", { status: "completed" }] },
    ]);
    rest.fail = { updateCall: new Error("down") };
    await expect(client.redirectCall("CA1", "<Response/>")).resolves.toBe(false);
    await expect(client.endCall("CA2")).resolves.toBe(false);
  });

  it("fetchAccountType caches Trial/Full, shares one in-flight fetch, and retries after a failure or an unknown answer", async () => {
    const rest = new FakeRest();
    rest.accountType = "Trial";
    const { client } = make(rest);
    const [a, b] = await Promise.all([client.fetchAccountType(), client.fetchAccountType()]);
    expect([a, b]).toEqual(["Trial", "Trial"]);
    expect(await client.fetchAccountType()).toBe("Trial");
    expect(rest.calls.filter((call) => call.op === "fetchAccountType")).toHaveLength(1);

    const failing = new FakeRest();
    failing.fail = { fetchAccountType: new Error("401") };
    const second = make(failing).client;
    expect(await second.fetchAccountType()).toBe("unknown");
    failing.fail = {};
    failing.accountType = "Full";
    expect(await second.fetchAccountType()).toBe("Full");
    expect(await second.fetchAccountType()).toBe("Full");
    expect(failing.calls.filter((call) => call.op === "fetchAccountType")).toHaveLength(2);

    const odd = new FakeRest();
    odd.accountType = "Weird";
    expect(await make(odd).client.fetchAccountType()).toBe("unknown");
  });

  it("twilioErrorFields keeps the code and status and redacts phone numbers in the message", () => {
    expect(twilioErrorFields(unverifiedNumberError("+15550100002"))).toEqual({
      code: 21219,
      status: 400,
      message: "The number …0002 is unverified. Trial accounts cannot make calls to unverified numbers.",
    });
    expect(twilioErrorFields(new Error("Unable to create record: 555-010-0002 is not a valid phone number"))).toEqual({
      message: "Unable to create record: …0002 is not a valid phone number",
    });
    // Short digit runs (error codes, HTTP statuses) stay readable.
    expect(twilioErrorFields(new Error("HTTP 429 after 21219"))).toEqual({ message: "HTTP 429 after 21219" });
    expect(twilioErrorFields("boom")).toEqual({ message: "boom" });
    expect(twilioErrorFields(undefined)).toEqual({ message: "request failed" });
  });

  it("never logs the protected number when Twilio rejects a request (message and stack are the usual leak)", async () => {
    const rest = new FakeRest();
    const error = unverifiedNumberError(PROTECTED_NUMBER);
    rest.fail = { createParticipant: error, updateParticipant: error, updateConference: error, updateCall: error, fetchAccountType: error };
    const { logger, lines } = recordingLogger();
    const client = createTwilioClient({ config: testTwilioConfig(), publicBaseUrl: BASE, logger, rest });
    const s = session();
    s.conferenceSid = "CF" + "4".repeat(32);
    await expect(client.speakToUser(s, "x")).resolves.toBe(false);
    await expect(client.hangUp(s)).resolves.toBe(false);
    await expect(client.redirectCall("CA1", "<Response/>")).resolves.toBe(false);
    await expect(client.endCall("CA1")).resolves.toBe(false);
    await expect(client.fetchAccountType()).resolves.toBe("unknown");
    // `dialProtectedUser` rethrows; the route logs it with the same helper.
    await expect(client.dialProtectedUser(s)).rejects.toThrow();
    const output = lines.join("\n");
    expect(lines.length).toBeGreaterThanOrEqual(5);
    expect(output).toContain("21219");
    expect(output).toContain("…0002");
    expect(output).not.toContain(PROTECTED_NUMBER);
    expect(output).not.toContain(PROTECTED_NUMBER.slice(1));
    expect(output).not.toContain('"stack"');
  });

  it("validateSignature uses the SDK's HMAC over the public URL and the sorted form fields", () => {
    const { client } = make();
    const url = "https://relay.test/v1/calls/twilio/status?callID=abc&token=def&leg=user";
    const params = { CallSid: "CA123", CallStatus: "completed", From: GUARD_NUMBER };
    const good = twilio.getExpectedTwilioSignature(TWILIO_AUTH_TOKEN, url, params);
    expect(client.validateSignature(good, url, params)).toBe(true);
    expect(client.validateSignature(good, `${url}&extra=1`, params)).toBe(false);
    expect(client.validateSignature(good, url, { ...params, CallStatus: "failed" })).toBe(false);
    expect(client.validateSignature("bogus", url, params)).toBe(false);
    expect(client.validateSignature(undefined, url, params)).toBe(false);
    // A WebSocket handshake: the wss URL with no parameters.
    const wss = "wss://relay.test/v1/calls/twilio/media/0123456789abcdef0123456789abcdef";
    expect(client.validateSignature(twilio.getExpectedTwilioSignature(TWILIO_AUTH_TOKEN, wss, {}), wss, {})).toBe(true);
  });
});

describe("speakToUser conference resolution", () => {
  it("resolves the conference SID by friendly name when conference-start has not arrived yet", async () => {
    const { rest, client } = make();
    const s = session();
    s.userCallSid = "CA" + "u".repeat(32);
    expect(await client.speakToUser(s, "warning")).toBe(true);
    expect(rest.calls[0]).toEqual({ op: "findConferenceSid", args: [s.conferenceName] });
    expect(rest.calls[1]?.op).toBe("updateParticipant");
    expect(rest.calls[1]?.args[0]).toBe("CF" + "r".repeat(32));
    expect(s.conferenceSid).toBe("CF" + "r".repeat(32));
  });

  it("falls back to the friendly name when no in-progress conference is listed, and skips the lookup once the SID is known", async () => {
    const rest = new FakeRest();
    rest.resolvedConferenceSid = undefined;
    const { client } = make(rest);
    const s = session();
    expect(await client.speakToUser(s, "warning")).toBe(true);
    expect(rest.calls.map((c) => c.op)).toEqual(["findConferenceSid", "updateParticipant"]);
    expect(rest.calls[1]?.args[0]).toBe(s.conferenceName);

    s.conferenceSid = "CF" + "k".repeat(32);
    rest.calls.length = 0;
    expect(await client.speakToUser(s, "warning")).toBe(true);
    expect(rest.calls.map((c) => c.op)).toEqual(["updateParticipant"]);
    expect(rest.calls[0]?.args[0]).toBe("CF" + "k".repeat(32));
  });
});

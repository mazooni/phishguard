import { describe, expect, it } from "vitest";

import { CallSessionManager } from "../../src/calls/session.js";
import {
  findSessionByMediaToken,
  formParams,
  lookupSessionFromQuery,
  publicUrlFor,
  queryParams,
  websocketUrlFor,
} from "../../src/calls/twilio/signature.js";
import { CALLER_NUMBER, GUARD_NUMBER } from "./fakes.js";

function manager(): CallSessionManager {
  return new CallSessionManager({ store: { upsertCall: () => undefined }, retainEndedMs: 60_000, now: () => 1_760_000_000_000 });
}

function create(sessions: CallSessionManager) {
  return sessions.create({
    deviceId: "device-1",
    line: null,
    source: "twilio",
    callerNumber: CALLER_NUMBER,
    calledNumber: GUARD_NUMBER,
    startedAt: 1_760_000_000_000,
  });
}

describe("signature helpers", () => {
  it("reconstructs the public URL from PUBLIC_BASE_URL and the raw request URL, query string included", () => {
    expect(publicUrlFor("https://abc.ngrok.app", "/v1/calls/twilio/voice")).toBe("https://abc.ngrok.app/v1/calls/twilio/voice");
    expect(publicUrlFor("https://abc.ngrok.app/", "/v1/calls/twilio/status?callID=1&token=2&leg=user")).toBe(
      "https://abc.ngrok.app/v1/calls/twilio/status?callID=1&token=2&leg=user",
    );
    expect(websocketUrlFor("https://abc.ngrok.app", "/v1/calls/twilio/media/tok")).toBe("wss://abc.ngrok.app/v1/calls/twilio/media/tok");
    expect(websocketUrlFor("http://localhost:8080", "/v1/calls/twilio/media/tok")).toBe("ws://localhost:8080/v1/calls/twilio/media/tok");
  });

  it("flattens parsed form and query bodies to strings", () => {
    expect(formParams({ CallSid: "CA1", Digits: 1, Flag: true, Multi: ["a", "b"], Skip: undefined, Nested: { x: 1 } })).toEqual({
      CallSid: "CA1",
      Digits: "1",
      Flag: "true",
      Multi: "a,b",
    });
    expect(formParams(undefined)).toEqual({});
    expect(formParams("string")).toEqual({});
    expect(queryParams({ callID: "abc", token: "def" })).toEqual({ callID: "abc", token: "def" });
  });
});

describe("session lookups", () => {
  it("lookupSessionFromQuery answers 404 for an unknown callID, 403 for a wrong or missing token, and the session otherwise", () => {
    const sessions = manager();
    const session = create(sessions);
    expect(lookupSessionFromQuery(sessions, {})).toEqual({ status: 404, error: "not_found" });
    expect(lookupSessionFromQuery(sessions, { callID: "missing", token: session.mediaToken })).toEqual({ status: 404, error: "not_found" });
    expect(lookupSessionFromQuery(sessions, { callID: session.callId })).toEqual({ status: 403, error: "bad_token" });
    expect(lookupSessionFromQuery(sessions, { callID: session.callId, token: session.mediaToken.slice(0, -1) })).toEqual({ status: 403, error: "bad_token" });
    expect(lookupSessionFromQuery(sessions, { callID: session.callId, token: `${session.mediaToken}0` })).toEqual({ status: 403, error: "bad_token" });
    expect(lookupSessionFromQuery(sessions, { callID: session.callId, token: session.mediaToken })).toEqual({ session });
    // A retained (ended) session still answers its callbacks: late status events must not 404.
    session.end("completed");
    expect(lookupSessionFromQuery(sessions, { callID: session.callId, token: session.mediaToken })).toEqual({ session });
    sessions.close();
  });

  it("findSessionByMediaToken finds only live sessions", () => {
    const sessions = manager();
    const first = create(sessions);
    const second = create(sessions);
    expect(findSessionByMediaToken(sessions, first.mediaToken)).toBe(first);
    expect(findSessionByMediaToken(sessions, second.mediaToken)).toBe(second);
    expect(findSessionByMediaToken(sessions, "nope")).toBeUndefined();
    expect(findSessionByMediaToken(sessions, undefined)).toBeUndefined();
    first.end("completed");
    expect(findSessionByMediaToken(sessions, first.mediaToken)).toBeUndefined();
    sessions.close();
  });
});

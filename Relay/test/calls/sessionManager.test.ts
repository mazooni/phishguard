import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CallSessionManager, MIN_RETAIN_ENDED_MS, type CallSession } from "../../src/calls/session.js";
import type { CallRecord } from "../../src/calls/types.js";
import { DEVICE_ID, FakeClock } from "../helpers.js";
import { CALLER_NUMBER, PROTECTED_NUMBER } from "./fakes.js";

/**
 * The seam between the Twilio routes and the session registry: every SID the routes bind with `index()` (the
 * dialled user leg, a conference `participant-join`, a status callback) must be forgotten when the ended session
 * is evicted, not only the two SIDs the session stores on itself.
 */
describe("CallSessionManager SID index", () => {
  // The manager keeps an ended session at least MIN_RETAIN_ENDED_MS (the detector's final pass must land).
  const RETAIN_MS = Math.max(1_000, MIN_RETAIN_ENDED_MS);
  let clock: FakeClock;
  let sessions: CallSessionManager;

  const create = (twilioCallSid: string): CallSession =>
    sessions.create({
      deviceId: DEVICE_ID,
      line: null,
      source: "twilio",
      callerNumber: CALLER_NUMBER,
      calledNumber: PROTECTED_NUMBER,
      startedAt: clock.now(),
      twilioCallSid,
      status: "ringing",
    });

  beforeEach(() => {
    vi.useFakeTimers();
    clock = new FakeClock();
    const store = { upsertCall: (_record: CallRecord): void => undefined };
    sessions = new CallSessionManager({ store, retainEndedMs: RETAIN_MS, now: clock.now });
  });

  afterEach(() => {
    sessions.close();
    vi.useRealTimers();
  });

  it("forgets every SID bound with index() when the ended session is evicted", () => {
    const session = create("CA-caller");
    session.userCallSid = "CA-user";
    sessions.index(session, "CA-user");
    // A conference participant-join reporting a SID the session never stored on itself.
    sessions.index(session, "CA-conference-leg");
    expect(sessions.byTwilioSid("CA-caller")).toBe(session);
    expect(sessions.byTwilioSid("CA-user")).toBe(session);
    expect(sessions.byTwilioSid("CA-conference-leg")).toBe(session);

    session.end("completed");
    expect(sessions.get(session.callId)).toBe(session); // retained, transcript still fetchable
    vi.advanceTimersByTime(RETAIN_MS);

    expect(sessions.get(session.callId)).toBeUndefined();
    expect(sessions.byTwilioSid("CA-caller")).toBeUndefined();
    expect(sessions.byTwilioSid("CA-user")).toBeUndefined();
    expect(sessions.byTwilioSid("CA-conference-leg")).toBeUndefined();
    expect(sessions.all()).toHaveLength(0);
  });

  it("leaves another live session's SIDs in place", () => {
    const ended = create("CA-ended");
    sessions.index(ended, "CA-ended-user");
    const live = create("CA-live");
    sessions.index(live, "CA-live-user");

    ended.end("completed");
    vi.advanceTimersByTime(RETAIN_MS);

    expect(sessions.byTwilioSid("CA-ended")).toBeUndefined();
    expect(sessions.byTwilioSid("CA-ended-user")).toBeUndefined();
    expect(sessions.byTwilioSid("CA-live")).toBe(live);
    expect(sessions.byTwilioSid("CA-live-user")).toBe(live);
    expect(sessions.active()).toEqual([live]);
  });
});

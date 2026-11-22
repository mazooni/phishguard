import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { DEFAULT_AI_VOICE_WARNING } from "../../src/calls/config.js";
import { CallSession } from "../../src/calls/session.js";
import { createTwilioClient, type TwilioRest } from "../../src/calls/twilio/client.js";
import type { CallLine, CallSource } from "../../src/calls/types.js";
import { closeTestApp, createCallsTestApp, type CallsTestContext } from "../helpers.js";
import { CALLER_NUMBER, FakeTwilioClient, GUARD_NUMBER, PROTECTED_NUMBER, silentLogger, testTwilioConfig, testVoiceConfig } from "./fakes.js";
import { conferenceForm, inboundCall, postForm, registerLine, tokenQuery } from "./twilio-helpers.js";

/**
 * The announcement slots (types.ts `AnnouncementSlot`): the scam warning keeps the exact request and URL it has
 * always had; the AI-voice warning is a second, separately remembered text behind `slot=voice` on the same
 * announce callback, so two warnings requested close together can never play each other's words.
 */

const BASE = "https://relay.test";
const SCAM_TEXT = "This call shows signs of a scam.";
const VOICE_TEXT = "The caller's voice appears to be A.I. generated.";

type Call = { op: string; args: unknown[] };

/** Records the REST operations `speakToUser` can reach; the rest of the port is never called here. */
class RecordingRest implements TwilioRest {
  readonly calls: Call[] = [];
  failUpdateParticipant: Error | undefined;
  async createParticipant(): Promise<{ callSid: string }> {
    throw new Error("not used");
  }
  async updateParticipant(conference: string, participant: string, params: unknown): Promise<unknown> {
    this.calls.push({ op: "updateParticipant", args: [conference, participant, params] });
    if (this.failUpdateParticipant) throw this.failUpdateParticipant;
    return {};
  }
  async updateConference(): Promise<unknown> {
    throw new Error("not used");
  }
  async findConferenceSid(friendlyName: string): Promise<string | undefined> {
    this.calls.push({ op: "findConferenceSid", args: [friendlyName] });
    return undefined;
  }
  async createCall(): Promise<{ sid: string }> {
    throw new Error("not used");
  }
  async updateCall(sid: string, params: unknown): Promise<unknown> {
    this.calls.push({ op: "updateCall", args: [sid, params] });
    return {};
  }
  async stopStream(): Promise<unknown> {
    throw new Error("not used");
  }
  async fetchAccountType(): Promise<string> {
    return "Full";
  }
}

const LINE: CallLine = {
  lineId: "line-1",
  deviceId: "device-1",
  guardNumber: GUARD_NUMBER,
  phoneNumber: PROTECTED_NUMBER,
  minimumLevel: "medium",
  spokenWarning: true,
  createdAt: 0,
  updatedAt: 0,
};

function session(source: CallSource = "twilio"): CallSession {
  const created = new CallSession({
    deviceId: "device-1",
    line: LINE,
    source,
    callerNumber: CALLER_NUMBER,
    calledNumber: GUARD_NUMBER,
    startedAt: 1_760_000_000_000,
    twilioCallSid: "CA" + "a".repeat(32),
    status: "in_progress",
  });
  created.conferenceName = `cg-${created.callId}`;
  created.conferenceSid = "CF" + "1".repeat(32);
  created.userCallSid = "CA" + "b".repeat(32);
  return created;
}

function make(): { rest: RecordingRest; client: ReturnType<typeof createTwilioClient> } {
  const rest = new RecordingRest();
  return { rest, client: createTwilioClient({ config: testTwilioConfig(), publicBaseUrl: BASE, logger: silentLogger(), rest }) };
}

describe("TwilioClient announcement slots", () => {
  it("the scam slot — explicit or by default — builds the announce URL exactly as before", async () => {
    const { rest, client } = make();
    const s = session();
    await expect(client.speakToUser(s, SCAM_TEXT)).resolves.toBe(true);
    await expect(client.speakToUser(s, SCAM_TEXT, "scam")).resolves.toBe(true);
    const expected = {
      op: "updateParticipant",
      args: [s.conferenceSid, s.userCallSid, { announceUrl: `${BASE}/v1/calls/twilio/announce?callID=${s.callId}&token=${s.mediaToken}`, announceMethod: "POST" }],
    };
    expect(rest.calls).toEqual([expected, expected]);
    expect(client.announcementText(s)).toBe(SCAM_TEXT);
    expect(client.announcementText(s, "scam")).toBe(SCAM_TEXT);
    expect(client.announcementText(s, "voice")).toBeUndefined();
  });

  it("the voice slot announces to the same participant through the announce URL with slot=voice", async () => {
    const { rest, client } = make();
    const s = session();
    await expect(client.speakToUser(s, VOICE_TEXT, "voice")).resolves.toBe(true);
    expect(rest.calls).toEqual([
      {
        op: "updateParticipant",
        args: [s.conferenceSid, s.userCallSid, { announceUrl: `${BASE}/v1/calls/twilio/announce?callID=${s.callId}&token=${s.mediaToken}&slot=voice`, announceMethod: "POST" }],
      },
    ]);
    expect(client.announcementText(s, "voice")).toBe(VOICE_TEXT);
    expect(client.announcementText(s)).toBeUndefined();
  });

  it("keeps the two texts apart, per call, whichever was requested last", async () => {
    const { client } = make();
    const first = session();
    const second = session();
    await client.speakToUser(first, SCAM_TEXT);
    await client.speakToUser(first, VOICE_TEXT, "voice");
    await client.speakToUser(second, "Another call's AI-voice warning.", "voice");
    expect(client.announcementText(first)).toBe(SCAM_TEXT);
    expect(client.announcementText(first, "voice")).toBe(VOICE_TEXT);
    expect(client.announcementText(second)).toBeUndefined();
    expect(client.announcementText(second, "voice")).toBe("Another call's AI-voice warning.");
    await client.speakToUser(first, "A louder scam warning.");
    expect(client.announcementText(first)).toBe("A louder scam warning.");
    expect(client.announcementText(first, "voice")).toBe(VOICE_TEXT);
  });

  it("refuses the voice slot on a test call instead of replacing its TwiML; the scam slot still replaces it", async () => {
    const { rest, client } = make();
    const test = session("test-call");
    await expect(client.speakToUser(test, VOICE_TEXT, "voice")).resolves.toBe(false);
    expect(rest.calls).toEqual([]);
    expect(client.announcementText(test, "voice")).toBeUndefined();
    await expect(client.speakToUser(test, SCAM_TEXT)).resolves.toBe(true);
    expect(rest.calls).toEqual([{ op: "updateCall", args: [test.twilioCallSid, { twiml: expect.stringContaining(`<Say voice="Polly.Joanna-Neural">${SCAM_TEXT}</Say>`) }] }]);
  });

  it("answers false for the voice slot on a demo or replay session, and when Twilio rejects the request", async () => {
    const { rest, client } = make();
    await expect(client.speakToUser(session("demo"), VOICE_TEXT, "voice")).resolves.toBe(false);
    await expect(client.speakToUser(session("replay"), VOICE_TEXT, "voice")).resolves.toBe(false);
    expect(rest.calls).toEqual([]);
    rest.failUpdateParticipant = new Error("20404");
    await expect(client.speakToUser(session(), VOICE_TEXT, "voice")).resolves.toBe(false);
  });
});

describe("FakeTwilioClient announcement slots", () => {
  it("records voice-slot requests apart from `spoken`, and refuses them on a test call like the real client", async () => {
    const fake = new FakeTwilioClient();
    const s = session();
    await expect(fake.speakToUser(s, SCAM_TEXT)).resolves.toBe(true);
    await expect(fake.speakToUser(s, VOICE_TEXT, "voice")).resolves.toBe(true);
    expect(fake.spoken).toEqual([{ callId: s.callId, text: SCAM_TEXT }]);
    expect(fake.voiceSpoken).toEqual([{ callId: s.callId, text: VOICE_TEXT }]);
    expect(fake.announcementText(s)).toBe(SCAM_TEXT);
    expect(fake.announcementText(s, "voice")).toBe(VOICE_TEXT);
    await expect(fake.speakToUser(session("test-call"), VOICE_TEXT, "voice")).resolves.toBe(false);
    expect(fake.voiceSpoken).toHaveLength(1);
  });
});

describe("announce webhook slots", () => {
  let ctx: CallsTestContext;
  afterEach(async () => {
    await closeTestApp(ctx);
  });

  const say = (text: string): string => `<?xml version="1.0" encoding="UTF-8"?><Response><Say voice="Polly.Joanna-Neural">${text}</Say></Response>`;

  describe("with AI-voice detection configured", () => {
    beforeEach(async () => {
      ctx = await createCallsTestApp({ voice: testVoiceConfig({ warningText: "Configured AI-voice warning." }) });
      await registerLine(ctx);
    });

    it("plays each slot's own text, falling back to each slot's own configured default", async () => {
      const { session: live } = await inboundCall(ctx);
      const scamUrl = `/v1/calls/twilio/announce?${tokenQuery(live)}`;
      const voiceUrl = `/v1/calls/twilio/announce?${tokenQuery(live, { slot: "voice" })}`;

      // Nothing requested yet: the configured defaults, each in its own slot.
      expect((await postForm(ctx.app, scamUrl, conferenceForm("announcement"))).body).toBe(say(ctx.config.calls!.spokenWarningText));
      const voiceDefault = await postForm(ctx.app, voiceUrl, conferenceForm("announcement"));
      expect(voiceDefault.statusCode).toBe(200);
      expect(voiceDefault.headers["content-type"]).toMatch(/^text\/xml/);
      expect(voiceDefault.body).toBe(say("Configured AI-voice warning."));

      await ctx.twilio.speakToUser(live, "Custom scam warning.");
      await ctx.twilio.speakToUser(live, "Custom voice warning.", "voice");
      expect((await postForm(ctx.app, scamUrl, conferenceForm("announcement"))).body).toBe(say("Custom scam warning."));
      expect((await postForm(ctx.app, voiceUrl, conferenceForm("announcement"))).body).toBe(say("Custom voice warning."));
      // An unknown slot value is the scam warning, like no slot at all.
      const other = await postForm(ctx.app, `/v1/calls/twilio/announce?${tokenQuery(live, { slot: "other" })}`, conferenceForm("announcement"));
      expect(other.body).toBe(say("Custom scam warning."));
    });

    it("checks the session token for the voice slot too", async () => {
      const { session: live } = await inboundCall(ctx);
      const bad = await postForm(ctx.app, `/v1/calls/twilio/announce?callID=${live.callId}&token=guess&slot=voice`, conferenceForm("announcement"));
      expect(bad.statusCode).toBe(403);
    });
  });

  it("falls back to the built-in AI-voice warning on a relay without a `voice` section", async () => {
    ctx = await createCallsTestApp();
    await registerLine(ctx);
    const { session: live } = await inboundCall(ctx);
    const voice = await postForm(ctx.app, `/v1/calls/twilio/announce?${tokenQuery(live, { slot: "voice" })}`, conferenceForm("announcement"));
    expect(voice.body).toBe(say(DEFAULT_AI_VOICE_WARNING));
    // …and the scam slot is what it always was.
    const scam = await postForm(ctx.app, `/v1/calls/twilio/announce?${tokenQuery(live)}`, conferenceForm("announcement"));
    expect(scam.body).toBe(say(ctx.config.calls!.spokenWarningText));
  });
});

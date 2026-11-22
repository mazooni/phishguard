import type { AddressInfo } from "node:net";
import { runInNewContext } from "node:vm";
import type { FastifyBaseLogger } from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { VOICE_ALERT_BODY, alertSubtitle } from "../../src/calls/alerts/text.js";
import { DEMO_VOICE_DETECTED_AFTER_MS, DEMO_VOICE_PROVIDER, DemoCallRunner } from "../../src/calls/demo/runner.js";
import { renderConsolePage } from "../../src/calls/live/console.js";
import { CallSessionManager } from "../../src/calls/session.js";
import type { CallLine, CallRecord, CallSummaryJSON, CallVoiceAssessment, LiveEvent } from "../../src/calls/types.js";
import { API_KEY, APNS_TOKEN, DEVICE_ID, FakeClock, closeTestApp, createCallsTestApp, deviceHeaders, registerDevice, type CallsTestContext } from "../helpers.js";
import { GUARD_NUMBER, PROTECTED_NUMBER, silentLogger } from "./fakes.js";
import { LiveClient, waitFor } from "./liveClient.js";

/**
 * The demo flag and the operator console's side of AI-voice detection: `aiVoice: true` on a demo call scripts the
 * detector through `session.setVoice`, so the whole downstream — live feed, warning, push, call record — runs with
 * no Twilio and no Modulate key; without the flag a demo call is exactly what it was. The console page shows the
 * assessment and offers the flag, and still loads nothing from anywhere.
 */

const keyHeaders = { "x-api-key": API_KEY };

describe("DemoCallRunner with aiVoice", () => {
  let clock: FakeClock;
  let sessions: CallSessionManager;
  let runner: DemoCallRunner;
  let records: CallRecord[];
  let logged: { fields: unknown; message: string }[];

  beforeEach(() => {
    vi.useFakeTimers();
    clock = new FakeClock();
    records = [];
    logged = [];
    const logger = { ...silentLogger(), info: (fields: unknown, message: string) => logged.push({ fields, message }) } as unknown as FastifyBaseLogger;
    sessions = new CallSessionManager({ store: { upsertCall: (record) => records.push(record) }, retainEndedMs: 60_000, now: clock.now });
    runner = new DemoCallRunner({ sessions, logger, now: clock.now });
  });

  afterEach(() => {
    runner.close();
    sessions.close();
    vi.useRealTimers();
  });

  it("without the flag — absent or false — never touches the voice assessment, and logs what it always logged", () => {
    for (const aiVoice of [undefined, false]) {
      const session = runner.start({ deviceId: DEVICE_ID, line: null, scenario: "benign", ...(aiVoice === undefined ? {} : { aiVoice }) });
      const events: CallVoiceAssessment[] = [];
      session.on("voice", (voice) => events.push(voice));
      expect(session.voice).toBeUndefined();
      vi.runAllTimers();
      expect(session.isEnded).toBe(true);
      expect(session.voice).toBeUndefined();
      expect(events).toEqual([]);
      expect(session.toSummaryJSON()).not.toHaveProperty("voice");
    }
    expect(records.every((record) => record.voice === undefined)).toBe(true);
    expect(logged.filter((entry) => entry.message === "demo: call started").map((entry) => Object.keys(entry.fields as object))).toEqual([
      ["callId", "deviceId", "scenario", "speed", "lines"],
      ["callId", "deviceId", "scenario", "speed", "lines"],
    ]);
  });

  it("with the flag reports `analyzing` at the start and `synthetic` a few seconds in, through the session's own entry point", () => {
    const session = runner.start({ deviceId: DEVICE_ID, line: null, scenario: "grandparent", aiVoice: true });
    expect(session.voice).toEqual({ status: "analyzing", syntheticShare: 0, confidence: 0, speechMs: 0, provider: "demo:scripted", updatedAt: clock.now() });
    expect(DEMO_VOICE_PROVIDER).toBe("demo:scripted");
    const events: CallVoiceAssessment[] = [];
    session.on("voice", (voice) => events.push(voice));

    vi.advanceTimersByTime(DEMO_VOICE_DETECTED_AFTER_MS - 1);
    expect(session.voice?.status).toBe("analyzing");
    clock.advance(DEMO_VOICE_DETECTED_AFTER_MS);
    vi.advanceTimersByTime(1);
    expect(events).toHaveLength(1);
    expect(session.voice).toMatchObject({ status: "synthetic", provider: "demo:scripted", detectedAt: clock.now() });
    expect(session.voice!.syntheticShare).toBeGreaterThanOrEqual(0.8);
    expect(session.voice!.confidence).toBeGreaterThanOrEqual(0.8);
    expect(session.voice!.speechMs).toBeGreaterThan(0);
    // The transcript script is unchanged by the flag, and the scam verdict is nobody's business here.
    expect(session.verdict).toBeUndefined();
    vi.runAllTimers();
    expect(session.isEnded).toBe(true);
    expect(session.voice?.status).toBe("synthetic");
    expect(records.at(-1)).toMatchObject({ status: "completed", voice: { status: "synthetic", provider: "demo:scripted" } });
    expect(logged.find((entry) => entry.message === "demo: call started")?.fields).toMatchObject({ aiVoice: true });
  });

  it("scales the moment of detection by speed, and never reports on a call that ended first", () => {
    const fast = runner.start({ deviceId: DEVICE_ID, line: null, scenario: "prize", speed: 4, aiVoice: true });
    vi.advanceTimersByTime(DEMO_VOICE_DETECTED_AFTER_MS / 4 - 1);
    expect(fast.voice?.status).toBe("analyzing");
    vi.advanceTimersByTime(1);
    expect(fast.voice?.status).toBe("synthetic");

    const early = runner.start({ deviceId: DEVICE_ID, line: null, scenario: "prize", aiVoice: true });
    vi.advanceTimersByTime(1000);
    early.end("canceled");
    vi.runAllTimers();
    expect(early.voice?.status).toBe("inconclusive"); // what `end()` makes of a leftover `analyzing`
  });
});

describe("demo call with aiVoice, end to end", () => {
  let ctx: CallsTestContext;
  const clients: LiveClient[] = [];

  beforeEach(async () => {
    // The smallest relay that can run it: no Twilio, no OpenAI, no Modulate key.
    ctx = await createCallsTestApp({ twilio: undefined, openai: undefined, transcriptionSource: "auto" });
    expect(ctx.voiceDetector).toBeUndefined();
    expect(ctx.config.calls?.voice).toBeUndefined();
    await registerDevice(ctx.app);
  });

  afterEach(async () => {
    for (const client of clients.splice(0)) await client.close();
    await closeTestApp(ctx);
  });

  async function liveFeed(): Promise<LiveClient> {
    await ctx.app.listen({ port: 0, host: "127.0.0.1" });
    const { port } = ctx.app.server.address() as AddressInfo;
    const client = await LiveClient.connect(`ws://127.0.0.1:${port}/v1/devices/calls/live`, deviceHeaders());
    clients.push(client);
    await client.next("hello");
    return client;
  }

  const voiceEvents = (client: LiveClient): Extract<LiveEvent, { type: "voice.updated" }>[] =>
    client.received.filter((event): event is Extract<LiveEvent, { type: "voice.updated" }> => event.type === "voice.updated");

  it("device route: voice.updated events, the AI-voice push, an alerted summary and voice_json in the calls row", async () => {
    const live = await liveFeed();
    const started = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "benign", speed: 4, aiVoice: true } });
    expect(started.statusCode).toBe(202);
    const { callID } = started.json() as { callID: string };
    const session = ctx.app.callGuard.sessions.get(callID)!;
    expect(session).toMatchObject({ source: "demo", status: "in_progress" });

    expect(await live.next("call.started")).toMatchObject({ call: { callID, source: "demo" } });
    // analysing at once, synthetic ~1.25 s in (speed 4), then the same assessment carrying the warning.
    await waitFor(() => voiceEvents(live).length >= 3, 6000);
    const updates = voiceEvents(live);
    expect(updates.every((event) => event.callID === callID)).toBe(true);
    expect(updates.map((event) => [event.voice.status, event.voice.alert !== undefined])).toEqual([["analyzing", false], ["synthetic", false], ["synthetic", true]]);
    expect(updates[0]!.voice).toMatchObject({ provider: "demo:scripted", syntheticShare: 0, speechMs: 0 });
    expect(updates[2]!.voice.alert).toEqual({
      title: "AI voice detected",
      subtitle: alertSubtitle(session.callerNumber),
      body: VOICE_ALERT_BODY,
      sentAt: expect.any(Number),
      pushed: true,
      spoken: false, // nobody is on a phone in a demo
    });
    expect(updates[2]!.voice.alert!.subtitle).toMatch(/^Call from \+1 \(\d{3}\) \d{3}-\d{4}$/);

    // One push, the AI-voice one: a benign script raises no scam alert.
    expect(ctx.sender.alerts).toHaveLength(1);
    expect(ctx.sender.alerts[0]).toMatchObject({
      apnsToken: APNS_TOKEN,
      title: "AI voice detected",
      collapseId: `call-voice-${callID}`,
      interruptionLevel: "time-sensitive",
      contentAvailable: true,
      data: { kind: "call-voice-alert", callID, voice: "synthetic", level: "low", category: "safe", callerNumber: session.callerNumber },
    });
    expect(session.alerts).toHaveLength(0);
    expect(session.alertLevel).toBeUndefined();

    session.end("completed");
    const ended = await live.next("call.ended");
    expect(ended).toMatchObject({ type: "call.ended", call: { callID, status: "completed", alerted: true, voice: { status: "synthetic", provider: "demo:scripted", alert: { pushed: true, spoken: false } } } });
    expect(ended.type === "call.ended" && ended.call.alertLevel).toBeUndefined();
    expect(live.received.some((event) => event.type === "call.alert")).toBe(false);

    // The record: alerted, with the assessment in voice_json and still not a word of the conversation.
    const row = ctx.db.db.prepare("SELECT * FROM calls WHERE call_id = ?").get(callID) as Record<string, unknown>;
    expect(row["alerted"]).toBe(1);
    expect(row["alert_level"]).toBeNull();
    expect(JSON.parse(String(row["voice_json"]))).toMatchObject({ status: "synthetic", provider: "demo:scripted", alert: { title: "AI voice detected", pushed: true, spoken: false } });
    expect(JSON.stringify(row)).not.toContain("transcript");
    const listed = await ctx.app.inject({ method: "GET", url: "/v1/devices/calls", headers: deviceHeaders() });
    expect((listed.json() as { calls: CallSummaryJSON[] }).calls[0]).toMatchObject({ callID, alerted: true, voice: { status: "synthetic" } });
  }, 15_000);

  it("device route: without the flag a demo call has no voice assessment, no voice event and no extra push", async () => {
    const live = await liveFeed();
    const started = [];
    for (const payload of [{ scenario: "benign", speed: 4 }, { scenario: "benign", speed: 4, aiVoice: false }]) {
      const response = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload });
      expect(response.statusCode).toBe(202);
      const session = ctx.app.callGuard.sessions.get((response.json() as { callID: string }).callID)!;
      expect(session.voice).toBeUndefined();
      started.push(session);
    }
    // Past the moment a flagged call would have been judged, with the script well under way.
    await new Promise((resolve) => setTimeout(resolve, DEMO_VOICE_DETECTED_AFTER_MS / 4 + 150));
    for (const session of started) {
      expect(session.segments.filter((segment) => segment.final).length).toBeGreaterThanOrEqual(2);
      expect(session.voice).toBeUndefined();
      session.end("completed");
      expect(ctx.db.db.prepare("SELECT voice_json, alerted FROM calls WHERE call_id = ?").get(session.callId)).toEqual({ voice_json: null, alerted: 0 });
    }
    expect(voiceEvents(live)).toHaveLength(0);
    expect(ctx.sender.alerts).toHaveLength(0);
  }, 15_000);

  it("device route: the body schema accepts a boolean only", async () => {
    const bad = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "benign", aiVoice: "maybe" } });
    expect(bad.statusCode).toBe(400);
    expect(ctx.app.callGuard.sessions.all()).toHaveLength(0);
    // Fastify strips keys the schema does not name: a misspelt flag starts an ordinary demo call, not a scripted voice.
    const misspelt = await ctx.app.inject({ method: "POST", url: "/v1/devices/calls/demo", headers: deviceHeaders(), payload: { scenario: "benign", speed: 4, aivoice: true } });
    expect(misspelt.statusCode).toBe(202);
    expect(ctx.app.callGuard.sessions.get((misspelt.json() as { callID: string }).callID)!.voice).toBeUndefined();
  });

  it("console route: aiVoice reaches the runner (and is not silently stripped); without it nothing is scripted", async () => {
    const flagged = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { deviceID: DEVICE_ID, scenario: "prize", speed: 4, aiVoice: true } });
    expect(flagged.statusCode).toBe(202);
    const session = ctx.app.callGuard.sessions.get((flagged.json() as { callID: string }).callID)!;
    expect(session.voice).toMatchObject({ status: "analyzing", provider: "demo:scripted" });
    await waitFor(() => session.voice?.alert !== undefined, 6000);
    expect(session.voice).toMatchObject({ status: "synthetic", alert: { pushed: true, spoken: false } });
    expect(ctx.sender.alerts.filter((request) => request.collapseId === `call-voice-${session.callId}`)).toHaveLength(1);

    const plain = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { deviceID: DEVICE_ID, scenario: "prize", speed: 4 } });
    expect(plain.statusCode).toBe(202);
    expect(ctx.app.callGuard.sessions.get((plain.json() as { callID: string }).callID)!.voice).toBeUndefined();
    const bad = await ctx.app.inject({ method: "POST", url: "/v1/calls/console/demo", headers: keyHeaders, payload: { deviceID: DEVICE_ID, scenario: "prize", aiVoice: 3 } });
    expect(bad.statusCode).toBe(400);
  }, 15_000);
});

// MARK: the console page, run against a stand-in DOM

/** Just enough of an element for the page's script: it only ever creates nodes and sets `textContent`. */
class StubElement {
  children: StubElement[] = [];
  parentNode: StubElement | null = null;
  className = "";
  type = "";
  title = "";
  checked = false;
  disabled = false;
  selected = false;
  scrollTop = 0;
  scrollHeight = 0;
  onclick: ((event: { preventDefault(): void }) => void) | null = null;
  readonly attributes = new Map<string, string>();
  /** Assignments to `innerHTML` would be a way around textContent-only rendering: recorded so the test can forbid them. */
  static htmlWrites = 0;
  private text = "";
  private ownValue = "";

  constructor(readonly tagName: string) {}

  get textContent(): string {
    return this.text + this.children.map((child) => child.textContent).join("");
  }
  set textContent(value: string | null) {
    for (const child of this.children) child.parentNode = null;
    this.children = [];
    this.text = value ?? "";
  }
  set innerHTML(_value: string) {
    StubElement.htmlWrites += 1;
  }
  get value(): string {
    if (this.tagName !== "select") return this.ownValue;
    return (this.children.find((child) => child.selected) ?? this.children[0])?.value ?? "";
  }
  set value(value: string) {
    this.ownValue = value;
  }
  get firstChild(): StubElement | null {
    return this.children[0] ?? null;
  }
  get lastChild(): StubElement | null {
    return this.children.at(-1) ?? null;
  }
  get childElementCount(): number {
    return this.children.length;
  }
  appendChild(child: StubElement): StubElement {
    child.parentNode?.removeChild(child);
    child.parentNode = this;
    this.children.push(child);
    return child;
  }
  insertBefore(child: StubElement, reference: StubElement | null): StubElement {
    child.parentNode?.removeChild(child);
    child.parentNode = this;
    const index = reference ? this.children.indexOf(reference) : -1;
    if (index < 0) this.children.push(child);
    else this.children.splice(index, 0, child);
    return child;
  }
  removeChild(child: StubElement): StubElement {
    this.children = this.children.filter((candidate) => candidate !== child);
    child.parentNode = null;
    return child;
  }
  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
    if (name === "class") this.className = value;
  }
  readonly classList = {
    add: (name: string): void => {
      if (!this.classList.contains(name)) this.className = `${this.className} ${name}`.trim();
    },
    remove: (name: string): void => {
      this.className = this.className.split(/\s+/).filter((part) => part !== name).join(" ");
    },
    contains: (name: string): boolean => this.className.split(/\s+/).includes(name),
    toggle: (name: string, force?: boolean): void => {
      const on = force ?? !this.classList.contains(name);
      if (on) this.classList.add(name);
      else this.classList.remove(name);
    },
  };
  /** Every descendant (depth first) matching the predicate. */
  find(predicate: (element: StubElement) => boolean): StubElement[] {
    const found: StubElement[] = [];
    for (const child of this.children) {
      if (predicate(child)) found.push(child);
      found.push(...child.find(predicate));
    }
    return found;
  }
}

interface PageHarness {
  byId: Map<string, StubElement>;
  /** Delivers one live event as the console WebSocket would. */
  deliver(event: LiveEvent): void;
  posts: { path: string; body: Record<string, unknown> }[];
  /** Runs the page's pending `setTimeout` callbacks (the move of an ended call into History). */
  runTimers(): void;
}

function runConsolePage(lines: CallLine[]): PageHarness {
  const html = renderConsolePage({ nonce: "test-nonce", lines, devices: [], twilioConfigured: true });
  const data = /<script nonce="test-nonce" id="data" type="application\/json">([\s\S]*?)<\/script>/.exec(html)?.[1];
  const script = /<script nonce="test-nonce">([\s\S]*?)<\/script>/.exec(html)?.[1];
  if (data === undefined || script === undefined) throw new Error("console page: script blocks not found");

  const byId = new Map<string, StubElement>();
  for (const id of ["data", "dot", "conn", "reload", "lines", "live", "liveEmpty", "history", "histEmpty", "toast"]) byId.set(id, new StubElement("div"));
  byId.get("data")!.textContent = data;
  const sockets: { onmessage?: (message: { data: string }) => void; onopen?: () => void }[] = [];
  const posts: { path: string; body: Record<string, unknown> }[] = [];
  let timers: (() => void)[] = [];
  class StubSocket {
    readyState = 1;
    onmessage?: (message: { data: string }) => void;
    onopen?: () => void;
    constructor(readonly url: string) {
      sockets.push(this);
    }
    send(): void {}
    close(): void {}
  }
  StubElement.htmlWrites = 0;
  runInNewContext(script, {
    document: {
      getElementById: (id: string) => byId.get(id) ?? null,
      createElement: (tag: string) => new StubElement(tag),
      createElementNS: (_namespace: string, tag: string) => new StubElement(tag),
    },
    window: { prompt: () => "" },
    location: { search: "?key=console-key", protocol: "https:", host: "relay.test", pathname: "/v1/calls/console", reload: () => undefined },
    history: { replaceState: () => undefined },
    sessionStorage: { getItem: () => null, setItem: () => undefined },
    WebSocket: StubSocket,
    fetch: async (path: string, init: { body: string }) => {
      posts.push({ path, body: JSON.parse(init.body) as Record<string, unknown> });
      return { ok: true, status: 202, json: async () => ({ callID: "started" }) };
    },
    setTimeout: (callback: () => void) => {
      timers.push(callback);
      return timers.length;
    },
    clearTimeout: () => undefined,
    setInterval: () => 0,
    clearInterval: () => undefined,
    URLSearchParams,
    encodeURIComponent,
  });
  const socket = sockets[0];
  if (!socket?.onmessage) throw new Error("console page: no WebSocket was opened");
  return {
    byId,
    posts,
    deliver: (event) => socket.onmessage!({ data: JSON.stringify(event) }),
    runTimers: () => {
      const due = timers;
      timers = [];
      for (const callback of due) callback();
    },
  };
}

const CONSOLE_LINE: CallLine = {
  lineId: "line-1",
  deviceId: DEVICE_ID,
  guardNumber: GUARD_NUMBER,
  phoneNumber: PROTECTED_NUMBER,
  minimumLevel: "medium",
  spokenWarning: true,
  createdAt: 0,
  updatedAt: 0,
};

function summary(overrides: Partial<CallSummaryJSON> = {}): CallSummaryJSON {
  return { callID: "call-1", source: "twilio", callerNumber: "+15550100003", calledNumber: PROTECTED_NUMBER, startedAt: 1_760_000_000_000, status: "in_progress", alerted: false, ...overrides };
}

function assessment(status: CallVoiceAssessment["status"], overrides: Partial<CallVoiceAssessment> = {}): CallVoiceAssessment {
  return { status, syntheticShare: 0, confidence: 0, speechMs: 0, provider: "modulate:velma-2-synthetic-voice-detection-streaming", updatedAt: 1_760_000_001_000, ...overrides };
}

describe("operator console page: AI voice", () => {
  let ctx: CallsTestContext | undefined;
  afterEach(async () => {
    if (ctx) await closeTestApp(ctx);
    ctx = undefined;
  });

  it("still serves one self-contained page under the nonce CSP, now with the voice line and the demo checkbox", async () => {
    ctx = await createCallsTestApp();
    await registerDevice(ctx.app);
    const response = await ctx.app.inject({ method: "GET", url: "/v1/calls/console", headers: keyHeaders });
    expect(response.statusCode).toBe(200);
    const csp = String(response.headers["content-security-policy"]);
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain(`style-src 'nonce-${nonce}'`);
    expect(csp).toContain("connect-src 'self' ws: wss:");
    const html = response.body;
    expect(html).not.toMatch(/<script[^>]+src=/);
    expect(html).not.toMatch(/<link[^>]+href=/);
    expect(html).not.toMatch(/<img|<iframe|@import|url\(/);
    expect(html).not.toMatch(/https?:\/\/(?!www\.w3\.org\/2000\/svg)/); // the SVG namespace is the only absolute URL
    expect(html).not.toMatch(/innerHTML|insertAdjacentHTML|document\.write|\beval\(/);
    expect([...html.matchAll(/<script\b[^>]*>/g)].every((tag) => tag[0].includes(`nonce="${nonce}"`))).toBe(true);
    expect(html).toContain('"voice.updated"');
    expect(html).toContain("aiVoice");
    expect(html).toContain("AI voice");
  });

  it("shows the assessment on a live call card in plain words, follows voice.updated, and keeps it in the history row", () => {
    const page = runConsolePage([CONSOLE_LINE]);
    const live = page.byId.get("live")!;
    page.deliver({ type: "hello", serverTime: 1_760_000_002_000, activeCalls: [summary({ voice: assessment("analyzing") })] });
    expect(live.children).toHaveLength(1);
    const voiceLine = live.find((element) => element.className.split(" ").includes("voice"))[0]!;
    expect(voiceLine.textContent).toBe("Caller's voicelistening to the caller's voice…");
    expect(voiceLine.classList.contains("hidden")).toBe(false);

    page.deliver({ type: "voice.updated", callID: "call-1", voice: assessment("analyzing", { syntheticShare: 0.5, speechMs: 2000 }) });
    expect(voiceLine.textContent).toContain("50% of the speech judged synthetic");
    page.deliver({ type: "voice.updated", callID: "call-1", voice: assessment("synthetic", { syntheticShare: 0.923, confidence: 0.94, speechMs: 6000, detectedAt: 1_760_000_003_000 }) });
    expect(voiceLine.textContent).toContain("appears AI-generated");
    expect(voiceLine.textContent).toContain("92% of the speech judged synthetic");
    expect(voiceLine.textContent).not.toContain("warned");
    expect(voiceLine.classList.contains("synthetic")).toBe(true);

    const alert = { title: "AI voice detected", subtitle: "Call from +1 (555) 010-0003", body: VOICE_ALERT_BODY, sentAt: 1_760_000_003_500, pushed: true, spoken: false };
    page.deliver({ type: "voice.updated", callID: "call-1", voice: assessment("synthetic", { syntheticShare: 0.923, alert }) });
    expect(voiceLine.textContent).toContain("warned · pushed");
    expect(voiceLine.textContent).not.toContain("spoken");
    page.deliver({ type: "voice.updated", callID: "call-1", voice: assessment("synthetic", { syntheticShare: 0.923, alert: { ...alert, spoken: true } }) });
    expect(voiceLine.textContent).toContain("warned · pushed · spoken");
    // An event for a call the page does not know is ignored.
    page.deliver({ type: "voice.updated", callID: "other", voice: assessment("human") });
    expect(live.children).toHaveLength(1);

    const ended = summary({ status: "completed", endedAt: 1_760_000_030_000, durationSeconds: 30, alerted: true, voice: assessment("synthetic", { syntheticShare: 0.923, alert: { ...alert, pushed: false, spoken: false } }) });
    page.deliver({ type: "call.ended", call: ended });
    page.runTimers();
    const history = page.byId.get("history")!;
    expect(live.children).toHaveLength(0);
    expect(history.children).toHaveLength(1);
    expect(history.textContent).toContain("voice: appears AI-generated");
    expect(history.textContent).toContain("92% of the speech judged synthetic");
    expect(history.textContent).toContain("warned · not pushed");
    expect(history.textContent).toContain("alerted");
    expect(StubElement.htmlWrites).toBe(0);
  });

  it("uses plain words for every status, and shows nothing for a call without an assessment", () => {
    const page = runConsolePage([CONSOLE_LINE]);
    const live = page.byId.get("live")!;
    page.deliver({ type: "hello", serverTime: 1_760_000_002_000, activeCalls: [] });
    page.deliver({ type: "call.started", call: summary() });
    const voiceLine = live.find((element) => element.className.split(" ").includes("voice"))[0]!;
    expect(voiceLine.classList.contains("hidden")).toBe(true);
    expect(voiceLine.textContent).toBe("");
    const words: [CallVoiceAssessment["status"], string][] = [
      ["human", "sounds human"],
      ["inconclusive", "not enough speech to tell"],
      ["unavailable", "voice check unavailable"],
    ];
    for (const [status, text] of words) {
      page.deliver({ type: "voice.updated", callID: "call-1", voice: assessment(status, { syntheticShare: 0.04, speechMs: 6000, updatedAt: 1_760_000_004_000 }) });
      expect(voiceLine.textContent).toContain(text);
      expect(voiceLine.classList.contains("hidden")).toBe(false);
    }
    expect(voiceLine.textContent).not.toContain("%"); // no share for a check that never ran
    page.deliver({ type: "voice.updated", callID: "call-1", voice: assessment("human", { syntheticShare: 0.04, speechMs: 6000 }) });
    expect(voiceLine.textContent).toContain("4% of the speech judged synthetic");

    // A call that ends without an assessment gets no voice entry in its history row.
    page.deliver({ type: "call.started", call: summary({ callID: "call-2" }) });
    page.deliver({ type: "call.ended", call: summary({ callID: "call-2", status: "completed", endedAt: 1_760_000_010_000, durationSeconds: 10 }) });
    page.runTimers();
    expect(page.byId.get("history")!.textContent).not.toContain("voice:");
  });

  it("offers an `AI voice` checkbox next to the demo button and sends aiVoice only when it is ticked", async () => {
    const page = runConsolePage([CONSOLE_LINE]);
    const lines = page.byId.get("lines")!;
    const [checkbox] = lines.find((element) => element.tagName === "input" && element.type === "checkbox");
    const [button] = lines.find((element) => element.tagName === "button" && element.textContent === "Start demo call");
    expect(checkbox).toBeDefined();
    expect(checkbox!.parentNode?.textContent).toBe("AI voice");
    expect(checkbox!.checked).toBe(false);

    button!.onclick!({ preventDefault: () => undefined });
    await Promise.resolve();
    expect(page.posts).toEqual([{ path: "/v1/calls/console/demo", body: { scenario: "grandparent", speed: 1, lineID: "line-1" } }]);
    checkbox!.checked = true;
    button!.onclick!({ preventDefault: () => undefined });
    await Promise.resolve();
    expect(page.posts[1]).toEqual({ path: "/v1/calls/console/demo", body: { scenario: "grandparent", speed: 1, lineID: "line-1", aiVoice: true } });
  });
});

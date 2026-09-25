import { randomBytes } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { constantTimeEqual } from "../../auth.js";
import type { RelayConfig } from "../../config.js";
import type { DeviceRow, RelayDb } from "../../db.js";
import type { CallsConfig } from "../config.js";
import { DEMO_SCENARIOS } from "../demo/scenarios.js";
import { DEMO_CALLED_NUMBER, MAX_DEMO_SPEED, MIN_DEMO_SPEED, type DemoCallRunner } from "../demo/runner.js";
import { startTestCall } from "../routes/devices.js";
import type { CallSessionManager } from "../session.js";
import type { TwilioClient } from "../twilio/client.js";
import { DEMO_SCENARIO_IDS, redactNumber, type CallLine, type DemoScenarioId, type Transcriber } from "../types.js";
import { ensureWebSocketPlugin } from "../websocket.js";
import type { LiveHub } from "./hub.js";

/**
 * Operator console (docs/CALLS.md §5.3): one self-contained HTML page plus its WebSocket and three action
 * routes, all behind one key (`?key=` or `X-API-Key`): `CALLS_CONSOLE_KEY` when set, else `RELAY_API_KEY` as the
 * contract says. The console shows every device's live transcript and can ring any registered line, while
 * `RELAY_API_KEY` is compiled into every app build — hence the key of its own. Registered only when
 * `CALLS_CONSOLE_ENABLED` is true (index.ts), so every path here answers 404 otherwise.
 *
 *   GET  /v1/calls/console                the page
 *   GET  /v1/calls/console/ws             WebSocket: every device's live events
 *   POST /v1/calls/console/demo           {lineID | deviceID, scenario, speed?} → 202 {callID}; 403 demo_disabled
 *   POST /v1/calls/console/test-call      {lineID, scenario} → 202 {callID}; 503 twilio_not_configured
 *   POST /v1/calls/console/replay         {lineID | deviceID} → 202 {callID, mediaToken, mediaPath} (a `replay`
 *                                         session); 503 openai_not_configured without a transcriber
 *   POST /v1/calls/console/replay/end     {callID} → 200 (the replay script ends its session once the audio is in)
 *
 * A demo or a replay targets a line or, on a relay without Twilio (where no line can exist), a registered device
 * (`deviceID`; 404 unknown_device); the page lists both. A test call always needs a line.
 */

export interface ConsoleRoutesOptions {
  config: RelayConfig;
  calls: CallsConfig;
  db: RelayDb;
  sessions: CallSessionManager;
  hub: LiveHub;
  demo: DemoCallRunner;
  twilio: TwilioClient | undefined;
  /** What a replay session feeds (Media Streams → OpenAI); undefined without OPENAI_API_KEY. */
  transcriber?: Transcriber | undefined;
  now?: (() => number) | undefined;
}

/** The fictional caller of a replayed recording. */
export const REPLAY_CALLER_NUMBER = "+15550100199";
export const MEDIA_PATH_PREFIX = "/v1/calls/twilio/media/";

interface KeyQuery {
  key?: string;
}

/** Exactly one of `lineID` / `deviceID` names what a demo or replay is aimed at. */
interface TargetBody {
  lineID?: string;
  deviceID?: string;
}

interface ConsoleDemoBody extends TargetBody {
  scenario: DemoScenarioId;
  speed?: number;
}

interface ConsoleTestCallBody {
  lineID: string;
  scenario: DemoScenarioId;
}

type ReplayBody = TargetBody;

interface ReplayEndBody {
  callID: string;
}

const BODY_LIMIT = 16 * 1024;
const lineIdSchema = { type: "string", minLength: 1, maxLength: 128 } as const;
const scenarioSchema = { type: "string", enum: [...DEMO_SCENARIO_IDS] } as const;

const demoBodySchema = {
  type: "object",
  required: ["scenario"],
  additionalProperties: false,
  properties: {
    lineID: lineIdSchema,
    deviceID: lineIdSchema,
    scenario: scenarioSchema,
    speed: { type: "number", minimum: MIN_DEMO_SPEED, maximum: MAX_DEMO_SPEED },
  },
} as const;

const testCallBodySchema = {
  type: "object",
  required: ["lineID", "scenario"],
  additionalProperties: false,
  properties: { lineID: lineIdSchema, scenario: scenarioSchema },
} as const;

const replayBodySchema = {
  type: "object",
  additionalProperties: false,
  properties: { lineID: lineIdSchema, deviceID: lineIdSchema },
} as const;

const replayEndBodySchema = {
  type: "object",
  required: ["callID"],
  additionalProperties: false,
  properties: { callID: { type: "string", minLength: 1, maxLength: 128 } },
} as const;

/** The console's session cookie: set when the key arrived as `?key=`, so a browser reload (which the page has stripped the key from) still works. */
export const CONSOLE_COOKIE = "pg_console_key";
const CONSOLE_COOKIE_MAX_AGE_SECONDS = 12 * 60 * 60;

function cookieValue(request: FastifyRequest, name: string): string | undefined {
  const header = request.headers.cookie;
  if (typeof header !== "string") return undefined;
  for (const part of header.split(";")) {
    const [rawName, ...rest] = part.split("=");
    if (rawName?.trim() === name) {
      const value = rest.join("=").trim();
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }
  return undefined;
}

function presentedKey(request: FastifyRequest): { key: string; source: "query" | "header" | "cookie" } | undefined {
  const query = request.query as KeyQuery | undefined;
  if (typeof query?.key === "string" && query.key.length > 0) return { key: query.key, source: "query" };
  const header = request.headers["x-api-key"];
  const fromHeader = Array.isArray(header) ? header[0] : header;
  if (typeof fromHeader === "string" && fromHeader.length > 0) return { key: fromHeader, source: "header" };
  const fromCookie = cookieValue(request, CONSOLE_COOKIE);
  if (fromCookie) return { key: fromCookie, source: "cookie" };
  return undefined;
}

/**
 * `?key=`, `X-API-Key` or the console cookie, compared in constant time; anything else is 401. A key that arrived in
 * the query string is echoed back as an `HttpOnly` cookie scoped to the console path (`SameSite=Strict`, `Secure`
 * behind https), because the page immediately removes `?key=` from the address bar and the next reload would
 * otherwise be a bare, unauthorised request.
 */
export function consoleKeyGuard(expectedApiKey: string) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply | undefined> => {
    const presented = presentedKey(request);
    if (presented === undefined || !constantTimeEqual(presented.key, expectedApiKey)) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    if (presented.source === "query") {
      const secure = request.protocol === "https" ? "; Secure" : "";
      reply.header(
        "set-cookie",
        `${CONSOLE_COOKIE}=${encodeURIComponent(presented.key)}; Path=/v1/calls/console; Max-Age=${CONSOLE_COOKIE_MAX_AGE_SECONDS}; HttpOnly; SameSite=Strict${secure}`,
      );
    }
    return undefined;
  };
}

interface Target {
  deviceId: string;
  line: CallLine | null;
}

interface TargetError {
  status: number;
  error: string;
  message?: string;
}

/**
 * Resolves the line (by id) or the device (by id, together with its line when it has one) a console action is
 * aimed at. A device without a line is what a relay without Twilio has; demos and replays still run for it.
 */
export function resolveTarget(db: RelayDb, body: TargetBody): Target | TargetError {
  if (body.lineID !== undefined && body.deviceID !== undefined) {
    return { status: 400, error: "bad_request", message: "send either lineID or deviceID, not both" };
  }
  if (body.lineID !== undefined) {
    const line = db.findCallLineById(body.lineID);
    return line ? { deviceId: line.deviceId, line } : { status: 404, error: "no_line" };
  }
  if (body.deviceID !== undefined) {
    const device = db.findDevice(body.deviceID);
    if (!device) return { status: 404, error: "unknown_device" };
    return { deviceId: device.deviceId, line: db.findCallLine(device.deviceId) ?? null };
  }
  return { status: 400, error: "bad_request", message: "body must have lineID or deviceID" };
}

function sendTargetError(reply: FastifyReply, failure: TargetError): FastifyReply {
  return reply.code(failure.status).send(failure.message === undefined ? { error: failure.error } : { error: failure.error, message: failure.message });
}

export function registerConsoleRoutes(app: FastifyInstance, options: ConsoleRoutesOptions): void {
  const { config, calls, db, sessions, hub, demo, twilio, transcriber } = options;
  const now = options.now ?? Date.now;
  ensureWebSocketPlugin(app);

  if (!calls.consoleKey) {
    app.log.warn("calls: console guarded by RELAY_API_KEY, the key every app build carries; set CALLS_CONSOLE_KEY to give it its own");
  }

  app.register(async (scoped) => {
    scoped.addHook("onRequest", consoleKeyGuard(calls.consoleKey ?? config.relayApiKey));

    scoped.get(
      "/v1/calls/console",
      {
        onSend: async (request, reply, payload) => {
          // The relay's global CSP is `default-src 'none'`; the page needs its own inline script and styles.
          const nonce = (request as FastifyRequest & { consoleNonce?: string }).consoleNonce ?? "";
          reply.header(
            "content-security-policy",
            `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self' ws: wss:; ` +
              "img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
          );
          return payload;
        },
      },
      async (request, reply) => {
        const nonce = randomBytes(16).toString("base64");
        (request as FastifyRequest & { consoleNonce?: string }).consoleNonce = nonce;
        const html = renderConsolePage({ nonce, lines: db.listCallLines(), devices: db.listDevices(), twilioConfigured: twilio !== undefined });
        return reply.code(200).type("text/html; charset=utf-8").send(html);
      },
    );

    scoped.get("/v1/calls/console/ws", { websocket: true }, (socket) => {
      hub.subscribeConsole(socket);
    });

    scoped.post<{ Body: ConsoleDemoBody }>("/v1/calls/console/demo", { schema: { body: demoBodySchema }, bodyLimit: BODY_LIMIT }, async (request, reply) => {
      if (!calls.demoEnabled) return reply.code(403).send({ error: "demo_disabled" });
      const target = resolveTarget(db, request.body);
      if ("error" in target) return sendTargetError(reply, target);
      const session = demo.start({ deviceId: target.deviceId, line: target.line, scenario: request.body.scenario, speed: request.body.speed });
      return reply.code(202).send({ callID: session.callId });
    });

    scoped.post<{ Body: ConsoleTestCallBody }>(
      "/v1/calls/console/test-call",
      { schema: { body: testCallBodySchema }, bodyLimit: BODY_LIMIT },
      async (request, reply) => {
        if (!twilio) return reply.code(503).send({ error: "twilio_not_configured" });
        const line = db.findCallLineById(request.body.lineID);
        if (!line) return reply.code(404).send({ error: "no_line" });
        const session = await startTestCall({ sessions, twilio, calls, line, scenario: request.body.scenario, now, log: request.log });
        if (!session) return reply.code(502).send({ error: "twilio_error" });
        return reply.code(202).send({ callID: session.callId });
      },
    );

    scoped.post<{ Body: ReplayBody }>("/v1/calls/console/replay", { schema: { body: replayBodySchema }, bodyLimit: BODY_LIMIT }, async (request, reply) => {
      // A replay is Media Streams audio into the OpenAI transcriber; without one it would produce nothing at all.
      if (!transcriber) return reply.code(503).send({ error: "openai_not_configured" });
      const target = resolveTarget(db, request.body);
      if ("error" in target) return sendTargetError(reply, target);
      const session = sessions.create({
        deviceId: target.deviceId,
        line: target.line,
        source: "replay",
        callerNumber: REPLAY_CALLER_NUMBER,
        calledNumber: target.line?.phoneNumber ?? DEMO_CALLED_NUMBER,
        startedAt: now(),
        status: "in_progress",
        transcriptionSource: "openai",
      });
      request.log.info({ callId: session.callId, deviceId: target.deviceId, phone: redactNumber(session.calledNumber) }, "replay: session created");
      return reply.code(202).send({ callID: session.callId, mediaToken: session.mediaToken, mediaPath: `${MEDIA_PATH_PREFIX}${session.mediaToken}` });
    });

    scoped.post<{ Body: ReplayEndBody }>("/v1/calls/console/replay/end", { schema: { body: replayEndBodySchema }, bodyLimit: BODY_LIMIT }, async (request, reply) => {
      const session = sessions.get(request.body.callID);
      if (!session || session.source !== "replay") return reply.code(404).send({ error: "not_found" });
      session.end("completed");
      return reply.code(200).send({ callID: session.callId, status: session.status });
    });
  });
}

// MARK: page

export interface ConsolePageInput {
  nonce: string;
  lines: CallLine[];
  /** Registered devices; those without a line get a demo-only row (secrets are never embedded). */
  devices?: DeviceRow[];
  twilioConfigured: boolean;
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

/** JSON safe to embed in a `<script>` block: `<` is escaped, and so are the U+2028 / U+2029 line terminators. */
function embedJson(value: unknown): string {
  const lineSeparator = new RegExp(String.fromCharCode(0x2028), "g");
  const paragraphSeparator = new RegExp(String.fromCharCode(0x2029), "g");
  return JSON.stringify(value).replace(/</g, "\\u003c").replace(lineSeparator, "\\u2028").replace(paragraphSeparator, "\\u2029");
}

export function renderConsolePage(input: ConsolePageInput): string {
  const nonce = escapeHtml(input.nonce);
  const linedDevices = new Set(input.lines.map((line) => line.deviceId));
  const data = {
    twilioConfigured: input.twilioConfigured,
    scenarios: DEMO_SCENARIO_IDS.map((id) => ({ id, title: DEMO_SCENARIOS[id].title })),
    lines: input.lines.map((line) => ({
      lineID: line.lineId,
      guardNumber: line.guardNumber,
      protectedLast4: redactNumber(line.phoneNumber),
      minimumLevel: line.minimumLevel,
      spokenWarning: line.spokenWarning,
    })),
    devices: (input.devices ?? [])
      .filter((device) => !linedDevices.has(device.deviceId))
      .map((device) => ({ deviceID: device.deviceId, lastSeenAt: device.lastSeenAt })),
  };
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>PhishGuard · Call Guard console</title>
<style nonce="${nonce}">
:root{--bg:#f4f5f8;--card:#fff;--text:#1b1e26;--muted:#6b7280;--border:#e2e5ea;--accent:#2563eb;--safe:#16a34a;--low:#ca8a04;--medium:#ea580c;--high:#dc2626}
@media (prefers-color-scheme:dark){:root{--bg:#0e1014;--card:#171a21;--text:#e7e9ef;--muted:#98a1b0;--border:#2a2f3a;--accent:#60a5fa}}
*{box-sizing:border-box}
body{margin:0;font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text)}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--border);background:var(--card);position:sticky;top:0;z-index:2}
h1{font-size:17px;margin:0}
.grow{flex:1}
.dot{width:10px;height:10px;border-radius:50%;background:var(--muted);flex:none}
.dot.on{background:var(--safe)}
main{padding:18px 20px;display:grid;gap:22px;max-width:1240px;margin:0 auto}
section h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:0 0 10px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden}
#lines table+table,#lines p+table{margin-top:10px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);font-size:14px;vertical-align:middle}
th{color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}
td.ctl{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
button{font:inherit;padding:6px 10px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);cursor:pointer}
button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
button:disabled{opacity:.45;cursor:not-allowed}
select{font:inherit;padding:5px 8px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text)}
a{color:var(--accent)}
.cards{display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(380px,1fr))}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px;display:grid;gap:10px;align-content:start}
.top{display:flex;align-items:center;gap:12px}
.gauge{width:76px;height:76px;position:relative;flex:none}
.gauge svg{transform:rotate(-90deg)}
.gauge circle{fill:none;stroke-width:8}
.gauge .bg{stroke:var(--border)}
.gauge .fg{stroke:var(--muted);transition:stroke-dashoffset .4s}
.gauge .fg.safe{stroke:var(--safe)}.gauge .fg.low{stroke:var(--low)}.gauge .fg.medium{stroke:var(--medium)}.gauge .fg.high{stroke:var(--high)}
.gauge .val{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:16px}
.who{flex:1;min-width:0}
.who .caller{font-weight:600;font-size:16px}
.who .meta{color:var(--muted);font-size:13px}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;background:var(--border);color:var(--text)}
.pill.high{background:var(--high);color:#fff}.pill.medium{background:var(--medium);color:#fff}.pill.low{background:var(--low);color:#fff}.pill.safe{background:var(--safe);color:#fff}
.summary{font-size:14px}
.action{font-size:14px;font-weight:600}
.reasons{margin:0;padding-left:18px;font-size:13px;display:grid;gap:2px}
.reasons li span{color:var(--muted)}
.transcript{max-height:280px;overflow:auto;border:1px solid var(--border);border-radius:8px;padding:8px 10px;font-size:14px;display:grid;gap:4px;align-content:start}
.line b{color:var(--muted);font-weight:600;margin-right:6px}
.line.user b{color:var(--accent)}
.line.partial{opacity:.5;font-style:italic}
.alerts{display:grid;gap:4px;font-size:13px}
.alert{padding:6px 8px;border-radius:8px;background:rgba(220,38,38,.12);border-left:3px solid var(--high)}
.history{display:grid;gap:6px}
.hist{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:8px 12px;display:flex;gap:10px;align-items:center;font-size:14px;flex-wrap:wrap}
.hist .muted{color:var(--muted)}
.empty{color:var(--muted);font-size:14px;margin:0}
.hidden{display:none}
.toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:var(--text);color:var(--bg);padding:8px 14px;border-radius:8px;font-size:13px;opacity:0;transition:opacity .2s;pointer-events:none;z-index:3}
.toast.show{opacity:1}
</style>
</head>
<body>
<header>
  <h1>PhishGuard · Call Guard</h1>
  <span class="dot" id="dot"></span><span id="conn" class="empty">connecting…</span>
  <span class="grow"></span>
  <a href="#" id="reload">Reload lines</a>
</header>
<main>
  <section><h2>Lines</h2><div id="lines"></div></section>
  <section><h2>Live calls</h2><div id="live" class="cards"></div><p id="liveEmpty" class="empty">No active calls. Start a demo call above, or call the guard number.</p></section>
  <section><h2>History</h2><div id="history" class="history"></div><p id="histEmpty" class="empty">Ended calls appear here.</p></section>
</main>
<div id="toast" class="toast"></div>
<script nonce="${nonce}" id="data" type="application/json">${embedJson(data)}</script>
<script nonce="${nonce}">
(function () {
  "use strict";
  var data = JSON.parse(document.getElementById("data").textContent);
  var params = new URLSearchParams(location.search);
  var key = params.get("key") || "";
  try { if (!key) key = sessionStorage.getItem("cg.key") || ""; } catch (e) {}
  if (!key) key = window.prompt("Relay API key (RELAY_API_KEY)") || "";
  try { if (key) sessionStorage.setItem("cg.key", key); } catch (e) {}
  // The key came in the URL for convenience; keep it out of the address bar, history and any copied link.
  if (params.has("key")) { params.delete("key"); try { history.replaceState(null, "", location.pathname + (params.toString() ? "?" + params.toString() : "")); } catch (e) {} }

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
  function fmtPhone(n) { var m = /^\\+1(\\d{3})(\\d{3})(\\d{4})$/.exec(n || ""); return m ? "+1 (" + m[1] + ") " + m[2] + "-" + m[3] : (n || "unknown"); }
  function fmtElapsed(ms) { var s = Math.max(0, Math.floor(ms / 1000)); return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0"); }
  function fmtTime(t) { var d = new Date(t); return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); }
  function fmtDate(t) { return new Date(t).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }); }
  var toastTimer;
  function toast(msg) { var t = $("toast"); t.textContent = msg; t.classList.add("show"); clearTimeout(toastTimer); toastTimer = setTimeout(function () { t.classList.remove("show"); }, 2800); }
  function post(path, body) {
    return fetch(path, { method: "POST", headers: { "content-type": "application/json", "x-api-key": key }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; }); });
  }

  // Lines --------------------------------------------------------------------------------------------------------
  // target is {lineID} for a line or {deviceID} for a device without one (demo only: a test call needs a line).
  function demoControls(target, withTestCall) {
    var ctl = el("td", "ctl");
    var scenario = el("select"); data.scenarios.forEach(function (s) { var o = el("option", null, s.title); o.value = s.id; scenario.appendChild(o); });
    var speed = el("select"); [["0.5", "0.5×"], ["1", "1×"], ["2", "2×"], ["4", "4×"]].forEach(function (p) { var o = el("option", null, p[1]); o.value = p[0]; if (p[0] === "1") o.selected = true; speed.appendChild(o); });
    var demoBtn = el("button", "primary", "Start demo call");
    demoBtn.onclick = function () {
      demoBtn.disabled = true;
      post("/v1/calls/console/demo", Object.assign({ scenario: scenario.value, speed: Number(speed.value) }, target))
        .then(function (j) { toast("Demo call started"); }).catch(function (e) { toast("Demo failed: " + e.message); })
        .then(function () { demoBtn.disabled = false; });
    };
    ctl.appendChild(scenario); ctl.appendChild(speed); ctl.appendChild(demoBtn);
    if (withTestCall) {
      var testBtn = el("button", null, "Place test call");
      testBtn.disabled = !data.twilioConfigured;
      testBtn.title = data.twilioConfigured ? "Twilio dials the protected phone and speaks the scenario" : "Twilio is not configured";
      testBtn.onclick = function () {
        testBtn.disabled = true;
        post("/v1/calls/console/test-call", Object.assign({ scenario: scenario.value }, target))
          .then(function () { toast("Test call placed — the protected phone should ring"); }).catch(function (e) { toast("Test call failed: " + e.message); })
          .then(function () { testBtn.disabled = !data.twilioConfigured; });
      };
      ctl.appendChild(testBtn);
    }
    return ctl;
  }

  function renderLines() {
    var host = $("lines"); host.textContent = "";
    if (!data.lines.length && !data.devices.length) {
      host.appendChild(el("p", "empty", "No device registered yet. Open the app once (it registers itself with the relay), or register one with curl (Relay/README.md), then start a demo call here."));
      return;
    }
    if (data.lines.length) {
      var table = el("table"); var head = el("tr");
      ["Guard number", "Protected", "Alerts from", "Spoken warning", "Actions"].forEach(function (h) { head.appendChild(el("th", null, h)); });
      table.appendChild(head);
      data.lines.forEach(function (line) {
        var tr = el("tr");
        tr.appendChild(el("td", null, fmtPhone(line.guardNumber)));
        tr.appendChild(el("td", null, line.protectedLast4));
        var lv = el("td"); lv.appendChild(el("span", "pill " + line.minimumLevel, line.minimumLevel)); tr.appendChild(lv);
        tr.appendChild(el("td", null, line.spokenWarning ? "on" : "off"));
        tr.appendChild(demoControls({ lineID: line.lineID }, true)); table.appendChild(tr);
      });
      host.appendChild(table);
    } else {
      host.appendChild(el("p", "empty", data.twilioConfigured
        ? "No line registered yet. In the app: Calls › Set up call protection. Scripted demo calls already work for the devices below."
        : "Twilio is not configured on this relay, so no line can be registered and no real or test call can be placed. Scripted demo calls work for the devices below."));
    }
    if (data.devices.length) {
      var t2 = el("table"); var h2 = el("tr");
      ["Device without a line", "Last seen", "Actions"].forEach(function (h) { h2.appendChild(el("th", null, h)); });
      t2.appendChild(h2);
      data.devices.forEach(function (device) {
        var tr = el("tr");
        tr.appendChild(el("td", null, device.deviceID));
        tr.appendChild(el("td", null, fmtDate(device.lastSeenAt)));
        tr.appendChild(demoControls({ deviceID: device.deviceID }, false)); t2.appendChild(tr);
      });
      host.appendChild(t2);
    }
  }
  $("reload").onclick = function (e) { e.preventDefault(); location.reload(); };
  renderLines();

  // Calls --------------------------------------------------------------------------------------------------------
  var calls = new Map();
  var serverOffset = 0;
  var C = 2 * Math.PI * 30;

  function ensureCall(summary) {
    var call = calls.get(summary.callID);
    if (!call) {
      call = { id: summary.callID, summary: summary, segments: new Map(), order: [], verdict: summary.verdict || null, alerts: [], ended: false, card: null };
      calls.set(summary.callID, call);
      call.card = buildCard(call);
      $("live").appendChild(call.card.root);
    } else {
      call.summary = summary;
      if (summary.verdict && (!call.verdict || summary.verdict.sequence >= call.verdict.sequence)) call.verdict = summary.verdict;
    }
    updateCard(call);
    return call;
  }

  function buildCard(call) {
    var root = el("article", "card");
    var top = el("div", "top");
    var gauge = el("div", "gauge");
    var svgNS = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(svgNS, "svg"); svg.setAttribute("viewBox", "0 0 76 76"); svg.setAttribute("width", "76"); svg.setAttribute("height", "76");
    var bg = document.createElementNS(svgNS, "circle"); bg.setAttribute("class", "bg"); bg.setAttribute("cx", "38"); bg.setAttribute("cy", "38"); bg.setAttribute("r", "30");
    var fg = document.createElementNS(svgNS, "circle"); fg.setAttribute("class", "fg"); fg.setAttribute("cx", "38"); fg.setAttribute("cy", "38"); fg.setAttribute("r", "30");
    fg.setAttribute("stroke-dasharray", String(C)); fg.setAttribute("stroke-dashoffset", String(C)); fg.setAttribute("stroke-linecap", "round");
    svg.appendChild(bg); svg.appendChild(fg); gauge.appendChild(svg);
    var val = el("div", "val", "–"); gauge.appendChild(val);
    var who = el("div", "who");
    var caller = el("div", "caller"); var meta = el("div", "meta");
    who.appendChild(caller); who.appendChild(meta);
    var status = el("span", "pill", "");
    top.appendChild(gauge); top.appendChild(who); top.appendChild(status);
    var summary = el("div", "summary hidden"); var action = el("div", "action hidden");
    var reasons = el("ul", "reasons hidden");
    var transcript = el("div", "transcript");
    var alerts = el("div", "alerts hidden");
    root.appendChild(top); root.appendChild(summary); root.appendChild(action); root.appendChild(reasons); root.appendChild(transcript); root.appendChild(alerts);
    return { root: root, fg: fg, val: val, caller: caller, meta: meta, status: status, summary: summary, action: action, reasons: reasons, transcript: transcript, alerts: alerts };
  }

  function updateCard(call) {
    var c = call.card, s = call.summary, v = call.verdict;
    c.caller.textContent = fmtPhone(s.callerNumber) + (s.source !== "twilio" ? "  ·  " + s.source : "");
    c.status.textContent = s.status.replace("_", " ");
    c.status.className = "pill " + (v ? v.level : "");
    updateElapsed(call);
    if (v) {
      var pct = Math.round(v.confidence * 100);
      c.val.textContent = pct + "%";
      c.fg.setAttribute("class", "fg " + v.level);
      c.fg.setAttribute("stroke-dashoffset", String(C * (1 - Math.max(0, Math.min(1, v.confidence)))));
      c.summary.textContent = v.summary; c.summary.classList.toggle("hidden", !v.summary);
      c.action.textContent = v.recommendedAction; c.action.classList.toggle("hidden", !v.recommendedAction);
      c.reasons.textContent = "";
      v.reasons.forEach(function (r) { var li = el("li", null, r.title + " "); li.appendChild(el("span", null, "— " + r.detail)); c.reasons.appendChild(li); });
      c.reasons.classList.toggle("hidden", !v.reasons.length);
    }
  }

  function updateElapsed(call) {
    var s = call.summary;
    var ms = s.endedAt ? s.endedAt - s.startedAt : (Date.now() + serverOffset) - s.startedAt;
    call.card.meta.textContent = fmtElapsed(ms) + "  ·  started " + fmtTime(s.startedAt) + (s.alertLevel ? "  ·  alerted " + s.alertLevel : "");
  }

  function addSegment(call, seg) {
    var line = call.segments.get(seg.id);
    if (!line) {
      line = el("div", "line"); line.appendChild(el("b", null, seg.speaker === "caller" ? "Caller" : "You")); line.appendChild(el("span", null, ""));
      call.segments.set(seg.id, line); call.card.transcript.appendChild(line);
    }
    line.className = "line " + seg.speaker + (seg.final ? "" : " partial");
    line.lastChild.textContent = seg.text;
    call.card.transcript.scrollTop = call.card.transcript.scrollHeight;
  }

  function addAlert(call, alert) {
    call.alerts.push(alert);
    var a = el("div", "alert", fmtTime(alert.sentAt) + "  " + alert.title + " — " + alert.body + (alert.pushed ? "  · pushed" : "  · not pushed") + (alert.spoken ? "  · spoken" : ""));
    call.card.alerts.appendChild(a); call.card.alerts.classList.remove("hidden");
  }

  function endCall(call, summary) {
    call.summary = summary; if (summary.verdict) call.verdict = summary.verdict; call.ended = true;
    updateCard(call);
    setTimeout(function () {
      if (call.card.root.parentNode) call.card.root.parentNode.removeChild(call.card.root);
      var h = el("div", "hist");
      h.appendChild(el("span", "pill " + (call.verdict ? call.verdict.level : ""), call.verdict ? call.verdict.level : "no verdict"));
      h.appendChild(el("strong", null, fmtPhone(summary.callerNumber)));
      h.appendChild(el("span", "muted", summary.source + " · " + summary.status.replace("_", " ") + " · " + fmtElapsed((summary.durationSeconds || 0) * 1000) + " · " + fmtTime(summary.startedAt)));
      if (call.verdict && call.verdict.summary) h.appendChild(el("span", "grow", call.verdict.summary));
      if (summary.alerted) h.appendChild(el("span", "pill high", "alerted"));
      var hist = $("history"); hist.insertBefore(h, hist.firstChild); $("histEmpty").classList.add("hidden");
      refreshEmpty();
    }, 4000);
  }

  function refreshEmpty() { $("liveEmpty").classList.toggle("hidden", $("live").childElementCount > 0); }
  setInterval(function () { calls.forEach(function (c) { if (!c.ended) updateElapsed(c); }); }, 1000);

  // WebSocket ----------------------------------------------------------------------------------------------------
  var ws, retry = 0, pingTimer;
  function setConn(on, text) { $("dot").classList.toggle("on", on); $("conn").textContent = text; }
  function connect() {
    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(proto + "//" + location.host + "/v1/calls/console/ws?key=" + encodeURIComponent(key));
    ws.onopen = function () { retry = 0; setConn(true, "live"); clearInterval(pingTimer); pingTimer = setInterval(function () { if (ws.readyState === 1) ws.send(JSON.stringify({ type: "ping" })); }, 25000); };
    ws.onclose = function () { setConn(false, "reconnecting…"); clearInterval(pingTimer); var wait = Math.min(15000, 500 * Math.pow(2, retry++)); setTimeout(connect, wait); };
    ws.onerror = function () { try { ws.close(); } catch (e) {} };
    ws.onmessage = function (m) {
      var ev; try { ev = JSON.parse(m.data); } catch (e) { return; }
      var call;
      switch (ev.type) {
        case "hello": serverOffset = ev.serverTime - Date.now(); ev.activeCalls.forEach(ensureCall); break;
        case "call.started": ensureCall(ev.call); break;
        case "call.status": call = calls.get(ev.callID); if (call) { call.summary.status = ev.status; updateCard(call); } break;
        case "transcript.segment": call = calls.get(ev.callID); if (call) addSegment(call, ev.segment); break;
        case "verdict.updated": call = calls.get(ev.callID); if (call && (!call.verdict || ev.verdict.sequence >= call.verdict.sequence)) { call.verdict = ev.verdict; updateCard(call); } break;
        case "call.alert": call = calls.get(ev.callID); if (call) { call.summary.alerted = true; call.summary.alertLevel = ev.alert.level; addAlert(call, ev.alert); updateCard(call); } break;
        case "call.ended": call = calls.get(ev.call.callID); if (call) endCall(call, ev.call); break;
        default: break;
      }
      refreshEmpty();
    };
  }
  connect();
})();
</script>
</body>
</html>
`;
}

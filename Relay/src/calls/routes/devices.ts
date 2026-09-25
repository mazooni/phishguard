import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";

import { apiKeyGuard, deviceAuthGuard } from "../../auth.js";
import type { RelayConfig } from "../../config.js";
import type { RelayDb } from "../../db.js";
import type { CallsConfig } from "../config.js";
import { MAX_DEMO_SPEED, MIN_DEMO_SPEED, type DemoCallRunner } from "../demo/runner.js";
import type { LiveHub } from "../live/hub.js";
import { recordToSummaryJSON, type CallSession, type CallSessionManager } from "../session.js";
import { twilioErrorFields, type TwilioClient } from "../twilio/client.js";
import {
  ALERT_LEVELS,
  DEMO_SCENARIO_IDS,
  E164_PATTERN,
  redactNumber,
  type AlertLevel,
  type CallLine,
  type CallLineJSON,
  type CallSummaryJSON,
  type DemoScenarioId,
  type TranscriptSegment,
} from "../types.js";
import { ensureWebSocketPlugin } from "../websocket.js";

/**
 * App-facing device-scoped routes (docs/CALLS.md §5.1). Every route — the WebSocket one included — runs
 * `apiKeyGuard` then `deviceAuthGuard`; @fastify/websocket runs `onRequest` hooks before the upgrade, so an
 * unauthenticated upgrade is answered 401 and never becomes a socket.
 *
 *   PUT    /v1/devices/call-line          register / update this device's protected line
 *   GET    /v1/devices/call-line          the line, or 404 no_line
 *   DELETE /v1/devices/call-line          204 (idempotent)
 *   GET    /v1/devices/calls?limit=50     this device's calls, newest first (active sessions first)
 *   GET    /v1/devices/calls/:callID      one call (+ transcript while the session is retained in memory)
 *   POST   /v1/devices/calls/demo         {scenario, speed?} → 202 {callID}; 429 too_many_demo_calls
 *   POST   /v1/devices/calls/test-call    {scenario} → 202 {callID}
 *   GET    /v1/devices/calls/live         WebSocket: hello + every LiveEvent for this device
 */

export interface CallDeviceRoutesOptions {
  config: RelayConfig;
  calls: CallsConfig;
  db: RelayDb;
  sessions: CallSessionManager;
  hub: LiveHub;
  demo: DemoCallRunner;
  twilio: TwilioClient | undefined;
  now?: (() => number) | undefined;
}

interface LineBody {
  phoneNumber: string;
  minimumLevel: AlertLevel;
  spokenWarning: boolean;
}

interface DemoBody {
  scenario: DemoScenarioId;
  speed?: number;
}

interface TestCallBody {
  scenario: DemoScenarioId;
}

interface CallParams {
  callID: string;
}

interface ListQuery {
  limit?: number;
}

const BODY_LIMIT = 16 * 1024;
export const DEFAULT_CALLS_LIMIT = 50;
export const MAX_CALLS_LIMIT = 200;
/** Demo calls one device may have running at once: each holds timers and a transcript until it ends (429 beyond). */
export const MAX_ACTIVE_DEMO_CALLS_PER_DEVICE = 3;

const lineSchema = {
  type: "object",
  required: ["phoneNumber", "minimumLevel", "spokenWarning"],
  additionalProperties: false,
  properties: {
    phoneNumber: { type: "string", minLength: 8, maxLength: 16, pattern: E164_PATTERN },
    minimumLevel: { type: "string", enum: [...ALERT_LEVELS] },
    spokenWarning: { type: "boolean" },
  },
} as const;

const demoSchema = {
  type: "object",
  required: ["scenario"],
  additionalProperties: false,
  properties: {
    scenario: { type: "string", enum: [...DEMO_SCENARIO_IDS] },
    speed: { type: "number", minimum: MIN_DEMO_SPEED, maximum: MAX_DEMO_SPEED },
  },
} as const;

const testCallSchema = {
  type: "object",
  required: ["scenario"],
  additionalProperties: false,
  properties: { scenario: { type: "string", enum: [...DEMO_SCENARIO_IDS] } },
} as const;

const callParamsSchema = {
  type: "object",
  required: ["callID"],
  properties: { callID: { type: "string", minLength: 1, maxLength: 128 } },
} as const;

const listQuerySchema = {
  type: "object",
  properties: { limit: { type: "integer", minimum: 1, maximum: MAX_CALLS_LIMIT } },
} as const;

export function lineToJSON(line: CallLine): CallLineJSON {
  return {
    lineID: line.lineId,
    guardNumber: line.guardNumber,
    phoneNumber: line.phoneNumber,
    minimumLevel: line.minimumLevel,
    spokenWarning: line.spokenWarning,
    createdAt: line.createdAt,
  };
}

/**
 * Active in-memory sessions of the device first (their live summary), then persisted records not already
 * listed, newest first, at most `limit`.
 */
export function mergeCallList(active: CallSession[], stored: Iterable<CallSummaryJSON>, limit: number, now: number): CallSummaryJSON[] {
  const seen = new Set<string>();
  const result: CallSummaryJSON[] = [];
  for (const session of [...active].sort((a, b) => b.startedAt - a.startedAt)) {
    seen.add(session.callId);
    result.push(session.toSummaryJSON(now));
  }
  for (const summary of stored) {
    if (seen.has(summary.callID)) continue;
    seen.add(summary.callID);
    result.push(summary);
  }
  return result.slice(0, limit);
}

export function registerCallDeviceRoutes(app: FastifyInstance, options: CallDeviceRoutesOptions): void {
  const { config, calls, db, sessions, hub, demo, twilio } = options;
  const now = options.now ?? Date.now;
  ensureWebSocketPlugin(app);

  app.register(async (scoped) => {
    scoped.addHook("onRequest", apiKeyGuard(config.relayApiKey));
    scoped.addHook("onRequest", deviceAuthGuard(db));

    scoped.put<{ Body: LineBody }>("/v1/devices/call-line", { schema: { body: lineSchema }, bodyLimit: BODY_LIMIT }, async (request, reply) => {
      const device = request.device!;
      const guardNumber = calls.twilio?.number;
      if (!guardNumber) return reply.code(503).send({ error: "twilio_not_configured" });
      const { line, displacedDeviceId } = db.upsertCallLine(
        {
          lineId: randomUUID(),
          deviceId: device.deviceId,
          guardNumber,
          phoneNumber: request.body.phoneNumber,
          minimumLevel: request.body.minimumLevel,
          spokenWarning: request.body.spokenWarning,
        },
        now(),
      );
      if (displacedDeviceId) {
        request.log.warn({ deviceId: device.deviceId, displacedDeviceId, guard: redactNumber(guardNumber) }, "call-line: guard number reassigned");
      }
      request.log.info(
        { deviceId: device.deviceId, lineId: line.lineId, phone: redactNumber(line.phoneNumber), minimumLevel: line.minimumLevel, spokenWarning: line.spokenWarning },
        "call-line: registered",
      );
      return reply.code(200).send(lineToJSON(line));
    });

    scoped.get("/v1/devices/call-line", async (request, reply) => {
      const line = db.findCallLine(request.device!.deviceId);
      if (!line) return reply.code(404).send({ error: "no_line" });
      return reply.code(200).send(lineToJSON(line));
    });

    scoped.delete("/v1/devices/call-line", async (request, reply) => {
      const device = request.device!;
      const removed = db.deleteCallLine(device.deviceId);
      request.log.info({ deviceId: device.deviceId, removed }, "call-line: removed");
      return reply.code(204).send();
    });

    scoped.get<{ Querystring: ListQuery }>("/v1/devices/calls", { schema: { querystring: listQuerySchema } }, async (request, reply) => {
      const deviceId = request.device!.deviceId;
      const limit = request.query.limit ?? DEFAULT_CALLS_LIMIT;
      const at = now();
      const stored = db.listCalls(deviceId, limit).map((record) => recordToSummaryJSON(record, at));
      return reply.code(200).send({ calls: mergeCallList(sessions.activeForDevice(deviceId), stored, limit, at) });
    });

    scoped.get<{ Params: CallParams }>("/v1/devices/calls/:callID", { schema: { params: callParamsSchema } }, async (request, reply) => {
      const deviceId = request.device!.deviceId;
      const session = sessions.get(request.params.callID);
      if (session) {
        if (session.deviceId !== deviceId) return reply.code(404).send({ error: "not_found" });
        const transcript: TranscriptSegment[] = [...session.segments];
        return reply.code(200).send({ ...session.toSummaryJSON(now()), transcript });
      }
      const record = db.findCall(request.params.callID);
      if (!record || record.deviceId !== deviceId) return reply.code(404).send({ error: "not_found" });
      return reply.code(200).send(recordToSummaryJSON(record, now()));
    });

    scoped.post<{ Body: DemoBody }>("/v1/devices/calls/demo", { schema: { body: demoSchema }, bodyLimit: BODY_LIMIT }, async (request, reply) => {
      if (!calls.demoEnabled) return reply.code(403).send({ error: "demo_disabled" });
      const deviceId = request.device!.deviceId;
      const running = sessions.activeForDevice(deviceId).filter((session) => session.source === "demo").length;
      if (running >= MAX_ACTIVE_DEMO_CALLS_PER_DEVICE) return reply.code(429).send({ error: "too_many_calls" });
      const line = db.findCallLine(deviceId) ?? null;
      const session = demo.start({ deviceId, line, scenario: request.body.scenario, speed: request.body.speed });
      return reply.code(202).send({ callID: session.callId });
    });

    scoped.post<{ Body: TestCallBody }>("/v1/devices/calls/test-call", { schema: { body: testCallSchema }, bodyLimit: BODY_LIMIT }, async (request, reply) => {
      if (!twilio) return reply.code(503).send({ error: "twilio_not_configured" });
      const deviceId = request.device!.deviceId;
      const line = db.findCallLine(deviceId);
      if (!line) return reply.code(409).send({ error: "no_line" });
      const session = await startTestCall({ sessions, twilio, calls, line, scenario: request.body.scenario, now, log: request.log });
      if (!session) return reply.code(502).send({ error: "twilio_error" });
      return reply.code(202).send({ callID: session.callId });
    });

    scoped.get("/v1/devices/calls/live", { websocket: true }, (socket, request) => {
      hub.subscribeDevice(request.device!.deviceId, socket);
    });
  });
}

export interface StartTestCallInput {
  sessions: CallSessionManager;
  twilio: TwilioClient;
  calls: CallsConfig;
  line: CallLine;
  scenario: DemoScenarioId;
  now: () => number;
  log: { info: (obj: object, msg: string) => void; error: (obj: object, msg: string) => void };
}

/**
 * Creates the `test-call` session (status `ringing`) and asks Twilio to dial the protected phone from the guard
 * number with the scenario's spoken script (docs/CALLS.md §7.2). Shared by the device route and the console.
 * Resolves undefined (and ends the session as `failed`) when Twilio refuses the call.
 */
export async function startTestCall(input: StartTestCallInput): Promise<CallSession | undefined> {
  const { sessions, twilio, calls, line, scenario, now, log } = input;
  const source = calls.transcriptionSource;
  const session = sessions.create({
    deviceId: line.deviceId,
    line,
    source: "test-call",
    callerNumber: line.guardNumber,
    calledNumber: line.phoneNumber,
    startedAt: now(),
    status: "ringing",
    ...(source === "twilio" || source === "openai" ? { transcriptionSource: source } : {}),
  });
  try {
    const sid = await twilio.placeTestCall(session, scenario);
    if (!session.twilioCallSid) session.twilioCallSid = sid;
    sessions.index(session, sid);
    log.info({ callId: session.callId, deviceId: line.deviceId, scenario, phone: redactNumber(line.phoneNumber) }, "test-call: placed");
    return session;
  } catch (error) {
    // Fields only: a Twilio RestException names the dialled number in full (error 21219 on a trial account).
    log.error({ reason: twilioErrorFields(error), callId: session.callId, deviceId: line.deviceId, scenario }, "test-call: Twilio refused the call");
    session.end("failed");
    return undefined;
  }
}

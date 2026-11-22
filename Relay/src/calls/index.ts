import type { FastifyInstance } from "fastify";

import type { PushSender } from "../apns.js";
import type { RelayConfig } from "../config.js";
import type { RelayDb } from "../db.js";
import { CallAlertDispatcher } from "./alerts/dispatcher.js";
import { VoiceAlertDispatcher } from "./alerts/voiceDispatcher.js";
import type { CallsConfig } from "./config.js";
import { DemoCallRunner } from "./demo/runner.js";
import { isDemoScenarioId, scriptForScenario } from "./demo/scenarios.js";
import { LiveHub } from "./live/hub.js";
import { registerConsoleRoutes } from "./live/console.js";
import { createVoiceDetector } from "./modulate/voiceDetector.js";
import { createTranscriber } from "./openai/transcriber.js";
import { createModelScorer, type ModelScorer } from "./openai/scorer.js";
import { registerCallDeviceRoutes } from "./routes/devices.js";
import { ScamDetector } from "./scoring/detector.js";
import { CallSessionManager } from "./session.js";
import { createTwilioClient, type TwilioClient } from "./twilio/client.js";
import { registerTwilioRoutes } from "./twilio/routes.js";
import { ensureWebPlugins } from "./websocket.js";
import type { Transcriber, VoiceDetector } from "./types.js";

/**
 * Call Guard wiring (docs/CALLS.md §3). `buildApp` calls this when `config.calls` is set; tests inject fakes
 * for the three external services through `CallsDependencies`.
 *
 * Attach order on `created` matters: the live hub first (so the console sees every event), then the detector
 * (verdicts), then the alert dispatcher (reacts to verdicts), then the AI-voice dispatcher (reacts to `voice`
 * events only, which never fire without a voice detector or a demo call's `aiVoice` flag).
 */

export interface CallsDependencies {
  config: RelayConfig;
  calls: CallsConfig;
  db: RelayDb;
  pushSender: PushSender;
  /** Twilio REST + TwiML; `undefined` in tests that never reach Twilio. Defaults to the SDK client when configured. */
  twilio?: TwilioClient | undefined;
  /** OpenAI Realtime transcription; defaults to the real client when `OPENAI_API_KEY` is set, else a no-op. */
  transcriber?: Transcriber | undefined;
  /** OpenAI text scorer; defaults to the real client when `OPENAI_API_KEY` is set, else rules-only. */
  scorer?: ModelScorer | undefined;
  /** Modulate AI-voice detection on the caller's audio; defaults to the real client when `MODULATE_API_KEY` is set, else none. */
  voiceDetector?: VoiceDetector | undefined;
  now?: () => number;
}

export interface CallsRuntime {
  sessions: CallSessionManager;
  hub: LiveHub;
  detector: ScamDetector;
  dispatcher: CallAlertDispatcher;
  voiceDispatcher: VoiceAlertDispatcher;
  demo: DemoCallRunner;
  close(): Promise<void>;
}

declare module "fastify" {
  interface FastifyInstance {
    callGuard: CallsRuntime;
  }
}

export function registerCalls(app: FastifyInstance, deps: CallsDependencies): CallsRuntime {
  const { config, calls, db, pushSender } = deps;
  const now = deps.now ?? Date.now;
  const log = app.log.child({ module: "calls" });

  const sessions = new CallSessionManager({
    store: db,
    retainEndedMs: calls.retainEndedMs,
    now,
    onError: (error, context) => log.error({ err: error, context }, "calls: session persistence failed"),
  });

  const twilio: TwilioClient | undefined =
    deps.twilio ?? (calls.twilio ? createTwilioClient({ config: calls.twilio, publicBaseUrl: config.publicBaseUrl, logger: log }) : undefined);
  const transcriber: Transcriber | undefined =
    deps.transcriber ?? (calls.openai ? createTranscriber({ config: calls.openai, logger: log }) : undefined);
  const scorer: ModelScorer | undefined =
    deps.scorer ?? (calls.openai ? createModelScorer({ config: calls.openai, logger: log }) : undefined);
  const voiceDetector: VoiceDetector | undefined =
    deps.voiceDetector ?? (calls.voice ? createVoiceDetector({ config: calls.voice, logger: log, now }) : undefined);

  const hub = new LiveHub({ sessions, logger: log, now });
  const detector = new ScamDetector({ scorer, config: calls, logger: log, now });
  const voiceDispatcher = new VoiceAlertDispatcher({
    db,
    pushSender,
    apnsConfigured: config.apns !== undefined,
    voice: twilio,
    config: calls,
    logger: log,
    now,
    // Late-bound: the scam dispatcher is built next and takes this one as its `voiceAddendum`.
    scamAlertInFlight: (callId) => dispatcher.isAlerting(callId),
  });
  const dispatcher: CallAlertDispatcher = new CallAlertDispatcher({
    db,
    pushSender,
    apnsConfigured: config.apns !== undefined,
    voice: twilio,
    config: calls,
    logger: log,
    now,
    voiceAddendum: voiceDispatcher,
  });
  const demo = new DemoCallRunner({ sessions, logger: log, now });

  sessions.on("created", (session) => {
    hub.attach(session);
    detector.attach(session);
    dispatcher.attach(session);
    voiceDispatcher.attach(session);
  });

  app.decorate("callGuard", { sessions, hub, detector, dispatcher, voiceDispatcher, demo, close } satisfies CallsRuntime);

  // Shutdown order (docs/CALLS.md §4): live subscribers are terminated in `preClose`, before Fastify waits for the
  // HTTP server to drain — a subscriber that never answers the close handshake (a phone that dropped off the
  // network) would otherwise hold `app.close()`, and with it the persistence in `close()` below, for ws's 30 s
  // close timeout. `close()` then runs from `onClose`: demo timers, detector, hub (already empty), sessions.
  app.addHook("preClose", async () => hub.close());

  // @fastify/formbody + @fastify/websocket exactly once, at the root, before any route module that needs them.
  ensureWebPlugins(app);
  registerCallDeviceRoutes(app, { config, calls, db, sessions, hub, demo, twilio, now });
  // A test call speaks the scenario the app or the console chose (docs/CALLS.md §7.2); an unknown id gets the built-in script.
  const testCallScript = (scenarioId: string) => (isDemoScenarioId(scenarioId) ? scriptForScenario(scenarioId) : undefined);
  registerTwilioRoutes(app, { config, calls, db, sessions, twilio, transcriber, voiceDetector, logger: log, now, testCallScript });
  if (calls.consoleEnabled) registerConsoleRoutes(app, { config, calls, db, sessions, hub, demo, twilio, transcriber, voiceDetector, now });

  // Old call records are pruned once at start-up and then daily.
  const prune = (): void => {
    try {
      const removed = db.pruneCalls(now() - calls.retentionDays * 24 * 60 * 60 * 1000);
      if (removed > 0) log.info({ removed }, "calls: pruned old records");
    } catch (error) {
      log.error({ err: error }, "calls: prune failed");
    }
  };
  prune();
  const pruneTimer = setInterval(prune, 24 * 60 * 60 * 1000);
  pruneTimer.unref();

  async function close(): Promise<void> {
    clearInterval(pruneTimer);
    demo.close();
    voiceDispatcher.close();
    await detector.close();
    // Every vendor socket is torn down at once (no end-of-stream grace); a failure here must not skip the persistence below.
    await voiceDetector?.close().catch((error: unknown) => {
      log.error({ errorName: error instanceof Error ? error.name : "unknown" }, "calls: voice detector close failed");
    });
    hub.close();
    sessions.close();
  }

  log.info(
    {
      twilio: twilio !== undefined,
      openai: calls.openai !== undefined,
      voice: voiceDetector !== undefined,
      apns: config.apns !== undefined,
      demo: calls.demoEnabled,
      console: calls.consoleEnabled,
    },
    "calls: Call Guard ready",
  );

  return { sessions, hub, detector, dispatcher, voiceDispatcher, demo, close };
}

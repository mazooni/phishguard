import type { FastifyBaseLogger } from "fastify";
import { WebSocket } from "ws";

import type { CallSession, CallSessionManager } from "../session.js";
import type { LiveEvent, SessionObserver } from "../types.js";

/**
 * Fan-out of `LiveEvent`s (docs/CALLS.md §4, §5.1 live route, §5.3 console). Every session's events go to the
 * sockets of its device and to every console socket; a new subscriber gets `hello` with the active calls and
 * then, per active call, the current verdict and the last 50 segments as ordinary events. There is no queue per
 * socket beyond ws's own send buffer: a socket that fails to send, closes, or falls too far behind is dropped.
 */

export const CATCH_UP_SEGMENTS = 50;
/** A subscriber whose socket buffer grows past this is too slow to be worth keeping (it is a live feed). */
export const MAX_BUFFERED_BYTES = 1024 * 1024;

export interface LiveHubOptions {
  sessions: CallSessionManager;
  logger: FastifyBaseLogger;
  now: () => number;
}

const CONSOLE = Symbol("console");

export class LiveHub implements SessionObserver {
  private readonly deviceSockets = new Map<string, Set<WebSocket>>();
  private readonly consoleSockets = new Set<WebSocket>();
  /** Reverse index: which subscription a socket belongs to. */
  private readonly owners = new Map<WebSocket, string | typeof CONSOLE>();

  constructor(private readonly options: LiveHubOptions) {}

  get subscriberCount(): { devices: number; consoles: number } {
    let devices = 0;
    for (const set of this.deviceSockets.values()) devices += set.size;
    return { devices, consoles: this.consoleSockets.size };
  }

  attach(session: CallSession): void {
    const callID = session.callId;
    this.broadcast(session.deviceId, { type: "call.started", call: session.toSummaryJSON(this.options.now()) });
    session.on("status", (status) => this.broadcast(session.deviceId, { type: "call.status", callID, status }));
    session.on("segment", (segment) => this.broadcast(session.deviceId, { type: "transcript.segment", callID, segment }));
    session.on("verdict", (verdict) => this.broadcast(session.deviceId, { type: "verdict.updated", callID, verdict }));
    session.on("alert", (alert) => this.broadcast(session.deviceId, { type: "call.alert", callID, alert }));
    session.on("ended", () => this.broadcast(session.deviceId, { type: "call.ended", call: session.toSummaryJSON(this.options.now()) }));
  }

  subscribeDevice(deviceId: string, socket: WebSocket): void {
    let set = this.deviceSockets.get(deviceId);
    if (!set) {
      set = new Set();
      this.deviceSockets.set(deviceId, set);
    }
    set.add(socket);
    this.owners.set(socket, deviceId);
    this.wire(socket);
    const active = this.options.sessions.activeForDevice(deviceId);
    this.sendHello(socket, active);
  }

  subscribeConsole(socket: WebSocket): void {
    this.consoleSockets.add(socket);
    this.owners.set(socket, CONSOLE);
    this.wire(socket);
    this.sendHello(socket, this.options.sessions.active());
  }

  /** Terminates every subscriber (shutdown). */
  close(): void {
    for (const socket of this.owners.keys()) {
      try {
        socket.terminate();
      } catch {
        // already gone
      }
    }
    this.owners.clear();
    this.deviceSockets.clear();
    this.consoleSockets.clear();
  }

  // MARK: internals

  private wire(socket: WebSocket): void {
    socket.on("message", (raw) => {
      let message: unknown;
      try {
        message = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (typeof message === "object" && message !== null && (message as { type?: unknown }).type === "ping") {
        this.send(socket, { type: "pong" });
      }
    });
    socket.on("close", () => this.drop(socket));
    socket.on("error", (error) => {
      this.options.logger.debug({ err: error }, "live: socket error");
      this.drop(socket, true);
    });
  }

  private sendHello(socket: WebSocket, active: CallSession[]): void {
    const now = this.options.now();
    this.send(socket, { type: "hello", activeCalls: active.map((session) => session.toSummaryJSON(now)), serverTime: now });
    for (const session of active) {
      const callID = session.callId;
      if (session.verdict) this.send(socket, { type: "verdict.updated", callID, verdict: session.verdict });
      const segments = session.segments;
      const start = Math.max(0, segments.length - CATCH_UP_SEGMENTS);
      for (let i = start; i < segments.length; i += 1) {
        this.send(socket, { type: "transcript.segment", callID, segment: segments[i]! });
      }
    }
  }

  private broadcast(deviceId: string, event: LiveEvent): void {
    const encoded = JSON.stringify(event);
    const targets = this.deviceSockets.get(deviceId);
    if (targets) for (const socket of targets) this.sendRaw(socket, encoded);
    for (const socket of this.consoleSockets) this.sendRaw(socket, encoded);
  }

  private send(socket: WebSocket, event: LiveEvent): void {
    this.sendRaw(socket, JSON.stringify(event));
  }

  private sendRaw(socket: WebSocket, encoded: string): void {
    if (socket.readyState !== WebSocket.OPEN) {
      this.drop(socket, true);
      return;
    }
    if (socket.bufferedAmount > MAX_BUFFERED_BYTES) {
      this.options.logger.warn("live: subscriber too slow; dropping");
      this.drop(socket, true);
      return;
    }
    try {
      socket.send(encoded, (error) => {
        if (error) this.drop(socket, true);
      });
    } catch {
      this.drop(socket, true);
    }
  }

  private drop(socket: WebSocket, terminate = false): void {
    const owner = this.owners.get(socket);
    if (owner === undefined) return;
    this.owners.delete(socket);
    if (owner === CONSOLE) {
      this.consoleSockets.delete(socket);
    } else {
      const set = this.deviceSockets.get(owner);
      if (set) {
        set.delete(socket);
        if (set.size === 0) this.deviceSockets.delete(owner);
      }
    }
    if (terminate) {
      try {
        socket.terminate();
      } catch {
        // already gone
      }
    }
  }
}

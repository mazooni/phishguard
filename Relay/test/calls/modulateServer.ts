import { once } from "node:events";
import type { IncomingHttpHeaders, IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { WebSocketServer, type WebSocket } from "ws";

/**
 * An in-process `ws` server that speaks Modulate's documented streaming protocol (docs.modulate.ai "Deepfake
 * Detection Streaming"): binary audio frames in, an empty TEXT frame as end of stream, then `frame` messages, a
 * `done` message and a 1000 close. It is the only stand-in for the real vendor in this test suite: the real
 * default socket factory of src/calls/modulate/voiceDetector.ts connects to it over a real socket.
 */

export interface ModulateConnection {
  /** Path and query string of the upgrade request, exactly as the client sent them. */
  requestUrl: string;
  headers: IncomingHttpHeaders;
  /** Every WebSocket message received, in order, with its frame type. */
  messages: { binary: boolean; data: Buffer }[];
}

export interface ModulateServerScript {
  /** Runs when a client connects (e.g. to refuse it with an `error` message and a close code). */
  onConnect?: (socket: WebSocket, connection: ModulateConnection) => void;
  /** Runs when the empty TEXT frame arrives. Default: `replyDone(socket, connection, [])`. */
  onEndOfStream?: (socket: WebSocket, connection: ModulateConnection) => void;
  /** Holds the upgrade back this long, like a TLS handshake to a server that is not on this machine. */
  handshakeDelayMs?: number;
  /** Answers the upgrade with this HTTP status instead of accepting it. */
  rejectUpgradeWith?: number;
}

export interface FakeModulateServer {
  /** `ws://127.0.0.1:<port>/api/velma-2-synthetic-voice-detection-streaming` — the endpoint without a query string. */
  url: string;
  connections: ModulateConnection[];
  /** Upgrade requests received, accepted or not. */
  upgradeAttempts(): number;
  close(): Promise<void>;
}

export interface ServerFrame {
  start_time_ms: number;
  end_time_ms: number;
  verdict: "synthetic" | "non-synthetic" | "no-content";
  confidence: number;
}

/** The documented tail of a stream: the remaining frames, `done`, then a normal closure. */
export function replyDone(socket: WebSocket, connection: ModulateConnection, frames: ServerFrame[]): void {
  for (const frame of frames) socket.send(JSON.stringify({ type: "frame", frame }));
  const audioBytes = connection.messages.filter((message) => message.binary).reduce((sum, message) => sum + message.data.length, 0);
  socket.send(JSON.stringify({ type: "done", duration_ms: Math.round(audioBytes / 8), frame_count: frames.length }));
  socket.close(1000);
}

/** The documented refusal: an `error` message, then the close code. */
export function refuse(socket: WebSocket, code: number, error: string): void {
  socket.send(JSON.stringify({ type: "error", error }));
  socket.close(code);
}

export async function startModulateServer(script: ModulateServerScript = {}): Promise<FakeModulateServer> {
  let upgradeAttempts = 0;
  const server = new WebSocketServer({
    port: 0,
    host: "127.0.0.1",
    verifyClient: (_info, done) => {
      upgradeAttempts += 1;
      const answer = (): void => (script.rejectUpgradeWith !== undefined ? done(false, script.rejectUpgradeWith, "refused") : done(true));
      if (script.handshakeDelayMs) setTimeout(answer, script.handshakeDelayMs);
      else answer();
    },
  });
  await once(server, "listening");
  const connections: ModulateConnection[] = [];
  server.on("connection", (socket: WebSocket, request: IncomingMessage) => {
    const connection: ModulateConnection = { requestUrl: request.url ?? "", headers: request.headers, messages: [] };
    connections.push(connection);
    socket.on("message", (data, isBinary) => {
      const bytes = Buffer.isBuffer(data) ? data : Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data);
      connection.messages.push({ binary: isBinary, data: bytes });
      if (!isBinary && bytes.length === 0) {
        if (script.onEndOfStream) script.onEndOfStream(socket, connection);
        else replyDone(socket, connection, []);
      }
    });
    script.onConnect?.(socket, connection);
  });
  const { port } = server.address() as AddressInfo;
  return {
    url: `ws://127.0.0.1:${port}/api/velma-2-synthetic-voice-detection-streaming`,
    connections,
    upgradeAttempts: () => upgradeAttempts,
    close: () =>
      new Promise((resolve) => {
        for (const client of server.clients) client.terminate();
        server.close(() => resolve());
      }),
  };
}

import { WebSocket } from "ws";

import type { LiveEvent } from "../../src/calls/types.js";

/**
 * A tiny WebSocket client for the live-feed tests: collects every JSON frame and hands them out in order.
 * `open()` rejects with the HTTP status when the upgrade is refused (e.g. 401 from the auth guards).
 */
export class LiveClient {
  readonly socket: WebSocket;
  readonly received: LiveEvent[] = [];
  private readonly waiters: ((event: LiveEvent) => void)[] = [];
  private queue: LiveEvent[] = [];
  closed = false;
  closeCode: number | undefined;

  constructor(url: string, headers: Record<string, string> = {}) {
    this.socket = new WebSocket(url, { headers });
    this.socket.on("message", (raw) => {
      const event = JSON.parse(raw.toString()) as LiveEvent;
      this.received.push(event);
      const waiter = this.waiters.shift();
      if (waiter) waiter(event);
      else this.queue.push(event);
    });
    this.socket.on("close", (code) => {
      this.closed = true;
      this.closeCode = code;
    });
  }

  static async connect(url: string, headers: Record<string, string> = {}): Promise<LiveClient> {
    const client = new LiveClient(url, headers);
    await client.open();
    return client;
  }

  open(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket.once("open", () => resolve());
      this.socket.once("unexpected-response", (_request, response) => {
        reject(new Error(`upgrade refused: ${response.statusCode}`));
        this.socket.terminate();
      });
      this.socket.once("error", (error) => reject(error));
    });
  }

  /** The next event, optionally skipping events of other types. */
  next(type?: LiveEvent["type"], timeoutMs = 2000): Promise<LiveEvent> {
    return new Promise((resolve, reject) => {
      // Already-received events first; events of other types are skipped (consumed), as on the live path.
      while (this.queue.length > 0) {
        const event = this.queue.shift()!;
        if (!type || event.type === type) {
          resolve(event);
          return;
        }
      }
      const timer = setTimeout(() => reject(new Error(`timed out waiting for ${type ?? "an event"}`)), timeoutMs);
      const take = (event: LiveEvent): void => {
        if (type && event.type !== type) {
          this.waiters.push(take);
          return;
        }
        clearTimeout(timer);
        resolve(event);
      };
      this.waiters.push(take);
    });
  }

  /** Waits until `count` events (of `type`, when given) have been received in total. */
  async collect(count: number, type?: LiveEvent["type"], timeoutMs = 2000): Promise<LiveEvent[]> {
    const deadline = Date.now() + timeoutMs;
    const matching = (): LiveEvent[] => this.received.filter((event) => !type || event.type === type);
    while (matching().length < count) {
      if (Date.now() > deadline) throw new Error(`timed out: ${matching().length}/${count} ${type ?? "events"}`);
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    return matching();
  }

  send(message: unknown): void {
    this.socket.send(JSON.stringify(message));
  }

  close(): Promise<void> {
    if (this.closed) return Promise.resolve();
    return new Promise((resolve) => {
      this.socket.once("close", () => resolve());
      this.socket.close();
    });
  }
}

export function waitFor(condition: () => boolean, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tick = (): void => {
      if (condition()) {
        resolve();
        return;
      }
      if (Date.now() > deadline) {
        reject(new Error("waitFor: condition not met in time"));
        return;
      }
      setTimeout(tick, 2);
    };
    tick();
  });
}

/** Lets pending promise callbacks (the dispatcher's async handler) run. */
export async function flushPromises(turns = 4): Promise<void> {
  for (let i = 0; i < turns; i += 1) await new Promise((resolve) => setImmediate(resolve));
}

/**
 * Replays a WAV recording into the relay exactly as Twilio Media Streams would (docs/CALLS.md §4 `replay`,
 * docs/research/twilio.md §1.3): it asks the console for a `replay` session, connects to that session's media
 * WebSocket and sends `connected`, `start`, one 160-byte μ-law `media` frame per track every 20 ms, then `stop`,
 * and finally ends the session. Mono files are the caller only; stereo files use channel 0 as the caller and
 * channel 1 as the protected person.
 *
 *   npm run calls:replay -- call.wav --base http://localhost:8080 --key <RELAY_API_KEY> --line <lineID> [--rate 1] [--tail 4]
 *   npm run calls:replay -- call.wav --device <deviceID> …        (a registered device without a line, e.g. no Twilio)
 *
 * `--base` and `--key` default to PUBLIC_BASE_URL and RELAY_API_KEY from Relay/.env (the npm script loads it).
 * The relay needs OPENAI_API_KEY: the audio goes to the OpenAI transcriber (503 openai_not_configured otherwise).
 * Nothing here needs ffmpeg: WAV parsing, resampling to 8 kHz and G.711 μ-law encoding are in src/calls/audio.ts.
 */

import { readFile } from "node:fs/promises";
import { WebSocket } from "ws";

import { MULAW_FRAME_MS, MULAW_SAMPLE_RATE, mulawEncode, parseWav, resample, splitFrames } from "../src/calls/audio.js";

/** Who the replay is for: a line, or a registered device without one (a relay without Twilio has no lines). */
type ReplayTarget = { lineID: string } | { deviceID: string };

interface Args {
  file: string;
  base: string;
  key: string;
  target: ReplayTarget;
  rate: number;
  tailSeconds: number;
}

function usage(message?: string): never {
  if (message) console.error(`error: ${message}\n`);
  console.error(
    "usage: npm run calls:replay -- <file.wav> --base http://localhost:8080 --key <RELAY_API_KEY> (--line <lineID> | --device <deviceID>) [--rate 1] [--tail 4]\n" +
      "  --base / --key default to PUBLIC_BASE_URL / RELAY_API_KEY from Relay/.env; lineIDs and deviceIDs are on the console page.",
  );
  process.exit(2);
}

function parseArgs(argv: string[]): Args {
  let file: string | undefined;
  const options = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg.startsWith("--")) {
      const value = argv[i + 1];
      if (value === undefined) usage(`${arg} needs a value`);
      options.set(arg.slice(2), value);
      i += 1;
    } else if (!file) {
      file = arg;
    } else {
      usage(`unexpected argument ${arg}`);
    }
  }
  if (!file) usage("missing <file.wav>");
  const base = options.get("base") ?? process.env["PUBLIC_BASE_URL"] ?? "http://localhost:8080";
  const key = options.get("key") ?? process.env["RELAY_API_KEY"];
  const line = options.get("line");
  const device = options.get("device");
  if (!key) usage("--key (or RELAY_API_KEY in Relay/.env) is required");
  if (line && device) usage("give either --line or --device, not both");
  const target: ReplayTarget | undefined = line ? { lineID: line } : device ? { deviceID: device } : undefined;
  if (!target) usage("--line <lineID> (the console page, or GET /v1/devices/call-line) or --device <deviceID> (a registered device) is required");
  const rate = Number(options.get("rate") ?? "1");
  if (!Number.isFinite(rate) || rate <= 0 || rate > 50) usage("--rate must be between 0 and 50");
  const tailSeconds = Number(options.get("tail") ?? "4");
  if (!Number.isFinite(tailSeconds) || tailSeconds < 0 || tailSeconds > 120) usage("--tail must be between 0 and 120 seconds");
  return { file, base: base.replace(/\/+$/, ""), key, target, rate, tailSeconds };
}

/** What the relay's refusal means for the person at the keyboard. */
function refusalHint(error: string | undefined): string {
  switch (error) {
    case "openai_not_configured":
      return " — a replay needs OPENAI_API_KEY on the relay (scripted demos do not: use the console's Start demo call)";
    case "unknown_device":
      return " — no device with that id is registered on the relay (the console page lists them)";
    case "no_line":
      return " — no line with that id (the console page lists them; without Twilio use --device)";
    case "unauthorized":
      return " — the key does not match the relay's RELAY_API_KEY";
    default:
      return "";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface ReplayTicket {
  callID: string;
  mediaToken: string;
  mediaPath: string;
}

async function requestSession(args: Args): Promise<ReplayTicket> {
  const response = await fetch(`${args.base}/v1/calls/console/replay`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": args.key },
    body: JSON.stringify(args.target),
  });
  const body = (await response.json().catch(() => ({}))) as Partial<ReplayTicket> & { error?: string };
  if (!response.ok || !body.callID || !body.mediaToken || !body.mediaPath) {
    throw new Error(`relay refused the replay session: HTTP ${response.status} ${body.error ?? ""}${refusalHint(body.error)}`.trim());
  }
  return { callID: body.callID, mediaToken: body.mediaToken, mediaPath: body.mediaPath };
}

async function endSession(args: Args, callID: string): Promise<void> {
  const response = await fetch(`${args.base}/v1/calls/console/replay/end`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": args.key },
    body: JSON.stringify({ callID }),
  });
  if (!response.ok) console.error(`warning: could not end the session (HTTP ${response.status}); the relay will end it on its own`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const wav = parseWav(new Uint8Array(await readFile(args.file)));
  const callerPcm = resample(wav.channels[0]!, wav.sampleRate, MULAW_SAMPLE_RATE);
  const userPcm = wav.channels[1] ? resample(wav.channels[1], wav.sampleRate, MULAW_SAMPLE_RATE) : undefined;
  const inbound = splitFrames(mulawEncode(callerPcm));
  const outbound = userPcm ? splitFrames(mulawEncode(userPcm)) : undefined;
  const frameCount = Math.max(inbound.length, outbound?.length ?? 0);
  console.log(
    `${args.file}: ${wav.channels.length} channel(s) @ ${wav.sampleRate} Hz → ${frameCount} frames of ${MULAW_FRAME_MS} ms ` +
      `(${(frameCount * MULAW_FRAME_MS) / 1000} s) at ${args.rate}× real time`,
  );

  const ticket = await requestSession(args);
  console.log(`session ${ticket.callID} created; streaming to ${ticket.mediaPath}`);
  try {
    await stream(args, ticket, inbound, outbound, frameCount);
  } catch (error) {
    // Never leave a half-fed replay session live on the relay.
    await endSession(args, ticket.callID).catch(() => undefined);
    throw error;
  }
  await endSession(args, ticket.callID);
  console.log(`done; call ${ticket.callID} ended (see the console page or GET /v1/devices/calls/${ticket.callID})`);
}

async function stream(args: Args, ticket: ReplayTicket, inbound: Uint8Array[], outbound: Uint8Array[] | undefined, frameCount: number): Promise<void> {
  const wsBase = args.base.replace(/^http/i, "ws");
  const socket = new WebSocket(`${wsBase}${ticket.mediaPath}`, { headers: { "x-api-key": args.key } });
  await new Promise<void>((resolve, reject) => {
    socket.once("open", () => resolve());
    socket.once("error", reject);
    socket.once("unexpected-response", (_request, response) => reject(new Error(`media socket refused: HTTP ${response.statusCode}`)));
  });
  socket.on("error", (error) => console.error(`socket error: ${error.message}`));

  const streamSid = `MZreplay${ticket.callID.replace(/-/g, "").slice(0, 26)}`;
  const callSid = `CAreplay${ticket.callID.replace(/-/g, "").slice(0, 26)}`;
  let sequence = 0;
  const send = (message: Record<string, unknown>): void => {
    sequence += 1;
    socket.send(JSON.stringify({ ...message, sequenceNumber: String(sequence) }));
  };
  send({ event: "connected", protocol: "Call", version: "1.0.0" });
  send({
    event: "start",
    start: {
      accountSid: "ACreplay00000000000000000000000000",
      streamSid,
      callSid,
      tracks: outbound ? ["inbound", "outbound"] : ["inbound"],
      mediaFormat: { encoding: "audio/x-mulaw", sampleRate: MULAW_SAMPLE_RATE, channels: 1 },
      customParameters: { callID: ticket.callID },
    },
    streamSid,
  });

  const startedAt = Date.now();
  // Twilio numbers chunks per track (docs/research/twilio.md §1.3).
  const chunks = { inbound: 0, outbound: 0 };
  for (let i = 0; i < frameCount; i += 1) {
    if (socket.readyState !== WebSocket.OPEN) throw new Error("media socket closed by the relay");
    const due = startedAt + (i * MULAW_FRAME_MS) / args.rate;
    const wait = due - Date.now();
    if (wait > 0) await sleep(wait);
    const timestamp = String(i * MULAW_FRAME_MS);
    const frameIn = inbound[i];
    if (frameIn) {
      chunks.inbound += 1;
      send({ event: "media", media: { track: "inbound", chunk: String(chunks.inbound), timestamp, payload: Buffer.from(frameIn).toString("base64") }, streamSid });
    }
    const frameOut = outbound?.[i];
    if (frameOut) {
      chunks.outbound += 1;
      send({ event: "media", media: { track: "outbound", chunk: String(chunks.outbound), timestamp, payload: Buffer.from(frameOut).toString("base64") }, streamSid });
    }
    if (i % 250 === 0) process.stdout.write(`\r${((i * MULAW_FRAME_MS) / 1000).toFixed(1)} s sent`);
  }
  process.stdout.write(`\r${((frameCount * MULAW_FRAME_MS) / 1000).toFixed(1)} s sent\n`);
  send({ event: "stop", stop: { accountSid: "ACreplay00000000000000000000000000", callSid }, streamSid });
  await sleep(200);
  socket.close();

  if (args.tailSeconds > 0) {
    console.log(`waiting ${args.tailSeconds} s for the transcriber and the final verdict…`);
    await sleep(args.tailSeconds * 1000);
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

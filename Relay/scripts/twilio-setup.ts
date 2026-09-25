import { pathToFileURL } from "node:url";
import twilio from "twilio";
import type { IncomingPhoneNumberContextUpdateOptions } from "twilio/lib/rest/api/v2010/account/incomingPhoneNumber.js";

import { ConfigError, loadConfig } from "../src/config.js";

/**
 * `npm run calls:setup` — one-shot: points the guard number's voice webhook and status callback at
 * `PUBLIC_BASE_URL` and prints the account type with the trial caveats (docs/CALLS.md §9, §11; docs/research/
 * twilio.md §3.1, §5). Reads the same `.env` as `npm run dev`. Idempotent: run it again after the tunnel URL changes.
 */

export interface SetupNumber {
  sid: string;
  phoneNumber: string;
  update(params: IncomingPhoneNumberContextUpdateOptions): Promise<unknown>;
}

export interface SetupAccount {
  type: string;
  friendlyName: string;
  status: string;
}

/** The two Twilio calls the script makes, as a port so tests run it without the network. */
export interface SetupClient {
  listNumbers(phoneNumber: string): Promise<SetupNumber[]>;
  fetchAccount(): Promise<SetupAccount>;
}

export interface SetupIO {
  env: NodeJS.ProcessEnv;
  /** Defaults to the twilio SDK. */
  client?: SetupClient;
  out: (line: string) => void;
}

export const TRIAL_CAVEATS: readonly string[] = [
  "Calls only to and from verified numbers (Console › Phone Numbers › Verified Caller IDs, up to five) — the phone that plays the scammer must be verified too.",
  "A spoken \"press any key\" preamble may play before the call connects.",
  "10 minutes per call, 75 free minutes in total, and the trial expires 30 days after sign-up.",
  "<Stream> (Media Streams) is blocked: CALLS_TRANSCRIPTION_SOURCE=auto uses Twilio's own <Transcription> instead of OpenAI Realtime.",
  "<Dial><Number> is blocked; Call Guard uses <Dial><Conference> + the Participants API, which are allowed.",
  "A small prepaid balance removes every restriction.",
];

export function sdkSetupClient(accountSid: string, authToken: string): SetupClient {
  const client = twilio(accountSid, authToken);
  return {
    listNumbers: async (phoneNumber) => {
      const numbers = await client.incomingPhoneNumbers.list({ phoneNumber, limit: 5 });
      return numbers.map((number) => ({
        sid: number.sid,
        phoneNumber: number.phoneNumber,
        // Not `number.update(params)`: in twilio-node 6.1.1 the instance method of a *listed* number throws
        // "Parameter 'sid' is not valid" (its context is built without the SID); the context form works.
        update: (params) => client.incomingPhoneNumbers(number.sid).update(params),
      }));
    },
    fetchAccount: async () => {
      const account = await client.api.v2010.accounts(accountSid).fetch();
      return { type: account.type, friendlyName: account.friendlyName, status: account.status };
    },
  };
}

/**
 * One message for a failed Twilio API call, naming what to check. Only the message, code and status are used —
 * never the auth token — and the account SID Twilio echoes back is not a secret.
 */
export function describeSetupFailure(error: unknown): string {
  const record = typeof error === "object" && error !== null ? (error as Record<string, unknown>) : {};
  const message = error instanceof Error ? error.message : String(error);
  const status = typeof record["status"] === "number" ? record["status"] : undefined;
  const code = typeof record["code"] === "number" ? record["code"] : undefined;
  const detail = status === undefined ? "" : ` (HTTP ${status}${code === undefined ? "" : `, error ${code}`})`;
  const headline = `Twilio refused the request${detail}: ${message}`;
  if (status === 401 || code === 20003) {
    return `${headline}\nCheck TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN in Relay/.env (Twilio Console › Account Info).`;
  }
  const looksLikeNetwork = /ENOTFOUND|ECONNREFUSED|ECONNRESET|ETIMEDOUT|EAI_AGAIN|fetch failed|socket hang up/i.test(
    `${message} ${typeof record["code"] === "string" ? record["code"] : ""}`,
  );
  if (status === undefined && code === undefined && looksLikeNetwork) {
    return `${headline}\nTwilio's API (api.twilio.com) could not be reached — is this Mac online?`;
  }
  if (status === undefined && code === undefined) {
    return `${headline}\nThe Twilio SDK rejected the request before it was sent — check TWILIO_NUMBER (E.164) and the SDK version.`;
  }
  return `${headline}\nCheck TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_NUMBER in Relay/.env.`;
}

export async function runTwilioSetup(io: SetupIO): Promise<number> {
  const { out } = io;
  let config;
  try {
    config = loadConfig(io.env);
  } catch (error) {
    if (error instanceof ConfigError) {
      out(`Configuration error: ${error.message}`);
      out("Fill Relay/.env (see .env.example) and run `npm run calls:setup` again.");
      return 1;
    }
    throw error;
  }
  const calls = config.calls;
  if (!calls?.twilio) {
    out("Call Guard is not configured: set CALLS_ENABLED=true, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_NUMBER in Relay/.env.");
    return 1;
  }
  const { twilio: twilioConfig } = calls;
  const base = config.publicBaseUrl.replace(/\/+$/, "");
  const voiceUrl = `${base}/v1/calls/twilio/voice`;
  const statusCallback = `${base}/v1/calls/twilio/status?leg=caller`;
  if (!base.startsWith("https://")) {
    out(`Warning: PUBLIC_BASE_URL is ${base} — Twilio can only reach a public https URL (ngrok http 8080 or cloudflared tunnel).`);
  }

  const client = io.client ?? sdkSetupClient(twilioConfig.accountSid, twilioConfig.authToken);
  let numbers: SetupNumber[];
  try {
    numbers = await client.listNumbers(twilioConfig.number);
  } catch (error) {
    out(describeSetupFailure(error));
    return 1;
  }
  const number = numbers.find((candidate) => candidate.phoneNumber === twilioConfig.number) ?? numbers[0];
  if (!number) {
    out(`No incoming phone number ${twilioConfig.number} on this account. Check TWILIO_NUMBER (E.164) and the account SID.`);
    return 1;
  }
  let account: SetupAccount;
  try {
    await number.update({ voiceUrl, voiceMethod: "POST", statusCallback, statusCallbackMethod: "POST" });
    out(`Guard number ${number.phoneNumber} (${number.sid})`);
    out(`  voice webhook   → POST ${voiceUrl}`);
    out(`  status callback → POST ${statusCallback}`);
    account = await client.fetchAccount();
  } catch (error) {
    out(describeSetupFailure(error));
    return 1;
  }
  out(`Account "${account.friendlyName}": type ${account.type}, status ${account.status}`);
  const openai = calls.openai !== undefined;
  const configured = calls.transcriptionSource;
  const resolved = configured === "auto" ? (openai && account.type === "Full" ? "openai" : "twilio") : configured;
  out(`Transcription source: ${configured}${configured === "auto" ? ` → ${resolved}` : ""}${openai ? "" : " (no OPENAI_API_KEY: rules-only verdicts)"}`);
  if (account.type === "Trial") {
    out("Trial account caveats:");
    for (const caveat of TRIAL_CAVEATS) out(`  - ${caveat}`);
  }
  out("Done. Start the relay (`npm run dev`) and call the guard number, or place a test call from the app or the console.");
  return 0;
}

const invokedDirectly = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  runTwilioSetup({ env: process.env, out: (line) => console.log(line) })
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
}

import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

import type { ApnsEnvironment } from "./config.js";
import type { AlertLevel, CallLine, CallRecord, CallSource, CallStatus, CallVerdict } from "./calls/types.js";

/**
 * SQLite storage. The relay stores only opaque identifiers: device ids, hashed device secrets, APNs tokens,
 * salted account-key hashes, Graph subscription ids and hashed clientStates. No email addresses, no mail.
 * All timestamps are integer milliseconds since the Unix epoch.
 */

export type Provider = "gmail" | "microsoft";
export const PROVIDERS: readonly Provider[] = ["gmail", "microsoft"];

export interface DeviceRow {
  deviceId: string;
  secretHash: string;
  apnsToken: string | null;
  environment: ApnsEnvironment;
  bundleId: string;
  createdAt: number;
  updatedAt: number;
  lastSeenAt: number;
}

export interface DeviceAccountRow {
  deviceId: string;
  accountKey: string;
  provider: Provider;
  createdAt: number;
}

/** A device that can currently receive a push for an account. */
export interface PushTarget {
  deviceId: string;
  apnsToken: string;
  environment: ApnsEnvironment;
  bundleId: string;
  /** When the token was last (re)registered; used to ignore stale APNs 410 timestamps. */
  updatedAt: number;
}

export interface GraphSubscriptionRow {
  subscriptionId: string;
  accountKey: string;
  /** sha256 hex of the clientState the app registered (the plaintext is never stored). */
  clientStateHash: string;
  deviceId: string;
  createdAt: number;
}

interface Migration {
  version: number;
  statements: string[];
}

const MIGRATIONS: Migration[] = [
  {
    version: 1,
    statements: [
      `CREATE TABLE IF NOT EXISTS devices (
         device_id    TEXT PRIMARY KEY,
         secret_hash  TEXT NOT NULL UNIQUE,
         apns_token   TEXT,
         environment  TEXT NOT NULL CHECK (environment IN ('sandbox', 'production')),
         bundle_id    TEXT NOT NULL,
         created_at   INTEGER NOT NULL,
         updated_at   INTEGER NOT NULL,
         last_seen_at INTEGER NOT NULL
       )`,
      `CREATE TABLE IF NOT EXISTS device_accounts (
         device_id   TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
         account_key TEXT NOT NULL,
         provider    TEXT NOT NULL CHECK (provider IN ('gmail', 'microsoft')),
         created_at  INTEGER NOT NULL,
         PRIMARY KEY (device_id, account_key)
       )`,
      `CREATE INDEX IF NOT EXISTS idx_device_accounts_account ON device_accounts(account_key, provider)`,
      `CREATE TABLE IF NOT EXISTS graph_subscriptions (
         subscription_id TEXT PRIMARY KEY,
         account_key     TEXT NOT NULL,
         client_state    TEXT NOT NULL,
         device_id       TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
         created_at      INTEGER NOT NULL
       )`,
      `CREATE INDEX IF NOT EXISTS idx_graph_subscriptions_device ON graph_subscriptions(device_id, account_key)`,
      `CREATE TABLE IF NOT EXISTS push_log (
         account_key TEXT NOT NULL,
         sent_at     INTEGER NOT NULL
       )`,
      `CREATE INDEX IF NOT EXISTS idx_push_log_account ON push_log(account_key, sent_at)`,
    ],
  },
  {
    // Call Guard (docs/CALLS.md §10): one protected line per device, and per-call records without transcripts.
    version: 2,
    statements: [
      `CREATE TABLE IF NOT EXISTS call_lines (
         line_id        TEXT PRIMARY KEY,
         device_id      TEXT NOT NULL UNIQUE REFERENCES devices(device_id) ON DELETE CASCADE,
         guard_number   TEXT NOT NULL UNIQUE,
         phone_number   TEXT NOT NULL,
         minimum_level  TEXT NOT NULL CHECK (minimum_level IN ('low', 'medium', 'high')),
         spoken_warning INTEGER NOT NULL DEFAULT 1,
         created_at     INTEGER NOT NULL,
         updated_at     INTEGER NOT NULL
       )`,
      `CREATE TABLE IF NOT EXISTS calls (
         call_id         TEXT PRIMARY KEY,
         device_id       TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
         source          TEXT NOT NULL CHECK (source IN ('twilio', 'test-call', 'demo', 'replay')),
         caller_number   TEXT NOT NULL,
         called_number   TEXT NOT NULL,
         started_at      INTEGER NOT NULL,
         ended_at        INTEGER,
         status          TEXT NOT NULL,
         verdict_json    TEXT,
         alerted         INTEGER NOT NULL DEFAULT 0,
         alert_level     TEXT,
         twilio_call_sid TEXT,
         updated_at      INTEGER NOT NULL
       )`,
      `CREATE INDEX IF NOT EXISTS idx_calls_device ON calls(device_id, started_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_calls_sid ON calls(twilio_call_sid)`,
    ],
  },
];

interface RawDevice {
  device_id: string;
  secret_hash: string;
  apns_token: string | null;
  environment: ApnsEnvironment;
  bundle_id: string;
  created_at: number;
  updated_at: number;
  last_seen_at: number;
}

interface RawTarget {
  device_id: string;
  apns_token: string;
  environment: ApnsEnvironment;
  bundle_id: string;
  updated_at: number;
}

interface RawGraphSubscription {
  subscription_id: string;
  account_key: string;
  client_state: string;
  device_id: string;
  created_at: number;
}

interface RawDeviceAccount {
  device_id: string;
  account_key: string;
  provider: Provider;
  created_at: number;
}

interface RawCallLine {
  line_id: string;
  device_id: string;
  guard_number: string;
  phone_number: string;
  minimum_level: AlertLevel;
  spoken_warning: number;
  created_at: number;
  updated_at: number;
}

interface RawCall {
  call_id: string;
  device_id: string;
  source: CallSource;
  caller_number: string;
  called_number: string;
  started_at: number;
  ended_at: number | null;
  status: CallStatus;
  verdict_json: string | null;
  alerted: number;
  alert_level: AlertLevel | null;
  twilio_call_sid: string | null;
  updated_at: number;
}

function toCallLine(row: RawCallLine): CallLine {
  return {
    lineId: row.line_id,
    deviceId: row.device_id,
    guardNumber: row.guard_number,
    phoneNumber: row.phone_number,
    minimumLevel: row.minimum_level,
    spokenWarning: row.spoken_warning === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toCallRecord(row: RawCall): CallRecord {
  const record: CallRecord = {
    callId: row.call_id,
    deviceId: row.device_id,
    source: row.source,
    callerNumber: row.caller_number,
    calledNumber: row.called_number,
    startedAt: row.started_at,
    status: row.status,
    alerted: row.alerted === 1,
    updatedAt: row.updated_at,
  };
  if (row.ended_at !== null) record.endedAt = row.ended_at;
  if (row.verdict_json !== null) {
    try {
      record.verdict = JSON.parse(row.verdict_json) as CallVerdict;
    } catch {
      // A corrupt verdict column loses the verdict, not the call.
    }
  }
  if (row.alert_level !== null) record.alertLevel = row.alert_level;
  if (row.twilio_call_sid !== null) record.twilioCallSid = row.twilio_call_sid;
  return record;
}

function toDevice(row: RawDevice): DeviceRow {
  return {
    deviceId: row.device_id,
    secretHash: row.secret_hash,
    apnsToken: row.apns_token,
    environment: row.environment,
    bundleId: row.bundle_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastSeenAt: row.last_seen_at,
  };
}

export class RelayDb {
  private readonly stmts;

  private constructor(readonly db: Database.Database) {
    this.stmts = {
      findDevice: db.prepare<[string], RawDevice>("SELECT * FROM devices WHERE device_id = ?"),
      findDeviceBySecretHash: db.prepare<[string], RawDevice>("SELECT * FROM devices WHERE secret_hash = ?"),
      listDevices: db.prepare<[], RawDevice>("SELECT * FROM devices ORDER BY created_at"),
      insertDevice: db.prepare<[string, string, string | null, string, string, number, number, number]>(
        `INSERT INTO devices (device_id, secret_hash, apns_token, environment, bundle_id, created_at, updated_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ),
      // A registration without a token (no push entitlement) keeps whatever token is already stored.
      updateDevice: db.prepare<[string | null, string, string, number, number, string]>(
        `UPDATE devices SET apns_token = COALESCE(?, apns_token), environment = ?, bundle_id = ?, updated_at = ?, last_seen_at = ?
         WHERE device_id = ?`,
      ),
      touchDevice: db.prepare<[number, string]>("UPDATE devices SET last_seen_at = ? WHERE device_id = ?"),
      deleteDevice: db.prepare<[string]>("DELETE FROM devices WHERE device_id = ?"),
      clearToken: db.prepare<[string, string]>(
        "UPDATE devices SET apns_token = NULL WHERE device_id = ? AND apns_token = ?",
      ),
      addAccount: db.prepare<[string, string, string, number]>(
        `INSERT INTO device_accounts (device_id, account_key, provider, created_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(device_id, account_key) DO UPDATE SET provider = excluded.provider`,
      ),
      removeAccount: db.prepare<[string, string]>(
        "DELETE FROM device_accounts WHERE device_id = ? AND account_key = ?",
      ),
      listAccounts: db.prepare<[string], RawDeviceAccount>(
        "SELECT * FROM device_accounts WHERE device_id = ? ORDER BY created_at",
      ),
      targets: db.prepare<[string, string], RawTarget>(
        `SELECT d.device_id, d.apns_token, d.environment, d.bundle_id, d.updated_at
         FROM device_accounts a JOIN devices d ON d.device_id = a.device_id
         WHERE a.account_key = ? AND a.provider = ? AND d.apns_token IS NOT NULL`,
      ),
      upsertGraphSubscription: db.prepare<[string, string, string, string, number]>(
        `INSERT INTO graph_subscriptions (subscription_id, account_key, client_state, device_id, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(subscription_id) DO UPDATE SET
           account_key = excluded.account_key, client_state = excluded.client_state,
           device_id = excluded.device_id, created_at = excluded.created_at`,
      ),
      findGraphSubscription: db.prepare<[string], RawGraphSubscription>(
        "SELECT * FROM graph_subscriptions WHERE subscription_id = ?",
      ),
      deleteGraphSubscriptionsForAccount: db.prepare<[string, string]>(
        "DELETE FROM graph_subscriptions WHERE device_id = ? AND account_key = ?",
      ),
      lastPushAt: db.prepare<[string], { sent_at: number | null }>(
        "SELECT MAX(sent_at) AS sent_at FROM push_log WHERE account_key = ?",
      ),
      recordPush: db.prepare<[string, number]>("INSERT INTO push_log (account_key, sent_at) VALUES (?, ?)"),
      prunePushLog: db.prepare<[number]>("DELETE FROM push_log WHERE sent_at < ?"),
      // Call Guard
      findLineByDevice: db.prepare<[string], RawCallLine>("SELECT * FROM call_lines WHERE device_id = ?"),
      findLineByGuardNumber: db.prepare<[string], RawCallLine>("SELECT * FROM call_lines WHERE guard_number = ?"),
      findLineById: db.prepare<[string], RawCallLine>("SELECT * FROM call_lines WHERE line_id = ?"),
      listLines: db.prepare<[], RawCallLine>("SELECT * FROM call_lines ORDER BY created_at"),
      deleteLineByGuardNumber: db.prepare<[string]>("DELETE FROM call_lines WHERE guard_number = ?"),
      deleteLineByDevice: db.prepare<[string]>("DELETE FROM call_lines WHERE device_id = ?"),
      upsertLine: db.prepare<[string, string, string, string, string, number, number, number]>(
        `INSERT INTO call_lines (line_id, device_id, guard_number, phone_number, minimum_level, spoken_warning, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(device_id) DO UPDATE SET
           guard_number = excluded.guard_number, phone_number = excluded.phone_number,
           minimum_level = excluded.minimum_level, spoken_warning = excluded.spoken_warning,
           updated_at = excluded.updated_at`,
      ),
      upsertCall: db.prepare<
        [string, string, string, string, string, number, number | null, string, string | null, number, string | null, string | null, number]
      >(
        `INSERT INTO calls (call_id, device_id, source, caller_number, called_number, started_at, ended_at, status, verdict_json, alerted, alert_level, twilio_call_sid, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(call_id) DO UPDATE SET
           ended_at = excluded.ended_at, status = excluded.status, verdict_json = excluded.verdict_json,
           alerted = excluded.alerted, alert_level = excluded.alert_level, twilio_call_sid = excluded.twilio_call_sid,
           updated_at = excluded.updated_at`,
      ),
      findCall: db.prepare<[string], RawCall>("SELECT * FROM calls WHERE call_id = ?"),
      listCalls: db.prepare<[string, number], RawCall>(
        "SELECT * FROM calls WHERE device_id = ? ORDER BY started_at DESC LIMIT ?",
      ),
      pruneCalls: db.prepare<[number]>("DELETE FROM calls WHERE started_at < ?"),
    };
  }

  /** Opens (creating if needed) the database at `path` (`":memory:"` for tests) and applies migrations. */
  static open(path: string): RelayDb {
    const inMemory = path === ":memory:";
    if (!inMemory) mkdirSync(dirname(path), { recursive: true });
    const db = new Database(path);
    if (!inMemory) db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    db.pragma("busy_timeout = 5000");
    RelayDb.migrate(db);
    return new RelayDb(db);
  }

  /** Idempotent: every statement is `CREATE ... IF NOT EXISTS` and `user_version` gates each migration. */
  static migrate(db: Database.Database): void {
    const current = db.pragma("user_version", { simple: true }) as number;
    const apply = db.transaction((migration: Migration) => {
      for (const statement of migration.statements) db.exec(statement);
      db.pragma(`user_version = ${migration.version}`);
    });
    for (const migration of MIGRATIONS) {
      if (migration.version > current) apply(migration);
    }
  }

  close(): void {
    this.db.close();
  }

  // MARK: devices

  findDevice(deviceId: string): DeviceRow | undefined {
    const row = this.stmts.findDevice.get(deviceId);
    return row ? toDevice(row) : undefined;
  }

  findDeviceBySecretHash(secretHash: string): DeviceRow | undefined {
    const row = this.stmts.findDeviceBySecretHash.get(secretHash);
    return row ? toDevice(row) : undefined;
  }

  /** Every registered device, oldest first (the operator console lists them; secrets stay hashed). */
  listDevices(): DeviceRow[] {
    return this.stmts.listDevices.all().map(toDevice);
  }

  createDevice(
    input: { deviceId: string; secretHash: string; apnsToken: string | null; environment: ApnsEnvironment; bundleId: string },
    now: number,
  ): void {
    this.stmts.insertDevice.run(
      input.deviceId,
      input.secretHash,
      input.apnsToken,
      input.environment,
      input.bundleId,
      now,
      now,
      now,
    );
  }

  /** `apnsToken: null` keeps the stored token (a tokenless re-registration must not wipe a working one). */
  updateDevice(
    input: { deviceId: string; apnsToken: string | null; environment: ApnsEnvironment; bundleId: string },
    now: number,
  ): void {
    this.stmts.updateDevice.run(input.apnsToken, input.environment, input.bundleId, now, now, input.deviceId);
  }

  touchDevice(deviceId: string, now: number): void {
    this.stmts.touchDevice.run(now, deviceId);
  }

  deleteDevice(deviceId: string): boolean {
    return this.stmts.deleteDevice.run(deviceId).changes > 0;
  }

  /**
   * Forgets `apnsToken` for a device (the row and its account registrations survive so a fresh
   * `POST /v1/devices` restores pushes). Only clears if the stored token is still the one that failed,
   * so a token re-registered in the meantime is kept.
   */
  clearApnsToken(deviceId: string, apnsToken: string): boolean {
    return this.stmts.clearToken.run(deviceId, apnsToken).changes > 0;
  }

  // MARK: accounts

  addDeviceAccount(deviceId: string, accountKey: string, provider: Provider, now: number): void {
    this.stmts.addAccount.run(deviceId, accountKey, provider, now);
  }

  removeDeviceAccount(deviceId: string, accountKey: string): boolean {
    const removed = this.stmts.removeAccount.run(deviceId, accountKey).changes > 0;
    this.stmts.deleteGraphSubscriptionsForAccount.run(deviceId, accountKey);
    return removed;
  }

  listDeviceAccounts(deviceId: string): DeviceAccountRow[] {
    return this.stmts.listAccounts.all(deviceId).map((row) => ({
      deviceId: row.device_id,
      accountKey: row.account_key,
      provider: row.provider,
      createdAt: row.created_at,
    }));
  }

  pushTargets(accountKey: string, provider: Provider): PushTarget[] {
    return this.stmts.targets.all(accountKey, provider).map((row) => ({
      deviceId: row.device_id,
      apnsToken: row.apns_token,
      environment: row.environment,
      bundleId: row.bundle_id,
      updatedAt: row.updated_at,
    }));
  }

  // MARK: Graph subscriptions

  upsertGraphSubscription(
    input: { subscriptionId: string; accountKey: string; clientStateHash: string; deviceId: string },
    now: number,
  ): void {
    this.stmts.upsertGraphSubscription.run(input.subscriptionId, input.accountKey, input.clientStateHash, input.deviceId, now);
  }

  findGraphSubscription(subscriptionId: string): GraphSubscriptionRow | undefined {
    const row = this.stmts.findGraphSubscription.get(subscriptionId);
    if (!row) return undefined;
    return {
      subscriptionId: row.subscription_id,
      accountKey: row.account_key,
      clientStateHash: row.client_state,
      deviceId: row.device_id,
      createdAt: row.created_at,
    };
  }

  // MARK: push log (debounce)

  lastPushAt(accountKey: string): number | undefined {
    const row = this.stmts.lastPushAt.get(accountKey);
    return row && row.sent_at !== null ? row.sent_at : undefined;
  }

  recordPush(accountKey: string, sentAt: number): void {
    this.stmts.recordPush.run(accountKey, sentAt);
  }

  prunePushLog(olderThan: number): number {
    return this.stmts.prunePushLog.run(olderThan).changes;
  }

  // MARK: Call Guard lines

  findCallLine(deviceId: string): CallLine | undefined {
    const row = this.stmts.findLineByDevice.get(deviceId);
    return row ? toCallLine(row) : undefined;
  }

  findCallLineByGuardNumber(guardNumber: string): CallLine | undefined {
    const row = this.stmts.findLineByGuardNumber.get(guardNumber);
    return row ? toCallLine(row) : undefined;
  }

  findCallLineById(lineId: string): CallLine | undefined {
    const row = this.stmts.findLineById.get(lineId);
    return row ? toCallLine(row) : undefined;
  }

  /** Every registered line, oldest first (the operator console lists them). */
  listCallLines(): CallLine[] {
    return this.stmts.listLines.all().map(toCallLine);
  }

  /**
   * Registers (or updates) the device's line. A guard number is held by at most one device: a line another
   * device holds for the same guard number is removed first, so a reinstalled app can take over. Returns the
   * stored line and whether another device was displaced.
   */
  upsertCallLine(
    input: { lineId: string; deviceId: string; guardNumber: string; phoneNumber: string; minimumLevel: AlertLevel; spokenWarning: boolean },
    now: number,
  ): { line: CallLine; displacedDeviceId: string | undefined } {
    const run = this.db.transaction(() => {
      const holder = this.stmts.findLineByGuardNumber.get(input.guardNumber);
      let displaced: string | undefined;
      if (holder && holder.device_id !== input.deviceId) {
        this.stmts.deleteLineByGuardNumber.run(input.guardNumber);
        displaced = holder.device_id;
      }
      const existing = this.stmts.findLineByDevice.get(input.deviceId);
      this.stmts.upsertLine.run(
        existing?.line_id ?? input.lineId,
        input.deviceId,
        input.guardNumber,
        input.phoneNumber,
        input.minimumLevel,
        input.spokenWarning ? 1 : 0,
        existing?.created_at ?? now,
        now,
      );
      const stored = this.stmts.findLineByDevice.get(input.deviceId)!;
      return { line: toCallLine(stored), displacedDeviceId: displaced };
    });
    return run();
  }

  deleteCallLine(deviceId: string): boolean {
    return this.stmts.deleteLineByDevice.run(deviceId).changes > 0;
  }

  // MARK: Call Guard records (never transcripts)

  upsertCall(record: CallRecord): void {
    this.stmts.upsertCall.run(
      record.callId,
      record.deviceId,
      record.source,
      record.callerNumber,
      record.calledNumber,
      record.startedAt,
      record.endedAt ?? null,
      record.status,
      record.verdict ? JSON.stringify(record.verdict) : null,
      record.alerted ? 1 : 0,
      record.alertLevel ?? null,
      record.twilioCallSid ?? null,
      record.updatedAt,
    );
  }

  findCall(callId: string): CallRecord | undefined {
    const row = this.stmts.findCall.get(callId);
    return row ? toCallRecord(row) : undefined;
  }

  listCalls(deviceId: string, limit: number): CallRecord[] {
    return this.stmts.listCalls.all(deviceId, limit).map(toCallRecord);
  }

  pruneCalls(startedBefore: number): number {
    return this.stmts.pruneCalls.run(startedBefore).changes;
  }
}

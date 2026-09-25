import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { RelayDb } from "../src/db.js";

describe("RelayDb", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  it("creates the data directory, applies migrations once and reopens idempotently", () => {
    const dir = mkdtempSync(join(tmpdir(), "pg-relay-"));
    dirs.push(dir);
    const path = join(dir, "nested", "relay.sqlite");

    const first = RelayDb.open(path);
    expect(first.db.pragma("user_version", { simple: true })).toBe(2);
    expect(first.db.pragma("journal_mode", { simple: true })).toBe("wal");
    first.createDevice(
      { deviceId: "d1", secretHash: "h1", apnsToken: "t1", environment: "sandbox", bundleId: "com.x.y" },
      1_000,
    );
    first.close();

    const second = RelayDb.open(path);
    expect(second.db.pragma("user_version", { simple: true })).toBe(2);
    expect(second.findDevice("d1")?.apnsToken).toBe("t1");
    const tables = second.db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
      .all() as { name: string }[];
    expect(tables.map((row) => row.name)).toEqual(["call_lines", "calls", "device_accounts", "devices", "graph_subscriptions", "push_log"]);
    second.close();
  });

  it("cascades account and subscription rows when a device is deleted", () => {
    const db = RelayDb.open(":memory:");
    db.createDevice({ deviceId: "d1", secretHash: "h1", apnsToken: "t1", environment: "sandbox", bundleId: "b" }, 1);
    db.addDeviceAccount("d1", "k".repeat(64), "microsoft", 2);
    db.upsertGraphSubscription({ subscriptionId: "s1", accountKey: "k".repeat(64), clientStateHash: "c", deviceId: "d1" }, 3);
    expect(db.pushTargets("k".repeat(64), "microsoft")).toHaveLength(1);

    expect(db.deleteDevice("d1")).toBe(true);
    expect(db.deleteDevice("d1")).toBe(false);
    expect(db.listDeviceAccounts("d1")).toHaveLength(0);
    expect(db.findGraphSubscription("s1")).toBeUndefined();
    expect(db.pushTargets("k".repeat(64), "microsoft")).toHaveLength(0);
    db.close();
  });

  it("only clears the token that failed", () => {
    const db = RelayDb.open(":memory:");
    db.createDevice({ deviceId: "d1", secretHash: "h1", apnsToken: "old", environment: "sandbox", bundleId: "b" }, 1);
    db.updateDevice({ deviceId: "d1", apnsToken: "new", environment: "sandbox", bundleId: "b" }, 2);
    expect(db.clearApnsToken("d1", "old")).toBe(false);
    expect(db.findDevice("d1")?.apnsToken).toBe("new");
    expect(db.clearApnsToken("d1", "new")).toBe(true);
    expect(db.findDevice("d1")?.apnsToken).toBeNull();
    db.close();
  });

  it("tracks and prunes the push log", () => {
    const db = RelayDb.open(":memory:");
    expect(db.lastPushAt("k")).toBeUndefined();
    db.recordPush("k", 100);
    db.recordPush("k", 200);
    db.recordPush("other", 300);
    expect(db.lastPushAt("k")).toBe(200);
    expect(db.prunePushLog(250)).toBe(2);
    expect(db.lastPushAt("k")).toBeUndefined();
    expect(db.lastPushAt("other")).toBe(300);
    db.close();
  });

  it("enforces secret uniqueness and the provider/environment check constraints", () => {
    const db = RelayDb.open(":memory:");
    db.createDevice({ deviceId: "d1", secretHash: "h1", apnsToken: "t", environment: "sandbox", bundleId: "b" }, 1);
    expect(() =>
      db.createDevice({ deviceId: "d2", secretHash: "h1", apnsToken: "t", environment: "sandbox", bundleId: "b" }, 1),
    ).toThrow(/UNIQUE/);
    expect(() =>
      db.createDevice(
        { deviceId: "d3", secretHash: "h3", apnsToken: "t", environment: "staging" as "sandbox", bundleId: "b" },
        1,
      ),
    ).toThrow(/CHECK/);
    expect(() => db.addDeviceAccount("d1", "k", "yahoo" as "gmail", 1)).toThrow(/CHECK/);
    db.close();
  });
});

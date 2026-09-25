import { createHash } from "node:crypto";

/**
 * Mirrors `AppConfig.accountKey(for:)` in App/PhishGuard/Config/AppConfig.swift exactly:
 *
 *     let normalized = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
 *     SHA256(normalized + ":" + relaySalt) → lowercase hex
 *
 * The relay only ever stores and logs this key, never the email address it was derived from.
 */
export function deriveAccountKey(email: string, relaySalt: string): string {
  const normalized = email.trim().toLowerCase();
  return createHash("sha256").update(`${normalized}:${relaySalt}`, "utf8").digest("hex");
}

export const ACCOUNT_KEY_PATTERN = "^[0-9a-f]{64}$";
const ACCOUNT_KEY_REGEX = new RegExp(ACCOUNT_KEY_PATTERN);

export function isAccountKey(value: unknown): value is string {
  return typeof value === "string" && ACCOUNT_KEY_REGEX.test(value);
}

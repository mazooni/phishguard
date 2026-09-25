import { truncate, type AlertLevel, type CallReason } from "../types.js";

/**
 * The words of a call alert (docs/CALLS.md §5.4). These rules are mirrored by the iOS app's local fallback
 * notification (`NotificationManager.postCallAlert`), so a change here is a change there.
 */

export const MAX_ALERT_BODY_CHARS = 160;
export const ALERT_REASON_SEPARATOR = " · ";
/** When a verdict carries neither reasons nor a summary the body must still say something. */
export const ALERT_BODY_FALLBACK = "This call shows signs of a scam.";

export interface AlertText {
  title: string;
  subtitle: string;
  body: string;
}

const TITLES: Readonly<Record<AlertLevel, string>> = {
  low: "Suspicious call",
  medium: "Possible scam call",
  high: "Likely scam call",
};

export function alertTitle(level: AlertLevel): string {
  return TITLES[level];
}

/** "+1 (415) 555-0134" for an 11-digit +1 number; any other E.164 number is returned as is. */
export function formatPhoneNumber(e164: string): string {
  const match = /^\+1(\d{3})(\d{3})(\d{4})$/.exec(e164.trim());
  if (!match) return e164;
  return `+1 (${match[1]}) ${match[2]}-${match[3]}`;
}

/**
 * Body = the top reasons' titles (already severity-ordered) joined by " · " while the result stays ≤ 160
 * characters; with no reason that fits, the summary (truncated) is used; with neither, a fixed sentence.
 */
export function alertBody(reasons: readonly CallReason[], summary = ""): string {
  const titles = reasons.map((reason) => reason.title.trim()).filter((title) => title.length > 0);
  let body = "";
  for (const title of titles) {
    const next = body ? `${body}${ALERT_REASON_SEPARATOR}${title}` : title;
    if (next.length > MAX_ALERT_BODY_CHARS) break;
    body = next;
  }
  if (body) return body;
  const fallback = summary.trim() || titles[0] || ALERT_BODY_FALLBACK;
  return truncate(fallback, MAX_ALERT_BODY_CHARS);
}

/** "Call from +1 (415) 555-0134"; with no number at all, "Call from an unknown number" — the app's `CallAlertText` says the same. */
export function alertSubtitle(callerNumber: string): string {
  const number = callerNumber.trim();
  return number.length === 0 ? "Call from an unknown number" : `Call from ${formatPhoneNumber(number)}`;
}

export function alertText(level: AlertLevel, callerNumber: string, reasons: readonly CallReason[], summary = ""): AlertText {
  return {
    title: alertTitle(level),
    subtitle: alertSubtitle(callerNumber),
    body: alertBody(reasons, summary),
  };
}

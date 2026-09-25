import { describe, expect, it } from "vitest";

import { ALERT_BODY_FALLBACK, MAX_ALERT_BODY_CHARS, alertBody, alertSubtitle, alertText, formatPhoneNumber } from "../../src/calls/alerts/text.js";
import type { CallReason } from "../../src/calls/types.js";

function reason(title: string, severity: CallReason["severity"] = "high"): CallReason {
  return { id: `call.${title.toLowerCase().replace(/\W+/g, "_")}`, title, detail: `${title} (detail)`, severity, source: "heuristic" };
}

describe("formatPhoneNumber", () => {
  it("formats 11-digit +1 numbers the way the app does", () => {
    expect(formatPhoneNumber("+14155550134")).toBe("+1 (415) 555-0134");
    expect(formatPhoneNumber("+12025550147")).toBe("+1 (202) 555-0147");
  });

  it("returns any other E.164 number unchanged", () => {
    expect(formatPhoneNumber("+442071234567")).toBe("+442071234567");
    expect(formatPhoneNumber("+1415555013")).toBe("+1415555013");
    expect(formatPhoneNumber("+141555501345")).toBe("+141555501345");
    expect(formatPhoneNumber("anonymous")).toBe("anonymous");
  });
});

describe("alertText", () => {
  it("uses the three fixed titles and the 'Call from' subtitle", () => {
    expect(alertText("low", "+14155550134", []).title).toBe("Suspicious call");
    expect(alertText("medium", "+14155550134", []).title).toBe("Possible scam call");
    expect(alertText("high", "+14155550134", []).title).toBe("Likely scam call");
    expect(alertText("high", "+14155550134", []).subtitle).toBe("Call from +1 (415) 555-0134");
    expect(alertText("high", "+442071234567", []).subtitle).toBe("Call from +442071234567");
  });

  it("says 'an unknown number' when there is no caller number at all, exactly like the app's CallAlertText", () => {
    expect(alertText("high", "", []).subtitle).toBe("Call from an unknown number");
    expect(alertText("high", "   ", []).subtitle).toBe("Call from an unknown number");
    expect(alertSubtitle(" +14155550134 ")).toBe("Call from +1 (415) 555-0134");
    expect(alertSubtitle("anonymous")).toBe("Call from anonymous");
  });

  it("joins the top reason titles with ' · ' in order", () => {
    const reasons = [reason("Asks for gift cards"), reason("Claims to be a grandchild in trouble"), reason("Says not to tell anyone")];
    expect(alertText("high", "+14155550134", reasons).body).toBe("Asks for gift cards · Claims to be a grandchild in trouble · Says not to tell anyone");
  });

  it("stops adding titles once the body would exceed 160 characters", () => {
    const reasons = [reason("A".repeat(70)), reason("B".repeat(70)), reason("C".repeat(70)), reason("D")];
    const body = alertBody(reasons);
    expect(body).toBe(`${"A".repeat(70)} · ${"B".repeat(70)}`);
    expect(body.length).toBeLessThanOrEqual(MAX_ALERT_BODY_CHARS);
  });

  it("falls back to the summary when no reason title fits", () => {
    expect(alertBody([], "The caller pretends to be a grandchild and asks for gift cards.")).toBe(
      "The caller pretends to be a grandchild and asks for gift cards.",
    );
    const body = alertBody([reason("X".repeat(200))], "Y".repeat(300));
    expect(body.length).toBeLessThanOrEqual(MAX_ALERT_BODY_CHARS);
    expect(body.startsWith("Y")).toBe(true);
  });

  it("truncates an oversized first title when there is no summary, and never returns an empty body", () => {
    const body = alertBody([reason("Z".repeat(200))]);
    expect(body.length).toBeLessThanOrEqual(MAX_ALERT_BODY_CHARS);
    expect(body.startsWith("Z")).toBe(true);
    expect(alertBody([], "")).toBe(ALERT_BODY_FALLBACK);
    expect(alertBody([reason("   ")], "  ")).toBe(ALERT_BODY_FALLBACK);
  });
});

import { describe, expect, it } from "vitest";

import { constantTimeEqual, isPlausibleDeviceSecret, parseBearer, sha256Hex } from "../src/auth.js";

describe("constantTimeEqual", () => {
  it("is true only for identical strings", () => {
    expect(constantTimeEqual("secret", "secret")).toBe(true);
    expect(constantTimeEqual("secret", "secreT")).toBe(false);
    expect(constantTimeEqual("secret", "secret ")).toBe(false);
    expect(constantTimeEqual("", "")).toBe(true);
    expect(constantTimeEqual("", "x")).toBe(false);
  });

  it("handles unicode without throwing on differing byte lengths", () => {
    expect(constantTimeEqual("clé", "cle")).toBe(false);
    expect(constantTimeEqual("clé", "clé")).toBe(true);
  });
});

describe("sha256Hex", () => {
  it("hashes strings and buffers identically", () => {
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(sha256Hex(Buffer.from("abc"))).toBe(sha256Hex("abc"));
  });
});

describe("parseBearer", () => {
  it("extracts the token", () => {
    expect(parseBearer("Bearer abc.def")).toBe("abc.def");
    expect(parseBearer("bearer abc")).toBe("abc");
    expect(parseBearer("Bearer   spaced  ")).toBe("spaced");
  });

  it("rejects other schemes, arrays and empty values", () => {
    expect(parseBearer("Basic abc")).toBeUndefined();
    expect(parseBearer("Bearer")).toBeUndefined();
    expect(parseBearer("Bearer ")).toBeUndefined();
    expect(parseBearer(["Bearer a", "Bearer b"])).toBeUndefined();
    expect(parseBearer(undefined)).toBeUndefined();
  });
});

describe("isPlausibleDeviceSecret", () => {
  it("accepts 64 hex characters (what the app generates)", () => {
    expect(isPlausibleDeviceSecret("0123456789abcdef".repeat(4))).toBe(true);
  });

  it("rejects short, huge, or non-printable secrets", () => {
    expect(isPlausibleDeviceSecret("short")).toBe(false);
    expect(isPlausibleDeviceSecret("a".repeat(513))).toBe(false);
    expect(isPlausibleDeviceSecret(`${"a".repeat(40)} b`)).toBe(false);
    expect(isPlausibleDeviceSecret(`${"a".repeat(40)}\n`)).toBe(false);
  });
});

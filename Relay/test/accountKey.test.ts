import { describe, expect, it } from "vitest";

import { deriveAccountKey, isAccountKey } from "../src/accountKey.js";

// Vectors computed independently with `printf '<email>:<salt>' | shasum -a 256`.
const SALT = "test-salt-0123456789abcdef";

describe("deriveAccountKey", () => {
  it("matches SHA256(lowercased(email) + ':' + salt) hex, as AppConfig.accountKey(for:) computes it", () => {
    expect(deriveAccountKey("user@example.com", SALT)).toBe(
      "5aa70456aa62f574c838ac376ec9f6da72e2cc8fabbc7e55630d045c7324cd91",
    );
    expect(deriveAccountKey("someone@outlook.com", SALT)).toBe(
      "35e71a0be918b6b79846fbad3003465df3aef4c2d115db173e869c4f3312f811",
    );
  });

  it("trims whitespace/newlines and lowercases before hashing (mirrors the Swift normalization)", () => {
    const expected = deriveAccountKey("user@example.com", SALT);
    expect(deriveAccountKey("  User@Example.COM \n", SALT)).toBe(expected);
    expect(deriveAccountKey("\tUSER@EXAMPLE.COM", SALT)).toBe(expected);
  });

  it("depends on the salt", () => {
    expect(deriveAccountKey("user@example.com", SALT)).not.toBe(deriveAccountKey("user@example.com", `${SALT}x`));
  });

  it("recognizes well-formed keys", () => {
    expect(isAccountKey(deriveAccountKey("user@example.com", SALT))).toBe(true);
    expect(isAccountKey("5AA70456AA62F574C838AC376EC9F6DA72E2CC8FABBC7E55630D045C7324CD91")).toBe(false);
    expect(isAccountKey("abc")).toBe(false);
    expect(isAccountKey(42)).toBe(false);
  });
});

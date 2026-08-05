import { describe, it, expect } from "vitest";
import { generateCiApiKey, hashCiApiKey, looksLikeCiApiKey } from "./ciApiKeys.js";

describe("generateCiApiKey", () => {
  it("produces a token with the expected prefix", () => {
    const { token } = generateCiApiKey();
    expect(token.startsWith("vibescan_ci_")).toBe(true);
  });

  it("produces a token that passes looksLikeCiApiKey", () => {
    const { token } = generateCiApiKey();
    expect(looksLikeCiApiKey(token)).toBe(true);
  });

  it("returns a tokenHash that matches hashCiApiKey(token)", () => {
    const { token, tokenHash } = generateCiApiKey();
    expect(tokenHash).toBe(hashCiApiKey(token));
  });

  it("never returns the full token in tokenPrefix", () => {
    const { token, tokenPrefix } = generateCiApiKey();
    expect(tokenPrefix.length).toBeLessThan(token.length);
    expect(token.startsWith(tokenPrefix)).toBe(true);
  });

  it("generates unique tokens across calls", () => {
    const a = generateCiApiKey();
    const b = generateCiApiKey();
    expect(a.token).not.toBe(b.token);
  });
});

describe("hashCiApiKey", () => {
  it("is deterministic for the same input", () => {
    expect(hashCiApiKey("vibescan_ci_abc123")).toBe(hashCiApiKey("vibescan_ci_abc123"));
  });

  it("produces different hashes for different inputs", () => {
    expect(hashCiApiKey("vibescan_ci_abc123")).not.toBe(hashCiApiKey("vibescan_ci_abc124"));
  });
});

describe("looksLikeCiApiKey", () => {
  it("rejects a UUID-style token", () => {
    expect(looksLikeCiApiKey("550e8400-e29b-41d4-a716-446655440000")).toBe(false);
  });

  it("rejects an empty string", () => {
    expect(looksLikeCiApiKey("")).toBe(false);
  });

  it("rejects a short string with the right prefix but too little entropy", () => {
    expect(looksLikeCiApiKey("vibescan_ci_x")).toBe(false);
  });
});

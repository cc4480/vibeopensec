import { describe, it, expect } from "vitest";
import { analyzeJwts } from "./jwtAnalysis.js";

/**
 * JWT analysis tests — passive extraction + decode, no network calls.
 * Covers each finding type in isolation (separate analyzeJwts calls per
 * case, since findings are deduped by *type* across all tokens in a single
 * call — see the cross-token dedup test at the bottom for that behavior
 * tested deliberately).
 */

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function jwt(header: unknown, payload: unknown, signature = "sig"): string {
  return `${b64url(header)}.${b64url(payload)}.${signature}`;
}

function htmlWith(token: string): string {
  return `<script>const t = "${token}";</script>`;
}

const NOW = Math.floor(Date.now() / 1000);

describe("analyzeJwts — alg:none", () => {
  it("flags alg:none as critical signature bypass", async () => {
    const token = jwt({ alg: "none", typ: "JWT" }, { sub: "user1", exp: NOW + 3600 }, "");
    const result = await analyzeJwts({}, htmlWith(token));
    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("JWT Using alg:none — Signature Verification Bypass");
    expect(result[0]!.severity).toBe("critical");
  });

  it("does not also fire the empty-signature check for alg:none", async () => {
    // alg:none tokens legitimately have no signature — that's not a *separate* finding.
    const token = jwt({ alg: "none" }, { sub: "user1", exp: NOW + 3600 }, "");
    const result = await analyzeJwts({}, htmlWith(token));
    expect(result.map((v) => v.name)).not.toContain("JWT Has Empty Signature — Possible Verification Bypass");
  });
});

describe("analyzeJwts — empty signature with a real algorithm", () => {
  it("flags empty signature segment when alg is not none", async () => {
    const token = jwt({ alg: "HS256", typ: "JWT" }, { sub: "user2", exp: NOW + 3600 }, "");
    const result = await analyzeJwts({}, htmlWith(token));
    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("JWT Has Empty Signature — Possible Verification Bypass");
    expect(result[0]!.severity).toBe("critical");
  });
});

describe("analyzeJwts — missing expiry", () => {
  it("flags a token with no exp claim (RS256, isolated from HS256-specific check)", async () => {
    const token = jwt({ alg: "RS256", typ: "JWT" }, { sub: "user3" });
    const result = await analyzeJwts({}, htmlWith(token));
    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("JWT Token Has No Expiry (exp Claim Missing)");
    expect(result[0]!.severity).toBe("high");
  });
});

describe("analyzeJwts — excessive lifetime", () => {
  it("flags a token with lifetime over 365 days and reports the correct day count", async () => {
    const iat = 1_700_000_000;
    const exp = iat + 400 * 24 * 3600;
    const token = jwt({ alg: "RS256", typ: "JWT" }, { sub: "user4", iat, exp });
    const result = await analyzeJwts({}, htmlWith(token));
    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("JWT Token Lifetime Is 400 Days — Excessive");
    expect(result[0]!.severity).toBe("medium");
  });

  it("does not flag a token with a 1-hour lifetime", async () => {
    const token = jwt({ alg: "RS256" }, { sub: "user4b", iat: NOW, exp: NOW + 3600 });
    const result = await analyzeJwts({}, htmlWith(token));
    expect(result).toHaveLength(0);
  });
});

describe("analyzeJwts — HS256 without expiry", () => {
  it("fires both 'no exp' and 'HS256 without expiry' together", async () => {
    const token = jwt({ alg: "HS256", typ: "JWT" }, { sub: "user5" });
    const result = await analyzeJwts({}, htmlWith(token));
    const names = result.map((v) => v.name).sort();
    expect(names).toEqual([
      "JWT Token Has No Expiry (exp Claim Missing)",
      "JWT Uses HS256 Without Expiry — Offline Brute-Force Risk",
    ].sort());
  });
});

describe("analyzeJwts — sensitive payload keys", () => {
  it("flags sensitive-looking keys in the payload and lists them", async () => {
    const token = jwt(
      { alg: "RS256", typ: "JWT" },
      { sub: "user6", exp: NOW + 3600, password: "hunter2", api_key: "abc" },
    );
    const result = await analyzeJwts({}, htmlWith(token));
    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("Sensitive Data Stored in JWT Payload");
    expect(result[0]!.description).toContain("password");
    expect(result[0]!.description).toContain("api_key");
  });

  it("does not flag a payload with only benign claims", async () => {
    const token = jwt({ alg: "RS256" }, { sub: "user6b", exp: NOW + 3600, name: "Jane" });
    const result = await analyzeJwts({}, htmlWith(token));
    expect(result).toHaveLength(0);
  });
});

describe("analyzeJwts — well-formed token", () => {
  it("produces zero findings for a properly-configured JWT", async () => {
    const token = jwt(
      { alg: "RS256", typ: "JWT" },
      { sub: "user7", iat: NOW, exp: NOW + 3600 },
      "realSignatureBytesHere",
    );
    const result = await analyzeJwts({}, htmlWith(token));
    expect(result).toHaveLength(0);
  });
});

describe("analyzeJwts — malformed tokens", () => {
  it("skips a token whose payload segment is not valid JSON without crashing", async () => {
    const header = b64url({ alg: "HS256", typ: "JWT" });
    // Truncated/invalid JSON that still base64url-decodes to something starting "eyJ"-shaped
    const badPayload = Buffer.from('{"sub":"broken', "utf8").toString("base64url");
    const token = `${header}.${badPayload}.sig`;
    await expect(analyzeJwts({}, htmlWith(token))).resolves.toEqual([]);
  });

  it("returns an empty array when no JWT-shaped strings are present", async () => {
    await expect(analyzeJwts({}, "<html><body>nothing here</body></html>")).resolves.toEqual([]);
  });
});

describe("analyzeJwts — extraction from multiple sources", () => {
  it("finds the same token whether it appears in headers or html, without duplicating findings", async () => {
    const token = jwt({ alg: "RS256" }, { sub: "user9" }); // triggers "no exp"
    const resultHtmlOnly = await analyzeJwts({}, htmlWith(token));
    const resultBoth = await analyzeJwts({ "x-auth-token": token }, htmlWith(token));
    expect(resultHtmlOnly).toHaveLength(1);
    expect(resultBoth).toHaveLength(1);
    expect(resultBoth[0]!.name).toBe(resultHtmlOnly[0]!.name);
  });
});

describe("analyzeJwts — cross-token dedup by finding type", () => {
  it("reports 'no exp' only once even when two different tokens are both missing it", async () => {
    const tokenA = jwt({ alg: "RS256" }, { sub: "userA" });
    const tokenB = jwt({ alg: "RS256" }, { sub: "userB" });
    const html = htmlWith(tokenA) + htmlWith(tokenB);
    const result = await analyzeJwts({}, html);
    const noExpFindings = result.filter((v) => v.name === "JWT Token Has No Expiry (exp Claim Missing)");
    expect(noExpFindings).toHaveLength(1);
  });
});

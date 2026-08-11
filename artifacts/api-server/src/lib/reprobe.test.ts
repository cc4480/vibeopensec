import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { reprobe } from "./reprobe.js";
import type { ScanVulnerability } from "./scanner.js";

/**
 * reprobe() tests — the differential re-probe pass that adjusts confidence
 * on borderline (50-69) findings by re-checking the live target. Confirmed
 * findings get +10 confidence; disconfirmed ones are dropped entirely.
 */

function makeVuln(partial: Partial<ScanVulnerability> & Pick<ScanVulnerability, "name" | "category">): ScanVulnerability {
  return {
    id: "v1",
    severity: "medium",
    description: "d",
    solution: "s",
    confidence: 100,
    ...partial,
  } as ScanVulnerability;
}

const log = { info: vi.fn(), warn: vi.fn() };

function htmlResponse(headers: Record<string, string> = {}): Response {
  return new Response("", { status: 200, headers });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
  log.info.mockClear();
  log.warn.mockClear();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("reprobe — no borderline findings", () => {
  it("returns vulns unchanged and makes no HTTP requests", async () => {
    const vulns = [makeVuln({ name: "X", category: "Y", confidence: 100 })];
    const result = await reprobe("https://example.com", vulns, log);
    expect(result).toEqual(vulns);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("reprobe — GET probe failure", () => {
  it("keeps original confidences when the re-probe GET fails", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("network error"));
    const vulns = [makeVuln({ name: "Missing HSTS", category: "Transport Security", confidence: 55 })];
    const result = await reprobe("https://example.com", vulns, log);
    expect(result).toEqual(vulns);
    expect(log.warn).toHaveBeenCalled();
  });
});

describe("reprobe — header-based confirmation", () => {
  it("boosts confidence by +10 when the header is still absent (confirmed)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(htmlResponse({})); // no HSTS header
    const vulns = [makeVuln({ name: "Missing HTTP Strict-Transport-Security (HSTS)", category: "Transport Security", confidence: 55 })];
    const result = await reprobe("https://example.com", vulns, log);
    expect(result).toHaveLength(1);
    expect(result[0]!.confidence).toBe(65);
  });

  it("drops the finding when the header is now present (disconfirmed)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(htmlResponse({ "strict-transport-security": "max-age=31536000" }));
    const vulns = [makeVuln({ name: "Missing HTTP Strict-Transport-Security (HSTS)", category: "Transport Security", confidence: 55 })];
    const result = await reprobe("https://example.com", vulns, log);
    expect(result).toHaveLength(0);
  });

  it("boosts the highest borderline confidence (69) to 79 — the 95 cap is unreachable given the 50-69 window", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(htmlResponse({}));
    const vulns = [makeVuln({ name: "Missing HTTP Strict-Transport-Security (HSTS)", category: "Transport Security", confidence: 69 })];
    const result = await reprobe("https://example.com", vulns, log);
    expect(result[0]!.confidence).toBe(79);
  });

  it("leaves an unrecognized finding class untouched (checkHeaderFinding returns null)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(htmlResponse({}));
    const vulns = [makeVuln({ name: "No Rate Limiting Detected", category: "Brute Force Protection", confidence: 52 })];
    const result = await reprobe("https://example.com", vulns, log);
    expect(result).toHaveLength(1);
    expect(result[0]!.confidence).toBe(52);
  });
});

describe("reprobe — findings outside the borderline window are untouched", () => {
  it("passes through a confidence>=70 finding unchanged even when another finding triggers a probe", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(htmlResponse({}));
    const vulns = [
      makeVuln({ name: "Missing HTTP Strict-Transport-Security (HSTS)", category: "Transport Security", confidence: 55 }),
      makeVuln({ name: "Some Other Finding", category: "Other", confidence: 85 }),
    ];
    const result = await reprobe("https://example.com", vulns, log);
    const other = result.find((v) => v.name === "Some Other Finding");
    expect(other?.confidence).toBe(85);
  });

  it("passes through a confidence<50 finding unchanged", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(htmlResponse({}));
    const vulns = [
      makeVuln({ name: "Missing HTTP Strict-Transport-Security (HSTS)", category: "Transport Security", confidence: 55 }),
      makeVuln({ name: "Low Confidence Finding", category: "Other", confidence: 40 }),
    ];
    const result = await reprobe("https://example.com", vulns, log);
    const low = result.find((v) => v.name === "Low Confidence Finding");
    expect(low?.confidence).toBe(40);
  });
});

describe("reprobe — DNS-based confirmation", () => {
  it("boosts confidence when SPF is still missing per the DNS TXT re-probe", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(htmlResponse({})) // GET probe
      .mockResolvedValueOnce(new Response(JSON.stringify({ Answer: [{ data: '"v=dmarc1; p=none"' }] }), { status: 200 })); // DNS TXT probe — no spf1 record

    const vulns = [makeVuln({ name: "Missing SPF Record — Email Spoofing Possible", category: "Email Security", confidence: 60 })];
    const result = await reprobe("https://example.com", vulns, log);
    expect(result).toHaveLength(1);
    expect(result[0]!.confidence).toBe(70);
  });

  it("drops the SPF finding when the DNS re-probe now finds a v=spf1 record", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(htmlResponse({}))
      .mockResolvedValueOnce(new Response(JSON.stringify({ Answer: [{ data: '"v=spf1 -all"' }] }), { status: 200 }));

    const vulns = [makeVuln({ name: "Missing SPF Record — Email Spoofing Possible", category: "Email Security", confidence: 60 })];
    const result = await reprobe("https://example.com", vulns, log);
    expect(result).toHaveLength(0);
  });
});

describe("reprobe — CORS-based confirmation via active OPTIONS probe", () => {
  it("boosts confidence when the OPTIONS probe still reflects a wildcard origin", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(htmlResponse({})) // GET probe
      .mockResolvedValueOnce(htmlResponse({ "access-control-allow-origin": "*" })); // OPTIONS probe

    const vulns = [makeVuln({ name: "Permissive CORS Policy (Wildcard Origin)", category: "CORS Misconfiguration", confidence: 60 })];
    const result = await reprobe("https://example.com", vulns, log);
    expect(result).toHaveLength(1);
    expect(result[0]!.confidence).toBe(70);
  });

  it("drops the CORS finding when the OPTIONS probe no longer reflects a wildcard", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(htmlResponse({}))
      .mockResolvedValueOnce(htmlResponse({ "access-control-allow-origin": "https://trusted.example.com" }));

    const vulns = [makeVuln({ name: "Permissive CORS Policy (Wildcard Origin)", category: "CORS Misconfiguration", confidence: 60 })];
    const result = await reprobe("https://example.com", vulns, log);
    expect(result).toHaveLength(0);
  });
});

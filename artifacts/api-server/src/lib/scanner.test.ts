import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Tests for scanner.ts's own header/cookie/HSTS-preload logic — NOT the
 * runScan() orchestrator's probe fan-out (probes.ts, dnsChecks.ts,
 * jsScanner.ts, crawler.ts, cveCheck.ts, jwtAnalysis.ts, subdomainTakeover.ts,
 * sourceMaps.ts, vibeStackProbes.ts, baasProbes.ts, graphqlProbe.ts,
 * apiDocsProbe.ts, nextjsProbe.ts, storageProbe.ts — each has its own test
 * coverage elsewhere).
 *
 * analyzeCookies() isn't exported, and the header checks (CSP/HSTS/XFO/etc.)
 * live inline in runScan() rather than as standalone functions. Rather than
 * touching scanner.ts to export them, every sub-probe module it imports is
 * mocked to a no-op here, so calling the real runScan() exercises only the
 * header/cookie logic this file owns — the rest of the pipeline contributes
 * nothing to the result.
 *
 * scanner.ts transitively imports cveCheck.ts -> eolFetcher.ts ->
 * @workspace/db, which throws at import time without DATABASE_URL set. Since
 * cveCheck.ts's exports are mocked below, that import chain never actually
 * runs — but @workspace/db is stubbed too as a safety net (same pattern as
 * baasQuickCheck.test.ts / ciScan.test.ts).
 */

vi.mock("@workspace/db", () => ({}));

vi.mock("./probes", () => ({ runAllProbes: vi.fn(async () => []) }));
vi.mock("./dnsChecks", () => ({ checkDnsSecurity: vi.fn(async () => []) }));
vi.mock("./jsScanner", () => ({ scanJavaScriptForSecrets: vi.fn(async () => []) }));
vi.mock("./crawler", () => ({
  crawlAndCheck: vi.fn(async () => ({ vulnerabilities: [], pagesVisited: [], probedNotFound: [] })),
  checkUrlEmbeddedSecrets: vi.fn(() => []),
}));
vi.mock("./cveCheck", () => ({
  checkForKnownVulnerabilities: vi.fn(async () => []),
  extractVersionedTechnologies: vi.fn(() => []),
}));
vi.mock("./jwtAnalysis", () => ({ analyzeJwts: vi.fn(async () => []) }));
vi.mock("./subdomainTakeover", () => ({ checkSubdomainTakeover: vi.fn(async () => []) }));
vi.mock("./pathTraversal", () => ({ checkPathTraversal: vi.fn(async () => []) }));
vi.mock("./sourceMaps", () => ({ checkSourceMaps: vi.fn(async () => []) }));
vi.mock("./vibeStackProbes", () => ({ checkVibeStackSecurity: vi.fn(async () => []) }));
vi.mock("./scoring", () => ({ autoEnrichConfidence: vi.fn((vulns: unknown[]) => vulns) }));
vi.mock("./techFingerprint", () => ({ detectTechnologies: vi.fn(() => []) }));
vi.mock("./baasProbes", () => ({ runBaasProbes: vi.fn(async () => []) }));
vi.mock("./graphqlProbe", () => ({ runGraphqlProbe: vi.fn(async () => []) }));
vi.mock("./apiDocsProbe", () => ({ runApiDocsProbe: vi.fn(async () => []) }));
vi.mock("./nextjsProbe", () => ({ runNextjsProbe: vi.fn(async () => []) }));
vi.mock("./storageProbe", () => ({ runStorageProbe: vi.fn(async () => []) }));

import { runScan, fetchTargetHtml, computeRiskScore, computeGrade, type ScanVulnerability } from "./scanner";

// ─── fetch mock helpers ─────────────────────────────────────────────────────

function htmlResponse(headers: Record<string, string>, body = "<html></html>", status = 200): Response {
  return new Response(body, { status, headers });
}

/** Response.url is a getter-only property on the native Response class — Object.assign can't override it. */
function withUrl(response: Response, url: string): Response {
  Object.defineProperty(response, "url", { value: url, configurable: true });
  return response;
}

/**
 * Routes the global fetch mock by URL: the main target fetch gets `mainHeaders`;
 * hstspreload.org gets `preloadStatus` (or 500 if undefined, simulating "API
 * doesn't know"); the http:// behavioral-fallback fetch gets `behavioralFinalUrl`.
 */
function mockFetchRouter(opts: {
  targetUrl: string;
  mainHeaders: Record<string, string>;
  mainBody?: string;
  preloadStatus?: "preloaded" | "pending" | "unknown" | "http-error";
  behavioralFinalUrl?: string;
}) {
  vi.mocked(fetch).mockImplementation(async (input) => {
    const url = String(input);
    if (url.startsWith("https://hstspreload.org")) {
      if (opts.preloadStatus === "http-error" || opts.preloadStatus === undefined) {
        return new Response("", { status: 500 });
      }
      return new Response(JSON.stringify({ status: opts.preloadStatus }), { status: 200 });
    }
    if (url.startsWith("http://") && !url.startsWith(opts.targetUrl)) {
      // behavioral fallback GET to http://<hostname>/
      const finalUrl = opts.behavioralFinalUrl ?? url;
      return withUrl(new Response("", { status: 200 }), finalUrl);
    }
    return htmlResponse(opts.mainHeaders, opts.mainBody ?? "<html></html>");
  });
}

function findByName(vulns: ScanVulnerability[], name: string) {
  return vulns.find((v) => v.name === name);
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

// ─── fetchTargetHtml ────────────────────────────────────────────────────────

describe("fetchTargetHtml", () => {
  it("returns html, finalUrl, rawHeaders, and status from a successful fetch", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      withUrl(new Response("<html>hi</html>", { status: 200, headers: { "x-test": "1" } }), "https://example.com/"),
    );
    const result = await fetchTargetHtml("https://example.com");
    expect(result.html).toBe("<html>hi</html>");
    expect(result.finalUrl).toBe("https://example.com/");
    expect(result.rawHeaders["x-test"]).toBe("1");
    expect(result.status).toBe(200);
  });

  it("wraps a network failure in a 'Failed to reach target URL' error", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error("ECONNREFUSED"));
    await expect(fetchTargetHtml("https://example.com")).rejects.toThrow("Failed to reach target URL");
  });
});

// ─── computeRiskScore / computeGrade ────────────────────────────────────────

describe("computeRiskScore", () => {
  const v = (severity: ScanVulnerability["severity"]): ScanVulnerability =>
    ({ id: "x", name: "x", severity, category: "x", description: "x", solution: "x" });

  it("sums critical=30, high=15, medium=5, low=1, info=0", () => {
    expect(computeRiskScore([v("critical")])).toBe(30);
    expect(computeRiskScore([v("high")])).toBe(15);
    expect(computeRiskScore([v("medium")])).toBe(5);
    expect(computeRiskScore([v("low")])).toBe(1);
    expect(computeRiskScore([v("info")])).toBe(0);
    expect(computeRiskScore([v("critical"), v("high"), v("medium"), v("low")])).toBe(51);
  });

  it("caps the score at 100", () => {
    expect(computeRiskScore(Array.from({ length: 10 }, () => v("critical")))).toBe(100);
  });

  it("returns 0 for no findings", () => {
    expect(computeRiskScore([])).toBe(0);
  });
});

describe("computeGrade", () => {
  it("maps score ranges to letter grades per the documented boundaries", () => {
    expect(computeGrade(0)).toBe("A");
    expect(computeGrade(10)).toBe("A");
    expect(computeGrade(11)).toBe("B");
    expect(computeGrade(25)).toBe("B");
    expect(computeGrade(26)).toBe("C");
    expect(computeGrade(45)).toBe("C");
    expect(computeGrade(46)).toBe("D");
    expect(computeGrade(65)).toBe("D");
    expect(computeGrade(66)).toBe("F");
    expect(computeGrade(100)).toBe("F");
  });
});

// ─── HTTPS enforcement ──────────────────────────────────────────────────────

describe("runScan — HTTPS enforcement", () => {
  it("flags plain HTTP as critical 'No HTTPS / Plaintext HTTP'", async () => {
    mockFetchRouter({ targetUrl: "http://example.com", mainHeaders: {} });
    const result = await runScan("http://example.com", "basic");
    const f = findByName(result.vulnerabilities, "No HTTPS / Plaintext HTTP");
    expect(f?.severity).toBe("critical");
  });

  it("does not flag an HTTPS target", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "strict-transport-security": "max-age=31536000" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "No HTTPS / Plaintext HTTP")).toBeUndefined();
  });
});

// ─── HSTS ───────────────────────────────────────────────────────────────────

describe("runScan — HSTS", () => {
  it("flags missing HSTS on an HTTPS target not on the preload list", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {}, preloadStatus: "http-error" });
    const result = await runScan("https://example.com", "basic");
    const f = findByName(result.vulnerabilities, "Missing HTTP Strict-Transport-Security (HSTS)");
    expect(f?.severity).toBe("medium");
  });

  it("does not flag missing HSTS on a plain HTTP target (HSTS is meaningless without HTTPS)", async () => {
    mockFetchRouter({ targetUrl: "http://example.com", mainHeaders: {} });
    const result = await runScan("http://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing HTTP Strict-Transport-Security (HSTS)")).toBeUndefined();
  });

  it("suppresses the finding when hstspreload.org reports the domain as preloaded", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {}, preloadStatus: "preloaded" });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing HTTP Strict-Transport-Security (HSTS)")).toBeUndefined();
  });

  it("does not suppress when hstspreload.org reports 'pending'", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {}, preloadStatus: "pending" });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing HTTP Strict-Transport-Security (HSTS)")).toBeDefined();
  });

  it("falls back to the behavioral check on 'unknown' status and suppresses if HTTP upgrades to HTTPS", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: {},
      preloadStatus: "unknown",
      behavioralFinalUrl: "https://example.com/",
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing HTTP Strict-Transport-Security (HSTS)")).toBeUndefined();
  });

  it("does not flag known Chrome-builtin-preloaded domains (fast path, no hstspreload.org call)", async () => {
    mockFetchRouter({ targetUrl: "https://google.com", mainHeaders: {} });
    const result = await runScan("https://google.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing HTTP Strict-Transport-Security (HSTS)")).toBeUndefined();
    const calledPreload = vi.mocked(fetch).mock.calls.some(([u]) => String(u).startsWith("https://hstspreload.org"));
    expect(calledPreload).toBe(false);
  });

  it("flags HSTS max-age below 180 days as low severity", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { "strict-transport-security": "max-age=3600" } });
    const result = await runScan("https://example.com", "basic");
    const f = findByName(result.vulnerabilities, "HSTS max-age Too Short");
    expect(f?.severity).toBe("low");
  });

  it("does not flag HSTS max-age of 180+ days", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "strict-transport-security": "max-age=31536000" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "HSTS max-age Too Short")).toBeUndefined();
  });
});

// ─── Content-Security-Policy ────────────────────────────────────────────────

describe("runScan — CSP", () => {
  it("flags a completely missing CSP as high", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {} });
    const result = await runScan("https://example.com", "basic");
    const f = findByName(result.vulnerabilities, "Missing Content-Security-Policy (CSP)");
    expect(f?.severity).toBe("high");
  });

  it("flags unsafe-inline in script-src as medium (not the missing-CSP finding)", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Content-Security-Policy (CSP)")).toBeUndefined();
    const f = findByName(result.vulnerabilities, "Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)");
    expect(f?.severity).toBe("medium");
  });

  it("flags unsafe-eval in script-src the same as unsafe-inline", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "content-security-policy": "script-src 'self' 'unsafe-eval'" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)")).toBeDefined();
  });

  it("falls back to default-src when script-src is absent", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "content-security-policy": "default-src 'unsafe-inline'" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)")).toBeDefined();
  });

  it("flags unsafe-inline in style-src only as low, when script-src is clean", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "content-security-policy": "script-src 'self'; style-src 'self' 'unsafe-inline'" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)")).toBeUndefined();
    const f = findByName(result.vulnerabilities, "Content-Security-Policy Allows Inline Styles (unsafe-inline in style-src)");
    expect(f?.severity).toBe("low");
  });

  it("flags no CSP-quality findings for a strict policy", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: {
        "content-security-policy":
          "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'",
      },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Content-Security-Policy (CSP)")).toBeUndefined();
    expect(findByName(result.vulnerabilities, "Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)")).toBeUndefined();
    expect(findByName(result.vulnerabilities, "Content-Security-Policy Allows Inline Styles (unsafe-inline in style-src)")).toBeUndefined();
    expect(findByName(result.vulnerabilities, "CSP Missing object-src 'none' Directive")).toBeUndefined();
    expect(findByName(result.vulnerabilities, "CSP Missing base-uri Directive")).toBeUndefined();
  });

  it("flags missing object-src 'none' unless default-src is 'none'", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "content-security-policy": "script-src 'self'" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "CSP Missing object-src 'none' Directive")).toBeDefined();
  });

  it("does not flag missing object-src when default-src is 'none'", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "content-security-policy": "default-src 'none'; script-src 'self'" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "CSP Missing object-src 'none' Directive")).toBeUndefined();
  });

  it("flags missing base-uri directive", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "content-security-policy": "script-src 'self'; object-src 'none'" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "CSP Missing base-uri Directive")).toBeDefined();
  });

  it("flags a wildcard in script-src as high", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "content-security-policy": "script-src *" },
    });
    const result = await runScan("https://example.com", "basic");
    const f = findByName(result.vulnerabilities, "CSP script-src Contains Wildcard — XSS Protection Bypassed");
    expect(f?.severity).toBe("high");
  });
});

// ─── X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy ──

describe("runScan — remaining single-header checks", () => {
  it("flags missing X-Frame-Options when CSP has no frame-ancestors either", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {} });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Clickjacking Protection (X-Frame-Options)")).toBeDefined();
  });

  it("does not flag X-Frame-Options: DENY", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { "x-frame-options": "DENY" } });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Clickjacking Protection (X-Frame-Options)")).toBeUndefined();
  });

  it("does not flag missing X-Frame-Options when CSP has frame-ancestors", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "content-security-policy": "frame-ancestors 'none'" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Clickjacking Protection (X-Frame-Options)")).toBeUndefined();
  });

  it("flags missing X-Content-Type-Options: nosniff", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {} });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing X-Content-Type-Options: nosniff")).toBeDefined();
  });

  it("flags X-Content-Type-Options set to something other than 'nosniff'", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { "x-content-type-options": "garbage" } });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing X-Content-Type-Options: nosniff")).toBeDefined();
  });

  it("does not flag X-Content-Type-Options: nosniff", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { "x-content-type-options": "nosniff" } });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing X-Content-Type-Options: nosniff")).toBeUndefined();
  });

  it("flags missing Referrer-Policy", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {} });
    const result = await runScan("https://example.com", "basic");
    const f = findByName(result.vulnerabilities, "Missing Referrer-Policy Header");
    expect(f?.severity).toBe("low");
  });

  it("does not flag Referrer-Policy when present", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { "referrer-policy": "no-referrer" } });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Referrer-Policy Header")).toBeUndefined();
  });

  it("flags missing Permissions-Policy (and accepts legacy Feature-Policy as satisfying it)", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {} });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Permissions-Policy Header")).toBeDefined();

    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { "feature-policy": "camera 'none'" } });
    const result2 = await runScan("https://example.com", "basic");
    expect(findByName(result2.vulnerabilities, "Missing Permissions-Policy Header")).toBeUndefined();
  });
});

// ─── COOP / COEP / CORP ─────────────────────────────────────────────────────

describe("runScan — cross-origin isolation headers", () => {
  it("flags all three of COOP/COEP/CORP as info when absent", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {} });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Cross-Origin-Opener-Policy (COOP)")?.severity).toBe("info");
    expect(findByName(result.vulnerabilities, "Missing Cross-Origin-Embedder-Policy (COEP)")?.severity).toBe("info");
    expect(findByName(result.vulnerabilities, "Missing Cross-Origin-Resource-Policy (CORP)")?.severity).toBe("info");
  });

  it("does not flag any of the three when all are present", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-resource-policy": "same-origin",
      },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Cross-Origin-Opener-Policy (COOP)")).toBeUndefined();
    expect(findByName(result.vulnerabilities, "Missing Cross-Origin-Embedder-Policy (COEP)")).toBeUndefined();
    expect(findByName(result.vulnerabilities, "Missing Cross-Origin-Resource-Policy (CORP)")).toBeUndefined();
  });
});

// ─── CORS wildcard / Server / X-Powered-By ─────────────────────────────────

describe("runScan — CORS wildcard and disclosure headers", () => {
  it("flags Access-Control-Allow-Origin: * as medium", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { "access-control-allow-origin": "*" } });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Permissive CORS Policy (Wildcard Origin)")?.severity).toBe("medium");
  });

  it("does not flag a specific (non-wildcard) allowed origin", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "access-control-allow-origin": "https://trusted.example.com" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Permissive CORS Policy (Wildcard Origin)")).toBeUndefined();
  });

  it("flags a Server header containing a version number", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { server: "Apache/2.4.41" } });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Server Version Disclosure")).toBeDefined();
  });

  it("does not flag a Server header with no digits", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { server: "nginx" } });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Server Version Disclosure")).toBeUndefined();
  });

  it("flags X-Powered-By when present", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { "x-powered-by": "Express" } });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "X-Powered-By Header Discloses Technology Stack")).toBeDefined();
  });

  it("does not flag X-Powered-By when absent", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {} });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "X-Powered-By Header Discloses Technology Stack")).toBeUndefined();
  });
});

// ─── Cache-Control (regression test for the isHttps-gate fix) ─────────────

describe("runScan — Cache-Control (regression: no longer gated on isHttps)", () => {
  it("flags missing Cache-Control/Pragma on an HTTPS target", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {} });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Cache-Control Headers")?.severity).toBe("info");
  });

  it("flags missing Cache-Control/Pragma on a plain HTTP target too", async () => {
    mockFetchRouter({ targetUrl: "http://example.com", mainHeaders: {} });
    const result = await runScan("http://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Cache-Control Headers")).toBeDefined();
  });

  it("does not flag when Cache-Control is present", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { "cache-control": "no-store" } });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Cache-Control Headers")).toBeUndefined();
  });

  it("does not flag when only Pragma is present", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { pragma: "no-cache" } });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Missing Cache-Control Headers")).toBeUndefined();
  });
});

// ─── Cookie analysis (tested indirectly via runScan, since analyzeCookies is unexported) ──

describe("runScan — cookie analysis", () => {
  it("flags a cookie missing Secure, HttpOnly, and SameSite all at once", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: { "set-cookie": "session=abc123; Path=/" } });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Cookie Missing Secure Flag")?.severity).toBe("high");
    expect(findByName(result.vulnerabilities, "Cookie Missing HttpOnly Flag")?.severity).toBe("medium");
    expect(findByName(result.vulnerabilities, "Cookie Missing SameSite Attribute")?.severity).toBe("medium");
  });

  it("does not flag a fully-correct cookie", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "set-cookie": "session=abc123; Secure; HttpOnly; SameSite=Lax" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Cookie Missing Secure Flag")).toBeUndefined();
    expect(findByName(result.vulnerabilities, "Cookie Missing HttpOnly Flag")).toBeUndefined();
    expect(findByName(result.vulnerabilities, "Cookie Missing SameSite Attribute")).toBeUndefined();
  });

  it("excludes third-party infrastructure cookies (e.g. __cf_bm, _ga) even with no flags", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "set-cookie": "__cf_bm=xyz; Path=/, _ga=GA1.2.123; Path=/" },
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Cookie Missing Secure Flag")).toBeUndefined();
  });

  it("groups multiple cookies missing the same flag into a single finding listing all names", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: { "set-cookie": "a=1; Path=/, b=2; Path=/" },
    });
    const result = await runScan("https://example.com", "basic");
    const secureFindings = result.vulnerabilities.filter((v) => v.name === "Cookie Missing Secure Flag");
    expect(secureFindings).toHaveLength(1);
    expect(secureFindings[0]!.evidence).toContain("a");
    expect(secureFindings[0]!.evidence).toContain("b");
  });

  it("produces no cookie findings when there is no Set-Cookie header", async () => {
    mockFetchRouter({ targetUrl: "https://example.com", mainHeaders: {} });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Cookie Missing Secure Flag")).toBeUndefined();
    expect(findByName(result.vulnerabilities, "Cookie Missing HttpOnly Flag")).toBeUndefined();
    expect(findByName(result.vulnerabilities, "Cookie Missing SameSite Attribute")).toBeUndefined();
  });
});

// ─── Mixed content ──────────────────────────────────────────────────────────

describe("runScan — mixed content", () => {
  it("flags an HTTPS page loading an HTTP resource", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: {},
      mainBody: `<html><script src="http://cdn.example.com/lib.js"></script></html>`,
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Mixed Content (HTTP Resources on HTTPS Page)")?.severity).toBe("medium");
  });

  it("does not flag mixed content on a plain HTTP page (not applicable)", async () => {
    mockFetchRouter({
      targetUrl: "http://example.com",
      mainHeaders: {},
      mainBody: `<html><script src="http://cdn.example.com/lib.js"></script></html>`,
    });
    const result = await runScan("http://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Mixed Content (HTTP Resources on HTTPS Page)")).toBeUndefined();
  });

  it("does not flag an HTTPS page with no HTTP resource references", async () => {
    mockFetchRouter({
      targetUrl: "https://example.com",
      mainHeaders: {},
      mainBody: `<html><script src="https://cdn.example.com/lib.js"></script></html>`,
    });
    const result = await runScan("https://example.com", "basic");
    expect(findByName(result.vulnerabilities, "Mixed Content (HTTP Resources on HTTPS Page)")).toBeUndefined();
  });
});

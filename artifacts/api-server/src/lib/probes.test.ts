import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Regression-lock tests for probes.ts — every function here was already
 * manually validated live against a real deliberately-vulnerable test app
 * earlier this session (headers, cookies, sensitive files, HTTP methods,
 * active CORS, open redirect, robots.txt, SRI, error disclosure, HTTPS
 * redirect, rate limiting, clickjacking, directory listing, security.txt
 * all fired correctly). These tests exist to catch future regressions and
 * to pin down the exact false-positive-exclusion behavior.
 */

import {
  checkSensitiveFiles,
  checkHttpMethods,
  checkActiveCors,
  checkOpenRedirect,
  checkRobotsTxt,
  checkSRI,
  checkErrorDisclosure,
  checkHttpsRedirect,
  checkRateLimiting,
  checkClickjacking,
  checkDirectoryListing,
  checkSecurityTxt,
  runAllProbes,
} from "./probes.js";

function jsonResponse(body: string, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(body, { status, headers });
}

// Response.url is a read-only accessor from the prototype — normally only
// ever set by a real fetch(). Object.assign silently no-ops on it, so any
// code that reads res.url (safeGet's finalUrl) sees "" from a plain `new
// Response(...)`. defineProperty shadows the inherited getter with an own
// data property, which actually works.
function respondAt(url: string, body: string, status = 200, headers: Record<string, string> = {}): Response {
  const res = new Response(body, { status, headers });
  Object.defineProperty(res, "url", { value: url, configurable: true });
  return res;
}

function mockFetchOnce(impl: (url: string, init?: RequestInit) => Response) {
  vi.mocked(fetch).mockImplementationOnce(async (input, init) => impl(String(input), init));
}

function mockFetchAlways(impl: (url: string, init?: RequestInit) => Response) {
  vi.mocked(fetch).mockImplementation(async (input, init) => impl(String(input), init));
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

// ─── checkSensitiveFiles ────────────────────────────────────────────────────

describe("checkSensitiveFiles", () => {
  it("flags a real .env file returned with 200", async () => {
    mockFetchAlways((url) => {
      if (url.endsWith("/.env")) {
        return respondAt(url, "DATABASE_URL=postgres://user:pass@host/db\n", 200, {
          "content-type": "text/plain",
        });
      }
      return respondAt(url, "", 404);
    });

    const results = await checkSensitiveFiles("https://example.com");
    expect(results.some((r) => r.name === "Environment File Exposed (.env)")).toBe(true);
  });

  it("does not flag .env when content is a 200 HTML soft-404", async () => {
    mockFetchAlways((url) => {
      if (url.endsWith("/.env")) {
        return respondAt(url, "<!DOCTYPE html><html>Not Found</html>", 200, {
          "content-type": "text/html",
        });
      }
      return respondAt(url, "", 404);
    });

    const results = await checkSensitiveFiles("https://example.com");
    expect(results.some((r) => r.name === "Environment File Exposed (.env)")).toBe(false);
  });

  it("flags wp-config.php when returned same-host with matching content", async () => {
    mockFetchAlways((url) => {
      if (url.endsWith("/wp-config.php")) {
        return respondAt(url, "define('DB_PASSWORD', 'x');", 200, { "content-type": "text/html" });
      }
      return respondAt(url, "", 404);
    });
    const results = await checkSensitiveFiles("https://example.com");
    expect(results.some((r) => r.name === "WordPress Config File Exposed (wp-config.php)")).toBe(true);
  });

  it("does not flag when the final URL redirects to a different host (catch-all login page)", async () => {
    mockFetchAlways((url) => {
      if (url.endsWith("/wp-config.php")) {
        // Redirected off-host (e.g. to a login page) — even with matching
        // body content, a different final hostname must suppress the finding.
        return respondAt("https://login.someotherhost.com/", "define('DB_PASSWORD', 'x');", 200, {
          "content-type": "text/html",
        });
      }
      return respondAt(url, "", 404);
    });
    const results = await checkSensitiveFiles("https://example.com");
    expect(results.some((r) => r.name === "WordPress Config File Exposed (wp-config.php)")).toBe(false);
  });
});

// ─── checkHttpMethods ────────────────────────────────────────────────────────

describe("checkHttpMethods", () => {
  it("flags TRACE when present in Allow header", async () => {
    mockFetchOnce(() => jsonResponse("", 200, { allow: "GET, POST, TRACE" }));
    const results = await checkHttpMethods("https://example.com");
    expect(results.some((r) => r.name === "HTTP TRACE Method Enabled (Cross-Site Tracing)")).toBe(true);
  });

  it("flags dangerous methods PUT/DELETE/PATCH and names exactly which ones", async () => {
    mockFetchOnce(() => jsonResponse("", 200, { allow: "GET, POST, PUT, DELETE" }));
    const results = await checkHttpMethods("https://example.com");
    const finding = results.find((r) => r.name.startsWith("Dangerous HTTP Methods Advertised"));
    expect(finding).toBeDefined();
    expect(finding!.name).toContain("PUT");
    expect(finding!.name).toContain("DELETE");
    expect(finding!.name).not.toContain("PATCH");
  });

  it("flags CONNECT when present", async () => {
    mockFetchOnce(() => jsonResponse("", 200, { allow: "GET, CONNECT" }));
    const results = await checkHttpMethods("https://example.com");
    expect(results.some((r) => r.name === "HTTP CONNECT Method Enabled")).toBe(true);
  });

  it("returns no findings when Allow header is absent", async () => {
    mockFetchOnce(() => jsonResponse("", 200));
    const results = await checkHttpMethods("https://example.com");
    expect(results).toEqual([]);
  });

  it("reads Allow, not Access-Control-Allow-Methods", async () => {
    mockFetchOnce(() => jsonResponse("", 200, { "access-control-allow-methods": "GET, PUT, DELETE" }));
    const results = await checkHttpMethods("https://example.com");
    expect(results).toEqual([]);
  });
});

// ─── checkActiveCors ─────────────────────────────────────────────────────────

describe("checkActiveCors", () => {
  it("flags critical when origin is reflected with credentials:true", async () => {
    mockFetchOnce((_, init) => {
      const origin = (init?.headers as Record<string, string>)?.["Origin"];
      return jsonResponse("", 200, {
        "access-control-allow-origin": origin ?? "",
        "access-control-allow-credentials": "true",
      });
    });
    const results = await checkActiveCors("https://example.com");
    expect(results.some((r) => r.name === "CORS Misconfiguration — Credentials Allowed from Arbitrary Origin")).toBe(true);
    expect(results[0]!.severity).toBe("critical");
  });

  it("flags medium when origin is reflected without credentials", async () => {
    mockFetchOnce((_, init) => {
      const origin = (init?.headers as Record<string, string>)?.["Origin"];
      return jsonResponse("", 200, { "access-control-allow-origin": origin ?? "" });
    });
    const results = await checkActiveCors("https://example.com");
    expect(results.some((r) => r.name === "CORS Misconfiguration — Origin Reflected Without Allowlist")).toBe(true);
    expect(results[0]!.severity).toBe("medium");
  });

  it("does not flag when ACAO is absent", async () => {
    mockFetchAlways(() => jsonResponse("", 200));
    const results = await checkActiveCors("https://example.com");
    expect(results).toEqual([]);
  });

  it("does not flag a real allowlist that doesn't reflect the sent origin", async () => {
    mockFetchAlways(() => jsonResponse("", 200, { "access-control-allow-origin": "https://trusted.example.com" }));
    const results = await checkActiveCors("https://example.com");
    expect(results).toEqual([]);
  });
});

// ─── checkOpenRedirect ───────────────────────────────────────────────────────

describe("checkOpenRedirect", () => {
  it("flags an open redirect when Location points to the probe domain", async () => {
    mockFetchOnce(() =>
      new Response(null, { status: 302, headers: { location: "https://evil-redirect-probe.com" } }),
    );
    const results = await checkOpenRedirect("https://example.com/go");
    expect(results.some((r) => r.name === "Open Redirect Vulnerability")).toBe(true);
  });

  it("does not flag a 200 response (no redirect)", async () => {
    mockFetchAlways(() => jsonResponse("", 200));
    const results = await checkOpenRedirect("https://example.com/go");
    expect(results).toEqual([]);
  });

  it("does not flag a redirect to an unrelated domain", async () => {
    mockFetchAlways(() =>
      new Response(null, { status: 302, headers: { location: "https://example.com/home" } }),
    );
    const results = await checkOpenRedirect("https://example.com/go");
    expect(results).toEqual([]);
  });
});

// ─── checkRobotsTxt ──────────────────────────────────────────────────────────

describe("checkRobotsTxt", () => {
  it("flags sensitive disallowed paths", async () => {
    mockFetchOnce(() =>
      jsonResponse("User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /public\n", 200),
    );
    const results = await checkRobotsTxt("https://example.com");
    const finding = results.find((r) => r.name === "robots.txt Discloses Sensitive Application Paths");
    expect(finding).toBeDefined();
    expect(finding!.evidence).toContain("/admin");
    expect(finding!.evidence).toContain("/backup");
  });

  it("does not flag when only non-sensitive paths (or /) are disallowed", async () => {
    mockFetchOnce(() => jsonResponse("User-agent: *\nDisallow: /\nDisallow: /public\n", 200));
    const results = await checkRobotsTxt("https://example.com");
    expect(results).toEqual([]);
  });

  it("does not flag when robots.txt is absent", async () => {
    mockFetchOnce(() => jsonResponse("", 404));
    const results = await checkRobotsTxt("https://example.com");
    expect(results).toEqual([]);
  });
});

// ─── checkSRI ────────────────────────────────────────────────────────────────

describe("checkSRI", () => {
  it("flags a cross-origin script missing integrity", async () => {
    const html = `<script src="https://cdn.example.net/lib.js"></script>`;
    const results = await checkSRI(html, "https://example.com");
    expect(results.some((r) => r.name === "External Resources Missing Subresource Integrity (SRI)")).toBe(true);
  });

  it("does not flag when integrity is present", async () => {
    const html = `<script src="https://cdn.example.net/lib.js" integrity="sha384-abc"></script>`;
    const results = await checkSRI(html, "https://example.com");
    expect(results).toEqual([]);
  });

  it("does not flag a content-hashed URL even without integrity", async () => {
    const html = `<script src="https://cdn.example.net/chunk.a1b2c3d4e5f6a7b8.js"></script>`;
    const results = await checkSRI(html, "https://example.com");
    expect(results).toEqual([]);
  });

  it("does not flag a same-origin script missing integrity", async () => {
    const html = `<script src="https://example.com/app.js"></script>`;
    const results = await checkSRI(html, "https://example.com");
    expect(results).toEqual([]);
  });
});

// ─── checkErrorDisclosure ────────────────────────────────────────────────────

describe("checkErrorDisclosure", () => {
  it("flags a Node.js stack trace leak", async () => {
    mockFetchOnce(() =>
      jsonResponse("Error\n    at handle (/app/server.js:42:15)\n    at next (/app/router.js:10:3)", 500),
    );
    const results = await checkErrorDisclosure("https://example.com");
    expect(results.some((r) => r.name === "Verbose Error Pages Expose Internal Application Details")).toBe(true);
  });

  it("flags Werkzeug/Flask debugger as critical RCE", async () => {
    mockFetchOnce(() => jsonResponse("Werkzeug Debugger caught an exception", 500));
    const results = await checkErrorDisclosure("https://example.com");
    const finding = results.find((r) => r.name.includes("Werkzeug Interactive Debugger"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("critical");
  });

  it("does not flag a clean generic 404 page", async () => {
    mockFetchOnce(() => jsonResponse("<html><body>404 Not Found</body></html>", 404));
    const results = await checkErrorDisclosure("https://example.com");
    expect(results).toEqual([]);
  });
});

// ─── checkHttpsRedirect ──────────────────────────────────────────────────────

describe("checkHttpsRedirect", () => {
  it("returns [] immediately for an http:// target without any fetch", async () => {
    const results = await checkHttpsRedirect("http://example.com");
    expect(results).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("flags when the http:// version never reaches https://", async () => {
    mockFetchAlways((url) => {
      if (url.startsWith("http://")) {
        return respondAt("http://example.com/", "");
      }
      // hstspreload.org check
      return respondAt(url, JSON.stringify({ status: "unknown" }));
    });
    const results = await checkHttpsRedirect("https://example.com");
    expect(results.some((r) => r.name === "HTTP Traffic Not Redirected to HTTPS")).toBe(true);
  });

  it("does not flag when the http:// version redirects to https://", async () => {
    mockFetchAlways((url) => {
      if (url.startsWith("http://")) {
        return respondAt("https://example.com/", "");
      }
      return respondAt(url, JSON.stringify({ status: "unknown" }));
    });
    const results = await checkHttpsRedirect("https://example.com");
    expect(results).toEqual([]);
  });

  it("suppresses the finding for an HSTS-preloaded domain", async () => {
    mockFetchAlways((url) => {
      if (url.startsWith("http://")) {
        return respondAt("http://mysite.example/", "");
      }
      if (url.includes("hstspreload.org")) {
        return respondAt(url, JSON.stringify({ status: "preloaded" }));
      }
      return respondAt(url, "");
    });
    const results = await checkHttpsRedirect("https://mysite.example");
    expect(results).toEqual([]);
  });
});

// ─── checkRateLimiting ───────────────────────────────────────────────────────

describe("checkRateLimiting", () => {
  it("flags when no rate-limit or infra signals are present", async () => {
    mockFetchOnce(() => jsonResponse("", 200));
    const results = await checkRateLimiting("https://example.com");
    expect(results.some((r) => r.name === "No Rate Limiting Detected")).toBe(true);
  });

  it("does not flag when a rate-limit header is present", async () => {
    mockFetchOnce(() => jsonResponse("", 200, { "x-ratelimit-limit": "100" }));
    const results = await checkRateLimiting("https://example.com");
    expect(results).toEqual([]);
  });

  it("does not flag when a Cloudflare cf-ray header is present", async () => {
    mockFetchOnce(() => jsonResponse("", 200, { "cf-ray": "abc123" }));
    const results = await checkRateLimiting("https://example.com");
    expect(results).toEqual([]);
  });
});

// ─── checkClickjacking ───────────────────────────────────────────────────────

describe("checkClickjacking", () => {
  it("flags a misconfigured X-Frame-Options value", async () => {
    mockFetchOnce(() => jsonResponse("", 200, { "x-frame-options": "ALLOW-FROM https://x.com" }));
    const results = await checkClickjacking("https://example.com");
    expect(results.some((r) => r.name === "X-Frame-Options Header Misconfigured")).toBe(true);
  });

  it("does not flag when X-Frame-Options is absent (handled elsewhere)", async () => {
    mockFetchOnce(() => jsonResponse("", 200));
    const results = await checkClickjacking("https://example.com");
    expect(results).toEqual([]);
  });

  it("does not flag DENY", async () => {
    mockFetchOnce(() => jsonResponse("", 200, { "x-frame-options": "DENY" }));
    const results = await checkClickjacking("https://example.com");
    expect(results).toEqual([]);
  });
});

// ─── checkDirectoryListing ───────────────────────────────────────────────────

describe("checkDirectoryListing", () => {
  it("flags a directory that returns an index listing", async () => {
    mockFetchAlways((url) => {
      if (url.endsWith("/uploads/")) {
        return jsonResponse("<title>Index of /uploads/</title>", 200);
      }
      return jsonResponse("normal page", 200);
    });
    const results = await checkDirectoryListing("https://example.com");
    expect(results.some((r) => r.name === "Directory Listing Enabled")).toBe(true);
  });

  it("does not flag a normal 200 page with no listing markers", async () => {
    mockFetchAlways(() => jsonResponse("<html>Nothing here</html>", 200));
    const results = await checkDirectoryListing("https://example.com");
    expect(results).toEqual([]);
  });

  it("caps at 3 findings even if more dirs match", async () => {
    mockFetchAlways(() => jsonResponse("Index of /", 200));
    const results = await checkDirectoryListing("https://example.com");
    expect(results.length).toBeLessThanOrEqual(3);
  });
});

// ─── checkSecurityTxt ────────────────────────────────────────────────────────

describe("checkSecurityTxt", () => {
  it("flags when both security.txt locations are absent", async () => {
    mockFetchAlways(() => jsonResponse("", 404));
    const results = await checkSecurityTxt("https://example.com");
    expect(results.some((r) => r.name === "Missing security.txt (RFC 9116)")).toBe(true);
  });

  it("does not flag when security.txt is present with Contact:", async () => {
    mockFetchAlways(() => jsonResponse("Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n", 200));
    const results = await checkSecurityTxt("https://example.com");
    expect(results).toEqual([]);
  });
});

// ─── runAllProbes orchestrator ───────────────────────────────────────────────

describe("runAllProbes", () => {
  it("aggregates findings from multiple independent probes", async () => {
    mockFetchAlways((url) => {
      if (url.endsWith("/.env")) {
        return respondAt(url, "SECRET=abc123\n", 200, { "content-type": "text/plain" });
      }
      if (url.endsWith("/robots.txt")) {
        return respondAt(url, "User-agent: *\nDisallow: /admin\n", 200);
      }
      return respondAt(url, "", 404);
    });

    const results = await runAllProbes("https://example.com", "<html></html>");
    expect(results.some((r) => r.name === "Environment File Exposed (.env)")).toBe(true);
    expect(results.some((r) => r.name === "robots.txt Discloses Sensitive Application Paths")).toBe(true);
  });

  it("one probe rejecting doesn't prevent others' results (Promise.allSettled)", async () => {
    mockFetchAlways((url) => {
      if (url.endsWith("/robots.txt")) {
        return jsonResponse("User-agent: *\nDisallow: /admin\n", 200);
      }
      if (url.endsWith("/") && !url.includes("robots") && !url.includes(".env")) {
        throw new Error("simulated network failure");
      }
      return jsonResponse("", 404);
    });

    const results = await runAllProbes("https://example.com", "<html></html>");
    expect(results.some((r) => r.name === "robots.txt Discloses Sensitive Application Paths")).toBe(true);
  });
});

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * cveCheck.test.ts — version extraction + known-vulnerability matching.
 *
 * ./eolFetcher is mocked so PHP/Nginx/Apache EOL data is deterministic
 * (the real module fetches live data via @workspace/db, which isn't
 * available in a unit test). This session already confirmed LIVE that
 * Apache 2.2.14 and PHP 5.6.40 Server-header spoofing correctly trigger
 * these exact findings against a real running scanner — these tests
 * regression-lock that behavior plus the branches that weren't exercised
 * live (Nginx, IIS, OSV.dev, EOL-cycle-without-CVE-match).
 */

vi.mock("./eolFetcher", () => ({
  getLivePhpEol: vi.fn(() => ({ "5.6": "PHP 5.6 reached end of life in December 2018." })),
  getLiveNginxEolCycles: vi.fn(() => new Set<string>()),
  getLiveApacheEolCycles: vi.fn(() => new Set<string>(["2.4"])),
  getEolDataFetchedAt: vi.fn(() => null),
}));

import { checkForKnownVulnerabilities, extractVersionedTechnologies } from "./cveCheck.js";

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

function osvResponse(vulns: unknown[]): Response {
  return new Response(JSON.stringify({ vulns }), { status: 200, headers: { "content-type": "application/json" } });
}

describe("extractVersionedTechnologies", () => {
  it("extracts jQuery version from a CDN script URL", () => {
    const html = `<script src="https://cdn.example.com/jquery/1.11.3/jquery.min.js"></script>`;
    const found = extractVersionedTechnologies(html, {});
    expect(found.some((f) => f.packageName === "jquery" && f.version === "1.11.3")).toBe(true);
  });

  it("extracts PHP version from X-Powered-By header", () => {
    const found = extractVersionedTechnologies("", { "x-powered-by": "PHP/5.6.40" });
    expect(found).toContainEqual(expect.objectContaining({ packageName: "php", version: "5.6.40", ecosystem: "local" }));
  });

  it("extracts Nginx version from Server header", () => {
    const found = extractVersionedTechnologies("", { server: "nginx/1.14.0" });
    expect(found).toContainEqual(expect.objectContaining({ packageName: "nginx", version: "1.14.0" }));
  });

  it("extracts Apache version from Server header", () => {
    const found = extractVersionedTechnologies("", { server: "Apache/2.2.14" });
    expect(found).toContainEqual(expect.objectContaining({ packageName: "apache", techName: "Apache", version: "2.2.14" }));
  });

  it("extracts IIS version from Server header", () => {
    const found = extractVersionedTechnologies("", { server: "Microsoft-IIS/6.0" });
    expect(found).toContainEqual(expect.objectContaining({ packageName: "iis", version: "6.0" }));
  });

  it("returns an empty array when nothing matches", () => {
    expect(extractVersionedTechnologies("<html>hello</html>", { server: "cloudflare" })).toEqual([]);
  });
});

describe("checkForKnownVulnerabilities — Apache", () => {
  it("flags Apache 2.2.14 with CVE-2023-25690 (matches the earlier live scan result)", async () => {
    const findings = await checkForKnownVulnerabilities("", { server: "Apache/2.2.14" });
    const cve = findings.find((f) => f.name.includes("CVE-2023-25690"));
    expect(cve).toBeDefined();
    expect(cve!.severity).toBe("critical");
    expect(cve!.cvssScore).toBe(9.8);
  });

  it("falls back to the EOL-cycle finding when the version escapes the CVE range but the branch is EOL", async () => {
    // 2.4.60 is NOT < 2.4.55 (no CVE match) but "2.4" is in the mocked EOL cycle set
    const findings = await checkForKnownVulnerabilities("", { server: "Apache/2.4.60" });
    expect(findings.some((f) => /end-of-life release branch/i.test(f.name))).toBe(true);
    expect(findings.some((f) => f.name.includes("CVE-"))).toBe(false);
  });

  it("does not flag a version outside both the CVE range and the EOL cycle set", async () => {
    const findings = await checkForKnownVulnerabilities("", { server: "Apache/2.6.1" });
    expect(findings.filter((f) => f.category === "Outdated Software")).toEqual([]);
  });
});

describe("checkForKnownVulnerabilities — Nginx", () => {
  it("flags the first matching CVE range when a version is below multiple thresholds", async () => {
    // 1.15.0 is < 1.20.1 (first entry) AND < 1.18.0 (second) — loop breaks on first match
    const findings = await checkForKnownVulnerabilities("", { server: "nginx/1.15.0" });
    expect(findings.some((f) => f.name.includes("CVE-2021-23017"))).toBe(true);
    expect(findings.some((f) => f.name.includes("CVE-2019-9511"))).toBe(false);
  });

  it("does not flag a current Nginx version", async () => {
    const findings = await checkForKnownVulnerabilities("", { server: "nginx/1.25.3" });
    expect(findings.filter((f) => f.category === "Outdated Software")).toEqual([]);
  });
});

describe("checkForKnownVulnerabilities — PHP EOL", () => {
  it("flags PHP 5.6.40 as end-of-life (matches the earlier live scan result)", async () => {
    const findings = await checkForKnownVulnerabilities("", { "x-powered-by": "PHP/5.6.40" });
    const phpFinding = findings.find((f) => f.name.includes("PHP 5.6.40"));
    expect(phpFinding).toBeDefined();
    expect(phpFinding!.severity).toBe("high");
  });

  it("does not flag a PHP version absent from the mocked EOL table", async () => {
    const findings = await checkForKnownVulnerabilities("", { "x-powered-by": "PHP/8.3.0" });
    expect(findings.filter((f) => f.name.includes("PHP"))).toEqual([]);
  });
});

describe("checkForKnownVulnerabilities — IIS", () => {
  it("flags IIS 6.0 with CVE-2017-7269 critical", async () => {
    const findings = await checkForKnownVulnerabilities("", { server: "Microsoft-IIS/6.0" });
    const iisFinding = findings.find((f) => f.name.includes("CVE-2017-7269"));
    expect(iisFinding).toBeDefined();
    expect(iisFinding!.severity).toBe("critical");
    expect(iisFinding!.cvssScore).toBe(9.8);
  });

  it("does not flag IIS 10.0", async () => {
    const findings = await checkForKnownVulnerabilities("", { server: "Microsoft-IIS/10.0" });
    expect(findings.filter((f) => f.name.includes("IIS"))).toEqual([]);
  });
});

describe("checkForKnownVulnerabilities — OSV.dev integration", () => {
  it("produces a finding when OSV.dev returns a matching vulnerability", async () => {
    vi.mocked(fetch).mockResolvedValue(
      osvResponse([{
        id: "GHSA-abcd-1234",
        aliases: ["CVE-2020-11022"],
        summary: "Cross-site scripting in jQuery",
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/7.4" }],
        affected: [{ ranges: [{ events: [{ fixed: "3.5.0" }] }] }],
      }]),
    );
    const html = `<script src="/jquery/1.11.3/jquery.min.js"></script>`;
    const findings = await checkForKnownVulnerabilities(html, {});
    const osvFinding = findings.find((f) => f.name.includes("CVE-2020-11022"));
    expect(osvFinding).toBeDefined();
    expect(osvFinding!.solution).toContain("3.5.0");
  });

  it("produces no finding when OSV.dev returns zero matches", async () => {
    vi.mocked(fetch).mockResolvedValue(osvResponse([]));
    const html = `<script src="/jquery/3.7.1/jquery.min.js"></script>`;
    const findings = await checkForKnownVulnerabilities(html, {});
    expect(findings).toEqual([]);
  });

  it("does not crash and produces no finding when the OSV.dev request fails", async () => {
    // Deliberately a different version than the other OSV tests in this file —
    // queryOsv() caches by (package, version, ecosystem) at module scope, so
    // reusing 1.11.3 here would return the earlier test's cached result
    // instead of actually exercising the network-failure path.
    vi.mocked(fetch).mockRejectedValue(new Error("network error"));
    const html = `<script src="/jquery/1.11.9/jquery.min.js"></script>`;
    const findings = await checkForKnownVulnerabilities(html, {});
    expect(findings).toEqual([]);
  });
});

describe("checkForKnownVulnerabilities — nothing detected", () => {
  it("returns an empty array and skips the OSV.dev call entirely when no versioned tech is found", async () => {
    const findings = await checkForKnownVulnerabilities("<html>hello</html>", { server: "cloudflare" });
    expect(findings).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });
});

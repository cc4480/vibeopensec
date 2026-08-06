import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * quickBaasCheck tests — verifies the fast-path orchestration (one fetch,
 * then checkVibeStackSecurity + runBaasProbes in parallel, tier fixed to
 * "deep", results merged) used by the MCP check_baas_security tool.
 * The probe implementations themselves are covered by supabase-probes.test.ts
 * etc. — this test only cares about the wiring.
 */

// baasQuickCheck imports fetchTargetHtml from ./scanner, which transitively
// imports eolFetcher.ts -> @workspace/db. The real @workspace/db module
// throws at import time if DATABASE_URL isn't set, so it's stubbed out here
// — nothing in this test's code path touches it (no module-scope DB calls
// in the transitive chain; see eolFetcher.ts/cveCheck.ts).
vi.mock("@workspace/db", () => ({}));

vi.mock("./vibeStackProbes", () => ({
  checkVibeStackSecurity: vi.fn(async () => [
    { id: "v1", name: "Supabase table readable unauthenticated", severity: "critical" },
  ]),
}));

vi.mock("./baasProbes", () => ({
  runBaasProbes: vi.fn(async () => [
    { id: "v2", name: "PocketBase collection readable unauthenticated", severity: "high" },
  ]),
}));

import { quickBaasCheck } from "./baasQuickCheck";
import { checkVibeStackSecurity } from "./vibeStackProbes";
import { runBaasProbes } from "./baasProbes";

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      new Response("<html><script>const x = createClient('https://abc.supabase.co','key')</script></html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      }),
    ),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe("quickBaasCheck", () => {
  it("fetches the target once and merges findings from both probe modules", async () => {
    const findings = await quickBaasCheck("https://example.com");

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.severity)).toEqual(["critical", "high"]);
  });

  it("always runs probes at deep tier regardless of caller", async () => {
    await quickBaasCheck("https://example.com");

    expect(checkVibeStackSecurity).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      "deep",
    );
  });

  it("returns an empty list (not a throw) when a probe module fails", async () => {
    vi.mocked(runBaasProbes).mockRejectedValueOnce(new Error("network blip"));

    const findings = await quickBaasCheck("https://example.com");

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical");
  });
});

import { describe, it, expect, vi, afterEach } from "vitest";

/**
 * vibeStackProbes.ts tests — this module is a thin orchestrator: it runs
 * runSupabaseProbes and runFirebaseProbes in parallel, both of which push
 * findings into a shared mutable array (not return values), and merges the
 * result. The probes' own detection logic is covered by
 * supabase-probes.test.ts — this file only tests the orchestration.
 */

vi.mock("./supabase-probes", () => ({
  runSupabaseProbes: vi.fn(),
}));
vi.mock("./firebase-probes", () => ({
  runFirebaseProbes: vi.fn(),
}));

import { checkVibeStackSecurity } from "./vibeStackProbes";
import { runSupabaseProbes } from "./supabase-probes";
import { runFirebaseProbes } from "./firebase-probes";

afterEach(() => {
  vi.clearAllMocks();
});

describe("checkVibeStackSecurity", () => {
  it("merges findings pushed by both Supabase and Firebase probes", async () => {
    vi.mocked(runSupabaseProbes).mockImplementation(async (_html, _tier, findings) => {
      findings.push({ id: "s1", name: "Supabase finding", severity: "critical" } as never);
    });
    vi.mocked(runFirebaseProbes).mockImplementation(async (_html, findings) => {
      findings.push({ id: "f1", name: "Firebase finding", severity: "high" } as never);
    });

    const result = await checkVibeStackSecurity("<html></html>", "https://example.com", "deep");

    expect(result.map((v) => v.name).sort()).toEqual(["Firebase finding", "Supabase finding"]);
  });

  it("still returns the other probe's findings when one probe rejects", async () => {
    vi.mocked(runSupabaseProbes).mockRejectedValue(new Error("network blip"));
    vi.mocked(runFirebaseProbes).mockImplementation(async (_html, findings) => {
      findings.push({ id: "f1", name: "Firebase finding", severity: "high" } as never);
    });

    const result = await checkVibeStackSecurity("<html></html>", "https://example.com", "deep");

    expect(result.map((v) => v.name)).toEqual(["Firebase finding"]);
  });

  it("returns an empty array when neither probe finds anything (no BaaS backend detected)", async () => {
    vi.mocked(runSupabaseProbes).mockResolvedValue(undefined);
    vi.mocked(runFirebaseProbes).mockResolvedValue(undefined);

    const result = await checkVibeStackSecurity("<html>no backend here</html>", "https://example.com", "basic");

    expect(result).toEqual([]);
  });

  it("passes the tier through to runSupabaseProbes unchanged", async () => {
    vi.mocked(runSupabaseProbes).mockResolvedValue(undefined);
    vi.mocked(runFirebaseProbes).mockResolvedValue(undefined);

    await checkVibeStackSecurity("<html></html>", "https://example.com", "basic");

    expect(runSupabaseProbes).toHaveBeenCalledWith("<html></html>", "basic", expect.any(Array));
  });
});

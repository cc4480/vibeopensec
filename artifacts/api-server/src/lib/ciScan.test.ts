import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * runScanAndWait tests — this logic was extracted verbatim out of routes/ci.ts
 * (the existing GitHub Action / CI pipeline endpoint) so the new MCP scan_url
 * tool can reuse it. These tests exist to prove the extraction preserved
 * behavior: the enqueue/poll/summarize flow, the failOn severity gate, and
 * the "still running" / "failed" terminal states.
 *
 * @workspace/db and ./queue are mocked — this is pure orchestration logic,
 * not a DB-integration test. fake timers drive the poll loop deterministically
 * instead of waiting on real 3s intervals.
 */

const selectQueue: unknown[][] = [];

function pushSelectResult(row: unknown) {
  selectQueue.push([row]);
}

vi.mock("@workspace/db", () => {
  return {
    db: {
      insert: vi.fn(() => ({
        values: vi.fn((v: Record<string, unknown>) => ({
          returning: vi.fn(async () => [{ id: "scan-1", ...v }]),
        })),
      })),
      update: vi.fn(() => ({
        set: vi.fn(() => ({
          where: vi.fn(async () => undefined),
        })),
      })),
      select: vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(async () => selectQueue.shift() ?? [undefined]),
        })),
      })),
    },
    scansTable: {},
    reportsTable: {},
  };
});

vi.mock("./queue", () => ({
  enqueueScan: vi.fn(async () => "job-1"),
}));

import { runScanAndWait } from "./ciScan";

const BASE_PARAMS = {
  userId: "user-1",
  userEmail: "dev@example.com",
  targetUrl: "https://example.com",
  origin: "https://seclayer.io",
} as const;

beforeEach(() => {
  selectQueue.length = 0;
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("runScanAndWait", () => {
  it("returns a passing summary when the worst finding is below failOn", async () => {
    pushSelectResult({ status: "complete" }); // status poll
    pushSelectResult({
      // reportsTable row
      id: "report-1",
      data: {
        summary: { grade: "B", riskScore: 12, totalVulnerabilities: 1, critical: 0, high: 0, medium: 1 },
        vulnerabilities: [{ name: "Missing HSTS", severity: "medium" }],
      },
    });

    const resultPromise = runScanAndWait({ ...BASE_PARAMS, tier: "basic", failOn: "high" });
    await vi.advanceTimersByTimeAsync(3_000);
    const result = await resultPromise;

    expect(result.status).toBe("complete");
    expect(result.grade).toBe("B");
    expect(result.passed).toBe(true);
    expect(result.reportUrl).toBe("https://seclayer.io/report/report-1");
    expect(result.topFindings).toEqual([{ name: "Missing HSTS", severity: "medium" }]);
  });

  it("fails the gate when a finding at or above failOn exists", async () => {
    pushSelectResult({ status: "complete" });
    pushSelectResult({
      id: "report-2",
      data: {
        summary: { grade: "F", riskScore: 80, totalVulnerabilities: 1, critical: 1, high: 0, medium: 0 },
        vulnerabilities: [{ name: "Exposed .env file", severity: "critical" }],
      },
    });

    const resultPromise = runScanAndWait({ ...BASE_PARAMS, tier: "deep", failOn: "high" });
    await vi.advanceTimersByTimeAsync(3_000);
    const result = await resultPromise;

    expect(result.passed).toBe(false);
  });

  it("failOn 'never' always passes regardless of severity", async () => {
    pushSelectResult({ status: "complete" });
    pushSelectResult({
      id: "report-3",
      data: {
        summary: { grade: "F", riskScore: 90, totalVulnerabilities: 1, critical: 1, high: 0, medium: 0 },
        vulnerabilities: [{ name: "Exposed .env file", severity: "critical" }],
      },
    });

    const resultPromise = runScanAndWait({ ...BASE_PARAMS, tier: "deep", failOn: "never" });
    await vi.advanceTimersByTimeAsync(3_000);
    const result = await resultPromise;

    expect(result.passed).toBe(true);
  });

  it("reports a failed scan without a report URL", async () => {
    pushSelectResult({ status: "failed" });

    const resultPromise = runScanAndWait({ ...BASE_PARAMS, tier: "basic", failOn: "high" });
    await vi.advanceTimersByTimeAsync(3_000);
    const result = await resultPromise;

    expect(result.status).toBe("failed");
    expect(result.reportUrl).toBeNull();
    expect(result.passed).toBeNull();
    expect(result.message).toBe("Scan failed to complete.");
  });

  it("reports still-running once the max wait is exceeded", async () => {
    // Every poll keeps returning "queued" — the queue never empties.
    vi.mocked((await import("@workspace/db")).db.select).mockImplementation(
      () =>
        ({
          from: () => ({ where: async () => [{ status: "queued" }] }),
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        }) as any,
    );

    const resultPromise = runScanAndWait({ ...BASE_PARAMS, tier: "basic", failOn: "high" });
    await vi.advanceTimersByTimeAsync(5 * 60 * 1000 + 3_000);
    const result = await resultPromise;

    expect(result.status).toBe("queued");
    expect(result.passed).toBeNull();
    expect(result.message).toContain("still running");
  });
});

/**
 * Shared "enqueue a scan, wait for it, summarize the result" helper.
 *
 * Originally lived inline in routes/ci.ts (the GitHub Action / CI pipeline
 * endpoint). Extracted so the MCP server's scan_url tool can trigger the
 * exact same full scan pipeline — same queue, same grading, same pass/fail
 * gate — without duplicating the polling logic.
 */

import { db, scansTable, reportsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { enqueueScan } from "./queue";
import type { ScanVulnerability } from "./scanner";

const POLL_INTERVAL_MS = 3_000;
const MAX_WAIT_MS = 5 * 60 * 1000; // covers the slowest deep scans

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export type FailOn = "critical" | "high" | "medium" | "never";

interface ReportSummary {
  grade?: string;
  riskScore?: number;
  totalVulnerabilities?: number;
  critical?: number;
  high?: number;
  medium?: number;
}

export interface RunScanAndWaitParams {
  userId: string;
  userEmail: string;
  targetUrl: string;
  tier: "basic" | "deep";
  failOn: FailOn;
  /** Origin used to build the human-readable report URL, e.g. from getOrigin(req). */
  origin: string;
}

export interface ScanAndWaitResult {
  scanId: string;
  status: "complete" | "queued" | "scanning" | "analyzing" | "failed";
  reportUrl: string | null;
  grade: string | null;
  riskScore: number | null;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  topFindings: { name: string; severity: string }[];
  passed: boolean | null;
  message?: string;
}

/**
 * Enqueues a scan for the given target, polls until it completes (or
 * MAX_WAIT_MS elapses), and returns a compact summary shaped for a
 * PR comment / build gate / MCP tool response.
 */
export async function runScanAndWait(params: RunScanAndWaitParams): Promise<ScanAndWaitResult> {
  const { userId, userEmail, targetUrl, tier, failOn, origin } = params;

  const [scan] = await db
    .insert(scansTable)
    .values({
      userId,
      userEmail,
      targetUrl,
      tier,
      // CI/MCP scans skip the credit/checkout flow entirely, same as free-mode web scans.
      status: "paid",
    })
    .returning();

  await enqueueScan({ scanId: scan.id, userId, targetUrl, tier });
  await db
    .update(scansTable)
    .set({ status: "queued", startedAt: new Date() })
    .where(eq(scansTable.id, scan.id));

  const reportUrlBase = `${origin}/report`;

  const deadline = Date.now() + MAX_WAIT_MS;
  let finalStatus = "queued";
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    const [row] = await db
      .select({ status: scansTable.status })
      .from(scansTable)
      .where(eq(scansTable.id, scan.id));
    finalStatus = row?.status ?? "failed";
    if (finalStatus === "complete" || finalStatus === "failed") break;
  }

  if (finalStatus !== "complete") {
    return {
      scanId: scan.id,
      status: finalStatus as ScanAndWaitResult["status"],
      reportUrl: null,
      grade: null,
      riskScore: null,
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      topFindings: [],
      passed: null,
      message:
        finalStatus === "failed"
          ? "Scan failed to complete."
          : `Scan is still running after ${Math.round(MAX_WAIT_MS / 1000)}s — check ${reportUrlBase}/pending or re-poll.`,
    };
  }

  const [report] = await db.select().from(reportsTable).where(eq(reportsTable.scanId, scan.id));
  const data = report?.data as { summary?: ReportSummary; vulnerabilities?: ScanVulnerability[] } | undefined;
  const summary = data?.summary;
  const vulnerabilities = data?.vulnerabilities ?? [];

  const worstSeverityRank = vulnerabilities.reduce(
    (max, v) => Math.max(max, SEVERITY_RANK[v.severity] ?? 0),
    0,
  );
  const passed = failOn === "never" ? true : worstSeverityRank < (SEVERITY_RANK[failOn] ?? SEVERITY_RANK.high!);

  return {
    scanId: scan.id,
    status: "complete",
    reportUrl: report ? `${reportUrlBase}/${report.id}` : null,
    grade: summary?.grade ?? null,
    riskScore: summary?.riskScore ?? null,
    totalVulnerabilities: summary?.totalVulnerabilities ?? 0,
    criticalCount: summary?.critical ?? 0,
    highCount: summary?.high ?? 0,
    mediumCount: summary?.medium ?? 0,
    topFindings: vulnerabilities
      .slice()
      .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0))
      .slice(0, 5)
      .map((v) => ({ name: v.name, severity: v.severity })),
    passed,
  };
}

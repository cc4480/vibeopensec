import { Router, type IRouter } from "express";
import { db, scansTable, reportsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { enqueueScan } from "../lib/queue";
import { getOrigin } from "../lib/stripe";
import type { ScanVulnerability } from "../lib/scanner";

const router: IRouter = Router();

const CiScanBody = z.object({
  targetUrl: z.string().url("Must be a valid URL"),
  tier: z.enum(["basic", "deep"]).default("deep"),
  // Fail the build (passed: false) when a finding at or above this severity exists.
  failOn: z.enum(["critical", "high", "medium", "never"]).default("high"),
});

const POLL_INTERVAL_MS = 3_000;
const MAX_WAIT_MS = 5 * 60 * 1000; // covers the slowest deep scans

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

interface ReportSummary {
  grade?: string;
  riskScore?: number;
  totalVulnerabilities?: number;
  critical?: number;
  high?: number;
  medium?: number;
}

// ── POST /api/ci/scan — synchronous scan-and-summarize for CI pipelines ───────
// Auth via any bearer token, but intended for a `vibescan_ci_*` API key
// (see ciKeys.ts). Blocks until the scan completes (or MAX_WAIT_MS elapses),
// then returns a compact JSON summary shaped for a PR comment / build gate.
router.post("/ci/scan", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = CiScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Invalid request" });
    return;
  }
  const { targetUrl, tier, failOn } = parsed.data;

  const [scan] = await db
    .insert(scansTable)
    .values({
      userId: req.user.id,
      userEmail: req.user.email ?? "",
      targetUrl,
      tier,
      // CI scans skip the credit/checkout flow entirely, same as free-mode web scans.
      status: "paid",
    })
    .returning();

  await enqueueScan({ scanId: scan.id, userId: req.user.id, targetUrl, tier });
  await db
    .update(scansTable)
    .set({ status: "queued", startedAt: new Date() })
    .where(eq(scansTable.id, scan.id));

  const reportUrlBase = `${getOrigin(req)}/report`;

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
    res.status(202).json({
      scanId: scan.id,
      status: finalStatus,
      reportUrl: null,
      passed: null,
      message:
        finalStatus === "failed"
          ? "Scan failed to complete."
          : `Scan is still running after ${Math.round(MAX_WAIT_MS / 1000)}s — check ${reportUrlBase}/pending or re-poll.`,
    });
    return;
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

  res.json({
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
  });
});

export default router;

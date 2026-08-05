import { Router, type IRouter } from "express";
import { db, reportsTable, reportSharesTable } from "@workspace/db";
import { eq, and, isNull } from "drizzle-orm";
import { randomBytes } from "node:crypto";
import { z } from "zod";

const router: IRouter = Router();

const CreateShareBody = z.object({
  expiresIn: z.enum(["7d", "30d", "never"]).default("never"),
});

function computeExpiry(expiresIn: "7d" | "30d" | "never"): Date | null {
  if (expiresIn === "never") return null;
  const days = expiresIn === "7d" ? 7 : 30;
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d;
}

export type ResolvedShare =
  | { status: "ok"; targetUrl: string; grade: string | null; riskScore: number | null }
  | { status: "not_found" }
  | { status: "expired" };

/**
 * Shared lookup used by both the public share JSON API and the OG-card
 * middleware in app.ts — a non-revoked, non-expired share plus its report's
 * grade/risk score, or a status explaining why it's unavailable.
 */
export async function resolveShare(token: string): Promise<ResolvedShare> {
  const [share] = await db
    .select()
    .from(reportSharesTable)
    .where(and(eq(reportSharesTable.token, token), isNull(reportSharesTable.revokedAt)));

  if (!share) return { status: "not_found" };
  if (share.expiresAt && share.expiresAt < new Date()) return { status: "expired" };

  const [report] = await db
    .select({ targetUrl: reportsTable.targetUrl, data: reportsTable.data })
    .from(reportsTable)
    .where(eq(reportsTable.id, share.reportId));

  if (!report) return { status: "not_found" };

  const data = report.data as { summary?: { grade?: string; riskScore?: number } } | undefined;
  return {
    status: "ok",
    targetUrl: report.targetUrl,
    grade: data?.summary?.grade ?? null,
    riskScore: data?.summary?.riskScore ?? null,
  };
}

// ── POST /api/reports/:id/shares — create a share link ────────────────────────
router.post("/reports/:id/shares", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const reportId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const parsed = CreateShareBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request" });
    return;
  }

  try {
    const [report] = await db
      .select({ id: reportsTable.id, userId: reportsTable.userId })
      .from(reportsTable)
      .where(eq(reportsTable.id, reportId));

    if (!report) {
      res.status(404).json({ error: "Report not found" });
      return;
    }
    if (report.userId !== req.user!.id) {
      res.status(403).json({ error: "Forbidden" });
      return;
    }

    const token = randomBytes(32).toString("hex");
    const expiresAt = computeExpiry(parsed.data.expiresIn);

    const [share] = await db
      .insert(reportSharesTable)
      .values({ reportId, userId: req.user!.id, token, expiresAt })
      .returning();

    res.status(201).json({
      id: share.id,
      token: share.token,
      expiresAt: share.expiresAt?.toISOString() ?? null,
      createdAt: share.createdAt.toISOString(),
      revokedAt: null,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to create share");
    res.status(500).json({ error: "Failed to create share" });
  }
});

// ── GET /api/reports/:id/shares — list share links for a report ───────────────
router.get("/reports/:id/shares", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const reportId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

  try {
    const [report] = await db
      .select({ id: reportsTable.id, userId: reportsTable.userId })
      .from(reportsTable)
      .where(eq(reportsTable.id, reportId));

    if (!report) {
      res.status(404).json({ error: "Report not found" });
      return;
    }
    if (report.userId !== req.user!.id) {
      res.status(403).json({ error: "Forbidden" });
      return;
    }

    const shares = await db
      .select()
      .from(reportSharesTable)
      .where(
        and(
          eq(reportSharesTable.reportId, reportId),
          isNull(reportSharesTable.revokedAt),
        ),
      );

    res.json(
      shares.map((s) => ({
        id: s.id,
        token: s.token,
        expiresAt: s.expiresAt?.toISOString() ?? null,
        createdAt: s.createdAt.toISOString(),
        revokedAt: s.revokedAt?.toISOString() ?? null,
      })),
    );
  } catch (err) {
    req.log.error({ err }, "Failed to list shares");
    res.status(500).json({ error: "Failed to list shares" });
  }
});

// ── DELETE /api/reports/:id/shares/:token — revoke a share link ───────────────
router.delete("/reports/:id/shares/:token", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const reportId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const token = Array.isArray(req.params.token) ? req.params.token[0] : req.params.token;

  try {
    const [report] = await db
      .select({ id: reportsTable.id, userId: reportsTable.userId })
      .from(reportsTable)
      .where(eq(reportsTable.id, reportId));

    if (!report) {
      res.status(404).json({ error: "Report not found" });
      return;
    }
    if (report.userId !== req.user!.id) {
      res.status(403).json({ error: "Forbidden" });
      return;
    }

    const result = await db
      .update(reportSharesTable)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(reportSharesTable.reportId, reportId),
          eq(reportSharesTable.token, token),
          isNull(reportSharesTable.revokedAt),
        ),
      )
      .returning({ id: reportSharesTable.id });

    if (result.length === 0) {
      res.status(404).json({ error: "Share link not found" });
      return;
    }

    res.status(204).send();
  } catch (err) {
    req.log.error({ err }, "Failed to revoke share");
    res.status(500).json({ error: "Failed to revoke share" });
  }
});

// ── GET /api/share/:token — public share endpoint (no auth required) ──────────
router.get("/share/:token", async (req, res): Promise<void> => {
  const token = Array.isArray(req.params.token) ? req.params.token[0] : req.params.token;

  try {
    const [share] = await db
      .select()
      .from(reportSharesTable)
      .where(
        and(
          eq(reportSharesTable.token, token),
          isNull(reportSharesTable.revokedAt),
        ),
      );

    if (!share) {
      res.status(404).json({ error: "Share link not found or has been revoked" });
      return;
    }

    if (share.expiresAt && share.expiresAt < new Date()) {
      res.status(410).json({ error: "Share link has expired" });
      return;
    }

    const [report] = await db
      .select()
      .from(reportsTable)
      .where(eq(reportsTable.id, share.reportId));

    if (!report) {
      res.status(404).json({ error: "Report not found" });
      return;
    }

    res.json({
      id: report.id,
      scanId: report.scanId,
      targetUrl: report.targetUrl,
      tier: report.tier,
      scannedAt: report.scannedAt,
      duration: report.duration ?? null,
      createdAt: report.createdAt,
      data: report.data,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to fetch shared report");
    res.status(500).json({ error: "Failed to fetch shared report" });
  }
});

// ── GET /api/badge/:token.svg — public, embeddable grade badge ────────────────
// No auth required — same trust model as the share link itself (possession of
// the token is the access control). Hand-templated SVG; no image library needed.

const GRADE_BADGE_COLORS: Record<string, { fg: string; bg: string }> = {
  A: { fg: "#34d399", bg: "#0f2e22" },
  B: { fg: "#4ade80", bg: "#122a17" },
  C: { fg: "#facc15", bg: "#332a0a" },
  D: { fg: "#fb923c", bg: "#332310" },
  F: { fg: "#f87171", bg: "#331414" },
};

function gradeBadgeSvg(grade: string | null): string {
  const key = grade ?? "?";
  const colors = GRADE_BADGE_COLORS[key] ?? { fg: "#9ca3af", bg: "#1f2430" };
  const label = "VibeScan";
  const width = 118;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="${label}: ${key}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".08"/>
    <stop offset="1" stop-opacity=".08"/>
  </linearGradient>
  <clipPath id="r"><rect width="${width}" height="20" rx="4" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="80" height="20" fill="#1a231f"/>
    <rect x="80" width="${width - 80}" height="20" fill="${colors.bg}"/>
    <rect width="${width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="41" y="14" fill="#0b0f0d" fill-opacity=".3">${label}</text>
    <text x="40" y="13">${label}</text>
    <text x="${80 + (width - 80) / 2}" y="14" fill="#0b0f0d" fill-opacity=".3" font-weight="bold">${key}</text>
    <text x="${80 + (width - 80) / 2 - 1}" y="13" fill="${colors.fg}" font-weight="bold">${key}</text>
  </g>
</svg>`;
}

router.get("/badge/:token.svg", async (req, res): Promise<void> => {
  const token = Array.isArray(req.params.token) ? req.params.token[0] : req.params.token;
  const resolved = await resolveShare(token);

  res.setHeader("Content-Type", "image/svg+xml");
  res.setHeader("Cache-Control", "public, max-age=300"); // 5 min — grade can change on rescan

  if (resolved.status !== "ok") {
    res.status(resolved.status === "expired" ? 410 : 404).send(gradeBadgeSvg(null));
    return;
  }

  res.send(gradeBadgeSvg(resolved.grade));
});

export default router;

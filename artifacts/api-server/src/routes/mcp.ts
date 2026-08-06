import { Router, type IRouter } from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { db, reportsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { getOrigin } from "../lib/stripe";
import { runScanAndWait } from "../lib/ciScan";
import { quickBaasCheck } from "../lib/baasQuickCheck";
import type { ScanVulnerability } from "../lib/scanner";

const router: IRouter = Router();

function formatBaasFindings(findings: ScanVulnerability[]): string {
  if (findings.length === 0) {
    return "No Supabase, Firebase, PocketBase, or Appwrite backend detected — or a backend was detected with no open-access issues found.";
  }
  return findings
    .map((f) => {
      const parts = [`[${f.severity.toUpperCase()}] ${f.name}`, `  ${f.description}`];
      if (f.evidence) parts.push(`  Evidence: ${f.evidence}`);
      if (f.solution) parts.push(`  Fix: ${f.solution}`);
      return parts.join("\n");
    })
    .join("\n\n");
}

/**
 * Builds a fresh McpServer scoped to one authenticated request. Stateless
 * mode (see the transport below) means every tool call gets its own server
 * instance — cheap, since these tools don't hold any state between calls.
 */
function buildMcpServer(userId: string, userEmail: string, origin: string): McpServer {
  const server = new McpServer({ name: "vibescan", version: "1.0.0" });

  server.registerTool(
    "scan_url",
    {
      title: "Run a full VibeScan security scan",
      description:
        "Runs a full graded VibeScan security scan (headers, TLS, DNS, JS secrets, Supabase/Firebase RLS, known CVEs, and 130+ other black-box checks) against a URL and waits for it to finish. Use tier 'deep' for the most thorough pass (adds JS secret scanning, a site crawl, and an AI-written fix prompt); use 'basic' for a faster pass. Set failOn to gate the result by severity, e.g. for a pre-deploy check.",
      inputSchema: {
        targetUrl: z.string().url().describe("The URL to scan, e.g. https://myapp.example.com"),
        tier: z.enum(["basic", "deep"]).default("deep").describe("Scan depth"),
        failOn: z
          .enum(["critical", "high", "medium", "never"])
          .default("high")
          .describe("Severity threshold at/above which the result is reported as failed"),
      },
    },
    async ({ targetUrl, tier, failOn }) => {
      const result = await runScanAndWait({ userId, userEmail, targetUrl, tier, failOn, origin });

      const lines = [
        `Scan ${result.status} for ${targetUrl}`,
        result.grade ? `Grade: ${result.grade} (risk score ${result.riskScore}/100)` : null,
        `Findings: ${result.totalVulnerabilities} total — ${result.criticalCount} critical, ${result.highCount} high, ${result.mediumCount} medium`,
        result.passed === null ? null : `Gate (failOn=${failOn}): ${result.passed ? "PASSED" : "FAILED"}`,
        result.topFindings.length > 0
          ? "Top findings:\n" + result.topFindings.map((f) => `  - [${f.severity}] ${f.name}`).join("\n")
          : null,
        result.reportUrl ? `Full report: ${result.reportUrl}` : null,
        result.message ?? null,
      ].filter((line): line is string => Boolean(line));

      return {
        content: [{ type: "text" as const, text: lines.join("\n") }],
        structuredContent: result as unknown as Record<string, unknown>,
      };
    },
  );

  server.registerTool(
    "check_baas_security",
    {
      title: "Quick Supabase/Firebase/PocketBase/Appwrite security check",
      description:
        "Fast, targeted check (a few seconds, not minutes) for the #1 documented vibe-coding vulnerability class: Supabase/Firebase/PocketBase/Appwrite tables or documents readable or writable without authentication (CVE-2025-48757). Detects the backend from the page's JS bundle and tests it live with safe, non-destructive probes. Use this for a quick 'is my database open' check while building; use scan_url for a full graded report.",
      inputSchema: {
        targetUrl: z.string().url().describe("The URL of the deployed app to check"),
      },
    },
    async ({ targetUrl }) => {
      const findings = await quickBaasCheck(targetUrl);
      return {
        content: [{ type: "text" as const, text: formatBaasFindings(findings) }],
        structuredContent: { targetUrl, findings } as unknown as Record<string, unknown>,
      };
    },
  );

  server.registerTool(
    "get_report",
    {
      title: "Fetch a previous VibeScan report",
      description: "Fetches a previously completed VibeScan report by the report ID returned from scan_url.",
      inputSchema: {
        reportId: z.string().describe("The report ID returned by scan_url"),
      },
    },
    async ({ reportId }) => {
      const [report] = await db.select().from(reportsTable).where(eq(reportsTable.id, reportId));
      if (!report) {
        return {
          content: [{ type: "text" as const, text: `No report found for id ${reportId}` }],
          isError: true,
        };
      }
      const data = report.data as { summary?: Record<string, unknown> } | undefined;
      return {
        content: [
          {
            type: "text" as const,
            text: `Report for ${report.targetUrl} (${report.tier}): ${JSON.stringify(data?.summary ?? {}, null, 2)}`,
          },
        ],
        structuredContent: {
          id: report.id,
          targetUrl: report.targetUrl,
          tier: report.tier,
          data: report.data,
        } as unknown as Record<string, unknown>,
      };
    },
  );

  return server;
}

// ── POST /api/mcp — Streamable HTTP MCP endpoint ──────────────────────────────
// Stateless mode: a fresh McpServer + transport per request, since every tool
// call here is a single self-contained request/response with no server-push
// notifications. Auth reuses the same vibescan_ci_* bearer key as
// /api/ci/scan — see middlewares/authMiddleware.ts. Point Claude Code, Cursor,
// or any MCP-compatible agent at this URL with a CI key as the bearer token.
router.post("/mcp", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({
      jsonrpc: "2.0",
      error: { code: -32001, message: "Unauthorized — pass a vibescan_ci_* API key as a Bearer token" },
      id: null,
    });
    return;
  }

  const server = buildMcpServer(req.user.id, req.user.email ?? "", getOrigin(req));
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

  res.on("close", () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    req.log.error({ err }, "MCP request failed");
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
});

export default router;

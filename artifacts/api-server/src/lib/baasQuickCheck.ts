/**
 * Fast, standalone BaaS/database-security check — Supabase, Firebase,
 * PocketBase, Appwrite. No scan queue, no DB write, no SSL Labs/recon/crawl.
 *
 * Built for the MCP `check_baas_security` tool: an AI coding agent can call
 * this mid-build and get an answer in a few seconds, instead of waiting on
 * the full graded scan pipeline (see ciScan.ts / worker.ts) which can take
 * minutes because of SSL Labs and reconnaissance.
 *
 * Reuses the exact probe logic the full scan uses (checkVibeStackSecurity,
 * runBaasProbes) — same findings, same false-positive prevention, just
 * invoked directly against a single fetched page instead of through the
 * queue.
 */

import { fetchTargetHtml, type ScanVulnerability } from "./scanner";
import { checkVibeStackSecurity } from "./vibeStackProbes";
import { runBaasProbes } from "./baasProbes";

/**
 * Fetches targetUrl once, then runs the Supabase/Firebase probes and the
 * PocketBase/Appwrite probes in parallel against that single page fetch.
 *
 * Tier is fixed to "deep" (not caller-configurable) so write-probes (INSERT
 * tests with safe rollback) always run — this tool is opt-in and explicit,
 * and all scan depth is free during beta (see replit.md), so there's no
 * reason to hold back signal the way the queued Basic tier does.
 */
export async function quickBaasCheck(targetUrl: string): Promise<ScanVulnerability[]> {
  const { html, finalUrl } = await fetchTargetHtml(targetUrl);

  const [vibeStackFindings, baasFindings] = await Promise.all([
    checkVibeStackSecurity(html, finalUrl, "deep").catch(() => []),
    runBaasProbes(finalUrl, html).catch(() => []),
  ]);

  return [...vibeStackFindings, ...baasFindings];
}

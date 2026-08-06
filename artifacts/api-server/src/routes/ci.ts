import { Router, type IRouter } from "express";
import { z } from "zod";
import { getOrigin } from "../lib/stripe";
import { runScanAndWait } from "../lib/ciScan";

const router: IRouter = Router();

const CiScanBody = z.object({
  targetUrl: z.string().url("Must be a valid URL"),
  tier: z.enum(["basic", "deep"]).default("deep"),
  // Fail the build (passed: false) when a finding at or above this severity exists.
  failOn: z.enum(["critical", "high", "medium", "never"]).default("high"),
});

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

  const result = await runScanAndWait({
    userId: req.user.id,
    userEmail: req.user.email ?? "",
    targetUrl,
    tier,
    failOn,
    origin: getOrigin(req),
  });

  // Matches the pre-refactor behavior: only a fully "complete" scan is 200,
  // every other terminal/in-progress state (including "failed") is 202 so
  // CI callers know to treat the body as non-final.
  res.status(result.status === "complete" ? 200 : 202).json(result);
});

export default router;

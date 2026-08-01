---
name: Monitor v2 schema
description: New tables and columns added for Continuous Monitoring v2 — score history, regressions, cert expiry, webhooks, adaptive scan cadence.
---

# Monitor v2 schema additions

## New tables
- `monitor_score_history` — per-scan grade/riskScore/criticalCount/highCount snapshot (one row per completed monitor scan)
- `monitor_regressions` — checks that newly appeared vs previous scan (subscriptionId, scanId, checkId, checkTitle, severity)
- `cert_expiry_alerts` — deduplication table for cert expiry alerts; unique on (subscriptionId, alertThreshold, expiryDate)

## New columns on existing tables
- `monitor_subscriptions.nextScanAt` — computed after each scan based on grade (A→14d, B/C→7d, D/F→3d). Scheduler sweeps every 6h for rows where nextScanAt ≤ now.
- `monitor_subscriptions.webhookUrl` — optional Slack-compatible outbound webhook URL
- `cve_alerts.epssScore` / `cve_alerts.epssPercentile` — enriched from api.first.org/data/json after CVE match

## Cadence logic
`computeNextScanAt(grade)` in `artifacts/api-server/src/lib/monitorScheduler.ts` — A→14d, B/C→7d, D/F→3d.

## Webhook events
`artifacts/api-server/src/lib/webhook.ts` fires `cve_alert`, `regression_detected`, `cert_expiry`, `scan_complete` as Slack-compatible JSON with single retry.

**Why:** Risk-adaptive cadence means high-risk sites get more frequent rescans without wasting resources on healthy ones. nextScanAt is the source of truth for when to rescan; the 6h sweep picks up any subscription where it's elapsed.

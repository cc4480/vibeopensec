---
name: FP-Prevention Architecture
description: False-positive prevention decisions for VibeScan scanner probes — key rules that must be preserved across all future changes
---

## Core rules

**Why:** The product differentiates on signal quality (like Aikido's "95% fewer alerts"). Non-technical founders trust or leave based on FP rate; a wolf-crying scanner trains users to ignore real issues.

**How to apply:** Apply to every new probe or pattern added to the scanner.

### GraphQL probe
- Endpoint confirmation requires `data.__typename` to be a string (unique to GraphQL — no REST API returns this).
- Paths `/api` and `/query` removed — too generic. Only `/graphql*` and extracted JS URLs.
- Field suggestion only flagged when `errors[].locations` array present (GraphQL spec field, absent in REST APIs).
- Content-Type must include `application/json` or `graphql`.

### SPA catch-all routing (apiDocsProbe)
- Before path probing, hit a random nonexistent path (e.g. `/vibescan-spacheck-abc-notfound`).
- If HTTP 200 returned, fingerprint: body length + `<title>` element.
- Any subsequent probe result within 3% body length OR same title → suppress (SPA catch-all FP).
- This prevents flagging `/swagger`, `/openapi.json`, `/api-docs` on Vite/React/Next.js apps.

### Supabase key classification (June 2025 key format change)
- `sb_publishable_*` = public-by-design (anon tier). Flag as Info, still probe tables.
- `sb_secret_*` = admin-tier (BYPASSRLS). Critical finding immediately.
- Legacy JWT: decode base64url payload, check `role` claim. `service_role` → Critical; `anon` → by-design.
- The ANON KEY ITSELF is never a security finding — only the data exposure from open tables is flagged.

### jsScanner key classification rules
- Stripe `pk_live_` / `pk_test_` → NOT flagged (public by design).
- Stripe `sk_live_` → Critical; `sk_test_` → Medium; `whsec_` → High.
- Mapbox `pk.ey…` → Info (public by design, warn about domain restriction). `sk.ey…` → Critical.
- Sentry DSN (`https://xxx@sentry.io/project`) → NOT flagged (ingest-only, public by design).
- Sentry auth token (`sntrys_eyJ…` or labeled 64-hex) → Critical.
- Supabase `sb_secret_*` → Critical. `sb_publishable_*` → NOT flagged.
- Firebase `AIza…` → Info (identifies project, security is in rules).

### Entropy validation
- `shannonEntropy()` helper added to jsScanner.ts.
- Generic password pattern: entropy ≥ 2.5 required.
- Generic secret key pattern: entropy ≥ 3.0 required.
- Real keys score >3.5 bits/char; placeholders/repeating strings score <3.0.

### Confidence levels (numeric, 0–100)
- ≥85 = directly observed / confirmed (HTTP response returned data).
- <75 = inferred / heuristic — should be visually distinct in UI as "needs verification".
- Never emit confidence ≥85 for pattern-only matches without behavioral confirmation.

### Removed patterns / paths (document WHY to prevent re-adding)
- `/docs`, `/docs/` — catch Docusaurus, GitBook, product wikis (NOT API docs).
- `/api`, `/query` from GraphQL paths — too generic, hit every REST API.
- Generic JWT pattern for Supabase (`/"(eyJ…)"/ `) — matches any JWT on authenticated pages.
- Appwrite `/v\d` URL fallback — matches any versioned REST API.
- `__NEXT_DATA__` large-blob heuristic (50KB threshold, 60% confidence) — fires on every data-rich Next.js app.

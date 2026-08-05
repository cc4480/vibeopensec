# VibeScan — Complete Check Coverage

## Module 1 — HTTP Response Headers
*Runs on every scan (Basic + Deep). Inspects the response from a single GET to the target URL.*

| # | Check | Severity if failing |
|---|---|---|
| 1 | HTTPS enforcement (plain HTTP served) | Critical |
| 2 | HTTP Strict Transport Security (HSTS) present | Medium |
| 3 | HSTS preload status (via hstspreload.org API) | Low |
| 4 | Content-Security-Policy present | High |
| 5 | CSP contains `unsafe-inline` | Medium |
| 6 | CSP contains `unsafe-eval` | Medium |
| 7 | X-Frame-Options present (clickjacking) | Medium |
| 8 | X-Content-Type-Options: nosniff | Low |
| 9 | Referrer-Policy present | Low |
| 10 | Permissions-Policy present | Low |
| 11 | Cross-Origin-Opener-Policy (COOP) | Info |
| 12 | Cross-Origin-Embedder-Policy (COEP) | Info |
| 13 | Cross-Origin-Resource-Policy (CORP) | Info |
| 14 | CORS wildcard `Access-Control-Allow-Origin: *` | Medium |
| 15 | Server header version number disclosure | Info |
| 16 | X-Powered-By header disclosure | Info |
| 17 | X-XSS-Protection explicitly disabled | Info |
| 18 | Cache-Control headers missing | Info |
| 19 | Mixed content (HTTP resources on HTTPS page) | Medium |

**Cookie analysis** — runs per cookie in Set-Cookie:

| # | Check | Severity if failing |
|---|---|---|
| 20 | Cookie missing `Secure` flag | Medium |
| 21 | Cookie missing `HttpOnly` flag | Medium |
| 22 | Cookie missing `SameSite` attribute | Low |

---

## Module 2 — Technology Fingerprinting
*Passive. Detects ~60 technologies from headers, cookies, and HTML.*

Categories: web servers (Nginx, Apache, IIS, Caddy, Gunicorn…), CDNs (Cloudflare, Vercel, Netlify, AWS CloudFront, Fastly, Azure…), CMS platforms (WordPress, Drupal, Joomla, Ghost, Shopify, Wix, Squarespace, Webflow…), JS frameworks (React, Vue, Angular, Next.js, Nuxt, Svelte, Remix, Astro, Gatsby…), CSS frameworks (Tailwind, Bootstrap, Bulma), analytics (GA, GTM, Hotjar, Mixpanel, Segment), and more.

---

## Module 3 — DNS Security
*Uses Cloudflare DNS-over-HTTPS — no account needed. Skipped entirely for subdomains on uncontrolled cloud-hosting platforms (Vercel, Netlify, Replit, etc.) where the app owner can't configure DNS records — this would otherwise be an unfixable false positive.*

| # | Check | Severity if failing |
|---|---|---|
| 23 | SPF record present | High (or Medium if no MX) |
| 24 | SPF uses `+all` (allows any sender) | Critical |
| 25 | SPF uses `?all` (neutral, no enforcement) | Medium |
| 26 | SPF exceeds 10 DNS lookup limit | Low |
| 27 | DMARC record present | High |
| 28 | DMARC policy is `p=none` (monitoring only) | Medium |
| 29 | DMARC missing aggregate report address `rua=` | Info |
| 30 | DKIM records present (probes selectors) | Low |
| 31 | DNSSEC enabled | Info |

---

## Module 4 — Active HTTP Probes
*Makes individual HTTP requests to specific paths/endpoints.*

### 4a. Sensitive File Exposure
Probes ~75 paths for publicly accessible files.

| Category | Examples |
|---|---|
| Source control | `.git/config`, `.gitignore` |
| Environment files | `.env`, `.env.local`, `.env.production`, `.env.backup` |
| Infrastructure | `docker-compose.yml`, `Dockerfile`, `docker-compose.override.yml` |
| Credentials | `/.htpasswd` |
| Admin panels | `/admin`, `/wp-admin`, `/phpmyadmin`, `/adminer` |
| Spring Boot Actuators | `/actuator/env`, `/actuator/health`, `/actuator/beans`, `/actuator/mappings`, `/actuator/heapdump`, `/actuator/loggers`, `/actuator/metrics` |
| IDE configs | `.vscode/settings.json`, `.idea/workspace.xml` |
| YAML configs | `config.yaml`, `config.yml`, `app.yaml` |
| Java internals | `/WEB-INF/web.xml`, `/WEB-INF/classes/application.properties` |
| WordPress | `/xmlrpc.php` |
| Server diagnostics | `/server-info`, `/nginx_status` |

| # | Check | Severity |
|---|---|---|
| 32 | Each confirmed sensitive file hit | Critical → Info (varies per file type) |

### 4b. HTTP Methods (OPTIONS probe)

| # | Check | Severity |
|---|---|---|
| 33 | HTTP TRACE enabled (Cross-Site Tracing / XST) | Medium |
| 34 | Dangerous methods advertised (PUT, DELETE, PATCH) | High |
| 35 | HTTP CONNECT enabled | Medium |

### 4c–4l. Individual Probes

| # | Check | Severity |
|---|---|---|
| 36 | Active CORS — arbitrary origin reflection | High |
| 37 | Active CORS — null origin accepted | Medium |
| 38 | Open redirect via common parameters | Medium |
| 39 | robots.txt exposes sensitive paths | Low |
| 40 | Subresource Integrity (SRI) missing on CDN scripts | Medium |
| 41 | Error/debug information disclosure | Medium |
| 42 | HTTPS redirect not enforced (HTTP stays HTTP) | High |
| 43 | Rate limiting absent on root endpoint | Low |
| 44 | X-Frame-Options misconfigured (non-DENY/SAMEORIGIN value) | Medium |
| 45–59 | Directory listing on 15 common dirs (`/uploads/`, `/logs/`, `/backup/`, etc.) | Medium |
| 60 | `security.txt` missing (RFC 9116) | Info |

---

## Module 5 — Known CVE / Version Matching
*Detects versioned software and queries OSV.dev, plus a curated list of specific high-impact CVEs for common web servers.*

| # | Check | Severity |
|---|---|---|
| 61 | Detected library version queried against OSV.dev CVE database | Critical → Low (per CVE CVSS) |
| 62 | PHP end-of-life version check (5.x, 7.0–7.3) | Critical / High |
| 63 | Apache — matched against a curated list of known high-impact CVEs by version range | Per CVE CVSS |
| 64 | Apache end-of-life release branch check (1.x, 2.2) | Critical / High |
| 65 | Nginx — matched against a curated list of known high-impact CVEs by version range | Per CVE CVSS |
| 66 | Nginx end-of-life release cycle check (live-fetched EOL data) | Medium |
| 67 | IIS 6.0 — CVE-2017-7269 (RCE via WebDAV, CVSS 9.8) | Critical |

---

## Module 6 — JWT Analysis
*Passive — extracts tokens from headers and HTML, no extra requests.*

| # | Check | Severity |
|---|---|---|
| 68 | `alg:none` — signature verification bypass | Critical |
| 69 | Empty signature segment (unsigned token accepted) | Critical |
| 70 | Missing `exp` claim (never expires) | High |
| 71 | Excessively long lifetime (>365 days) | Medium |
| 72 | HS256 without expiry (offline brute-force risk) | High |
| 73 | Sensitive data in JWT payload (passwords, tokens, etc.) | Medium |

---

## Module 7 — Subdomain Takeover
*Follows CNAME chains and checks cloud service fingerprints (AWS S3, Heroku, GitHub Pages, Netlify, Vercel, Azure, Fastly, Shopify, Ghost Pro, Surge.sh, Cargo, Readme.io, Pantheon, Squarespace, Tumblr, WP Engine, Fly.io, Render, Railway).*

| # | Check | Severity |
|---|---|---|
| 74 | Dangling CNAME pointing to an unclaimed service (takeover possible) | Critical |

---

## Module 8 — Vibe-Stack Database Security *(both tiers)*
*Detects Supabase and Firebase backends from the JS bundle, then actively tests their live API.*

### 8a. Supabase

| # | Check | Severity |
|---|---|---|
| 75 | Supabase **service_role key** in client-side JS (bypasses all RLS) | Critical |
| 76 | Supabase backend detected (informational) | Info |
| 77 | Tables returning rows to unauthenticated anon-key requests — **CVE-2025-48757** | Critical |
| 78 | Tables accessible unauthenticated but currently empty (RLS still missing) | High |
| 79 | Tables accepting unauthenticated INSERT writes | Critical |
| 80 | Storage bucket list exposed to anon key | Medium |
| 81 | Supabase detected, RLS appears configured (informational) | Info |

*Detection: extracts `supabaseUrl` + anon/publishable key from JS bundle (including the June 2025 `sb_secret_`/`sb_publishable_` key format), hits the PostgREST OpenAPI spec to enumerate up to 12 tables, tests each with real API calls. The anon/publishable key itself is NOT flagged — it is public by design; only the resulting data exposure is a finding.*

*Write probe safety: INSERT uses a sentinel field that cannot exist in any real schema, with `Prefer: tx=rollback` so nothing commits. A blocked response (401/403/404/405) proves the write path is closed; anything else confirms it's open. No PATCH or DELETE is ever sent against existing rows.*

### 8b. Firebase

| # | Check | Severity |
|---|---|---|
| 82 | Firestore returns documents to unauthenticated requests | Critical |
| 83 | Firebase Realtime Database returns data to unauthenticated requests | Critical |
| 84 | Firebase detected, rules appear restrictive (informational) | Info |

*Tests common collection names against the Firestore REST API. Firebase API key is NOT flagged as a secret — it identifies the project and is public by design.*

---

## Module 9 — BaaS Open-Data Checks: PocketBase & Appwrite *(both tiers)*
*Detects PocketBase and Appwrite backends from page HTML/JS, then performs read-only checks for open collection access. Supabase and Firebase are covered separately by Module 8 — this module exists specifically to avoid double-reporting the same finding under two different names.*

| # | Check | Severity |
|---|---|---|
| 85 | PocketBase collection readable without authentication | Critical / High |
| 86 | Appwrite collection document readable without authentication | Critical / High |

---

## Module 10 — GraphQL Security *(both tiers)*
*Discovers GraphQL endpoints from inline JS and known paths, confirmed via a strict `data.__typename` response check to eliminate REST API false positives.*

| # | Check | Severity |
|---|---|---|
| 87 | GraphQL introspection enabled in production (full schema exposed) | High |
| 88 | GraphQL field-name suggestions leak valid schema fields ("Did you mean…") | Low |

---

## Module 11 — Exposed API Documentation *(both tiers)*
*Checks ~17 candidate paths for publicly accessible OpenAPI/Swagger/ReDoc/GraphQL-SDL documentation. Structural validation (not just keyword matching) plus SPA-catch-all fingerprint suppression prevents false positives on React/Vite/Next.js apps that return 200 for every path.*

| # | Check | Severity |
|---|---|---|
| 89 | Publicly accessible API spec file or interactive docs UI (Swagger/OpenAPI/ReDoc/GraphQL SDL) | Medium |

---

## Module 12 — Next.js Data Leaks *(both tiers)*
*Parses the `__NEXT_DATA__` JSON blob Next.js serializes into every page's HTML for secrets accidentally returned from `getServerSideProps`/`getStaticProps`. Passive — no extra HTTP requests.*

| # | Check | Severity |
|---|---|---|
| 90 | Stripe live secret key in `__NEXT_DATA__` | Critical |
| 91 | Supabase service_role key in `__NEXT_DATA__` | Critical |
| 92 | Private key (RSA/EC/DSA/OpenSSH) in `__NEXT_DATA__` | Critical |
| 93 | AWS Access Key ID in `__NEXT_DATA__` | Critical |
| 94 | AWS Secret Access Key in `__NEXT_DATA__` | Critical |
| 95 | GitHub token in `__NEXT_DATA__` | Critical |
| 96 | SendGrid API key in `__NEXT_DATA__` | High |
| 97 | Slack token in `__NEXT_DATA__` | High |
| 98 | Database connection string with credentials in `__NEXT_DATA__` | Critical |

---

## Module 13 — Public Cloud Storage Listing *(both tiers)*
*Detects S3, GCS, and Azure Blob references in page HTML/JS, then makes read-only list requests to check for public bucket/container listing.*

| # | Check | Severity |
|---|---|---|
| 99 | Public S3 bucket listing | High |
| 100 | Public GCS bucket listing | High |
| 101 | Public Azure Blob container listing | High |

---

## Module 14 — Source Map Exposure
*Checks each JS bundle (up to 8 files) for accessible `.map` files.*

| # | Check | Severity |
|---|---|---|
| 102 | `.map` file directly accessible alongside JS bundle | High |
| 103 | `sourceMappingURL` comment points to accessible map file | High |

---

## Module 15 — JavaScript Secret Scanning ⚡ *Deep scans only*
*Scans inline scripts + up to 8 external JS files (up to 512 KB each). Generic secret/password patterns require Shannon-entropy validation to filter placeholder values.*

| # | Secret Pattern | Severity |
|---|---|---|
| 104 | AWS Access Key ID | Critical |
| 105 | AWS Secret Access Key | Critical |
| 106 | Google API Key | High |
| 107 | Google OAuth Client Secret | Critical |
| 108 | Stripe Live Secret Key | Critical |
| 109 | Stripe Test Secret Key | Medium |
| 110 | Stripe Webhook Secret | High |
| 111 | GitHub Personal Access Token | Critical |
| 112 | GitHub Fine-Grained Access Token | Critical |
| 113 | Slack Bot/OAuth Token | High |
| 114 | Slack Incoming Webhook URL | Medium |
| 115 | Twilio API Key | High |
| 116 | Supabase Service Role Key — new `sb_secret_` format (June 2025+) | Critical |
| 117 | Supabase Service Role Key — legacy JWT format | Critical |
| 118 | Sentry Auth Token — new `sntrys_` format | Critical |
| 119 | Sentry Auth Token — legacy 64-char hex format | Critical |
| 120 | SendGrid API Key | High |
| 121 | Mailchimp API Key | High |
| 122 | RSA / EC / SSH Private Key | Critical |
| 123 | Firebase API Key (open security rules risk) | Info |
| 124 | Hardcoded JWT token | High |
| 125 | Hardcoded password | High |
| 126 | Hardcoded secret / API key (generic pattern) | Medium |
| 127 | Internal IP address exposed | Low |
| 128 | OpenAI API Key | Critical |
| 129 | Anthropic (Claude) API Key | Critical |
| 130 | Resend API Key | High |
| 131 | Replicate API Token | High |
| 132 | ElevenLabs API Key | High |
| 133 | Secret-sounding `VITE_`/`REACT_APP_`/`NEXT_PUBLIC_` env var leaked in bundle | Critical |
| 134 | Database connection URL with credentials | Critical |
| 135 | Mapbox public token (`pk.ey…`, Info — public by design; a leaked `sk.ey…` secret token is Critical) | Info |

*Supabase publishable keys (`sb_publishable_`) and Stripe publishable keys (`pk_live_`/`pk_test_`) are NOT flagged — they are public by design.*

---

## Module 16 — URL-Embedded Secrets ⚡ *Deep scans only*
*Scans `<a href>`/`<form action>` attributes and inline `<script>` content for API credentials passed in a query string — a distinct exposure path from a hardcoded JS variable (server access logs, browser history, third-party Referer headers).*

| # | Check | Severity |
|---|---|---|
| 136 | API credential (`api_key`, `client_secret`, `access_token`, etc.) exposed in a URL query string | High |

*Generic session/CSRF/reset-flow token names, and paths matching known single-use-token flows (password reset, email verification, unsubscribe, invite), are deliberately excluded to avoid flagging expected patterns.*

---

## Module 17 — Path Traversal ⚡ *Deep scans only*
*Active probing of URL query parameters with `../` traversal payloads.*

| # | Check | Severity |
|---|---|---|
| 137 | Path traversal / Local File Inclusion (LFI) on URL parameters | Critical |

---

## Module 18 — Site Crawler ⚡ *Deep scans only*
*Crawls up to 20 internal pages and re-runs header + cookie checks on each.*

| # | Check |
|---|---|
| 138+ | All header and cookie checks (#1–22) repeated per crawled page |

---

## Summary

| Tier | Unique check types | Approximate HTTP requests |
|---|---|---|
| **Basic** | ~104 | ~100–150 |
| **Deep** | ~137+ | ~300–500+ (crawl + JS fetches + path probes) |

Modules 8–13 (Vibe-Stack DB security, PocketBase/Appwrite, GraphQL, exposed API docs, Next.js data leaks, cloud storage listing) run on **both** tiers — they're a handful of targeted API calls, not a full crawl, so there's no reason to gate them behind Deep.

## Grading Formula

Risk score accumulates per finding: **Critical = +30, High = +15, Medium = +5, Low = +1**.

| Score | Grade |
|---|---|
| 0–10 | A |
| 11–25 | B |
| 26–45 | C |
| 46–65 | D |
| 66+ | F |

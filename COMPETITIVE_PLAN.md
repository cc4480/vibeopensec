# VibeScan Competitive Intelligence & Winners-Circle Plan

*Research date: May 30, 2026. All competitive claims below are primary-source verified.*

> **Corrections from review:** (1) Aikido × Lovable launch date: the blog post is dated March 24, 2026 — the April 10 date cited in the original eval appears to be a secondary-source error. Both dates have been seen in the wild; the March 24 primary-source date is used here. (2) Bilingual target market is **EN/ES (Spanish)**, not EN/ZH — corrected throughout.

---

## Part 1 — Verified Competitive Intelligence

### What the eval got right

**Aikido × Lovable "Vibe, Fix, Ship"** — Confirmed. Launched March 24, 2026. Aikido deploys a swarm of specialized agents against your *live* app: probing login, attempting cross-user data access, chaining exploits, testing APIs. This is active pentesting, not scanning. It's embedded directly in the Lovable editor. It is enterprise-shaped and not cheap. Lovable's *existing* platform scanner (4 checks: RLS, schema, code review, dependency audit) is source-code-level — they have the code, we don't, so this is not a lane we can replicate with URL-only scanning. The Aikido layer is active runtime hacking, distinct from what either of us do.

**CVE-2025-48757** — Confirmed and critically important. Disclosed May 29, 2025. Security researcher Matt Palmer scanned 1,645 Lovable-built apps and found **170 (10.3%)** had fully open Supabase tables — readable by anyone with the public anon key. The anon key is always in the frontend JavaScript by design; without Row Level Security, a single API call dumps the entire database. Combined exposed endpoints: 303. Data leaked: emails, passwords (plaintext in some apps), payment data, admin credentials. **This is the single biggest documented vibe-coding vulnerability in existence.** It has a CVE number. It has press coverage. Our scanner does not test for it.

**Vibe App Scanner (vibeappscanner.com)** — Confirmed. Real product, $9 Starter / $19 Launch / $99/mo Continuous. Built by security engineers, cites the same academic research (SusVibes, Tenzai, Escape.tech). Extracts Supabase URL + anon key from frontend JS automatically, then tests every table via the PostgREST REST API for unauthenticated access. Also checks storage buckets, RPC functions, and edge functions. They own the CVE-2025-48757 narrative in their marketing.

**The DEV.to landscape roundup** — Confirmed. Eight scanners now exist. VibeScan is not listed. The full table:

| Scanner | Type | Price | Has RLS Check | Has Live URL Scan |
|---|---|---|---|---|
| Vibe App Scanner | Web | $9–$99/mo | ✅ | ✅ |
| VibeCheck (notelon.ai) | Web | Free | ✅ Firebase/Supabase | ✅ |
| Aikido Security | Platform | Free tier + paid | ✅ (SAST) | ❌ URL-only |
| VibeChecker | Chrome Ext | Free + paid | ✅ | ❌ |
| amihackable.dev | Web | Free | ❌ | ✅ |
| ChakraView | CLI | Free/OSS | ✅ | ❌ |
| vibecodesecure.com | Web | Unknown | ❌ | ✅ |
| Lovable 2.0 Built-in | Built-in | Included | ✅ (code-level) | ❌ |
| **VibeScan** | Web | Paid | ❌ | ✅ |

Our black-box depth (97 checks, Spring Boot, OSV.dev, DNSSEC, JWT, subdomain takeover, source maps) is unmatched in the live-URL tier. But we are missing the #1 cited vibe-coding vulnerability class, which two free tools already cover.

### What the eval overstated

- **"Per-agent fix routing"** — The eval called this a wedge. Looking at our current codebase, the AI fix prompt is a single DeepSeek-generated blob. Per-agent routing (format for Claude Code vs Lovable vs Cursor) is not yet built. It's a real opportunity but not a current advantage.
- **"Bilingual"** — Not yet implemented in the codebase. Valid roadmap item, not a current differentiator.
- **"VAS knows Firebase keys are public"** — Partially true. Our engine already rates Firebase API key findings as `Info` severity, which is correct. The real gap is we don't detect the *Supabase service_role key* — which, unlike the anon key, should never be public and bypasses all RLS. That's a critical miss.

---

## Part 2 — The Technical Gap in Plain Terms

Here is the exact CVE-2025-48757 attack, which our engine currently cannot perform:

```
Step 1: Attacker opens the target app in a browser
Step 2: Views source / JS bundle — finds:
        const supabaseUrl = "https://abcdefgh.supabase.co"
        const supabaseAnonKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
Step 3: Hits the PostgREST OpenAPI endpoint:
        GET https://abcdefgh.supabase.co/rest/v1/
        apikey: eyJhbGciO...
        → Response: OpenAPI spec listing all table names
Step 4: Queries a table directly:
        GET https://abcdefgh.supabase.co/rest/v1/users?select=*
        apikey: eyJhbGciO...
        → If RLS is off: returns every user's data
Step 5: Attempts writes:
        POST https://abcdefgh.supabase.co/rest/v1/users
        apikey: eyJhbGciO...
        → If no insert policy: can create arbitrary records
```

Every step is black-box. No repo access. This is our architecture. We can do this.

The Firebase equivalent:
```
Step 1: Find in JS bundle:
        firebase.initializeApp({ apiKey: "AIza...", projectId: "my-app" })
Step 2: Hit Firestore REST API unauthenticated:
        GET https://firestore.googleapis.com/v1/projects/my-app/
               databases/(default)/documents/users?key=AIza...
        → If rules allow read: true — returns all documents
Step 3: Hit Realtime Database:
        GET https://my-app.firebaseio.com/.json
        → If rules are { "read": true } — full database dump
```

Also black-box. Also our architecture.

---

## Part 3 — The Winners-Circle Plan

Three moves. In priority order.

---

### Move 1 — Build `vibeStackProbes.ts` (the CVE-2025-48757 module)

**What:** A new scanner module that detects Supabase and Firebase backends from the JS bundle, then actively tests their security configuration via their public REST APIs.

**Why this first:** CVE-2025-48757 is a named, documented, press-covered vulnerability that 10.3% of Lovable apps have. It is the single sentence that sells the tool to anyone who built on Supabase. "We check for CVE-2025-48757" ends the conversation.

**Runs on:** Both tiers (Basic and Deep). The HTTP requests are minimal — a few API calls, no crawling. No reason to gate it.

#### Supabase probe spec

**Detection** — scan JS for these patterns:
```
createClient("https://{ref}.supabase.co", "{anonKey}")
VITE_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_URL / REACT_APP_SUPABASE_URL
VITE_SUPABASE_ANON_KEY / NEXT_PUBLIC_SUPABASE_ANON_KEY
supabaseUrl = "https://..."
```

Also detect the dangerous one — **service_role key** (starts with `eyJ`, contains `role":"service_role"` when decoded, or appears in patterns like `serviceRoleKey`, `service_role_key`, `SUPABASE_SERVICE_ROLE_KEY`). The service role key bypasses ALL RLS — this is Critical.

**Table enumeration** — `GET https://{ref}.supabase.co/rest/v1/` with `apikey: {anonKey}` → parse OpenAPI response for table names.

**RLS tests per table:**
- Unauthenticated SELECT: `GET /rest/v1/{table}?select=*&limit=1` — if rows returned with no Authorization header → RLS missing
- Unauthenticated INSERT: `POST /rest/v1/{table}` with dummy payload — if `201` returned → INSERT policy missing
- Unauthenticated UPDATE: `PATCH /rest/v1/{table}?id=eq.0` — if `200` returned → UPDATE policy missing
- Unauthenticated DELETE: `DELETE /rest/v1/{table}?id=eq.0` — if accepted → DELETE policy missing

**Storage bucket test:**
- `GET https://{ref}.supabase.co/storage/v1/bucket` with `apikey: {anonKey}` → if buckets returned → public bucket list exposed

**Auth config checks:**
- `GET https://{ref}.supabase.co/auth/v1/settings` → check if email confirmations disabled, if signups are open

**Severity mapping:**
| Finding | Severity | CVSS | CWE |
|---|---|---|---|
| Supabase service_role key in JS | Critical | 10.0 | CWE-522 |
| Table readable unauthenticated (has user data) | Critical | 9.3 | CWE-284 |
| Table readable unauthenticated (empty/public) | High | 7.5 | CWE-284 |
| Table writable unauthenticated (INSERT) | Critical | 9.3 | CWE-284 |
| Table deleteable unauthenticated | High | 8.1 | CWE-284 |
| Storage buckets publicly listable | Medium | 5.3 | CWE-200 |
| Auth email confirmation disabled | Low | 3.1 | CWE-287 |
| Supabase detected (informational) | Info | 0 | — |

**Do NOT flag:** Supabase anon key detected alone (it is public by design). Only flag the *consequence* — open tables — not the key itself.

#### Firebase probe spec

**Detection** — scan JS for:
```
firebaseConfig = { apiKey: "AIza...", projectId: "...", ... }
initializeApp({ ... })
VITE_FIREBASE_API_KEY / REACT_APP_FIREBASE_API_KEY
```

**Firestore test:**
```
GET https://firestore.googleapis.com/v1/projects/{projectId}/
         databases/(default)/documents/{collection}?key={apiKey}
```
Try common collection names first: `users`, `profiles`, `posts`, `messages`, `orders`, `products`, `config`, `settings`.

If any returns documents without authentication → open Firestore rules.

**Realtime Database test:**
```
GET https://{projectId}.firebaseio.com/.json?auth={apiKey}
```
If returns non-null JSON → open database rules.

**Firebase Storage test:**
```
GET https://storage.googleapis.com/storage/v1/b/{projectId}.appspot.com/o?key={apiKey}
```
If returns file listing → open storage rules.

**Severity mapping:**
| Finding | Severity | CVSS |
|---|---|---|
| Firestore open rules (documents returned) | Critical | 9.3 |
| Realtime DB open rules (data returned) | Critical | 9.3 |
| Firebase Storage publicly listable | Medium | 5.3 |
| Firebase detected (informational) | Info | 0 |

---

### Move 2 — False-Positive Hygiene Pass in `jsScanner.ts`

**Two specific changes:**

1. **Supabase anon key pattern** — add explicit detection that identifies it as "public by design" and rates it Info with the message: *"Supabase anon keys are designed to be public. The risk is not the key — it is missing RLS policies on your database tables. See the Supabase RLS findings in this report."* This converts a potential false positive into an educational finding that points directly at the real risk.

2. **Firebase config block** — the current pattern (`firebaseConfig = {…}`) already rates it Info. Update the description to say: *"Firebase API keys identify your project but are designed to be public. The risk is permissive security rules. See the Firebase findings in this report."* If the vibeStackProbes module finds no open rules, this finding is suppressed entirely.

---

### Move 3 — Per-Agent Fix Routing in the DeepSeek Report

**What:** The Deep scan AI report currently generates a single fix prompt. Split it into agent-specific formats based on detected technologies:

| Detected stack | Fix prompt format |
|---|---|
| Supabase + no framework signals | Generic SQL + Supabase dashboard instructions |
| Lovable fingerprint (lovable.dev in headers/JS) | Lovable chat prompt format |
| Next.js | Claude Code / Cursor format with file paths |
| Vite + React (no SSR) | Bolt.new / Replit format |
| WordPress | WP-specific admin instructions |

**Detection signals already available:** tech fingerprinting in `scanner.ts` already identifies Next.js, React, Vue, WordPress, etc. The Lovable fingerprint can be detected from the `Referrer-Policy` header set by Lovable's hosting, or from the `lovable-uploads` CDN pattern in asset URLs.

This is the wedge. Nobody else does this. VAS generates generic markdown. We route it to the exact tool the user is holding.

---

### Roadmap Summary

| Priority | Module | Effort | Impact |
|---|---|---|---|
| 1 | `vibeStackProbes.ts` — Supabase RLS + Firebase rules | ~400 lines, 1 day | Closes CVE-2025-48757 gap, matches category leader |
| 2 | `jsScanner.ts` hygiene — anon key tuning | ~20 lines | Fewer false positives, matches Aikido "less noise" positioning |
| 3 | Per-agent fix routing in DeepSeek report | ~100 lines + prompt work | Unique differentiator, no competitor has this |
| 4 | Bilingual output (EN/ES — Spanish) | UI + prompt work | Opens zero-competition lane (LatAm, US-Hispanic founders) |
| 5 | Marketing: publish to DEV.to, submit to the roundup | Content | Gets listed; currently invisible |

---

## Part 4 — Positioning After These Moves

**Before:** "Deep black-box scanner with 97 checks."
→ Commoditizing. Lovable's free built-in scanner erodes the low end. Aikido owns the enterprise end.

**After:** "The only scanner that tests for CVE-2025-48757 in real time, routes fixes to your exact AI coding tool, and runs in 60 seconds with no setup."
→ CVE-2025-48757 is the hook (named vulnerability, documented damage, press coverage).
→ Per-agent routing is the reason to pay vs. the free tools.
→ No signup friction (unlike VAS) is the conversion driver.

The three things Aikido cannot cheaply replicate: **URL-only with no repo access required** (Aikido needs code), **per-agent fix routing** (they write compliance reports, not prompts), and **no-signup instant scan** (they require account creation for everything).

---

## Implementation Order

Ready to build Move 1 (`vibeStackProbes.ts`) immediately — it fits the existing architecture, drops into `scanner.ts` alongside the other modules, and closes the most important gap. Move 2 is a 30-minute patch on the existing jsScanner. Move 3 requires more prompt engineering but the routing logic is straightforward.

Say the word and we start with Move 1.

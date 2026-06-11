# VibeScan — Path to #1 Security App for VibeCoders

## Vision

VibeScan is the one-tap security button that every vibecoder hits before shipping.
No friction, no setup, no expertise needed — just the URL and 60 seconds.

## What "#1" Means

1. **Most cited** — when someone asks "how do I check my app is secure?" the answer is VibeScan
2. **Most complete** — no important vulnerability goes undetected
3. **Most actionable** — every finding comes with a fix you can literally paste into your AI coding tool
4. **Most viral** — the shareable report makes you look like a pro to clients
5. **Most accessible** — no signup needed, one click, and a Spanish version that competitors don't have

## The Competitive Field (2026)

| Competitor | Price | VibeCoder Fit | Weakness |
|---|---|---|---|
| **Vibe App Scanner** | $9-99/mo | Good — fast, detects Supabase | No AI fix routing, no free tier, English only |
| **VibeCheck** (notelon.ai) | Free | Good — detects Supabase + Firebase | No depth (only 2 checks), no report, no AI |
| **Aikido × Lovable** | Enterprise | Embedded but expensive | Requires Lovable account, not for non-Lovable users |
| **VibeChecker** | Chrome Ext | OK but limited | Browser-only, no deep scanning |
| **amihackable.dev** | Free | Basic — headers only | 15 checks, no CVE detection |
| **VibeScan** | $29-79 per scan | **Best depth + speed + AI + no-signup** | Brand awareness is the gap |

**Our moats:**
- **No login required** — VibeCheck requires OAuth; Vibe App Scanner requires signup; we just need a URL
- **97 black-box checks** — the most checks in the URL-only category
- **DeepSeek AI reports** — nobody else generates plain-English + AI fix prompts
- **Per-agent fix routing** — route fixes to your exact tool (Lovable, Cursor, Bolt, etc.)
- **Bilingual EN/ES** — zero Spanish-language competitors

## The 10-Point Dominance Plan

### 1. ✅ The CVE-2025-48757 Hook (BUILT)

Status: **Done.** The `vibeStackProbes.ts` module is live.

- Detects Supabase service_role key in JS (CVSS 10.0)
- Tests Supabase RLS via live API calls
- Tests Firebase Firestore + Realtime DB rules
- Write probes are safe and non-destructive

This is the killer feature. When someone says "I use Supabase" our response is "We check for CVE-2025-48757 — the vulnerability that exposed 10% of Lovable apps."

### 2. 🎯 Per-Agent Fix Routing (HIGH PRIORITY)

**The unique differentiator nobody has.**

After scanning a site, we know what stack it's built on (React, Next.js, Vite, WordPress, Lovable, etc.). The DeepSeek AI report should generate fixes in the format of the user's actual coding tool:

| Detected Stack | Fix Format |
|---|---|
| **Lovable** | "Add this to your supabase page in Lovable: [prompt]" |
| **Cursor** | File paths + code changes for Cursor Composer |
| **Bolt.new / Replit** | Full file edit with `\n\n---\n\n` separators |
| **Supabase** | SQL + RLS policy + dashboard instructions |
| **WordPress** | Plugin name + config path + htaccess rules |
| **Generic** | Markdown code blocks + terminal commands |

**Implementation:** In the DeepSeek prompt, inject: `Generate fixes in [detected-tool] format. The project is [detected-stack].` Stack detection is already in `scanner.ts` (technology fingerprinting).

**Impact:** Converts the report from "read and understand" to "copy and paste into your tool."

### 3. 🌎 Bilingual EN/ES (Spanish/LatAm) (HIGH PRIORITY)

**Zero Spanish-language competitors in the space.**

- Add a language selector on the landing page
- Store `lang: 'en' | 'es'` in the scan metadata
- Pass it to DeepSeek prompt: `Generate report in Spanish when lang === 'es'`
- All UI text becomes i18n via `react-i18next` (lightweight, easy)

**Why this matters:** The LatAm market is enormous (vibecoders in Brazil, Mexico, Colombia, Argentina), and the Spanish-speaking developer population in the US is growing. No competitor is here yet.

### 4. 🦠 Add the Top Missing Vibe-Coder Checks

CVE-2025-48757 was the biggest one. Now close the remaining gaps:

| Check | What | Severity | Why VibeCoders Need It |
|---|---|---|---|
| **Vercel function log exposure** | `/.well-known/vercel/functions` | High | Vercel is the #1 hosting platform |
| **Netlify function log exposure** | `/.netlify/functions/...` | High | Netlify is #2 |
| **API key in URL params** | `?apiKey=...` in server logs | High | Common in vibecoder tutorials |
| **Exposed .env via build output** | Vite/React build artifacts | Critical | Vite devs often miss `.env` bundling |
| **GraphQL introspection** | Introspection enabled on production | Medium | Common with Supabase GraphQL |
| **Sitemap/robots leaks** | Admin paths in robots.txt | Medium | Always there, never checked |
| **Open Graph scraping** | OG images exposing staging data | Low | Staging data leaks via social cards |
| **.well-known/security.txt** | Missing RFC 9116 | Info | Professional signal |
| **CSP bypass** | `script-src` includes `https://cdn.jsdelivr.net` | Medium | Vibecoders use CDNs liberally |

**Estimated work:** 200-300 lines across 3-4 new scanner modules.

### 5. ⚡ Speed & DX: The "Under 60 Seconds" Promise

**Current state:** Deep scans take 2-3 minutes. Perception matters.

- **Scan:** Add a fast-scan mode that skips the 20-page crawl and does a 5-page crawl (5s vs 30s)
- **Report:** Show a skeleton loading screen with the real findings streaming in as they're discovered
- **Dashboard:** Show the grade instantly while the full report loads in the background

**Implementation:** Stream vulnerabilities as they're found via a WebSocket or SSE connection to the frontend. The dashboard already polls every 3s — replace with SSE for real-time.

### 6. 🚀 Shareable Report: The Viral Engine

**Current state:** Reports are private. The share feature exists but nobody sees them.

**Make the report a marketing asset:**
- Every report gets a **public grade badge** (e.g., `vibescan.com/badge/grade-d.svg`)
- A **score badge** that shows the grade and score
- A **ranking widget** — "My app scores 72/100 (B-) — see what I found at [link]"
- A **social card** (Open Graph meta) that renders the grade and a summary

**VibeCoders love to show off:** A badge they can embed in their README, GitHub profile, or landing page is a free marketing channel.

### 7. 🎖️ The "Security Badge" Program

Create a **verified badge** that developers can put on their landing page:

- **VibeScan Verified** — the site was scanned within the last 30 days
- **VibeScan A+** — the site scored A+ (under 10 points)
- **VibeScan Protected** — the site has monitor enabled

This is a trust signal that drives conversions. Developers want to show their users they're secure.

**Implementation:** The badge is an iframe or SVG that calls back to VibeScan to verify the scan is still valid. When the badge is displayed, it shows the grade and a "Click to verify" link.

### 8. 📈 The "Free Scanner" Hook

**Current state:** No free tier. First scan is $29.

**The #1 way to get viral:** A free scan with limits.

- **Free tier:** 1 scan per week (or 3 per month). Same depth as Basic, but limited.
- **Deep scan:** One free per month. Same depth as Deep, but limited.
- **After free scan:** Upsell to paid.

**Why this works:** VibeCheck is free but too shallow. Vibe App Scanner is paid but has a free tier. Our free tier should be the best free tier in the category — same depth as Basic, just limited.

**Implementation:** Track free scans in the `credits` table. Add a `freeTier` column. If `credits.freeTier` > 0, deduct from free tier. If free tier is 0, redirect to paid.

### 9. 📢 Marketing: Own the "vibecoder security" Search

**SEO & Content:**
- Landing page title: "VibeScan — Security Scanner for VibeCoders | Check CVE-2025-48757"
- Blog post: "10.3% of Lovable apps are exposed. Here's how to check yours."
- DEV.to post: "I built a scanner that detects CVE-2025-48757 in 60 seconds"
- Reddit post: r/vibecoding, r/webdev, r/supabase — "How to check if your Supabase app has the RLS vulnerability"
- Hacker News: "Show HN: I built a security scanner for vibecoders"

**Keywords:**
- "vibecoder security"
- "vibe coding security"
- "supabase rls check"
- "firebase security check"
- "check my website security"
- "CVE-2025-48757"
- "lovable security"
- "bolt.new security"

**VibeCoders hang out on:** X/Twitter, DEV.to, Reddit (r/vibecoding), Discord (Lovable, Bolt.new, Cursor), YouTube

### 10. 💰 Pricing: The "No-Brainer" Tier

**Current pricing:**
- Basic: $29
- Deep: $79
- 5-Scan Pack: $99
- 20-Scan Pack: $299

**Add a "Monthly" tier** — $19/month for 3 Basic + 1 Deep per month. This is the recurring revenue model that makes SaaS work.

**Add a "Team" tier** — $49/month for 5 users, shared credits, monitor on all sites.

**Add a "Lifetime" tier** — $299 one-time for 20 Deep scans. This is the impulse buy for solo developers.

**Why this works:** VibeCoders are solo developers. They don't want to commit to $99/month (like Vibe App Scanner). They want to pay $19/month and get everything they need.

## The 90-Day Roadmap

### Week 1-2: Per-Agent Fix Routing
- Build the routing logic in `deepseek.ts`
- Detect stack from tech fingerprinting
- Test with Lovable, Cursor, Bolt.new

### Week 3-4: Bilingual EN/ES
- Add `react-i18next` to frontend
- Translate all UI text
- Add Spanish DeepSeek prompt
- Test with Spanish-speaking user

### Week 5-6: Vibe-Coder Check Gap Closure
- Add Vercel/Netlify function checks
- Add API key in URL check
- Add GraphQL introspection check
- Add `.env` exposure check

### Week 7: Speed & Streaming
- Add SSE to API server
- Replace dashboard polling with SSE
- Add skeleton loading screen
- Show grade instantly

### Week 8: Shareable Report & Badges
- Build public badge endpoint
- Build social card (Open Graph)
- Add shareable report link
- Add copy badge button

### Week 9: Free Tier
- Add free tier to credits system
- Add free tier UI in scan form
- Add upsell after free scan

### Week 10: Marketing & SEO
- Write DEV.to post
- Write Reddit post
- Write Hacker News post
- Add SEO meta tags

### Week 11-12: Polish & Launch
- Fix any bugs
- Add tests
- Deploy
- Announce

## The "What If Aikido Responds" Defense

Aikido has enterprise money and Lovable integration. They could copy our features.
**What they can't copy:**
1. **No-signup instant scan** — their model requires account creation
2. **Per-agent fix routing** — they generate compliance reports, not prompts
3. **Bilingual EN/ES** — they are English-only enterprise
4. **Price point** — they are enterprise-priced; we are indie-priced

## Success Metrics

| Metric | Target | 90 Days |
|---|---|---|
| Scans per week | 50 | 500 |
| Conversion rate | 5% | 10% |
| MRR | $0 | $5,000 |
| Newsletter signups | 0 | 1,000 |
| DEV.to mentions | 0 | 5 |
| Spanish-language users | 0% | 20% |

## The One Thing to Do Right Now

If you want to start winning today, the single highest-impact move is **per-agent fix routing**.

It's the feature that makes the report instantly useful. Not "here's a security report" — but "here's the exact code to paste into Lovable/Cursor/Bolt.new to fix it."

Nobody else does this. It is the reason to pay us instead of using the free tools.

Want to build it?

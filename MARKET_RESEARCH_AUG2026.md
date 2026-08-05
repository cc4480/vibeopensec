# VibeScan/Seclayer — Market Research Update (August 2026)

> Refresh of `COMPETITIVE_PLAN.md` / `WINNERS_CIRCLE_PLAN.md` (dated May 30, 2026). Focused on what changed since then, plus the general dev-tool security players (Aikido, Snyk, Socket.dev, Semgrep, GitGuardian) that the earlier docs mostly treated as background rather than researching directly.
> Compiled August 1, 2026 from live web search — treat exact prices as approximate; this market moves weekly, several sources are pricing aggregators rather than vendor pages.

---

## 1. What changed since May 2026

- **Pricing in the vibe-coder tier compressed further.** Vibe App Scanner — the category leader the earlier docs benchmarked against — cut its own prices: was $9 Starter / $19 Launch / $99/mo Continuous in May, is now (July 2026) **$5 Starter Scan / $19 one-time Deep Scan / $29/mo Continuous Protection**, plus a **free first scan**. The $9/$19/$79/$199/$49-mo pricing VibeScan itself used before going free-during-beta was already above where the market has since settled.
- **The field roughly doubled.** May's "8 scanners" roundup is now closer to 12-15 named products, including several genuinely new entrants: **CheckVibe**, **ZeriFlow**, **VibeWrench**, **UNPWNED**, **VibeEval** (now a real paid product, not just a research citation), **VibeSafe**, **VibeSec**.
- **Lovable's native scanner has a documented, exploitable blind spot.** Independent researchers found it "only checks for existence" of RLS, not whether it's actually restrictive — a table with `ENABLE ROW LEVEL SECURITY` and a policy of `USING (true)` gets a green check from Lovable while remaining fully world-readable. This is a concrete, citable claim: VibeScan's Supabase probe already tests for actual data return (not just RLS-enabled status), so it genuinely catches what Lovable's own scanner misses.
- **Lovable's scale is now public: $400M ARR, 200,000 new projects/day.** That's the size of the exposure surface every "vibe coding security" pitch is implicitly selling against.
- **Mainstream press picked it up.** The Verge published a piece (June 22, 2026) warning that vibe-coded apps are becoming a security nightmare — a citable, dated, non-vendor source for "this is a real, widely-recognized problem," useful in marketing copy that doesn't want to rely solely on vendor-cited stats.
- **A new academic data point:** SecureVibeBench (arXiv 2509.22097) found the best-performing agent config (SWE-agent + Claude Sonnet 4.5) produced correct-and-secure code only **23.8%** of the time — a 76.2% failure rate under controlled testing. Complements the already-known Veracode "~45% of AI code has vulnerabilities" and "91.5% of AI-generated apps have ≥1 critical flaw" stats.
- **A bundling pattern has emerged that didn't exist in May:** several new tools bundle security with adjacent "is my app ready to ship" checks — SEO, page speed, accessibility, legal — rather than competing on security depth alone (VibeWrench: security + SEO + speed + accessibility + legal; CheckVibe: security + 68 SEO checks + 46 "AI visibility/AEO" checks). This is a genuinely new go-to-market pattern worth watching.

---

## 2. Competitor breakdown

### Vibe-coder-niche direct competitors

**Vibe App Scanner (vibeappscanner.com)** — still the category leader.
- *Checks:* live Supabase/Firebase RLS and auth testing, storage buckets, RPC/edge functions, 150+ secret patterns, per-platform tailoring (Lovable/Bolt/Vercel/Render fingerprints).
- *Pricing:* free first scan → $5 Starter → $19 Deep (one-time) → $29/mo Continuous.
- *Marketing:* owns SEO for "is Supabase safe," "Lovable exposed API keys," CVE-2025-48757 — an "enormous" per-vulnerability/per-platform content footprint is repeatedly cited as their real moat, not the product itself. Sells "professional-grade," "15+ years security expertise," cites academic research (SusVibes, Escape.tech) for credibility.

**CheckVibe (checkvibe.dev)** — new since May.
- *Checks:* 100+ vulnerabilities (leaked OpenAI/Anthropic/Stripe keys, SQLi/XSS patterns, headers, Supabase/Firebase misconfig) **plus** 68 SEO checks and 46 "AI visibility / AEO" checks in the same scan.
- *Pricing:* free scan with full breakdown on a free account; paid tiers gate AI fix prompts, higher scan volume, continuous monitoring, "live threat detection" (price undisclosed on the page fetched).
- *Marketing hook:* "Apps built with AI... ship fast and leak secrets just as fast." "No install · No config · 30 seconds." Notably does **not** lead with false-positive/signal-quality messaging at all — pure speed/simplicity pitch.

**ZeriFlow** — new, CI/CD-first wedge.
- *Checks:* 80+ checks across 12 categories for the URL scan; the differentiator is a **GitHub Action** that runs on every commit/PR, comments pass/fail directly on the PR, and uses Claude Sonnet specifically to filter false positives per finding.
- *Pricing:* **$4.99/mo for 5 CI/CD scans** — deliberately the cheapest recurring option in the space.
- *Marketing:* "best for CI/CD integration," targets "developers, small teams, agencies, founders, AI-assisted software teams" who push to GitHub and want scans on every deploy — explicitly not the from-scratch-in-Lovable no-code audience.

**VibeWrench** — new, bundled pre-launch checklist.
- *Checks:* security + SEO + page speed + accessibility + legal, positioned as one pre-launch pass rather than a security-only tool.
- *Pricing:* free (3 scans/month) + paid tiers.
- *Marketing:* "all-in-one pre-launch tool" — competes on breadth of *what kind* of readiness it checks, not depth of any one category.

**UNPWNED (unpwned.io)** — new, explicitly positioned against VAS.
- *Checks:* claims "800 checks across 36 scanners," CVE intelligence baked into every result.
- *Pricing:* 2 free scans/month, no card → $9/mo Solo → $29/mo Studio → $49/mo Scale (domain-count tiers).
- *Marketing:* a dedicated "vs Vibe App Scanner" comparison page using what they call radical honesty — openly conceding VAS wins on authenticated in-app/form-injection testing, while claiming the win on breadth (800 vs "10-20 checks per scan"), price transparency (flat monthly vs per-scan credits), and on-demand re-scan cadence. This comparison-page-as-acquisition-content tactic is worth noting as a pattern (see §4).

**VibeEval (vibe-eval.com)** — now a real paid product (was research-citation-only in May).
- *Checks:* dynamic, **agent-based** live testing — an autonomous agent that probes the app like an attacker (RLS bypasses, exposed keys, auth weaknesses), including bypassing CAPTCHAs/auth walls; 310+ scenarios; every finding ships with a captured exploit, reproducible PoC, and a paste-ready fix for Claude/Cursor.
- *Pricing:* 14-day free trial (full Pro features, no card) → **$49/mo Pro** → $149/mo Team (5 seats, MCP integration, compliance-gap analysis) → **$499 one-time Lifetime** (adds real-time monitoring, 30-day money-back).
- *Marketing:* "A security smoke test in under 60 seconds." Central claim is **"engineer-verified" findings** — explicitly contrasts itself against pattern-matching scanners: "scanners report patterns; VibeEval delivers verified, exploitable vulnerabilities with evidence." This is the same rhetorical move Aikido and Lovable×Aikido make at the enterprise tier, now showing up at the $49/mo indie tier.

**VibeCheck (notelon.ai)** — unchanged from May: free, Firebase/Supabase-specific, no-signup, shareable README badges.

**Lovable built-in scanner** — free, native, pre-publish. 4 checks (RLS, schema, code review, dependency audit). **Confirmed limitation:** checks RLS *existence*, not correctness.

**Lovable × Aikido "Vibe, Fix, Ship"** — $100/pentest, autonomous agent swarm doing live exploitation (not scanning), confirmed-only findings, syncs into Lovable's Security view, audit-ready output for SOC2/ISO27001. Still Lovable-only.

**Others still active, roughly unchanged:** SiteSecurityScore (free, MCP for Claude Code/Codex — still the direct threat to any MCP-editor-integration wedge), Vibe Check / open-source "scan→fix→verify" loop, VibeSecurity (Go engine, hackathon-born), ChakraView (CLI/OSS), amihackable.dev (now $2/scan per one source, was free in May — worth re-verifying), SafeToShip (free quick scan / $9 one-time report / $24/mo Pro), VibeSafe (open-source DevSecOps toolkit for Cursor/v0/Windsurf/Replit), VibeSec.

### General-purpose dev-security platforms (not vibe-coding-specific, but the ceiling/vocabulary-setters)

**Aikido Security** — official pricing (fetched directly, aikido.dev/pricing):
- **Free (Developer):** $0 forever, 2 users, 10 repos, 2 container images, 1 domain, 1 cloud account, 10 AI AutoFixes/mo, 250K protected requests/mo. No credit card. Free repos rescan every 3 days.
- **Basic:** $300/mo for 10 users (~$30/user); Pro: $600/mo for 10 users ("most popular"); Advanced: $600–1,050/mo for 10 users at higher resource caps. Enterprise: custom.
- *Marketing:* leads with **cited noise-reduction percentages** from customer testimonials — "92% noise reduction," "75% reduction in noise" — plus "AutoTriage," "reachability analysis," "get started in 2 minutes," "onboarded 150+ developers in 45 minutes." This is the most quantified false-positive marketing found anywhere in this research — a bar worth matching with VibeScan's own entropy/confidence-scoring substance.

**Snyk** — Free (200 OSS tests/mo, 100 container tests/mo, 300 IaC tests/mo, all 5 products, no team features) → Team ~$25/dev/mo billed annually (some sources cite $52–98/dev/mo depending on bundle) → Enterprise custom. Positioning is IDE/CI-embedded, PR-native fixes, enterprise-shaped from the Team tier up.

**Socket.dev** — Free forever for open source ("Socket is and will always be free to use for open-source") → Team $25/seat/mo ($20/yr) → Business $50/dev/mo (unlimited scans, SBOM, SSO) → Enterprise custom (reachability analysis). **Distribution is 100% GitHub-Marketplace-first**: install the GitHub App, pick repos, get PR comments automatically — no dashboard-first onboarding. Raised a $60M Series C at a $1B valuation in May 2026, 27,000+ orgs protected — validates GitHub-app-native distribution as a real growth channel, not just a nice-to-have integration.

**Semgrep** — Community free tier now explicitly covers **Semgrep Code + Supply Chain + Secrets** (not just SAST) for up to 10 contributors / 10 private repos — notably generous, a full 3-product bundle free. Team: $35/contributor/mo (bundles the same 3 products + AI Assistant + dashboard). Enterprise custom. Positions as "developer-first, high signal-to-noise" — same signal-quality framing as Aikido, aimed at a more technical/self-serve audience.

**GitGuardian** — Free tier for individual devs on personal/public repos, genuinely usable (not a crippled trial). Team/Business/Enterprise quoted per seat, targeted at teams under ~25 developers scaling up. 420+ secret types detected — the specialist-depth number they lead with, directly comparable to VibeScan's own ~20-secret-pattern jsScanner (now ~30+ after the recent merge added OpenAI/Anthropic/Resend/etc.) — worth having a citable count of our own.

---

## 3. Feature-gap synthesis — what shows up repeatedly that VibeScan doesn't have

1. **CI/CD / GitHub Action integration.** ZeriFlow's entire pitch is "scan on every commit, comment on the PR." Socket.dev and Semgrep are GitHub-App-first by default. VibeScan is URL-only with no re-scan-on-deploy hook for repo-based (not just Lovable/Bolt) users. This is a real, cheap-to-build, currently-unclaimed-by-VibeScan wedge — ZeriFlow is charging $4.99/mo for it, suggesting low willingness-to-pay but real demand as a retention/stickiness feature.
2. **"Engineer-verified" / human-review upsell.** VAS's top tier and VibeEval both sell a manual-verification layer on top of automated findings. VibeScan has no human-in-the-loop option at any price point.
3. **A citable, quantified false-positive/signal-quality claim.** Aikido's "92% noise reduction," VibeEval's "engineer-verified, not theoretical" — VibeScan's FP-prevention architecture (Shannon-entropy validation, SPA-catch-all suppression, confidence scoring, "public-by-design" key classification) is arguably as sophisticated as what's being marketed here, but there's no number or slogan attached to it externally.
4. **Comparison/alternative content as an acquisition channel.** UNPWNED built a whole page positioned as "vs Vibe App Scanner." vibe-eval.com has a "Best Vibe App Scanner Alternatives" page. This is now a recognized, working tactic in this specific niche (ranks for "[competitor] alternative" searches) — VibeScan has none of this content.
5. **Bundled adjacent pre-launch checks (SEO/speed/a11y/legal).** New pattern (VibeWrench, CheckVibe) — not a gap VibeScan needs to close, but a competitive-encroachment risk worth monitoring: pure-security tools may get squeezed by broader "ready to ship" checklists targeting the same non-technical audience.
6. **A big, citable "checks" number for the comparison tables everyone is building.** UNPWNED leads with "800 checks / 36 scanners"; VibeEval with "310+ scenarios"; GitGuardian with "420+ secret types." VibeScan's real number (~97+ checks per `SCAN_COVERAGE.md`, since grown with the new probe modules) is comparable but isn't packaged as a marketing stat anywhere found.

---

## 4. Monetization pattern synthesis

Two distinct pricing shapes coexist, cleanly split by audience:

**Vibe-coder / indie tier (non-technical founders, solo devs):** near-universal freemium — free or near-free first/limited scan, then a cheap one-time "starter" ($2–$9), a deeper one-time scan ($14–$29), and a recurring "continuous/monitoring" tier ($4.99–$49/mo, with one $499-one-time "lifetime" outlier as an explicit subscription-fatigue alternative). **Per-scan/credit pricing dominates over pure subscription** at this tier — this is exactly the shape VibeScan's own pre-beta pricing had ($9/$19/$79 packs + $49/mo or $129/yr monitor), just priced somewhat above where the market has since settled ($5/$19/$29 is the new normal).

**Dev-tool / team tier (Aikido, Snyk, Socket, Semgrep, GitGuardian):** seat/contributor-based ($20–$98/developer/month) or flat org tiers gated by resource counts (repos, domains, cloud accounts) rather than crippled features — the free tier is *real* scanning with volume/frequency limits, not a stripped-down demo. This is worth noting because it's a different philosophy than a typical SaaS free trial: these tools give away genuine value for free specifically to build trust and habit before monetizing scale.

**Recommendation for VibeScan:** the free-during-beta stance is well-timed — it matches the direction the market's floor has moved (free-first-scan is now nearly universal at entry). When re-introducing payment, the evidence favors:
- A **genuinely capable free tier** (matches VibeCheck/CheckVibe/amihackable/GitGuardian's pattern of "real scanning, just capped"), not a crippled teaser — this is now the baseline expectation, not a differentiator, but under-delivering on it (like the old $29-minimum-to-see-anything model) is now a real competitive liability given $0 alternatives exist at comparable depth.
- **Re-price the paid tiers down** to the $5–$29 band that's now standard, rather than the old $9/$19/$79/$199 — the market compressed under VibeScan's prior pricing since it was set.
- Keep **Continuous Monitoring** in the $29–$49/mo band — this is where VAS Continuous ($29/mo) and VibeEval Pro ($49/mo) both sit; VibeScan's built Monitor v2 feature set (score history, regressions, cert-expiry, EPSS-weighted CVE alerts, webhooks) is genuinely more built-out than what's described for either competitor at that price point, which is a real argument for pricing at or above $29/mo once payments return.
- Consider a **one-time "lifetime"/pack option** for solo vibe-coders resistant to subscriptions — VibeEval's $499 lifetile tier suggests there's a segment willing to pay more up-front to avoid recurring billing; VibeScan's old 5-scan/20-scan credit packs already had this shape and could be reintroduced without recurring billing at all.

---

## 5. Marketing pattern synthesis + concrete recommendations for VibeScan

**What's now table stakes (stop treating these as differentiators):**
- "No signup, paste a URL, 30–60 seconds" — CheckVibe, SafeToShip, amihackable, UNPWNED, and VibeEval all say a version of this now. It's the baseline expectation for this niche, not a hook.
- Citing the 45%/91.5%/CVE-2025-48757 stats — nearly every competitor's homepage cites some version of these. Still worth having (it's the category-education layer), but it won't differentiate VibeScan from anyone else who also cites it.

**What's actually working as differentiation, by evidence found:**
- **A quantified signal-quality claim.** Aikido's specific percentages and VibeEval's "engineer-verified" framing are both doing real marketing work. VibeScan should give its FP-prevention architecture (documented in `.agents/memory/fp-prevention-architecture.md`) an external-facing number or slogan — e.g., a stated false-positive rate, or "confirmed, not theoretical" language tied to the fact that findings require actual data return / actual behavioral confirmation, not just pattern matches.
- **Content/SEO dominance is *the* primary channel in this specific niche**, more so than general SaaS go-to-market playbooks would suggest — VAS's entire moat is described by multiple sources as its content footprint, not its product. Reinforced by two new competitors (UNPWNED, vibe-eval.com) both independently building comparison/alternative pages as acquisition content. **Concrete recommendation:** build "VibeScan vs [Vibe App Scanner / Aikido / Lovable's built-in scanner]" comparison pages and per-vulnerability landing pages (e.g., "CVE-2025-48757 checker," "is my Supabase app safe") — this is a proven-working tactic in this exact market, not a generic suggestion.
- **A concrete, technical, competitor-specific claim beats a generic one.** The Lovable-scanner-only-checks-existence finding is a gift: it's independently verified (not VibeScan's own claim), specific, and directly contrasts with how VibeScan's Supabase probe actually works (tests for real data return, per `secret-pattern-data.ts`/`baasProbes.ts`/`supabase-probes.ts` design). "Lovable's own scanner gives a green check to a policy of `USING (true)` — we test whether a stranger can actually read your data" is a sharper, more credible hook than restating the CVE-2025-48757 stat everyone already cites.
- **GitHub-Marketplace/App-native distribution works as a channel**, evidenced by Socket.dev's $60M raise crediting 27,000+ orgs onboarded largely through GitHub App installs, and Semgrep/GitGuardian's CI-native free tiers. This is a channel VibeScan (URL-only, no repo access by design) can't directly copy, but reinforces that a lightweight "re-scan on every deploy" hook (§3.1) would open a real distribution channel, not just a feature.
- **Discord communities around the coding platforms themselves** (Lovable, Bolt, Cursor) are repeatedly named as where this audience actually congregates — more specific than generic "developer Twitter" advice.
- **Dated, non-vendor press coverage exists now** (The Verge, June 22 2026) that VibeScan can reference as third-party validation that this is a recognized, mainstream-covered problem — useful for credibility in marketing copy that shouldn't rely solely on self-cited or vendor-cited statistics.

**Still-uncontested positioning, confirmed as of this research (worth continuing to prioritize per the existing `WINNERS_CIRCLE_PLAN.md`):**
- Per-agent fix routing (Cursor/Claude Code/Lovable/Bolt-specific output) — no competitor found does this, including the newer entrants researched here.
- Bilingual EN/ES — zero competitors found in any tier, including the newer entrants.

**One new watch-item not in the earlier docs:** the emergence of bundled "pre-launch checklist" tools (VibeWrench, CheckVibe) suggests some competitors are betting that non-technical founders want one "am I ready to ship" pass covering security + SEO + speed + accessibility + legal, rather than a security-only tool. Not a recommendation to build this — VibeScan's depth-of-security-scanning is a real moat these breadth-first tools don't match — but worth knowing this positioning exists if a bundled competitor starts winning the same search terms.

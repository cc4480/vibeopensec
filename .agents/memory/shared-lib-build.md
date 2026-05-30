---
name: Shared lib build requirement
description: All workspace libs (db, api-zod, api-client-react, replit-auth-web) must emit .d.ts before typecheck
---

# Shared lib `.d.ts` build requirement

Each shared lib uses TypeScript project references (`composite: true`, `emitDeclarationOnly: true`).
Their `exports` point directly to `.ts` source files so Vite/editors work without a build step.
But `tsc --noEmit` (typecheck) follows `references:` and requires the `.d.ts` files to already exist.

**Rule:** Before running full typecheck, all four libs must be built:
`lib/db`, `lib/api-zod`, `lib/api-client-react`, `lib/replit-auth-web`
Each has `"build": "tsc -p tsconfig.json"` — the `typecheck` workflow does this automatically.

**Why:** Without the `.d.ts` files, tsc emits TS6305 for every import from these libs,
cascading into TS7006 (implicit any) for all callback parameters — 4 real errors become 60+ noise.

**How to apply:** If adding a new `lib/` package with `composite: true`, add a build script
and prepend it to the typecheck workflow command.

**Also fixed in this session:**
- `lib/api-zod/src/generated/types/index.ts` had `export * from "./deleteDismissalParams"` conflicting
  with same-named Zod schema in `api.ts`. Removed from types index (unused externally).
- `artifacts/vibescan/vite.config.ts` line 13: `const isProduction = process.env.NODE_ENV ===`
  (truncated, no RHS). Fixed to `=== "production"`.

---
name: React preamble crash in Replit canvas
description: Why @vitejs/plugin-react fails with "can't detect preamble" in the Replit canvas iframe environment, and the fix.
---

## The Rule
Always add a synchronous classic `<script>` at the top of `index.html` that patches `window.__REACT_DEVTOOLS_GLOBAL_HOOK__` before any module scripts execute, to ensure `renderers` is a `Map` and `inject` is a function.

## Why
Replit's canvas environment pre-installs a `window.__REACT_DEVTOOLS_GLOBAL_HOOK__` (via Replit's own tooling/DevTools shim) but the hook lacks `renderers: Map` and/or `inject: function`. When `@vitejs/plugin-react` v5's preamble runs `injectIntoGlobalHook(window)`, the React Refresh runtime tries to call `hook.renderers.forEach(...)` — which throws a TypeError because `renderers` is undefined. This kills the preamble module before `window.$RefreshReg$ = () => {}` is set. Every React component then immediately throws "can't detect preamble" on its HMR check.

## How to apply
In `artifacts/vibescan/index.html` (or any Vite React app on Replit), place this as the first child of `<head>`:

```html
<script>
  (function () {
    var hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
    if (hook) {
      if (!(hook.renderers instanceof Map)) hook.renderers = new Map();
      if (typeof hook.inject !== 'function') hook.inject = function () { return 0; };
    }
  })();
</script>
```

This runs synchronously during HTML parsing (classic script = not deferred), so by the time any module scripts execute the hook is in the correct shape.

## Notes
- CSP headers (`script-src 'unsafe-inline'`) are NOT the root cause even though the preamble is an inline module — removing them didn't fix the error.
- The `@replit/vite-plugin-runtime-error-modal` is also NOT the cause; it just listens for errors and forwards them to the parent canvas.
- This is specific to the Replit canvas iframe; in production (deployed) the hook isn't pre-set so this patch is a no-op and harmless.

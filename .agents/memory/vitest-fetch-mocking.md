---
name: Vitest fetch mocking
description: How to correctly stub globalThis.fetch in Vitest Node environment tests
---

## Rule
Use `vi.stubGlobal("fetch", vi.fn())` + `vi.unstubAllGlobals()` in afterEach.
Do NOT use `vi.spyOn(globalThis, "fetch")` — the spy object and `vi.mocked(fetch)` reference different things, causing mocks to silently not apply.

## Network failure simulation
Use `vi.mocked(fetch).mockRejectedValue(new Error("network error"))`, not `mockImplementation(() => { throw new Error() })`. Synchronous throws in mockImplementation propagate out of the test instead of being caught by the module's try/catch.

## URL object handling in mockImplementation
fetch receives `string | URL | Request` as its first argument. Always use `String(input)` to convert safely — `input.toString()` throws if input is undefined.

```ts
vi.mocked(fetch).mockImplementation((input) =>
  Promise.resolve(myFn(String(input)))
);
```

## Why
vi.spyOn wraps the existing property but the module under test closes over its own reference to `globalThis.fetch` at import time. vi.stubGlobal replaces the property on globalThis directly so the module sees the stub.

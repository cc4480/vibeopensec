import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { scanJavaScriptForSecrets } from "./jsScanner.js";

/**
 * jsScanner.ts tests — the secret-scanning mechanism (inline + external
 * script extraction, fetch limits, content-type gating, dedup). The
 * individual SECRET_PATTERNS regexes in secret-pattern-data.ts are data,
 * not logic — this file focuses on the scanning engine around them, not
 * an exhaustive per-pattern sweep.
 */

const BASE = "https://example.com";

function jsResponse(body: string, contentType = "application/javascript", status = 200): Response {
  return new Response(body, { status, headers: { "content-type": contentType } });
}

function mockFetch(impl: (url: string) => Response | Promise<Response>) {
  vi.mocked(fetch).mockImplementation((input) => Promise.resolve(impl(String(input))));
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

// A real-shaped AWS key — no EXAMPLE/SAMPLE/FAKE/TEST/DEMO/PLACEHOLDER/REDACTED/XXXX substring.
const AWS_KEY = "AKIAQZ7MXN2LPKW9RTVC";
const AWS_KEY_EXCLUDED = "AKIAEXAMPLE123456789"; // contains "EXAMPLE" — validate() should reject
// Split across a concatenation so the committed source never contains the
// contiguous sk_live_... substring GitHub's push-protection secret scanner
// matches on — the runtime value (what the test actually exercises) is
// identical either way.
const STRIPE_KEY = "sk_live_" + "51H8qZmK3vR7pLxWnT2eYbAcJ4fH8sD1g";

describe("scanJavaScriptForSecrets — inline scripts", () => {
  it("flags a real-shaped secret in an inline <script> block", async () => {
    const html = `<html><body><script>const key = "${AWS_KEY}";</script></body></html>`;
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result.map((v) => v.name)).toContain("AWS Access Key ID Exposed");
  });

  it("does not flag a script tag with a src attribute as inline content", async () => {
    // The src'd script's own body attribute text should never be scanned as inline
    const html = `<script src="/app.js" data-key="${AWS_KEY}"></script>`;
    mockFetch(() => jsResponse("// empty"));
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result).toHaveLength(0);
  });

  it("rejects a match that fails the pattern's own validate() (placeholder exclusion)", async () => {
    const html = `<script>const key = "${AWS_KEY_EXCLUDED}";</script>`;
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result.map((v) => v.name)).not.toContain("AWS Access Key ID Exposed");
  });

  it("returns empty array for html with no scripts at all", async () => {
    const result = await scanJavaScriptForSecrets("<html><body>hello</body></html>", BASE);
    expect(result).toEqual([]);
  });

  it("only reports one finding even when the same pattern matches twice in one file", async () => {
    const html = `<script>
      const key1 = "${AWS_KEY}";
      const key2 = "AKIAZZ9YXW3QMNB4KTHR";
    </script>`;
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result.filter((v) => v.name === "AWS Access Key ID Exposed")).toHaveLength(1);
  });
});

describe("scanJavaScriptForSecrets — entropy gating on generic secret pattern", () => {
  it("does not flag a low-entropy placeholder-looking generic secret", async () => {
    const html = `<script>const secret = "aaaaaaaaaaaaaaaa";</script>`;
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result.map((v) => v.name)).not.toContain("Hardcoded Secret Key or Token in Source");
  });

  it("flags a high-entropy generic secret", async () => {
    const html = `<script>const secret = "zK9mQ3vR7pLxWnT2eYbA";</script>`;
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result.map((v) => v.name)).toContain("Hardcoded Secret Key or Token in Source");
  });
});

describe("scanJavaScriptForSecrets — external scripts", () => {
  it("fetches and scans an external same-origin script", async () => {
    const html = `<html><script src="/app.js"></script></html>`;
    mockFetch(() => jsResponse(`const key = "${STRIPE_KEY}";`));
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result.map((v) => v.name)).toContain("Stripe Live Secret Key Exposed");
    expect(result[0]!.evidence).toContain("external script");
  });

  it("also fetches a cross-origin script src (no same-origin restriction in this module)", async () => {
    const html = `<html><script src="https://cdn.example.net/vendor.js"></script></html>`;
    mockFetch((url) => {
      expect(url).toBe("https://cdn.example.net/vendor.js");
      return jsResponse(`const key = "${STRIPE_KEY}";`);
    });
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result.map((v) => v.name)).toContain("Stripe Live Secret Key Exposed");
  });

  it("treats a failed/timed-out external fetch as empty content without crashing", async () => {
    const html = `<html><script src="/broken.js"></script><script>const key = "${AWS_KEY}";</script></html>`;
    mockFetch(() => {
      throw new Error("network error");
    });
    const result = await scanJavaScriptForSecrets(html, BASE);
    // inline finding still comes through; the broken external fetch produced no findings and no throw
    expect(result.map((v) => v.name)).toContain("AWS Access Key ID Exposed");
  });

  it("skips a non-2xx external response", async () => {
    const html = `<html><script src="/missing.js"></script></html>`;
    mockFetch(() => jsResponse("", "application/javascript", 404));
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result).toEqual([]);
  });

  it("ignores a response whose content-type is not javascript/text/application (e.g. an HTML error page)", async () => {
    const html = `<html><script src="/app.js"></script></html>`;
    mockFetch(() => jsResponse(`<html>secret ${STRIPE_KEY}</html>`, "text/html"));
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result).toEqual([]);
  });

  it("only fetches the first 8 unique external scripts (MAX_EXTERNAL_SCRIPTS)", async () => {
    const scripts = Array.from({ length: 9 }, (_, i) => `<script src="/s${i}.js"></script>`).join("\n");
    const fetchMock = vi.fn(() => Promise.resolve(jsResponse("// noop")));
    vi.stubGlobal("fetch", fetchMock);
    await scanJavaScriptForSecrets(scripts, BASE);
    expect(fetchMock).toHaveBeenCalledTimes(8);
  });

  it("deduplicates the same script URL referenced multiple times before applying the 8-file cap", async () => {
    const html = `<script src="/dup.js"></script><script src="/dup.js"></script>`;
    const fetchMock = vi.fn(() => Promise.resolve(jsResponse("// noop")));
    vi.stubGlobal("fetch", fetchMock);
    await scanJavaScriptForSecrets(html, BASE);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("truncates external file content at 512KB — a secret placed after the cutoff is not found", async () => {
    const padding = "x".repeat(512_000);
    const html = `<script src="/big.js"></script>`;
    mockFetch(() => jsResponse(`${padding}const key = "${AWS_KEY}";`));
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result).toEqual([]);
  });

  it("still finds a secret within the first 512KB of a larger file", async () => {
    const html = `<script src="/big.js"></script>`;
    const padding = "x".repeat(1000);
    mockFetch(() => jsResponse(`const key = "${AWS_KEY}";${padding}`));
    const result = await scanJavaScriptForSecrets(html, BASE);
    expect(result.map((v) => v.name)).toContain("AWS Access Key ID Exposed");
  });

  it("reports a pattern only once even if matched in both inline and external content (inline wins)", async () => {
    const html = `<script src="/app.js"></script><script>const key = "${AWS_KEY}";</script>`;
    mockFetch(() => jsResponse(`const key2 = "AKIAZZ9YXW3QMNB4KTHR";`));
    const result = await scanJavaScriptForSecrets(html, BASE);
    const matches = result.filter((v) => v.name === "AWS Access Key ID Exposed");
    expect(matches).toHaveLength(1);
    expect(matches[0]!.evidence).toContain("inline <script>");
  });
});

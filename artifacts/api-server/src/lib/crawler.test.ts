import { describe, it, expect } from "vitest";
import { extractInternalLinks, checkUrlEmbeddedSecrets } from "./crawler.js";

const BASE = "https://example.com";
// Not a Stripe-shaped prefix on purpose — this only needs to look like a
// plausible URL-embedded credential for checkUrlEmbeddedSecrets to flag,
// not trigger GitHub's Stripe-key push-protection pattern.
const REAL_LOOKING_KEY = "cred_9fK3mQzR7vLpXeT2wNbYcAj4_lookalike";

describe("extractInternalLinks", () => {
  it("returns empty array for an invalid baseUrl", () => {
    expect(extractInternalLinks(`<a href="/about">`, "not-a-url")).toEqual([]);
  });

  it("returns empty array for empty HTML", () => {
    expect(extractInternalLinks("", BASE)).toEqual([]);
  });

  it("extracts an absolute same-domain href", () => {
    const html = `<a href="https://example.com/about">About</a>`;
    expect(extractInternalLinks(html, BASE)).toContain("https://example.com/about");
  });

  it("resolves a root-relative href", () => {
    const html = `<a href="/contact">Contact</a>`;
    expect(extractInternalLinks(html, BASE)).toContain("https://example.com/contact");
  });

  it("resolves a relative href", () => {
    const html = `<a href="blog/post-1">Post</a>`;
    expect(extractInternalLinks(html, BASE)).toContain("https://example.com/blog/post-1");
  });

  it("excludes off-domain hrefs", () => {
    const html = `<a href="https://evil.com/steal">click</a>`;
    expect(extractInternalLinks(html, BASE)).toHaveLength(0);
  });

  it("excludes javascript: hrefs", () => {
    expect(extractInternalLinks(`<a href="javascript:void(0)">x</a>`, BASE)).toHaveLength(0);
  });

  it("excludes mailto: hrefs", () => {
    expect(extractInternalLinks(`<a href="mailto:foo@bar.com">email</a>`, BASE)).toHaveLength(0);
  });

  it("excludes tel: hrefs", () => {
    expect(extractInternalLinks(`<a href="tel:+15550001234">call</a>`, BASE)).toHaveLength(0);
  });

  it("deduplicates repeated hrefs", () => {
    const html = `<a href="/about">1</a><a href="/about">2</a><a href="/about">3</a>`;
    expect(extractInternalLinks(html, BASE)).toHaveLength(1);
  });

  it("excludes the root path '/'", () => {
    expect(extractInternalLinks(`<a href="/">Home</a>`, BASE)).toHaveLength(0);
  });

  it("excludes the base URL itself", () => {
    const html = `<a href="https://example.com">Home</a>`;
    expect(extractInternalLinks(html, BASE)).toHaveLength(0);
  });

  it("strips query strings when deduplicating", () => {
    const html = `<a href="/products?cat=shoes">1</a><a href="/products">2</a>`;
    expect(extractInternalLinks(html, BASE)).toHaveLength(1);
    expect(extractInternalLinks(html, BASE)[0]).toBe("https://example.com/products");
  });

  it("strips fragment anchors when deduplicating", () => {
    const html = `<a href="/products#top">1</a><a href="/products">2</a>`;
    expect(extractInternalLinks(html, BASE)).toHaveLength(1);
  });

  it("excludes dangerous path: /logout", () => {
    expect(extractInternalLinks(`<a href="/logout">Logout</a>`, BASE)).toHaveLength(0);
  });

  it("excludes dangerous path: /delete", () => {
    expect(extractInternalLinks(`<a href="/delete-account">Delete</a>`, BASE)).toHaveLength(0);
  });

  it("excludes dangerous path: /signout", () => {
    expect(extractInternalLinks(`<a href="/signout">Sign out</a>`, BASE)).toHaveLength(0);
  });

  it("excludes dangerous path: /reset", () => {
    expect(extractInternalLinks(`<a href="/reset-password">Reset</a>`, BASE)).toHaveLength(0);
  });

  it("extracts form action pointing to a .php page", () => {
    const html = `<form action="/submit.php"><input type="submit"/></form>`;
    expect(extractInternalLinks(html, BASE)).toContain("https://example.com/submit.php");
  });

  it("extracts img src pointing to an .asp page", () => {
    const html = `<img src="/image-handler.asp"/>`;
    expect(extractInternalLinks(html, BASE)).toContain("https://example.com/image-handler.asp");
  });

  it("handles multiple valid links at once", () => {
    const html = `
      <a href="/about">About</a>
      <a href="/pricing">Pricing</a>
      <a href="/blog">Blog</a>
      <a href="https://evil.com">Evil</a>
    `;
    const result = extractInternalLinks(html, BASE);
    expect(result).toHaveLength(3);
    expect(result).toContain("https://example.com/about");
    expect(result).toContain("https://example.com/pricing");
    expect(result).toContain("https://example.com/blog");
  });
});

describe("checkUrlEmbeddedSecrets", () => {
  it("flags a real-looking API key in an href query string", () => {
    const html = `<a href="/api/export?api_key=${REAL_LOOKING_KEY}">Export</a>`;
    const result = checkUrlEmbeddedSecrets(html, BASE);
    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("API Credential Exposed in URL Query String");
    expect(result[0]!.evidence).not.toContain(REAL_LOOKING_KEY);
  });

  it("flags a real-looking API key inside an inline script fetch call", () => {
    const html = `<script>fetch("https://api.example.com/v1/data?access_token=${REAL_LOOKING_KEY}");</script>`;
    expect(checkUrlEmbeddedSecrets(html, BASE)).toHaveLength(1);
  });

  it("ignores a generic 'token' param (too commonly legitimate)", () => {
    const html = `<a href="/reset?token=${REAL_LOOKING_KEY}">Reset</a>`;
    expect(checkUrlEmbeddedSecrets(html, BASE)).toHaveLength(0);
  });

  it("ignores a credential-named param on a password-reset path", () => {
    const html = `<a href="/reset-password?api_key=${REAL_LOOKING_KEY}">Reset</a>`;
    expect(checkUrlEmbeddedSecrets(html, BASE)).toHaveLength(0);
  });

  it("ignores placeholder values", () => {
    const html = `<a href="/api?api_key=YOUR_API_KEY_HERE">Docs</a>`;
    expect(checkUrlEmbeddedSecrets(html, BASE)).toHaveLength(0);
  });

  it("ignores low-entropy values", () => {
    const html = `<a href="/api?api_key=aaaaaaaaaaaaaaaa">Docs</a>`;
    expect(checkUrlEmbeddedSecrets(html, BASE)).toHaveLength(0);
  });

  it("ignores short values", () => {
    const html = `<a href="/api?api_key=abc123">Docs</a>`;
    expect(checkUrlEmbeddedSecrets(html, BASE)).toHaveLength(0);
  });

  it("returns empty array for empty HTML", () => {
    expect(checkUrlEmbeddedSecrets("", BASE)).toEqual([]);
  });

  it("deduplicates the same param name found in multiple places", () => {
    const html = `
      <a href="/a?api_key=${REAL_LOOKING_KEY}">1</a>
      <a href="/b?api_key=${REAL_LOOKING_KEY}">2</a>
    `;
    expect(checkUrlEmbeddedSecrets(html, BASE)).toHaveLength(1);
  });
});

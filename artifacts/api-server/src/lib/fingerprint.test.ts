import { describe, it, expect } from "vitest";
import { canonicalizeTargetUrl, normalizeEvidenceKey, findingFingerprint } from "./fingerprint.js";

describe("canonicalizeTargetUrl", () => {
  it("lowercases scheme and hostname", () => {
    expect(canonicalizeTargetUrl("HTTPS://Example.COM/Path")).toBe("https://example.com/Path");
  });

  it("strips trailing slash from non-root paths", () => {
    expect(canonicalizeTargetUrl("https://example.com/path/")).toBe("https://example.com/path");
  });

  it("does not strip the root path itself", () => {
    expect(canonicalizeTargetUrl("https://example.com/")).toBe("https://example.com/");
  });

  it("produces the same canonical form for equivalent mixed-case URLs", () => {
    const a = canonicalizeTargetUrl("HTTPS://Example.COM/Path/");
    const b = canonicalizeTargetUrl("https://example.com/Path");
    expect(a).toBe(b);
  });

  it("falls back to the raw string on unparseable input", () => {
    expect(canonicalizeTargetUrl("not a url")).toBe("not a url");
  });
});

describe("normalizeEvidenceKey", () => {
  it("returns empty string for null/undefined", () => {
    expect(normalizeEvidenceKey(null)).toBe("");
    expect(normalizeEvidenceKey(undefined)).toBe("");
  });

  it("normalizes URLs, versions, and punctuation to a stable structural key", () => {
    const a = normalizeEvidenceKey("Header 'Server' exposes version: Apache/2.4.51");
    const b = normalizeEvidenceKey("Header 'Server' exposes version: Apache/2.4.99");
    expect(a).toBe(b);
  });

  it("produces the same key for the same evidence shape with different cookie names", () => {
    const a = normalizeEvidenceKey("Cookie 'session' is missing the Secure flag");
    const b = normalizeEvidenceKey("Cookie 'session' is missing the Secure flag");
    expect(a).toBe(b);
  });

  it("lowercases and strips punctuation", () => {
    expect(normalizeEvidenceKey("ABC 'DEF' ghi;")).toBe("abc def ghi");
  });
});

describe("findingFingerprint", () => {
  it("is deterministic — same inputs produce the same output", () => {
    const a = findingFingerprint("Transport Security", "Missing HSTS", "evidence text");
    const b = findingFingerprint("Transport Security", "Missing HSTS", "evidence text");
    expect(a).toBe(b);
  });

  it("differs when category or name differs", () => {
    const base = findingFingerprint("Transport Security", "Missing HSTS", "evidence");
    expect(findingFingerprint("Other Category", "Missing HSTS", "evidence")).not.toBe(base);
    expect(findingFingerprint("Transport Security", "Different Name", "evidence")).not.toBe(base);
  });

  it("is stable across re-scans where only volatile evidence details change (via normalization)", () => {
    const a = findingFingerprint("Transport Security", "Server Version Disclosure", "Server: Apache/2.4.51");
    const b = findingFingerprint("Transport Security", "Server Version Disclosure", "Server: Apache/2.4.60");
    expect(a).toBe(b);
  });

  it("is lowercase/trim-insensitive on category and name", () => {
    const a = findingFingerprint("Transport Security", "Missing HSTS");
    const b = findingFingerprint("  transport security  ", "  missing hsts  ");
    expect(a).toBe(b);
  });

  it("produces a 20-character hex identifier", () => {
    const fp = findingFingerprint("Category", "Name", "evidence");
    expect(fp).toMatch(/^[0-9a-f]{20}$/);
  });

  it("differs with and without evidence when evidence normalizes to a non-empty key", () => {
    const withEvidence = findingFingerprint("Category", "Name", "Header 'X' present");
    const withoutEvidence = findingFingerprint("Category", "Name");
    expect(withEvidence).not.toBe(withoutEvidence);
  });
});

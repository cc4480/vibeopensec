import { describe, it, expect } from "vitest";
import { runNextjsProbe } from "./nextjsProbe.js";

/**
 * nextjsProbe.ts tests — __NEXT_DATA__ secret-leak detection. Purely
 * synchronous over already-fetched HTML, so no fetch mocking is needed.
 *
 * Note: several fixtures below are deliberately shaped to match real
 * provider key formats (sk_live_, AKIA, ghp_, etc.) — that's required to
 * exercise the actual regexes. If this file is ever pushed to a repo with
 * GitHub secret-scanning push protection enabled, expect it to flag these
 * as it did for a similar fixture in crawler.test.ts.
 */

function nextDataHtml(props: Record<string, unknown>): string {
  return `<!DOCTYPE html><html><body><div id="__next"></div>
<script id="__NEXT_DATA__" type="application/json">${JSON.stringify({ props: { pageProps: props }, page: "/", buildId: "test-build" })}</script>
</body></html>`;
}

describe("runNextjsProbe — page gating", () => {
  it("returns no findings and does no parsing when the page has no Next.js markers", async () => {
    const html = `<html><body><h1>Plain page</h1><script>const x = "sk_live_${"A".repeat(30)}";</script></body></html>`;
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings).toHaveLength(0);
  });

  it("returns no findings when __NEXT_DATA__ is present but contains no secrets", async () => {
    const html = nextDataHtml({ title: "Home", items: [1, 2, 3] });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings).toHaveLength(0);
  });

  it("falls back to scanning raw text when __NEXT_DATA__ content is malformed JSON", async () => {
    const secret = `sk_live_${"A".repeat(30)}`;
    const html = `<html><body>
<script id="__NEXT_DATA__" type="application/json">{not valid json, "key": "${secret}"</script>
</body></html>`;
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.some((f) => f.name.includes("Stripe"))).toBe(true);
  });
});

describe("runNextjsProbe — secret pattern detection", () => {
  it("flags a Stripe live secret key", async () => {
    const html = nextDataHtml({ stripeKey: `sk_live_${"A".repeat(30)}` });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.map((f) => f.name)).toContain("Stripe Live Secret Key in __NEXT_DATA__");
    expect(findings[0]!.severity).toBe("critical");
  });

  it("flags a Supabase service_role key as a real JSON property (the realistic leak shape)", async () => {
    // This is what an actual leak looks like after __NEXT_DATA__ is
    // normalized via JSON.stringify(JSON.parse(...)): a real JSON key:value
    // pair — "service_role_key":"eyJ... — with a closing-key-quote + colon +
    // opening-value-quote between the key name and the value, not just one
    // quote character. The pattern used to require exactly one quote char
    // in that gap and silently missed this exact shape — see the fix in
    // nextjsProbe.ts.
    const html = nextDataHtml({ service_role_key: `eyJ${"z".repeat(35)}` });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.map((f) => f.name)).toContain("Supabase Service Role Key in __NEXT_DATA__");
  });

  it("also flags the JS-assignment shape (service_role_key = \"eyJ...)", async () => {
    const html = nextDataHtml({ blob: `service_role_key = "eyJ${"z".repeat(35)}` });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.map((f) => f.name)).toContain("Supabase Service Role Key in __NEXT_DATA__");
  });

  it("flags a PEM private key block", async () => {
    const html = nextDataHtml({ key: "-----BEGIN RSA PRIVATE KEY-----\\nMIIEow...\\n-----END RSA PRIVATE KEY-----" });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.map((f) => f.name)).toContain("Private Key in __NEXT_DATA__");
  });

  it("flags an AWS Access Key ID", async () => {
    const html = nextDataHtml({ awsKey: `AKIA${"Q".repeat(16)}` });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.map((f) => f.name)).toContain("AWS Access Key ID in __NEXT_DATA__");
  });

  it("flags an AWS Secret Access Key in a labeled context", async () => {
    // No literal quote chars around the value — same escaping issue as above;
    // the separator class ["':\s] doesn't include a backslash, so a `\"`
    // produced by JSON.stringify would break the match.
    const html = nextDataHtml({ raw: `aws_secret_access_key: ${"C".repeat(40)}` });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.map((f) => f.name)).toContain("AWS Secret Access Key in __NEXT_DATA__");
  });

  it("flags a GitHub personal access token", async () => {
    const html = nextDataHtml({ token: `ghp_${"D".repeat(36)}` });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.map((f) => f.name)).toContain("GitHub Token in __NEXT_DATA__");
  });

  it("flags a SendGrid API key", async () => {
    const html = nextDataHtml({ key: `SG.${"A".repeat(22)}.${"B".repeat(43)}` });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.map((f) => f.name)).toContain("SendGrid API Key in __NEXT_DATA__");
  });

  it("flags a Slack token", async () => {
    const html = nextDataHtml({ token: `xoxb-${"1".repeat(10)}-${"2".repeat(10)}` });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.map((f) => f.name)).toContain("Slack Token in __NEXT_DATA__");
  });

  it("flags a hardcoded database connection string with credentials", async () => {
    const html = nextDataHtml({ dbUrl: "postgres://appuser:hunter2pass@db.internal.example:5432/appdb" });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.map((f) => f.name)).toContain("Hardcoded Database Connection String in __NEXT_DATA__");
  });

  it("flags multiple distinct secret types present at once, one finding per pattern", async () => {
    const html = nextDataHtml({
      stripeKey: `sk_live_${"A".repeat(30)}`,
      awsKey: `AKIA${"Q".repeat(16)}`,
      token: `ghp_${"D".repeat(36)}`,
    });
    const findings = await runNextjsProbe("https://example.com", html);
    const names = findings.map((f) => f.name);
    expect(names).toContain("Stripe Live Secret Key in __NEXT_DATA__");
    expect(names).toContain("AWS Access Key ID in __NEXT_DATA__");
    expect(names).toContain("GitHub Token in __NEXT_DATA__");
    expect(findings).toHaveLength(3);
  });
});

describe("runNextjsProbe — redaction", () => {
  it("never includes the full secret value in the finding evidence", async () => {
    const secret = `sk_live_${"A".repeat(30)}`;
    const html = nextDataHtml({ stripeKey: secret });
    const findings = await runNextjsProbe("https://example.com", html);
    const finding = findings.find((f) => f.name.includes("Stripe"))!;
    expect(finding.evidence).not.toContain(secret);
    expect(finding.evidence).toMatch(/…\[redacted\]…/);
  });
});

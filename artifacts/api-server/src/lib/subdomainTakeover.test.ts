import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkSubdomainTakeover } from "./subdomainTakeover.js";

/**
 * Subdomain takeover detection tests. Mocks both layers the real check hits:
 * Cloudflare DNS-over-HTTPS (CNAME resolution) and the HTTP fetch to the
 * CNAME target that confirms the "unclaimed resource" body fingerprint.
 */

function dnsJsonResponse(answer: unknown[]): Response {
  return new Response(JSON.stringify({ Status: 0, Answer: answer }), {
    status: 200,
    headers: { "content-type": "application/dns-json" },
  });
}

/** Builds a fetch mock: DoH CNAME lookups driven by a hostname->target map (missing = chain ends), HTTP verification driven by a url-prefix->body map. */
function mockDnsAndHttp(cnameMap: Record<string, string>, httpMap: Record<string, { status: number; body: string }>) {
  vi.mocked(fetch).mockImplementation(async (input) => {
    const url = String(input);
    if (url.includes("cloudflare-dns.com")) {
      const name = new URL(url).searchParams.get("name") ?? "";
      const target = cnameMap[name];
      if (target) {
        return dnsJsonResponse([{ name: `${name}.`, type: 5, TTL: 300, data: target }]);
      }
      return dnsJsonResponse([]);
    }
    for (const [prefix, resp] of Object.entries(httpMap)) {
      if (url.startsWith(prefix)) return new Response(resp.body, { status: resp.status });
    }
    return new Response("", { status: 500 });
  });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("checkSubdomainTakeover — confirmed dangling CNAMEs", () => {
  it("flags AWS S3 with the NoSuchBucket fingerprint", async () => {
    mockDnsAndHttp(
      { "old.example.com": "my-old-bucket.s3.amazonaws.com." },
      { "https://my-old-bucket.s3.amazonaws.com/": { status: 404, body: "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>" } },
    );

    const result = await checkSubdomainTakeover("https://old.example.com/");

    expect(result).toHaveLength(1);
    expect(result[0]!.name).toContain("AWS S3");
    expect(result[0]!.severity).toBe("critical");
    expect(result[0]!.evidence).toContain("my-old-bucket.s3.amazonaws.com");
  });

  it("flags Vercel with the deployment-not-found fingerprint", async () => {
    mockDnsAndHttp(
      { "preview.example.com": "old-project.vercel.app." },
      { "https://old-project.vercel.app/": { status: 404, body: "404: NOT_FOUND\nThe deployment could not be found." } },
    );

    const result = await checkSubdomainTakeover("https://preview.example.com/");

    expect(result).toHaveLength(1);
    expect(result[0]!.name).toContain("Vercel");
  });

  it("flags Render with its unclaimed-site fingerprint", async () => {
    mockDnsAndHttp(
      { "app.example.com": "old-app.onrender.com." },
      { "https://old-app.onrender.com/": { status: 404, body: "There is no site here" } },
    );

    const result = await checkSubdomainTakeover("https://app.example.com/");

    expect(result).toHaveLength(1);
    expect(result[0]!.name).toContain("Render");
  });

  it("follows a multi-hop CNAME chain to the final dangling target", async () => {
    mockDnsAndHttp(
      {
        "www.example.com": "edge.example.net.",
        "edge.example.net": "legacy.github.io.",
      },
      { "https://legacy.github.io/": { status: 404, body: "404 There is no GitHub Pages site here." } },
    );

    const result = await checkSubdomainTakeover("https://www.example.com/");

    expect(result).toHaveLength(1);
    expect(result[0]!.name).toContain("GitHub Pages");
    expect(result[0]!.evidence).toContain("www.example.com");
  });
});

describe("checkSubdomainTakeover — negative cases", () => {
  it("does not flag a CNAME pointing to a live, claimed service", async () => {
    mockDnsAndHttp(
      { "app.example.com": "my-live-app.vercel.app." },
      { "https://my-live-app.vercel.app/": { status: 200, body: "<html><body>Welcome to my live app</body></html>" } },
    );

    const result = await checkSubdomainTakeover("https://app.example.com/");

    expect(result).toEqual([]);
  });

  it("returns no finding and makes no verification fetch when there is no CNAME at all", async () => {
    mockDnsAndHttp({}, {});

    const result = await checkSubdomainTakeover("https://plain-a-record.example.com/");

    expect(result).toEqual([]);
    // Exactly one DoH lookup (hop 0), no HTTP verification request.
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
    expect(String(vi.mocked(fetch).mock.calls[0]![0])).toContain("cloudflare-dns.com");
  });

  it("does not crash and reports nothing on a DNS lookup failure", async () => {
    vi.mocked(fetch).mockImplementation(async () => {
      throw new Error("network unreachable");
    });

    const result = await checkSubdomainTakeover("https://flaky.example.com/");

    expect(result).toEqual([]);
  });

  it("skips bare IP-address and localhost targets without any DNS lookup", async () => {
    mockDnsAndHttp({}, {});

    const ipResult = await checkSubdomainTakeover("http://203.0.113.5/");
    const localhostResult = await checkSubdomainTakeover("http://localhost:3000/");

    expect(ipResult).toEqual([]);
    expect(localhostResult).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not flag a CNAME target whose service is recognized but body fingerprint doesn't match", async () => {
    mockDnsAndHttp(
      { "app.example.com": "some-bucket.s3.amazonaws.com." },
      { "https://some-bucket.s3.amazonaws.com/": { status: 200, body: "<ListBucketResult><Contents/></ListBucketResult>" } },
    );

    const result = await checkSubdomainTakeover("https://app.example.com/");

    expect(result).toEqual([]);
  });
});

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runBaasProbes } from "./baasProbes.js";

/**
 * BaaS probe tests — PocketBase and Appwrite detection + open-collection
 * checks. Supabase/Firebase have their own dedicated test files; this one
 * covers the two backends baasProbes.ts owns. PocketBase's core probe logic
 * was already validated live against a real running PocketBase instance
 * (see WINNERS_CIRCLE_PLAN-era session notes) — coverage here is lighter by
 * design. Appwrite has no prior validation, so it gets the deeper coverage.
 */

const TARGET = "https://example.com";

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

// ─── PocketBase (light coverage — see file header) ─────────────────────────

describe("runBaasProbes — PocketBase", () => {
  it("flags an open collection with records as critical", async () => {
    const html = `<script>const pb = new PocketBase("https://pb.example.com");</script>`;
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith("/api/health")) return Promise.resolve(jsonResponse({ code: 200 }));
      if (url.includes("/api/collections/users/records")) {
        return Promise.resolve(jsonResponse({ items: [{ id: "1" }], totalItems: 1 }));
      }
      return Promise.resolve(jsonResponse({ items: [], totalItems: 0 }));
    });

    const findings = await runBaasProbes(TARGET, html);
    const hit = findings.find((f) => /PocketBase.*'users'/.test(f.name));
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("critical");
  });

  it("flags an accessible-but-empty collection as high, not critical", async () => {
    const html = `<script>const pb = new PocketBase("https://pb.example.com");</script>`;
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith("/api/health")) return Promise.resolve(jsonResponse({ code: 200 }));
      if (url.includes("/api/collections/users/records")) {
        return Promise.resolve(jsonResponse({ items: [], totalItems: 0 }));
      }
      return Promise.resolve(new Response("", { status: 404 }));
    });

    const findings = await runBaasProbes(TARGET, html);
    const hit = findings.find((f) => /PocketBase.*'users'/.test(f.name));
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("high");
  });

  it("stops after a failed health check — never probes collections", async () => {
    // Same-origin constructor URL so the explicit-URL match and the generic
    // "mentions pocketbase" fallback (which adds targetOrigin) collapse to a
    // single candidate after dedup — isolates the health-check-gate behavior
    // from the (separately tested) multi-candidate fan-out.
    const html = `<script>const pb = new PocketBase("${TARGET}");</script>`;
    vi.mocked(fetch).mockImplementation(() => Promise.resolve(new Response("not pocketbase", { status: 404 })));

    const findings = await runBaasProbes(TARGET, html);

    expect(findings).toHaveLength(0);
    expect(vi.mocked(fetch).mock.calls).toHaveLength(1);
    expect(String(vi.mocked(fetch).mock.calls[0]![0])).toContain("/api/health");
  });

  it("caps PocketBase findings at 3 even when more collections are open", async () => {
    const html = `<script>const pb = new PocketBase("${TARGET}");</script>`;
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith("/api/health")) return Promise.resolve(jsonResponse({ code: 200 }));
      if (url.includes("/api/collections/")) {
        return Promise.resolve(jsonResponse({ items: [{ id: "1" }], totalItems: 1 }));
      }
      return Promise.resolve(new Response("", { status: 404 }));
    });

    const findings = await runBaasProbes(TARGET, html);
    const pbFindings = findings.filter((f) => f.name.startsWith("PocketBase"));
    expect(pbFindings).toHaveLength(3);
  });

  it("probes both an explicit-origin PocketBase URL and the page's own origin when both signals are present", async () => {
    // "new PocketBase(...)" itself contains the word "PocketBase", so the
    // generic-keyword fallback also fires and adds targetOrigin as a second,
    // distinct candidate — both get health-checked independently.
    const html = `<script>const pb = new PocketBase("https://pb.example.com");</script>`;
    vi.mocked(fetch).mockImplementation(() => Promise.resolve(new Response("", { status: 404 })));

    await runBaasProbes(TARGET, html);

    const healthCheckUrls = vi
      .mocked(fetch)
      .mock.calls.map((c) => String(c[0]))
      .filter((u) => u.endsWith("/api/health"));
    expect(healthCheckUrls.sort()).toEqual(
      ["https://pb.example.com/api/health", `${TARGET}/api/health`].sort(),
    );
  });
});

// ─── Appwrite ────────────────────────────────────────────────────────────────

const APPWRITE_SDK_HTML = `<script>
  // Appwrite client init
  const client = new Appwrite.Client();
  client.setEndpoint("https://cloud.appwrite.io/v1").setProject("64f1a2b3c4d5e6f7a8b9");
</script>`;

describe("runBaasProbes — Appwrite detection", () => {
  it("does not detect Appwrite when only the endpoint marker is present", async () => {
    const html = `<script>client.setEndpoint("https://cloud.appwrite.io/v1");</script>`;
    const findings = await runBaasProbes(TARGET, html);
    expect(findings).toHaveLength(0);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not detect Appwrite when the literal 'appwrite' word never appears", async () => {
    // Endpoint + project patterns both match syntactically, but nothing in the
    // content mentions Appwrite by name — the sanity check must reject this.
    const html = `<script>
      client.setEndpoint("https://cloud.example.io/v1").setProject("64f1a2b3c4d5e6f7a8b9");
    </script>`;
    const findings = await runBaasProbes(TARGET, html);
    expect(findings).toHaveLength(0);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not probe collections when the Appwrite health check fails", async () => {
    vi.mocked(fetch).mockImplementation(() => Promise.resolve(new Response("", { status: 404 })));

    const findings = await runBaasProbes(TARGET, APPWRITE_SDK_HTML);

    expect(findings).toHaveLength(0);
    expect(vi.mocked(fetch).mock.calls).toHaveLength(1);
    expect(String(vi.mocked(fetch).mock.calls[0]![0])).toContain("/health");
  });
});

describe("runBaasProbes — Appwrite open collections", () => {
  it("flags an open collection with documents as critical", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith("/health")) return Promise.resolve(jsonResponse({ ping: "pong" }));
      if (url.includes("/collections/users/documents")) {
        return Promise.resolve(jsonResponse({ documents: [{ $id: "1" }], total: 1 }));
      }
      return Promise.resolve(jsonResponse({ documents: [], total: 0 }));
    });

    const findings = await runBaasProbes(TARGET, APPWRITE_SDK_HTML);
    const hit = findings.find((f) => /Appwrite.*'users'/.test(f.name));
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("critical");
    expect(hit!.cvssScore).toBe(9.1);
  });

  it("flags an accessible-but-empty collection as high, not critical", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith("/health")) return Promise.resolve(jsonResponse({ ping: "pong" }));
      if (url.includes("/collections/users/documents")) {
        return Promise.resolve(jsonResponse({ documents: [], total: 0 }));
      }
      return Promise.resolve(new Response("", { status: 401 }));
    });

    const findings = await runBaasProbes(TARGET, APPWRITE_SDK_HTML);
    const hit = findings.find((f) => /Appwrite.*'users'/.test(f.name));
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("high");
    expect(hit!.cvssScore).toBe(7.5);
  });

  it("reports zero findings when every collection requires auth", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith("/health")) return Promise.resolve(jsonResponse({ ping: "pong" }));
      return Promise.resolve(new Response(JSON.stringify({ message: "unauthorized" }), { status: 401 }));
    });

    const findings = await runBaasProbes(TARGET, APPWRITE_SDK_HTML);
    expect(findings).toHaveLength(0);
  });

  it("caps Appwrite findings at 2 even when more collections are open", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.endsWith("/health")) return Promise.resolve(jsonResponse({ ping: "pong" }));
      if (url.includes("/documents")) {
        return Promise.resolve(jsonResponse({ documents: [{ $id: "1" }], total: 1 }));
      }
      return Promise.resolve(new Response("", { status: 404 }));
    });

    const findings = await runBaasProbes(TARGET, APPWRITE_SDK_HTML);
    const appwriteFindings = findings.filter((f) => f.name.startsWith("Appwrite"));
    expect(appwriteFindings).toHaveLength(2);
  });
});

describe("runBaasProbes — neither backend present", () => {
  it("returns no findings and makes no HTTP calls", async () => {
    const findings = await runBaasProbes(TARGET, "<html><body>plain page</body></html>");
    expect(findings).toHaveLength(0);
    expect(fetch).not.toHaveBeenCalled();
  });
});

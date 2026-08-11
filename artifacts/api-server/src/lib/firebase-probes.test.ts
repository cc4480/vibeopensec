import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runFirebaseProbes } from "./firebase-probes.js";

/**
 * Firebase probe tests — detects open Firestore collections and Realtime
 * Database access. All external HTTP calls are stubbed via
 * vi.stubGlobal("fetch", vi.fn()).
 */

// ─── HTML fixtures ──────────────────────────────────────────────────────────

function htmlWithFirebaseConfig(opts: { withDatabaseUrl?: boolean } = {}): string {
  return `<script>
    const firebaseConfig = {
      apiKey: "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWQ",
      projectId: "vibescan-test-project"${opts.withDatabaseUrl ? ',\n      databaseURL: "https://vibescan-test-project.firebaseio.com"' : ""}
    };
    firebase.initializeApp(firebaseConfig);
  </script>`;
}

function htmlWithEnvVarStyleConfig(): string {
  return `<script>
    const env = {
      VITE_FIREBASE_API_KEY: "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWQ",
      VITE_FIREBASE_PROJECT_ID: "vibescan-env-project"
    };
  </script>`;
}

function htmlWithApiKeyOnly(): string {
  return `<script>const apiKey = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWQ";</script>`;
}

function htmlWithNoFirebase(): string {
  return `<html><body>Hello world — no Firebase here</body></html>`;
}

// ─── Fetch mock helpers ─────────────────────────────────────────────────────

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: { "content-type": "application/json" } });
}

// ─── Setup / teardown ───────────────────────────────────────────────────────

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

// ─── No Firebase / incomplete config ────────────────────────────────────────

describe("runFirebaseProbes — no or incomplete config", () => {
  it("makes no HTTP calls and pushes nothing when Firebase is not present", async () => {
    const findings: any[] = [];
    await runFirebaseProbes(htmlWithNoFirebase(), findings);

    expect(findings).toHaveLength(0);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("pushes nothing when only apiKey is found (projectId missing)", async () => {
    const findings: any[] = [];
    await runFirebaseProbes(htmlWithApiKeyOnly(), findings);

    expect(findings).toHaveLength(0);
    expect(fetch).not.toHaveBeenCalled();
  });
});

// ─── Firestore ──────────────────────────────────────────────────────────────

describe("runFirebaseProbes — Firestore", () => {
  it("reports a critical finding when a common collection returns documents", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes("/documents/users")) {
        return Promise.resolve(jsonResponse({ documents: [{ name: "doc1" }] }));
      }
      return Promise.resolve(jsonResponse({}));
    });

    const findings: any[] = [];
    await runFirebaseProbes(htmlWithFirebaseConfig(), findings);

    const critical = findings.find(
      (f) => f.severity === "critical" && /Firestore Security Rules Allow Unauthenticated/i.test(f.name),
    );
    expect(critical).toBeDefined();
    expect(critical.cvssScore).toBe(9.3);
    expect(critical.cweId).toBe("CWE-284");
    expect(critical.evidence).toContain("users");
    // No databaseURL in this fixture — no RTDB finding, and only one finding total.
    expect(findings).toHaveLength(1);
  });

  it("reports an informational finding when no collection is open", async () => {
    vi.mocked(fetch).mockImplementation(() => Promise.resolve(jsonResponse({})));

    const findings: any[] = [];
    await runFirebaseProbes(htmlWithFirebaseConfig(), findings);

    expect(findings).toHaveLength(1);
    const info = findings[0];
    expect(info.severity).toBe("info");
    expect(info.name).toMatch(/Firebase Backend Detected/i);
    expect(info.cvssScore).toBe(0);
    expect(info.cweId).toBeNull();
  });

  it("falls back to the informational finding (not a crash or silent empty) on total network failure", async () => {
    vi.mocked(fetch).mockImplementation(() => Promise.reject(new Error("network down")));

    const findings: any[] = [];
    await runFirebaseProbes(htmlWithFirebaseConfig(), findings);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("info");
    expect(findings[0].name).toMatch(/Firebase Backend Detected/i);
  });

  it("does not treat an empty documents array as open", async () => {
    vi.mocked(fetch).mockImplementation(() => Promise.resolve(jsonResponse({ documents: [] })));

    const findings: any[] = [];
    await runFirebaseProbes(htmlWithFirebaseConfig(), findings);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("info");
  });

  it("extracts config from VITE_ env-var-style declarations, not just object literals", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes("/documents/users")) {
        return Promise.resolve(jsonResponse({ documents: [{ name: "doc1" }] }));
      }
      return Promise.resolve(jsonResponse({}));
    });

    const findings: any[] = [];
    await runFirebaseProbes(htmlWithEnvVarStyleConfig(), findings);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].evidence).toContain("vibescan-env-project");
  });
});

// ─── Realtime Database ──────────────────────────────────────────────────────

describe("runFirebaseProbes — Realtime Database", () => {
  it("reports a critical RTDB finding in addition to the Firestore finding when both are open", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes("firebaseio.com/.json")) {
        return Promise.resolve(textResponse(JSON.stringify({ users: { "1": { email: "a@b.com" } } })));
      }
      if (url.includes("/documents/users")) {
        return Promise.resolve(jsonResponse({ documents: [{ name: "doc1" }] }));
      }
      return Promise.resolve(jsonResponse({}));
    });

    const findings: any[] = [];
    await runFirebaseProbes(htmlWithFirebaseConfig({ withDatabaseUrl: true }), findings);

    expect(findings).toHaveLength(2);
    const rtdb = findings.find((f) => /Realtime Database Open/i.test(f.name));
    expect(rtdb).toBeDefined();
    expect(rtdb.severity).toBe("critical");
    expect(rtdb.cvssScore).toBe(9.8);
  });

  it("does not flag Realtime Database when the root value is null", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes("firebaseio.com/.json")) {
        return Promise.resolve(textResponse("null"));
      }
      return Promise.resolve(jsonResponse({}));
    });

    const findings: any[] = [];
    await runFirebaseProbes(htmlWithFirebaseConfig({ withDatabaseUrl: true }), findings);

    expect(findings.find((f) => /Realtime Database Open/i.test(f.name))).toBeUndefined();
  });

  it("does not flag Realtime Database on 401/403", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes("firebaseio.com/.json")) {
        return Promise.resolve(textResponse(JSON.stringify({ error: "Permission denied" }), 401));
      }
      return Promise.resolve(jsonResponse({}));
    });

    const findings: any[] = [];
    await runFirebaseProbes(htmlWithFirebaseConfig({ withDatabaseUrl: true }), findings);

    expect(findings.find((f) => /Realtime Database Open/i.test(f.name))).toBeUndefined();
  });

  it("does not probe Realtime Database at all when no databaseURL is in the config", async () => {
    vi.mocked(fetch).mockImplementation(() => Promise.resolve(jsonResponse({})));

    const findings: any[] = [];
    await runFirebaseProbes(htmlWithFirebaseConfig({ withDatabaseUrl: false }), findings);

    const calledUrls = vi.mocked(fetch).mock.calls.map((c) => String(c[0]));
    expect(calledUrls.some((u) => u.includes("firebaseio.com"))).toBe(false);
  });
});

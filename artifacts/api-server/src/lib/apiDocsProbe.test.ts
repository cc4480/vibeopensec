import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runApiDocsProbe } from "./apiDocsProbe.js";

/**
 * apiDocsProbe.ts tests — exposed OpenAPI/Swagger/ReDoc detection. The most
 * important case here is SPA catch-all suppression: Vite/React/Next.js apps
 * return HTTP 200 + the same HTML shell for every path, and every candidate
 * doc path must be checked against that baseline before being trusted.
 */

const ORIGIN = "https://example.com";
const NOT_FOUND_MARKER = "vibescan-spacheck-";

function res(body: string, status = 200, contentType = "application/json"): Response {
  return new Response(body, { status, headers: { "content-type": contentType } });
}

/**
 * routes: map of exact pathname -> Response. Any unmapped path (including
 * the random catch-all-detection nonce) returns `unmapped`.
 */
function mockRoutes(routes: Record<string, Response>, unmapped: Response) {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = new URL(String(input));
    if (url.pathname.includes(NOT_FOUND_MARKER)) return Promise.resolve(unmapped);
    return Promise.resolve(routes[url.pathname] ?? unmapped);
  });
}

const REAL_404 = res("Not Found", 404, "text/plain");

const VALID_OPENAPI_JSON = JSON.stringify({
  openapi: "3.0.0",
  info: { title: "Test API", version: "1.0.0", description: "x".repeat(150) },
  paths: { "/users": { get: {} } },
});

const VALID_SWAGGER2_JSON = JSON.stringify({
  swagger: "2.0",
  info: { title: "Test API", version: "1.0.0", description: "x".repeat(150) },
  paths: { "/users": { get: {} } },
});

const SWAGGER_UI_PAGE = `<html><head><title>Swagger UI</title><script src="swagger-ui-bundle.js"></script></head><body>${"x".repeat(200)}</body></html>`;

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("runApiDocsProbe — positive detections", () => {
  it("flags a valid OpenAPI 3.0 JSON spec at /openapi.json", async () => {
    mockRoutes({ "/openapi.json": res(VALID_OPENAPI_JSON) }, REAL_404);
    const findings = await runApiDocsProbe(ORIGIN);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.name).toContain("OpenAPI JSON spec at /openapi.json");
  });

  it("flags a valid Swagger 2.0 JSON spec at /swagger.json, labeled distinctly", async () => {
    mockRoutes({ "/swagger.json": res(VALID_SWAGGER2_JSON) }, REAL_404);
    const findings = await runApiDocsProbe(ORIGIN);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.name).toContain("Swagger 2.0 JSON spec at /swagger.json");
  });

  it("flags a Swagger UI page containing the bundle script marker", async () => {
    mockRoutes({ "/swagger-ui.html": res(SWAGGER_UI_PAGE, 200, "text/html") }, REAL_404);
    const findings = await runApiDocsProbe(ORIGIN);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.name).toContain("Swagger UI");
  });

  it("flags a ReDoc page containing Redoc.init(", async () => {
    const body = `<html><body>${"x".repeat(200)}<script>Redoc.init({}, {}, document.getElementById('x'));</script></body></html>`;
    mockRoutes({ "/redoc": res(body, 200, "text/html") }, REAL_404);
    const findings = await runApiDocsProbe(ORIGIN);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.name).toContain("ReDoc");
  });
});

describe("runApiDocsProbe — false-positive prevention", () => {
  it("does not flag a JSON body missing the paths key", async () => {
    const incomplete = JSON.stringify({ openapi: "3.0.0", info: { title: "x", description: "x".repeat(150) } });
    mockRoutes({ "/openapi.json": res(incomplete) }, REAL_404);
    const findings = await runApiDocsProbe(ORIGIN);
    expect(findings).toHaveLength(0);
  });

  it("does not flag a page that merely mentions 'swagger' in prose", async () => {
    const body = `<html><body>${"x".repeat(200)}<p>We used to use swagger for docs but moved away from it.</p></body></html>`;
    mockRoutes({ "/swagger-ui.html": res(body, 200, "text/html") }, REAL_404);
    const findings = await runApiDocsProbe(ORIGIN);
    expect(findings).toHaveLength(0);
  });

  it("does not flag a body under the 200-byte minimum even with valid markers", async () => {
    const tinyBody = JSON.stringify({ openapi: "3.0.0", info: {}, paths: {} }); // well under 200 bytes
    mockRoutes({ "/openapi.json": res(tinyBody) }, REAL_404);
    const findings = await runApiDocsProbe(ORIGIN);
    expect(findings).toHaveLength(0);
  });

  it("never probes /docs or /docs/ (Docusaurus/GitBook false-positive exclusion)", async () => {
    mockRoutes({}, REAL_404);
    await runApiDocsProbe(ORIGIN);
    const calledPaths = vi.mocked(fetch).mock.calls.map((c) => new URL(String(c[0])).pathname);
    expect(calledPaths).not.toContain("/docs");
    expect(calledPaths).not.toContain("/docs/");
  });

  it("caps results at 5 even when more candidate paths validate", async () => {
    const routes: Record<string, Response> = {
      "/openapi.json": res(VALID_OPENAPI_JSON),
      "/openapi.yaml": res(`openapi: '3.0.0'\ninfo:\n  title: x\ninfo:\n  description: ${"x".repeat(150)}\npaths:\n  /users: {}\n`, 200, "text/plain"),
      "/swagger.json": res(VALID_SWAGGER2_JSON),
      "/v1/openapi.json": res(VALID_OPENAPI_JSON),
      "/api-docs/swagger.json": res(VALID_OPENAPI_JSON),
      "/swagger-ui.html": res(SWAGGER_UI_PAGE, 200, "text/html"),
    };
    mockRoutes(routes, REAL_404);
    const findings = await runApiDocsProbe(ORIGIN);
    expect(findings.length).toBeLessThanOrEqual(5);
  });
});

describe("runApiDocsProbe — SPA catch-all suppression", () => {
  it("suppresses a doc-path finding when the response matches the SPA catch-all shell", async () => {
    const spaShell = `<html><head><title>My Vite App</title></head><body>${"x".repeat(300)}</body></html>`;
    // Every unmapped/nonce path AND /swagger.json return the identical SPA shell.
    mockRoutes({ "/swagger.json": res(spaShell, 200, "text/html") }, res(spaShell, 200, "text/html"));

    const findings = await runApiDocsProbe(ORIGIN);
    expect(findings).toHaveLength(0);
  });

  it("still flags a real spec when the catch-all baseline is a distinct 404 (no SPA)", async () => {
    mockRoutes({ "/swagger.json": res(VALID_SWAGGER2_JSON) }, REAL_404);
    const findings = await runApiDocsProbe(ORIGIN);
    expect(findings).toHaveLength(1);
  });
});

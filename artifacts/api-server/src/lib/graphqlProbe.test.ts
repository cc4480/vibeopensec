import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runGraphqlProbe } from "./graphqlProbe.js";

/**
 * graphqlProbe.ts tests — verifies GraphQL introspection/field-suggestion
 * detection is both sensitive (real GraphQL endpoints get caught) and
 * specific (REST APIs, generic paths, and thin signals are not flagged).
 */

const ORIGIN = "https://example.com";

function jsonRes(body: unknown, status = 200, contentType = "application/json"): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": contentType } });
}

interface PostCall {
  url: string;
  query: string;
}

function mockPost(handler: (call: PostCall) => Response): PostCall[] {
  const calls: PostCall[] = [];
  vi.mocked(fetch).mockImplementation((input, init) => {
    const url = String(input);
    let query = "";
    try {
      query = JSON.parse(String(init?.body ?? "{}")).query ?? "";
    } catch {
      /* ignore */
    }
    const call = { url, query };
    calls.push(call);
    return Promise.resolve(handler(call));
  });
  return calls;
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("runGraphqlProbe — endpoint confirmation + introspection", () => {
  it("confirms via __typename and flags introspection with type count in the description", async () => {
    mockPost(({ query }) => {
      if (query.includes("__schema")) {
        const types = Array.from({ length: 15 }, (_, i) => ({ name: `T${i}`, kind: "OBJECT" }));
        return jsonRes({ data: { __schema: { queryType: { name: "Query" }, types } } });
      }
      if (query.includes("nonExistentField")) {
        return jsonRes({ data: null });
      }
      return jsonRes({ data: { __typename: "Query" } });
    });

    const findings = await runGraphqlProbe(ORIGIN, "");

    expect(findings).toHaveLength(1);
    expect(findings[0]!.name).toBe("GraphQL Introspection Enabled in Production");
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.description).toContain("15 types exposed");
  });

  it("does not flag introspection when fewer than 10 types are returned", async () => {
    mockPost(({ query }) => {
      if (query.includes("__schema")) {
        const types = Array.from({ length: 5 }, (_, i) => ({ name: `T${i}`, kind: "OBJECT" }));
        return jsonRes({ data: { __schema: { queryType: { name: "Query" }, types } } });
      }
      if (query.includes("nonExistentField")) {
        return jsonRes({ data: null });
      }
      return jsonRes({ data: { __typename: "Query" } });
    });

    const findings = await runGraphqlProbe(ORIGIN, "");
    expect(findings).toHaveLength(0);
  });
});

describe("runGraphqlProbe — field suggestion leak", () => {
  it("flags field suggestions when errors[] has locations + a did-you-mean message", async () => {
    mockPost(({ query }) => {
      if (query.includes("__schema")) return jsonRes({ data: null });
      if (query.includes("nonExistentField")) {
        return jsonRes({
          errors: [
            {
              message: 'Cannot query field "usr" on type "Query". Did you mean "user"?',
              locations: [{ line: 1, column: 3 }],
            },
          ],
        });
      }
      return jsonRes({ data: { __typename: "Query" } });
    });

    const findings = await runGraphqlProbe(ORIGIN, "");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.name).toContain("GraphQL Field Suggestions Enabled");
    expect(findings[0]!.severity).toBe("low");
  });

  it("does not flag field suggestions when errors[] lacks a locations array", async () => {
    mockPost(({ query }) => {
      if (query.includes("__schema")) return jsonRes({ data: null });
      if (query.includes("nonExistentField")) {
        return jsonRes({
          errors: [{ message: 'Cannot query field "usr" on type "Query". Did you mean "user"?' }],
        });
      }
      return jsonRes({ data: { __typename: "Query" } });
    });

    const findings = await runGraphqlProbe(ORIGIN, "");
    expect(findings).toHaveLength(0);
  });
});

describe("runGraphqlProbe — false-positive prevention", () => {
  it("does not confirm a REST API returning data without __typename", async () => {
    mockPost(() => jsonRes({ data: { id: 123, name: "not graphql" } }));

    const findings = await runGraphqlProbe(ORIGIN, "");
    expect(findings).toHaveLength(0);
  });

  it("does not confirm a non-JSON content-type response even with a matching body shape", async () => {
    mockPost(() => jsonRes({ data: { __typename: "Query" } }, 200, "text/html"));

    const findings = await runGraphqlProbe(ORIGIN, "");
    expect(findings).toHaveLength(0);
  });

  it("never probes generic /api or /query paths", async () => {
    const calls = mockPost(() => jsonRes({ data: { id: 1 } }));

    await runGraphqlProbe(ORIGIN, `<script>fetch("/api/data"); fetch("/query?x=1");</script>`);

    const probedUrls = calls.map((c) => c.url);
    expect(probedUrls).not.toContain(`${ORIGIN}/api`);
    expect(probedUrls).not.toContain(`${ORIGIN}/query`);
  });
});

describe("runGraphqlProbe — JS-extracted endpoint discovery", () => {
  it("probes a GraphQL endpoint URL extracted from inline JS", async () => {
    const calls = mockPost(() => jsonRes({ data: { id: 1 } })); // never confirms — just verifying discovery

    const html = `<script>const GRAPHQL_ENDPOINT = "https://example.com/custom-graphql";</script>`;
    await runGraphqlProbe(ORIGIN, html);

    const probedUrls = calls.map((c) => c.url);
    expect(probedUrls).toContain("https://example.com/custom-graphql");
  });

  it("does not extract a URL from an external script (src= present, no inline body to scan)", async () => {
    const calls = mockPost(() => jsonRes({ data: { id: 1 } }));

    const html = `<script src="https://cdn.example.com/bundle.js"></script>`;
    await runGraphqlProbe(ORIGIN, html);

    // Only the 5 standard GRAPHQL_SPECIFIC_PATHS should have been probed — no extra JS-derived URL.
    expect(calls.length).toBe(5);
  });
});

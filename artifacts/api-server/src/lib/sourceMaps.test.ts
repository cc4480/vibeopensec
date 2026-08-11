import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkSourceMaps } from "./sourceMaps.js";

const BASE = "https://example.com";

function validMap(sourcesContent = false) {
  return JSON.stringify({
    version: 3,
    sources: ["app.ts"],
    ...(sourcesContent ? { sourcesContent: ["// original source"] } : {}),
    mappings: "",
  });
}

function res(body: string, status = 200) {
  return new Response(body, { status });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("checkSourceMaps — direct .map exposure", () => {
  it("flags a same-origin script whose <url>.map is directly accessible", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url === `${BASE}/app.js.map`) return Promise.resolve(res(validMap(true)));
      return Promise.resolve(res("not found", 404));
    });

    const html = `<script src="/app.js"></script>`;
    const result = await checkSourceMaps(html, BASE);
    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("JavaScript Source Map Exposed — Full Source Code Accessible");
    expect(result[0]!.severity).toBe("high");
    expect(result[0]!.evidence).toContain("sourcesContent");
  });

  it("does not flag when the .map response is not a valid source map", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url === `${BASE}/app.js.map`) return Promise.resolve(res("<html>404</html>"));
      if (url === `${BASE}/app.js`) return Promise.resolve(res("console.log('no mapping comment')"));
      return Promise.resolve(res("not found", 404));
    });

    const html = `<script src="/app.js"></script>`;
    const result = await checkSourceMaps(html, BASE);
    expect(result).toEqual([]);
  });
});

describe("checkSourceMaps — linked via sourceMappingURL comment", () => {
  it("follows the trailer comment to a same-origin map when the direct .map 404s", async () => {
    vi.mocked(fetch).mockImplementation((input, init) => {
      const url = String(input);
      if (url === `${BASE}/bundle.js.map`) return Promise.resolve(res("not found", 404));
      if (url === `${BASE}/bundle.js` && (init?.headers as Record<string, string>)?.["Range"]) {
        return Promise.resolve(res("console.log(1);\n//# sourceMappingURL=bundle.real.map"));
      }
      if (url === `${BASE}/bundle.real.map`) return Promise.resolve(res(validMap()));
      return Promise.resolve(res("not found", 404));
    });

    const html = `<script src="/bundle.js"></script>`;
    const result = await checkSourceMaps(html, BASE);
    expect(result).toHaveLength(1);
    expect(result[0]!.evidence).toContain("bundle.real.map");
  });

  it("does not fetch or flag a data: URI sourceMappingURL (inline map)", async () => {
    let fetchedDataUri = false;
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.startsWith("data:")) fetchedDataUri = true;
      if (url === `${BASE}/inline.js.map`) return Promise.resolve(res("not found", 404));
      if (url === `${BASE}/inline.js`) {
        return Promise.resolve(res("console.log(1);\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ=="));
      }
      return Promise.resolve(res("not found", 404));
    });

    const html = `<script src="/inline.js"></script>`;
    const result = await checkSourceMaps(html, BASE);
    expect(result).toEqual([]);
    expect(fetchedDataUri).toBe(false);
  });

  it("does not flag a sourceMappingURL that resolves cross-origin", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url === `${BASE}/cross.js.map`) return Promise.resolve(res("not found", 404));
      if (url === `${BASE}/cross.js`) {
        return Promise.resolve(res("console.log(1);\n//# sourceMappingURL=https://evil-cdn.example/leaked.map"));
      }
      // If the function incorrectly fetched the cross-origin map, fail loudly.
      if (url === "https://evil-cdn.example/leaked.map") return Promise.resolve(res(validMap()));
      return Promise.resolve(res("not found", 404));
    });

    const html = `<script src="/cross.js"></script>`;
    const result = await checkSourceMaps(html, BASE);
    expect(result).toEqual([]);
  });
});

describe("checkSourceMaps — script origin filtering", () => {
  it("never probes scripts loaded from a different origin (e.g. a CDN)", async () => {
    let cdnFetched = false;
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes("cdn.example.com")) cdnFetched = true;
      return Promise.resolve(res("not found", 404));
    });

    const html = `<script src="https://cdn.example.com/lib.js"></script>`;
    const result = await checkSourceMaps(html, BASE);
    expect(result).toEqual([]);
    expect(cdnFetched).toBe(false);
  });

  it("returns no findings and makes no requests when there are no external scripts", async () => {
    const result = await checkSourceMaps("<html><body>no scripts</body></html>", BASE);
    expect(result).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("checkSourceMaps — dedup across multiple exposed files", () => {
  it("reports the finding once even when two different JS files both expose maps", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url === `${BASE}/a.js.map` || url === `${BASE}/b.js.map`) return Promise.resolve(res(validMap()));
      return Promise.resolve(res("not found", 404));
    });

    const html = `<script src="/a.js"></script><script src="/b.js"></script>`;
    const result = await checkSourceMaps(html, BASE);
    expect(result).toHaveLength(1);
  });
});

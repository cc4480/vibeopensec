import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkPathTraversal } from "./pathTraversal.js";

/**
 * Path traversal / LFI tests. All HTTP calls are stubbed via
 * vi.stubGlobal("fetch", vi.fn()) — each test's mock implementation
 * decides, per URL, whether to return vulnerable content, so we can
 * confirm the function actually tried the specific candidate under test
 * rather than accidentally succeeding on a different one (the function
 * returns on the *first* confirmed hit across all candidates).
 */

const LINUX_PASSWD =
  "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n";
const WINDOWS_INI = "[fonts]\nsome=entry\n[extensions]\n";
const SAFE_BODY = "<html><body>nothing interesting here</body></html>";

function jsonResponse(body: string, status = 200) {
  return new Response(body, { status });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("checkPathTraversal — confirmed vulnerability", () => {
  it("flags a Linux traversal hit and classifies the OS", async () => {
    // Matches on path+param only, not the exact payload encoding — the real
    // function tries every payload template against the first vulnerable
    // candidate it finds, so a vulnerable endpoint responds the same way
    // regardless of which of the 10 encodings triggered it.
    vi.mocked(fetch).mockImplementation((input) => {
      const parsed = new URL(String(input));
      if (parsed.pathname === "/download" && parsed.searchParams.has("file")) {
        return Promise.resolve(jsonResponse(LINUX_PASSWD));
      }
      return Promise.resolve(jsonResponse(SAFE_BODY));
    });

    const result = await checkPathTraversal("http://example.com/", "<html></html>");
    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("Path Traversal / Local File Inclusion (LFI)");
    expect(result[0]!.severity).toBe("critical");
    expect(result[0]!.evidence).toContain("Linux/Unix");
  });

  it("flags a Windows traversal hit and classifies the OS", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const parsed = new URL(String(input));
      if (parsed.pathname === "/download" && parsed.searchParams.has("file")) {
        return Promise.resolve(jsonResponse(WINDOWS_INI));
      }
      return Promise.resolve(jsonResponse(SAFE_BODY));
    });

    const result = await checkPathTraversal("http://example.com/", "<html></html>");
    expect(result).toHaveLength(1);
    expect(result[0]!.evidence).toContain("Windows");
  });
});

describe("checkPathTraversal — candidate collection", () => {
  it("tests file-related params already present on the target URL", async () => {
    let hitOwnParam = false;
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      const parsed = new URL(url);
      // The target's own path is /page.php with a `doc` param — confirm the
      // function probes that exact path+param combo (not just generic ones).
      if (parsed.pathname === "/page.php" && parsed.searchParams.has("doc")) {
        hitOwnParam = true;
        return Promise.resolve(jsonResponse(LINUX_PASSWD));
      }
      return Promise.resolve(jsonResponse(SAFE_BODY));
    });

    const result = await checkPathTraversal("http://example.com/page.php?doc=readme.txt", "<html></html>");
    expect(hitOwnParam).toBe(true);
    expect(result).toHaveLength(1);
  });

  it("tests file-related params found in in-page links", async () => {
    let hitLinkParam = false;
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      const parsed = new URL(url);
      if (parsed.pathname === "/view-file" && parsed.searchParams.has("path")) {
        hitLinkParam = true;
        return Promise.resolve(jsonResponse(LINUX_PASSWD));
      }
      return Promise.resolve(jsonResponse(SAFE_BODY));
    });

    const html = `<a href="/view-file?path=notes.txt">Notes</a>`;
    const result = await checkPathTraversal("http://example.com/", html);
    expect(hitLinkParam).toBe(true);
    expect(result).toHaveLength(1);
  });

  it("falls back to generic probe endpoint/param combinations when nothing else is found", async () => {
    let hitGenericProbe = false;
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      const parsed = new URL(url);
      if (parsed.pathname === "/read" && parsed.searchParams.has("name")) {
        hitGenericProbe = true;
        return Promise.resolve(jsonResponse(LINUX_PASSWD));
      }
      return Promise.resolve(jsonResponse(SAFE_BODY));
    });

    const result = await checkPathTraversal("http://example.com/", "<html></html>");
    expect(hitGenericProbe).toBe(true);
    expect(result).toHaveLength(1);
  });
});

describe("checkPathTraversal — no false positives", () => {
  it("returns no findings when every probe returns safe content", async () => {
    vi.mocked(fetch).mockImplementation(() => Promise.resolve(jsonResponse(SAFE_BODY)));
    const result = await checkPathTraversal("http://example.com/?file=readme.txt", "<html></html>");
    expect(result).toEqual([]);
  });

  it("continues past network errors on individual candidates instead of crashing", async () => {
    let callCount = 0;
    vi.mocked(fetch).mockImplementation(() => {
      callCount += 1;
      if (callCount <= 3) return Promise.reject(new Error("network error"));
      return Promise.resolve(jsonResponse(SAFE_BODY));
    });

    await expect(checkPathTraversal("http://example.com/?file=readme.txt", "<html></html>")).resolves.toEqual([]);
    expect(callCount).toBeGreaterThan(3);
  });
});

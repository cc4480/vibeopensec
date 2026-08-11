import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkSslLabs } from "./ssllabs.js";

/**
 * SSL Labs API integration tests. Mocks the async analyze/poll cycle
 * (startNew=on -> poll status until READY/ERROR or timeout). Fake timers
 * drive the poll loop deterministically instead of waiting on real 10s ticks.
 */

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), { status: 200, headers: { "content-type": "application/json" } });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
  vi.useFakeTimers();
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("checkSslLabs — happy path", () => {
  it("returns the grade immediately when the first poll is already READY", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ status: "READY", endpoints: [{ grade: "A", hasWarnings: false, isExceptional: true }] }),
    );

    const result = await checkSslLabs("https://example.com");

    expect(result).toEqual({ grade: "A", hasWarnings: false, isExceptional: true, issues: [] });
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
    expect(String(vi.mocked(fetch).mock.calls[0]![0])).toContain("startNew=on");
  });

  it("polls through IN_PROGRESS before returning the final READY grade", async () => {
    let call = 0;
    vi.mocked(fetch).mockImplementation(async () => {
      call += 1;
      if (call === 1) return jsonResponse({ status: "IN_PROGRESS" });
      return jsonResponse({ status: "READY", endpoints: [{ grade: "B", hasWarnings: true }] });
    });

    const resultPromise = checkSslLabs("https://example.com");
    await vi.advanceTimersByTimeAsync(10_000);
    const result = await resultPromise;

    expect(result?.grade).toBe("B");
    expect(result?.hasWarnings).toBe(true);
    expect(result?.issues).toContain("SSL Labs flagged configuration warnings");
    expect(call).toBe(2);
    // Second poll must not restart the assessment.
    expect(String(vi.mocked(fetch).mock.calls[1]![0])).not.toContain("startNew=on");
  });

  it("adds a weak-configuration issue for a C-F grade", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ status: "READY", endpoints: [{ grade: "F" }] }));

    const result = await checkSslLabs("https://example.com");

    expect(result?.grade).toBe("F");
    expect(result?.issues).toContain("Weak SSL configuration — grade F");
  });
});

describe("checkSslLabs — graceful failure", () => {
  it("returns null on an ERROR status without throwing", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ status: "ERROR", errors: [{ message: "Unable to resolve domain name" }] }),
    );

    const result = await checkSslLabs("https://example.com");

    expect(result).toBeNull();
  });

  it("returns null and does not throw on a network error", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("network unreachable"));

    const result = await checkSslLabs("https://example.com");

    expect(result).toBeNull();
  });

  it("returns null when the API responds with a non-2xx status", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("Service Unavailable", { status: 503 }));

    const result = await checkSslLabs("https://example.com");

    expect(result).toBeNull();
  });

  it("returns null after exhausting the poll budget on perpetual IN_PROGRESS", async () => {
    vi.mocked(fetch).mockImplementation(async () => jsonResponse({ status: "IN_PROGRESS" }));

    const resultPromise = checkSslLabs("https://example.com");
    await vi.advanceTimersByTimeAsync(60_000);
    const result = await resultPromise;

    expect(result).toBeNull();
    // MAX_WAIT_MS=30s / POLL_INTERVAL_MS=10s => 1 initial + 3 polls = 4 calls.
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(4);
  });
});

describe("checkSslLabs — non-HTTPS / invalid input", () => {
  it("returns null for a plain HTTP target without making any request", async () => {
    const result = await checkSslLabs("http://example.com");

    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("returns null for an unparseable URL", async () => {
    const result = await checkSslLabs("not a url");

    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
});

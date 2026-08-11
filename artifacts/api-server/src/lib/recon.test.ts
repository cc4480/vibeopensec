import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * recon.test.ts — DNS enumeration (Cloudflare DoH, mocked via fetch),
 * subdomain resolution and port scanning (node:dns/promises + node:net,
 * mocked directly since they don't go through fetch).
 */

const portBehavior = vi.hoisted(() => ({
  map: new Map<number, "open" | "closed">(),
}));

vi.mock("node:net", () => {
  // require() instead of a top-level import — vi.mock factories are hoisted
  // above regular ES imports, so referencing a normally-imported binding here
  // throws "Cannot access ... before initialization".
  const { EventEmitter } = require("node:events");
  class FakeSocket extends EventEmitter {
    setTimeout(_ms: number) { /* no-op */ }
    connect(port: number, _host: string) {
      const behavior = portBehavior.map.get(port) ?? "closed";
      queueMicrotask(() => {
        if (behavior === "open") {
          this.emit("connect");
          // No banner data — simulate the timeout->finish(true) "open, no banner" path
          setTimeout(() => this.emit("timeout"), 0);
        } else {
          this.emit("error", new Error("ECONNREFUSED"));
        }
      });
      return this;
    }
    destroy() { /* no-op */ }
  }
  return { Socket: FakeSocket };
});

const dnsMock = vi.hoisted(() => ({
  lookup: vi.fn(),
  resolveCname: vi.fn(),
}));
vi.mock("node:dns/promises", () => dnsMock);

vi.mock("./logger", () => ({
  logger: { child: () => ({ info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() }) },
}));

import { runRecon } from "./recon.js";

function dohJson(answer: Array<{ data: string; TTL?: number }>): Response {
  return new Response(JSON.stringify({ Answer: answer.map((a) => ({ ...a, TTL: a.TTL ?? 300 })) }), {
    status: 200,
    headers: { "content-type": "application/dns-json" },
  });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
  portBehavior.map.clear();
  dnsMock.lookup.mockReset();
  dnsMock.resolveCname.mockReset();
  // Default: public IP, no subdomains resolve, no crt.sh results, no fetch DNS records
  dnsMock.lookup.mockResolvedValue({ address: "93.184.216.34" });
  dnsMock.resolveCname.mockRejectedValue(new Error("no cname"));
  vi.mocked(fetch).mockImplementation((input) => {
    const url = String(input);
    if (url.includes("crt.sh")) return Promise.resolve(new Response("[]", { status: 200 }));
    if (url.includes("dns-query")) return Promise.resolve(dohJson([]));
    return Promise.resolve(new Response("", { status: 404 }));
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("runRecon — SSRF guard", () => {
  it("skips the port scan when the target resolves to a private IP", async () => {
    dnsMock.lookup.mockResolvedValue({ address: "10.0.0.5" });
    portBehavior.map.set(22, "open"); // would be "open" if scanned
    const result = await runRecon("https://internal.example.com");
    expect(result.recon.openPorts).toEqual([]);
  });

  it("skips the port scan when the hostname doesn't resolve", async () => {
    dnsMock.lookup.mockRejectedValue(new Error("ENOTFOUND"));
    const result = await runRecon("https://doesnotexist.example.com");
    expect(result.recon.openPorts).toEqual([]);
  });

  it("scans ports normally for a public IP", async () => {
    dnsMock.lookup.mockResolvedValue({ address: "93.184.216.34" });
    const result = await runRecon("https://example.com");
    // No ports configured as open in portBehavior — expect none found, but no crash
    expect(result.recon.openPorts).toEqual([]);
  });
});

describe("runRecon — DNS enumeration", () => {
  it("collects A/MX/TXT/NS records from the DoH responses", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes("crt.sh")) return Promise.resolve(new Response("[]", { status: 200 }));
      if (url.includes("type=A") && !url.includes("_dmarc")) return Promise.resolve(dohJson([{ data: "93.184.216.34" }]));
      if (url.includes("type=MX")) return Promise.resolve(dohJson([{ data: "10 mail.example.com." }]));
      if (url.includes("type=NS")) return Promise.resolve(dohJson([{ data: "ns1.example.com." }]));
      if (url.includes("dns-query")) return Promise.resolve(dohJson([]));
      return Promise.resolve(new Response("", { status: 404 }));
    });
    const result = await runRecon("https://example.com");
    expect(result.recon.dnsRecords).toContainEqual(expect.objectContaining({ type: "A", value: "93.184.216.34" }));
    expect(result.recon.dnsRecords.some((r) => r.type === "MX")).toBe(true);
    expect(result.recon.dnsRecords.some((r) => r.type === "NS")).toBe(true);
  });

  it("prefixes _dmarc TXT record values with the queried name", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes("crt.sh")) return Promise.resolve(new Response("[]", { status: 200 }));
      if (url.includes("_dmarc") && url.includes("type=TXT")) {
        return Promise.resolve(dohJson([{ data: "v=DMARC1; p=reject" }]));
      }
      if (url.includes("dns-query")) return Promise.resolve(dohJson([]));
      return Promise.resolve(new Response("", { status: 404 }));
    });
    const result = await runRecon("https://example.com");
    expect(result.recon.dnsRecords.some((r) => r.type === "TXT" && r.value.startsWith("[_dmarc.example.com]"))).toBe(true);
  });

  it("does not crash and returns partial results when DNS enumeration fails entirely", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes("crt.sh")) return Promise.resolve(new Response("[]", { status: 200 }));
      return Promise.reject(new Error("network down"));
    });
    const result = await runRecon("https://example.com");
    expect(result.recon.dnsRecords).toEqual([]);
  });
});

describe("runRecon — subdomain enumeration", () => {
  it("adds a wordlist subdomain that resolves to an IP", async () => {
    dnsMock.lookup.mockImplementation((host: string) => {
      if (host === "www.example.com") return Promise.resolve([{ address: "93.184.216.35" }]);
      if (host === "example.com") return Promise.resolve({ address: "93.184.216.34" });
      return Promise.reject(new Error("ENOTFOUND"));
    });
    const result = await runRecon("https://example.com");
    expect(result.recon.subdomains).toContainEqual(
      expect.objectContaining({ subdomain: "www.example.com", ip: "93.184.216.35", source: "wordlist" }),
    );
  });

  it("does not add a wordlist subdomain that fails to resolve", async () => {
    const result = await runRecon("https://example.com");
    expect(result.recon.subdomains.find((s) => s.subdomain === "vpn.example.com")).toBeUndefined();
  });

  it("adds a crt.sh-discovered subdomain that resolves", async () => {
    dnsMock.lookup.mockImplementation((host: string) => {
      if (host === "unusual-name.example.com") return Promise.resolve([{ address: "93.184.216.40" }]);
      if (host === "example.com") return Promise.resolve({ address: "93.184.216.34" });
      return Promise.reject(new Error("ENOTFOUND"));
    });
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes("crt.sh")) {
        return Promise.resolve(new Response(JSON.stringify([{ name_value: "unusual-name.example.com" }]), { status: 200 }));
      }
      if (url.includes("dns-query")) return Promise.resolve(dohJson([]));
      return Promise.resolve(new Response("", { status: 404 }));
    });
    const result = await runRecon("https://example.com");
    expect(result.recon.subdomains).toContainEqual(
      expect.objectContaining({ subdomain: "unusual-name.example.com", source: "crt.sh" }),
    );
  });
});

describe("runRecon — port scanning and dangerous-port findings", () => {
  it("collects an open, non-dangerous port with no vulnerability finding", async () => {
    portBehavior.map.set(80, "open");
    const result = await runRecon("https://example.com");
    expect(result.recon.openPorts).toContainEqual(expect.objectContaining({ port: 80, service: "HTTP" }));
    expect(result.vulns).toEqual([]);
  });

  it("produces a critical finding for an exposed dangerous port (Telnet, 23)", async () => {
    portBehavior.map.set(23, "open");
    const result = await runRecon("https://example.com");
    expect(result.recon.openPorts).toContainEqual(expect.objectContaining({ port: 23, service: "Telnet" }));
    const finding = result.vulns.find((v) => v.name.includes("Telnet"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("critical");
  });

  it("produces a critical finding for exposed SMB (445)", async () => {
    portBehavior.map.set(445, "open");
    const result = await runRecon("https://example.com");
    const finding = result.vulns.find((v) => v.name.includes("SMB"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("critical");
  });

  it("does not report a vulnerability for a port that never opens", async () => {
    const result = await runRecon("https://example.com");
    expect(result.vulns).toEqual([]);
  });
});

describe("runRecon — invalid target", () => {
  it("throws for an unparseable target URL", async () => {
    await expect(runRecon("not a url")).rejects.toThrow();
  });
});

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import express, { type Express } from "express";
import request from "supertest";

/**
 * routes/mcp.ts tests — verifies the auth gate and that the three tools are
 * registered and callable through the Streamable HTTP transport. Deep
 * coverage of scan_url's polling/gate logic lives in ciScan.test.ts and
 * check_baas_security's probe-merging logic lives in baasQuickCheck.test.ts
 * — this file only covers the route/transport/auth wiring.
 *
 * A minimal Express app (authMiddleware + the mcp router only) is used
 * instead of the full app.ts to avoid pulling in every other router's
 * import graph (stripe, mailer, monitor scheduler, etc.).
 */

const CI_TOKEN = "vibescan_ci_" + "a".repeat(40);
const selectQueue: unknown[][] = [];
function pushSelect(row: unknown) {
  selectQueue.push(row === undefined ? [] : [row]);
}

vi.mock("@workspace/db", () => ({
  db: {
    select: vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(async () => selectQueue.shift() ?? []),
      })),
    })),
    update: vi.fn(() => ({
      set: vi.fn(() => ({
        where: vi.fn(async () => undefined),
      })),
    })),
  },
  ciApiKeysTable: {},
  usersTable: {},
  reportsTable: {},
  scansTable: {},
}));

// Pulled in transitively via ciScan.ts; throws at import time if
// DATABASE_URL isn't set, and isn't exercised by any test in this file.
vi.mock("../lib/queue", () => ({
  enqueueScan: vi.fn(async () => "job-1"),
}));

import { authMiddleware } from "../middlewares/authMiddleware";
import mcpRouter from "./mcp";

const app: Express = express();
app.use(express.json());
app.use(authMiddleware);
app.use("/api", mcpRouter);

beforeEach(() => {
  selectQueue.length = 0;
});

afterEach(() => {
  vi.clearAllMocks();
});

function mcpRequest(body: Record<string, unknown>) {
  return request(app)
    .post("/api/mcp")
    .set("Content-Type", "application/json")
    .set("Accept", "application/json, text/event-stream")
    .send(body);
}

/**
 * The Streamable HTTP transport responds with a `text/event-stream` body
 * (one or more `data: <json>` lines) rather than a plain JSON body, so
 * supertest's auto-parsed `res.body` is empty — pull the JSON-RPC payload
 * out of the SSE frame instead.
 */
function parseSseJsonRpc(res: request.Response): { result?: Record<string, unknown> } {
  const dataLine = res.text.split("\n").find((line) => line.startsWith("data: "));
  if (!dataLine) throw new Error(`No SSE data line found in response: ${res.text}`);
  return JSON.parse(dataLine.slice("data: ".length));
}

describe("POST /api/mcp", () => {
  it("rejects requests with no bearer token", async () => {
    const res = await mcpRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect(res.status).toBe(401);
  });

  it("lists all three tools once authenticated with a CI key", async () => {
    pushSelect({ id: "key-1", userId: "user-1" }); // resolveCiApiKey
    pushSelect({ id: "user-1", email: "dev@example.com", firstName: null, lastName: null, profileImageUrl: null }); // user lookup

    const res = await mcpRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" })
      .set("Authorization", `Bearer ${CI_TOKEN}`);

    expect(res.status).toBe(200);
    const payload = parseSseJsonRpc(res);
    const tools = (payload.result?.tools ?? []) as { name: string }[];
    expect(tools.map((t) => t.name).sort()).toEqual(["check_baas_security", "get_report", "scan_url"]);
  });

  it("returns a not-found message from get_report for an unknown report id", async () => {
    pushSelect({ id: "key-1", userId: "user-1" }); // resolveCiApiKey
    pushSelect({ id: "user-1", email: "dev@example.com", firstName: null, lastName: null, profileImageUrl: null }); // user lookup
    pushSelect(undefined); // reportsTable lookup — not found

    const res = await mcpRequest({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "get_report", arguments: { reportId: "does-not-exist" } },
    }).set("Authorization", `Bearer ${CI_TOKEN}`);

    expect(res.status).toBe(200);
    const payload = parseSseJsonRpc(res);
    const result = payload.result as { isError?: boolean; content?: { text?: string }[] };
    expect(result.isError).toBe(true);
    expect(result.content?.[0]?.text).toContain("No report found");
  });
});

import { Router, type IRouter } from "express";
import { db, ciApiKeysTable } from "@workspace/db";
import { eq, and, isNull, desc } from "drizzle-orm";
import { z } from "zod";
import { generateCiApiKey } from "../lib/ciApiKeys";

const router: IRouter = Router();

const CreateCiKeyBody = z.object({
  name: z.string().trim().min(1).max(60).optional(),
});

// ── POST /api/ci-keys — create a new CI key (token shown once) ────────────────
router.post("/ci-keys", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = CreateCiKeyBody.safeParse(req.body ?? {});
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Invalid request" });
    return;
  }

  const { token, tokenHash, tokenPrefix } = generateCiApiKey();

  const [key] = await db
    .insert(ciApiKeysTable)
    .values({
      userId: req.user.id,
      name: parsed.data.name || "CI key",
      tokenHash,
      tokenPrefix,
    })
    .returning();

  // The full token is only ever returned here — it cannot be retrieved again.
  res.status(201).json({
    id: key.id,
    name: key.name,
    token,
    tokenPrefix: key.tokenPrefix,
    createdAt: key.createdAt.toISOString(),
  });
});

// ── GET /api/ci-keys — list this user's keys (never returns the token) ────────
router.get("/ci-keys", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const keys = await db
    .select({
      id: ciApiKeysTable.id,
      name: ciApiKeysTable.name,
      tokenPrefix: ciApiKeysTable.tokenPrefix,
      lastUsedAt: ciApiKeysTable.lastUsedAt,
      createdAt: ciApiKeysTable.createdAt,
    })
    .from(ciApiKeysTable)
    .where(and(eq(ciApiKeysTable.userId, req.user.id), isNull(ciApiKeysTable.revokedAt)))
    .orderBy(desc(ciApiKeysTable.createdAt));

  res.json(
    keys.map((k) => ({
      id: k.id,
      name: k.name,
      tokenPrefix: k.tokenPrefix,
      lastUsedAt: k.lastUsedAt?.toISOString() ?? null,
      createdAt: k.createdAt.toISOString(),
    })),
  );
});

// ── DELETE /api/ci-keys/:id — revoke a key ─────────────────────────────────────
router.delete("/ci-keys/:id", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

  const result = await db
    .update(ciApiKeysTable)
    .set({ revokedAt: new Date() })
    .where(and(eq(ciApiKeysTable.id, id), eq(ciApiKeysTable.userId, req.user.id), isNull(ciApiKeysTable.revokedAt)))
    .returning({ id: ciApiKeysTable.id });

  if (result.length === 0) {
    res.status(404).json({ error: "Key not found" });
    return;
  }

  res.status(204).send();
});

export default router;

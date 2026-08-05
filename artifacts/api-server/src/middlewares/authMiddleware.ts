import { type Request, type Response, type NextFunction } from "express";
import type { AuthUser } from "@workspace/api-zod";
import { db, usersTable, ciApiKeysTable } from "@workspace/db";
import { eq, and, isNull } from "drizzle-orm";
import { getSession } from "../lib/auth";
import { looksLikeCiApiKey, hashCiApiKey } from "../lib/ciApiKeys";

/** Looks up the owning userId for a valid, non-revoked CI key. Updates lastUsedAt as a side effect. */
async function resolveCiApiKey(token: string): Promise<string | null> {
  const tokenHash = hashCiApiKey(token);

  const [key] = await db
    .select({ id: ciApiKeysTable.id, userId: ciApiKeysTable.userId })
    .from(ciApiKeysTable)
    .where(and(eq(ciApiKeysTable.tokenHash, tokenHash), isNull(ciApiKeysTable.revokedAt)));

  if (!key) return null;

  // Fire-and-forget — a missed lastUsedAt update should never block the request
  db.update(ciApiKeysTable)
    .set({ lastUsedAt: new Date() })
    .where(eq(ciApiKeysTable.id, key.id))
    .catch(() => {});

  return key.userId;
}

declare global {
  namespace Express {
    interface User extends AuthUser {}

    interface Request {
      isAuthenticated(): this is AuthedRequest;
      user?: User | undefined;
    }

    export interface AuthedRequest {
      user: User;
    }
  }
}

// Only accept UUID v4 tokens (used as anonymous user IDs)
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function authMiddleware(
  req: Request,
  _res: Response,
  next: NextFunction,
) {
  req.isAuthenticated = function (this: Request) {
    return this.user != null;
  } as Request["isAuthenticated"];

  // ── 1. Cookie-based OIDC session (highest priority) ──────────────────────
  const sid = req.cookies?.["sid"] as string | undefined;
  if (sid) {
    try {
      const session = await getSession(sid);
      if (session?.user) {
        req.user = session.user;
        next();
        return;
      }
    } catch {
      // non-fatal — fall through to Bearer token check
    }
  }

  // ── 2. Bearer UUID token (anonymous / localStorage-based auth) ───────────
  const authHeader = req.headers["authorization"];
  if (!authHeader?.startsWith("Bearer ")) {
    next();
    return;
  }

  const token = authHeader.slice(7).trim();

  // ── 2a. CI/CD API key (long-lived, tied to an existing user) ─────────────
  if (looksLikeCiApiKey(token)) {
    try {
      const userId = await resolveCiApiKey(token);
      if (userId) {
        const [dbUser] = await db.select().from(usersTable).where(eq(usersTable.id, userId));
        if (dbUser) {
          req.user = {
            id: dbUser.id,
            email: dbUser.email,
            firstName: dbUser.firstName,
            lastName: dbUser.lastName,
            profileImageUrl: dbUser.profileImageUrl,
          };
        }
      }
    } catch {
      // non-fatal — proceed unauthenticated
    }
    next();
    return;
  }

  if (!UUID_V4.test(token)) {
    next();
    return;
  }

  try {
    // Auto-create user on first request — the UUID IS the user ID
    await db
      .insert(usersTable)
      .values({
        id: token,
        email: null,
        firstName: null,
        lastName: null,
        profileImageUrl: null,
      })
      .onConflictDoNothing();

    const [dbUser] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, token));

    if (dbUser) {
      req.user = {
        id: dbUser.id,
        email: dbUser.email,
        firstName: dbUser.firstName,
        lastName: dbUser.lastName,
        profileImageUrl: dbUser.profileImageUrl,
      };
    }
  } catch {
    // non-fatal — proceed unauthenticated
  }

  next();
}

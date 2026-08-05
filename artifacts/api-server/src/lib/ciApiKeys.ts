/**
 * CI/CD API key generation, hashing, and lookup.
 *
 * Tokens are high-entropy random strings — the hash mainly protects against
 * exposure from a database read, not brute force. Format: vibescan_ci_<40 hex>.
 */

import { randomBytes, createHash } from "node:crypto";

const TOKEN_PREFIX = "vibescan_ci_";

export function generateCiApiKey(): { token: string; tokenHash: string; tokenPrefix: string } {
  const token = `${TOKEN_PREFIX}${randomBytes(20).toString("hex")}`;
  return {
    token,
    tokenHash: hashCiApiKey(token),
    // Shown in the UI so a user can tell keys apart without re-revealing the secret
    tokenPrefix: token.slice(0, TOKEN_PREFIX.length + 6),
  };
}

export function hashCiApiKey(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function looksLikeCiApiKey(token: string): boolean {
  return token.startsWith(TOKEN_PREFIX) && token.length > TOKEN_PREFIX.length + 20;
}

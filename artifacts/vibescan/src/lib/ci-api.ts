import { customFetch } from "@workspace/api-client-react";

export interface CiApiKey {
  id: string;
  name: string;
  tokenPrefix: string;
  lastUsedAt: string | null;
  createdAt: string;
}

export interface CreatedCiApiKey extends Omit<CiApiKey, "lastUsedAt"> {
  /** Only ever returned once, at creation time — cannot be retrieved again. */
  token: string;
}

export async function listCiApiKeys(): Promise<CiApiKey[]> {
  return customFetch<CiApiKey[]>("/api/ci-keys");
}

export async function createCiApiKey(name?: string): Promise<CreatedCiApiKey> {
  return customFetch<CreatedCiApiKey>("/api/ci-keys", {
    method: "POST",
    body: JSON.stringify({ name }),
    headers: { "Content-Type": "application/json" },
  });
}

export async function revokeCiApiKey(id: string): Promise<void> {
  await customFetch(`/api/ci-keys/${id}`, { method: "DELETE" });
}

export interface CiScanResult {
  scanId: string;
  status: string;
  reportUrl: string | null;
  passed: boolean | null;
  grade?: string | null;
  riskScore?: number | null;
  totalVulnerabilities?: number;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  topFindings?: { name: string; severity: string }[];
  message?: string;
}

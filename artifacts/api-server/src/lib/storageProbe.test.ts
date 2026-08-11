import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runStorageProbe } from "./storageProbe.js";

/**
 * Public cloud storage listing tests — S3, GCS, Azure Blob. Mocks the listing
 * API responses each provider returns (S3/GCS XML, GCS JSON, Azure XML).
 */

function mockByUrlPrefix(map: Record<string, { status: number; body: string; ct?: string }>) {
  vi.mocked(fetch).mockImplementation(async (input) => {
    const url = String(input);
    for (const [prefix, resp] of Object.entries(map)) {
      if (url.startsWith(prefix)) {
        return new Response(resp.body, {
          status: resp.status,
          headers: resp.ct ? { "content-type": resp.ct } : {},
        });
      }
    }
    return new Response("", { status: 404 });
  });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("runStorageProbe — S3", () => {
  it("flags a publicly listable bucket referenced virtual-hosted style", async () => {
    mockByUrlPrefix({
      "https://my-public-bucket.s3.amazonaws.com/?list-type=2": {
        status: 200,
        body: "<ListBucketResult><Contents><Key>file1.txt</Key></Contents><Contents><Key>file2.txt</Key></Contents></ListBucketResult>",
      },
    });
    const html = `<script>const url = "https://my-public-bucket.s3.amazonaws.com/file.png";</script>`;

    const result = await runStorageProbe("https://example.com", html);

    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("Public S3 Bucket Listing — 'my-public-bucket'");
    expect(result[0]!.severity).toBe("high");
    expect(result[0]!.description).toContain("2 object(s)");
  });

  it("flags a bucket referenced path-style", async () => {
    mockByUrlPrefix({
      "https://another-bucket.s3.amazonaws.com/?list-type=2": { status: 404, body: "not found" },
      "https://s3.amazonaws.com/another-bucket/?list-type=2": {
        status: 200,
        body: "<ListBucketResult><Contents><Key>a</Key></Contents></ListBucketResult>",
      },
    });
    const html = `<a href="https://s3.amazonaws.com/another-bucket/key.txt">download</a>`;

    const result = await runStorageProbe("https://example.com", html);

    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("Public S3 Bucket Listing — 'another-bucket'");
  });

  it("does not flag a bucket that returns AccessDenied", async () => {
    mockByUrlPrefix({
      "https://private-bucket.s3.amazonaws.com/?list-type=2": {
        status: 403,
        body: "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
      },
      "https://s3.amazonaws.com/private-bucket/?list-type=2": {
        status: 403,
        body: "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
      },
    });
    const html = `<script>"https://private-bucket.s3.amazonaws.com/file.png"</script>`;

    const result = await runStorageProbe("https://example.com", html);

    expect(result).toEqual([]);
  });
});

describe("runStorageProbe — GCS", () => {
  it("flags a publicly listable bucket via JSON API response", async () => {
    mockByUrlPrefix({
      "https://storage.googleapis.com/my-gcs-bucket?maxResults=5": {
        status: 200,
        ct: "application/json",
        body: JSON.stringify({ kind: "storage#objects", items: [{ name: "a" }, { name: "b" }] }),
      },
    });
    const html = `<script>fetch("https://storage.googleapis.com/my-gcs-bucket/data.json")</script>`;

    const result = await runStorageProbe("https://example.com", html);

    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("Public GCS Bucket Listing — 'my-gcs-bucket'");
    expect(result[0]!.description).toContain("2 object(s)");
  });

  it("does not flag a bucket that returns 403", async () => {
    mockByUrlPrefix({
      "https://storage.googleapis.com/locked-bucket?maxResults=5": { status: 403, body: "{}" },
      "https://storage.googleapis.com/storage/v1/b/locked-bucket/o?maxResults=5": { status: 403, body: "{}" },
    });
    const html = `<script>"https://storage.googleapis.com/locked-bucket/x.png"</script>`;

    const result = await runStorageProbe("https://example.com", html);

    expect(result).toEqual([]);
  });
});

describe("runStorageProbe — Azure Blob", () => {
  it("flags a publicly listable container", async () => {
    mockByUrlPrefix({
      "https://myaccount.blob.core.windows.net/mycontainer?restype=container&comp=list": {
        status: 200,
        body: "<EnumerationResults><Blobs><Blob><Name>file1</Name></Blob><Blob><Name>file2</Name></Blob></Blobs></EnumerationResults>",
      },
    });
    const html = `<img src="https://myaccount.blob.core.windows.net/mycontainer/blob1.png">`;

    const result = await runStorageProbe("https://example.com", html);

    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("Public Azure Blob Container Listing — 'myaccount/mycontainer'");
    expect(result[0]!.description).toContain("2 blob(s)");
  });

  it("does not flag a container that returns an error", async () => {
    mockByUrlPrefix({
      "https://myaccount.blob.core.windows.net/privatecontainer?restype=container&comp=list": {
        status: 403,
        body: "<Error><Code>ResourceNotFound</Code></Error>",
      },
    });
    const html = `<img src="https://myaccount.blob.core.windows.net/privatecontainer/blob1.png">`;

    const result = await runStorageProbe("https://example.com", html);

    expect(result).toEqual([]);
  });
});

describe("runStorageProbe — no references", () => {
  it("returns no findings and makes no fetch calls for a page with no storage references", async () => {
    const html = `<html><body>Nothing to see here</body></html>`;

    const result = await runStorageProbe("https://example.com", html);

    expect(result).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });
});

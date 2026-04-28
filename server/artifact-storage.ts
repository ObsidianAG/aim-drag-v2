/**
 * server/artifact-storage.ts — Artifact Storage Contract for Text2VideoRank
 *
 * Download MP4 from provider → SHA-256 hash → Store in object storage → Verify → Evidence record
 *
 * AIM DRAG: No video becomes real until generated, downloaded, hashed, stored, audited, shown with proof.
 */

import { createHash } from 'node:crypto';

// ═══════════════════════════════════════════════════════════════════════════
// OBJECT STORAGE INTERFACE (S3/MinIO compatible)
// ═══════════════════════════════════════════════════════════════════════════

export interface ObjectStorageClient {
  put(key: string, data: Buffer, metadata: Record<string, string>): Promise<string>;
  get(key: string): Promise<Buffer | null>;
  head(key: string): Promise<{ contentLength: number; sha256: string } | null>;
}

// ═══════════════════════════════════════════════════════════════════════════
// IN-MEMORY STUB (production would use S3/MinIO)
// ═══════════════════════════════════════════════════════════════════════════

const storage = new Map<string, { data: Buffer; metadata: Record<string, string> }>();

const inMemoryStorage: ObjectStorageClient = {
  async put(key: string, data: Buffer, metadata: Record<string, string>): Promise<string> {
    storage.set(key, { data, metadata });
    return `s3://text2video-rank-artifacts/${key}`;
  },

  async get(key: string): Promise<Buffer | null> {
    const entry = storage.get(key);
    return entry?.data ?? null;
  },

  async head(key: string): Promise<{ contentLength: number; sha256: string } | null> {
    const entry = storage.get(key);
    if (!entry) return null;
    return {
      contentLength: entry.data.length,
      sha256: entry.metadata['sha256'] ?? '',
    };
  },
};

/** Reset storage (for testing) */
export function resetStorage(): void {
  storage.clear();
}

// ═══════════════════════════════════════════════════════════════════════════
// ARTIFACT OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Download MP4 from provider URL.
 * In production, this would do an HTTP GET.
 * Stub returns a deterministic buffer.
 */
export async function downloadArtifact(providerUrl: string): Promise<Buffer> {
  // Stub: In production, fetch the actual MP4
  // We create a deterministic buffer based on the URL for testing
  const content = `STUB_MP4_CONTENT_${providerUrl}`;
  return Buffer.from(content, 'utf-8');
}

/**
 * Compute SHA-256 hash of artifact data.
 */
export function hashArtifact(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Store artifact in object storage with SHA-256 metadata.
 * Returns the storage path.
 */
export async function storeArtifact(
  jobId: string,
  data: Buffer,
  sha256: string,
): Promise<string> {
  const key = `artifacts/${jobId}/video.mp4`;
  const storagePath = await inMemoryStorage.put(key, data, {
    sha256,
    jobId,
    storedAt: new Date().toISOString(),
    contentType: 'video/mp4',
  });
  return storagePath;
}

/**
 * Verify stored artifact matches expected SHA-256 hash.
 * AIM DRAG: Fail-closed if verification fails.
 */
export async function verifyStoredArtifact(
  storagePath: string,
  expectedSha256: string,
): Promise<boolean> {
  // Extract key from storage path
  const key = storagePath.replace('s3://text2video-rank-artifacts/', '');
  const data = await inMemoryStorage.get(key);

  if (!data) {
    return false; // Fail-closed: artifact not found
  }

  const actualSha256 = hashArtifact(data);
  return actualSha256 === expectedSha256;
}

/**
 * Get artifact data from storage.
 */
export async function getStoredArtifact(
  jobId: string,
): Promise<Buffer | null> {
  const key = `artifacts/${jobId}/video.mp4`;
  return inMemoryStorage.get(key);
}

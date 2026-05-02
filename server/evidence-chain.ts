/**
 * server/evidence-chain.ts -- SHA-256 Evidence Chain
 *
 * Generates SHA-256 hash for every decision record.
 * Chains evidence: each record references previous record's hash.
 * Immutable — once written, cannot be modified without breaking chain.
 * Verifies chain integrity on read.
 *
 * Required fields: trace_id, policy_version, artifact_lineage, timestamp.
 * FAIL_CLOSED on missing required fields.
 *
 * AIM DRAG: observe → decide → enforce → prove
 */
import { createHash } from 'node:crypto';
import { z } from 'zod';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface EvidenceRecord {
  hash: string;
  previousHash: string | null;
  traceId: string;
  policyVersion: string;
  artifactLineage: string;
  timestamp: string;
  action: string;
  decision: string;
  metadata: Record<string, unknown>;
}

export type EvidenceCreateResult =
  | { status: 'OK'; record: EvidenceRecord }
  | { status: 'FAIL_CLOSED'; reason: string; timestamp: string };

export type ChainVerifyResult =
  | { status: 'VALID'; length: number }
  | { status: 'INVALID'; reason: string; brokenAtIndex: number };

// ═══════════════════════════════════════════════════════════════════════════
// INPUT SCHEMA (safeParse at entry boundary)
// ═══════════════════════════════════════════════════════════════════════════

const EvidenceInputSchema = z.object({
  traceId: z.string().min(1),
  policyVersion: z.string().min(1),
  artifactLineage: z.string().min(1),
  timestamp: z.string().min(1),
  action: z.string().min(1),
  decision: z.string().min(1),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

// ═══════════════════════════════════════════════════════════════════════════
// EVIDENCE CHAIN
// ═══════════════════════════════════════════════════════════════════════════

export class EvidenceChain {
  private readonly records: EvidenceRecord[] = [];
  private readonly nowFn: () => string;

  constructor(nowFn?: () => string) {
    this.nowFn = nowFn ?? (() => new Date().toISOString());
  }

  /**
   * Compute SHA-256 hash for a record's content (deterministic).
   */
  static computeHash(data: {
    previousHash: string | null;
    traceId: string;
    policyVersion: string;
    artifactLineage: string;
    timestamp: string;
    action: string;
    decision: string;
    metadata: Record<string, unknown>;
  }): string {
    const canonical = JSON.stringify({
      previousHash: data.previousHash,
      traceId: data.traceId,
      policyVersion: data.policyVersion,
      artifactLineage: data.artifactLineage,
      timestamp: data.timestamp,
      action: data.action,
      decision: data.decision,
      metadata: data.metadata,
    });
    return createHash('sha256').update(canonical).digest('hex');
  }

  /**
   * Append a new evidence record to the chain.
   * FAIL_CLOSED on missing required fields.
   */
  append(input: unknown): EvidenceCreateResult {
    const now = this.nowFn();

    // Validate input at entry boundary (safeParse only)
    const parsed = EvidenceInputSchema.safeParse(input);
    if (!parsed.success) {
      const firstIssue = parsed.error.issues[0];
      const fieldPath = firstIssue?.path?.join('.') ?? 'unknown';
      return {
        status: 'FAIL_CLOSED',
        reason: `Missing or invalid required field: ${fieldPath} — ${firstIssue?.message ?? 'validation failed'}`,
        timestamp: now,
      };
    }

    const data = parsed.data;
    const previousHash = this.records.length > 0
      ? this.records[this.records.length - 1]!.hash
      : null;

    const recordData = {
      previousHash,
      traceId: data.traceId,
      policyVersion: data.policyVersion,
      artifactLineage: data.artifactLineage,
      timestamp: data.timestamp,
      action: data.action,
      decision: data.decision,
      metadata: data.metadata ?? {},
    };

    const hash = EvidenceChain.computeHash(recordData);

    const record: EvidenceRecord = { hash, ...recordData };
    this.records.push(record);

    return { status: 'OK', record };
  }

  /**
   * Verify the integrity of the entire chain.
   * Returns INVALID if any record's hash doesn't match or chain links are broken.
   */
  verify(): ChainVerifyResult {
    for (let i = 0; i < this.records.length; i++) {
      const record = this.records[i]!;

      // Verify hash computation
      const { hash, ...data } = record;
      const expectedHash = EvidenceChain.computeHash(data);
      if (hash !== expectedHash) {
        return {
          status: 'INVALID',
          reason: `Hash mismatch at index ${i}: expected ${expectedHash}, got ${hash}`,
          brokenAtIndex: i,
        };
      }

      // Verify chain linkage
      if (i === 0) {
        if (record.previousHash !== null) {
          return {
            status: 'INVALID',
            reason: `First record should have null previousHash, got ${record.previousHash}`,
            brokenAtIndex: i,
          };
        }
      } else {
        const previousRecord = this.records[i - 1]!;
        if (record.previousHash !== previousRecord.hash) {
          return {
            status: 'INVALID',
            reason: `Chain broken at index ${i}: previousHash doesn't match record ${i - 1}`,
            brokenAtIndex: i,
          };
        }
      }
    }

    return { status: 'VALID', length: this.records.length };
  }

  /**
   * Get all records (read-only copy).
   */
  getRecords(): readonly EvidenceRecord[] {
    return [...this.records];
  }

  /**
   * Get chain length.
   */
  get length(): number {
    return this.records.length;
  }

  /**
   * Verify a standalone chain of records (static utility).
   */
  static verifyChain(records: readonly EvidenceRecord[]): ChainVerifyResult {
    for (let i = 0; i < records.length; i++) {
      const record = records[i]!;

      // Verify hash
      const { hash, ...data } = record;
      const expectedHash = EvidenceChain.computeHash(data);
      if (hash !== expectedHash) {
        return {
          status: 'INVALID',
          reason: `Hash mismatch at index ${i}: expected ${expectedHash}, got ${hash}`,
          brokenAtIndex: i,
        };
      }

      // Verify linkage
      if (i === 0) {
        if (record.previousHash !== null) {
          return {
            status: 'INVALID',
            reason: `First record should have null previousHash`,
            brokenAtIndex: i,
          };
        }
      } else {
        if (record.previousHash !== records[i - 1]!.hash) {
          return {
            status: 'INVALID',
            reason: `Chain broken at index ${i}: previousHash doesn't match`,
            brokenAtIndex: i,
          };
        }
      }
    }

    return { status: 'VALID', length: records.length };
  }
}

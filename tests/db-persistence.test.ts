/**
 * tests/db-persistence.test.ts -- Database persistence layer tests
 *
 * Tests all 6 transaction types, job lifecycle persistence, FK constraints,
 * CHECK constraints, and query helpers.
 *
 * Requires DATABASE_URL environment variable.
 * AIM DRAG: safeParse patterns, fail-closed verification.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { sql, eq } from 'drizzle-orm';
import * as schema from '../server/db/schema.js';
import {
  createJobWithEvent,
  submitProviderRequest,
  markProviderCompleted,
  storeArtifactWithVerification,
  writeClaimAuditAndDecision,
  writeProofRunWithResults,
  writeSafetyReview,
  updateJobStatus,
  getJobByJobId,
  getJobByIdempotencyKey,
  getArtifactBySha256,
  getClaimAuditsByClaimId,
  getProofRunByRunId,
  searchJobsByPrompt,
  filterClaimsByStatus,
  filterProviderRequests,
  seedClaimsForProof,
} from '../server/db/repository.js';

const DATABASE_URL = process.env['DATABASE_URL'];
if (!DATABASE_URL) throw new Error('DATABASE_URL required for DB tests');

const pgClient = postgres(DATABASE_URL, { max: 5 });
const db = drizzle(pgClient, { schema });

// Clean tables before each test
async function cleanAll() {
  await pgClient`DELETE FROM proof_gate_results`;
  await pgClient`DELETE FROM proof_runs`;
  await pgClient`DELETE FROM claim_audits`;
  await pgClient`DELETE FROM claim_sources`;
  await pgClient`DELETE FROM claims`;
  await pgClient`DELETE FROM artifact_verifications`;
  await pgClient`DELETE FROM artifacts`;
  await pgClient`DELETE FROM safety_reviews`;
  await pgClient`DELETE FROM provider_requests`;
  await pgClient`DELETE FROM video_job_events`;
  await pgClient`DELETE FROM audit_log`;
  await pgClient`DELETE FROM video_jobs`;
  await pgClient`DELETE FROM projects`;
  await pgClient`DELETE FROM providers`;
  await pgClient`DELETE FROM users`;
}

beforeEach(async () => {
  await cleanAll();
  // Seed required providers for FK constraint
  await pgClient`INSERT INTO providers (provider_id, name) VALUES ('runway', 'Runway') ON CONFLICT DO NOTHING`;
  await pgClient`INSERT INTO providers (provider_id, name) VALUES ('test_provider', 'Test Provider') ON CONFLICT DO NOTHING`;
  await pgClient`INSERT INTO providers (provider_id, name) VALUES ('minimax', 'Minimax') ON CONFLICT DO NOTHING`;
  await pgClient`INSERT INTO providers (provider_id, name) VALUES ('kling', 'Kling') ON CONFLICT DO NOTHING`;
});

afterAll(async () => {
  await cleanAll();
  await pgClient.end();
});

// ═══════════════════════════════════════════════════════════════════════════
// Transaction 1: Create job + initial event
// ═══════════════════════════════════════════════════════════════════════════

describe('Transaction 1: Create job + initial event', () => {
  it('creates a video_jobs row and video_job_events row atomically', async () => {
    const result = await createJobWithEvent(db, {
      jobId: 'job-tx1-001',
      idempotencyKey: 'idem-tx1-001',
      userPrompt: 'A sunset over the ocean',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    expect(result.jobId).toBe('job-tx1-001');

    // Verify job exists
    const job = await getJobByJobId(db, 'job-tx1-001');
    expect(job).not.toBeNull();
    expect(job!.status).toBe('queued');
    expect(job!.userPrompt).toBe('A sunset over the ocean');

    // Verify event exists
    const events = await db.select().from(schema.videoJobEvents)
      .where(eq(schema.videoJobEvents.jobId, 'job-tx1-001'));
    expect(events.length).toBe(1);
    expect(events[0]!.eventType).toBe('job_created');
  });

  it('writes audit_log entry on job creation', async () => {
    await createJobWithEvent(db, {
      jobId: 'job-tx1-audit',
      idempotencyKey: 'idem-tx1-audit',
      userPrompt: 'Test audit log',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    const logs = await db.select().from(schema.auditLog)
      .where(eq(schema.auditLog.entityId, 'job-tx1-audit'));
    expect(logs.length).toBe(1);
    expect(logs[0]!.action).toBe('job_created');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Transaction 2: Submit provider request + status update
// ═══════════════════════════════════════════════════════════════════════════

describe('Transaction 2: Submit provider request + status update', () => {
  it('creates provider_requests row and updates job status', async () => {
    await createJobWithEvent(db, {
      jobId: 'job-tx2-001',
      idempotencyKey: 'idem-tx2-001',
      userPrompt: 'Mountain landscape',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await submitProviderRequest(db, 'job-tx2-001', {
      jobId: 'job-tx2-001',
      provider: 'runway',
      model: 'gen4.5',
      providerRequestKey: 'req-tx2-001',
      requestPayload: { prompt: 'Mountain landscape' },
      status: 'submitted',
    });

    const job = await getJobByJobId(db, 'job-tx2-001');
    expect(job!.status).toBe('submitted');

    const reqs = await db.select().from(schema.providerRequests)
      .where(eq(schema.providerRequests.jobId, 'job-tx2-001'));
    expect(reqs.length).toBe(1);
    expect(reqs[0]!.providerRequestKey).toBe('req-tx2-001');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Transaction 3: Provider completed + event
// ═══════════════════════════════════════════════════════════════════════════

describe('Transaction 3: Provider completed + event', () => {
  it('marks job as provider_completed with event', async () => {
    await createJobWithEvent(db, {
      jobId: 'job-tx3-001',
      idempotencyKey: 'idem-tx3-001',
      userPrompt: 'Test provider complete',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await markProviderCompleted(db, 'job-tx3-001', 'runway_abc123');

    const job = await getJobByJobId(db, 'job-tx3-001');
    expect(job!.status).toBe('provider_completed');
    expect(job!.providerJobId).toBe('runway_abc123');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Transaction 4: Artifact + verification
// ═══════════════════════════════════════════════════════════════════════════

describe('Transaction 4: Artifact + sha256 + verification', () => {
  it('stores artifact and verification atomically', async () => {
    await createJobWithEvent(db, {
      jobId: 'job-tx4-001',
      idempotencyKey: 'idem-tx4-001',
      userPrompt: 'Test artifact',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await storeArtifactWithVerification(db, {
      jobId: 'job-tx4-001',
      artifactUrl: 'https://cdn.example.com/video.mp4',
      storageKey: 's3://bucket/job-tx4-001/video.mp4',
      sha256: 'a'.repeat(64),
      contentType: 'video/mp4',
      sizeBytes: 1024000,
    }, true, 'Hash verified');

    const artifact = await getArtifactBySha256(db, 'a'.repeat(64));
    expect(artifact).not.toBeNull();
    expect(artifact!.sizeBytes).toBe(1024000);

    const verifs = await db.select().from(schema.artifactVerifications)
      .where(eq(schema.artifactVerifications.jobId, 'job-tx4-001'));
    expect(verifs.length).toBe(1);
    expect(verifs[0]!.verified).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Transaction 5: Claim audit + final decision
// ═══════════════════════════════════════════════════════════════════════════

describe('Transaction 5: Claim audit + final decision', () => {
  it('writes claim, source, audit, and updates job decision', async () => {
    await createJobWithEvent(db, {
      jobId: 'job-tx5-001',
      idempotencyKey: 'idem-tx5-001',
      userPrompt: 'Test claim audit',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await writeClaimAuditAndDecision(db, 'job-tx5-001', {
      claimId: 'claim-tx5-001',
      claimText: 'Test claim text',
      toolId: 'test_tool',
    }, {
      claimId: 'claim-tx5-001',
      sourceUrl: 'https://example.com/source',
      sourceTitle: 'Test Source',
      retrievedAt: new Date(),
    }, {
      claimId: 'claim-tx5-001',
      confidence: 'HIGH',
      verificationStatus: 'VERIFIED',
      notes: 'Confirmed',
      uiBadgeExpected: 'Verified',
    }, 'ALLOW');

    const job = await getJobByJobId(db, 'job-tx5-001');
    expect(job!.decision).toBe('ALLOW');
    expect(job!.status).toBe('completed');

    const audits = await getClaimAuditsByClaimId(db, 'claim-tx5-001');
    expect(audits.length).toBe(1);
    expect(audits[0]!.confidence).toBe('HIGH');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Transaction 6: Proof run + gate results
// ═══════════════════════════════════════════════════════════════════════════

describe('Transaction 6: Proof run + gate results', () => {
  it('writes proof run and gate results atomically', async () => {
    await writeProofRunWithResults(db, 'run-tx6-001', 'ALLOW', [
      { gateName: 'typecheck', rawExitCode: 0, normalizedExitCode: 0, verdict: 'PASS' },
      { gateName: 'test', rawExitCode: 0, normalizedExitCode: 0, verdict: 'PASS' },
      { gateName: 'build', rawExitCode: 0, normalizedExitCode: 0, verdict: 'PASS' },
    ]);

    const run = await getProofRunByRunId(db, 'run-tx6-001');
    expect(run).not.toBeNull();
    expect(run!.finalDecision).toBe('ALLOW');

    const gates = await db.select().from(schema.proofGateResults)
      .where(eq(schema.proofGateResults.runId, 'run-tx6-001'));
    expect(gates.length).toBe(3);
  });

  it('stores both raw_exit_code and normalized_exit_code', async () => {
    await writeProofRunWithResults(db, 'run-tx6-002', 'ALLOW', [
      { gateName: 'secret_scan', rawExitCode: 1, normalizedExitCode: 0, verdict: 'PASS (normalized)' },
    ]);

    const gates = await db.select().from(schema.proofGateResults)
      .where(eq(schema.proofGateResults.runId, 'run-tx6-002'));
    expect(gates[0]!.rawExitCode).toBe(1);
    expect(gates[0]!.normalizedExitCode).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Safety review persistence
// ═══════════════════════════════════════════════════════════════════════════

describe('Safety review persistence', () => {
  it('writes safety review linked to job', async () => {
    await createJobWithEvent(db, {
      jobId: 'job-safety-001',
      idempotencyKey: 'idem-safety-001',
      userPrompt: 'Safe prompt',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await writeSafetyReview(db, 'job-safety-001', {
      containsPublicFigure: false,
      containsPrivatePerson: false,
      containsCopyrightedCharacter: false,
      containsExplicitContent: false,
      containsMedicalOrLegalClaim: false,
      status: 'PASS',
    });

    const reviews = await db.select().from(schema.safetyReviews)
      .where(eq(schema.safetyReviews.jobId, 'job-safety-001'));
    expect(reviews.length).toBe(1);
    expect(reviews[0]!.status).toBe('PASS');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// CHECK constraint enforcement
// ═══════════════════════════════════════════════════════════════════════════

describe('CHECK constraint enforcement', () => {
  it('rejects invalid job status at database level', async () => {
    await expect(
      createJobWithEvent(db, {
        jobId: 'job-check-001',
        idempotencyKey: 'idem-check-001',
        userPrompt: 'Test',
        provider: 'runway',
        model: 'gen4.5',
        status: 'INVALID_STATUS',
        decision: 'ALLOW',
      }),
    ).rejects.toThrow();
  });

  it('rejects invalid decision at database level', async () => {
    await expect(
      createJobWithEvent(db, {
        jobId: 'job-check-002',
        idempotencyKey: 'idem-check-002',
        userPrompt: 'Test',
        provider: 'runway',
        model: 'gen4.5',
        status: 'queued',
        decision: 'INVALID_DECISION',
      }),
    ).rejects.toThrow();
  });

  it('rejects invalid claim audit confidence', async () => {
    // First create a claim
    await db.insert(schema.claims).values({
      claimId: 'claim-check-001',
      claimText: 'Test',
      toolId: 'test',
    });

    await expect(
      db.insert(schema.claimAudits).values({
        claimId: 'claim-check-001',
        confidence: 'INVALID',
        verificationStatus: 'VERIFIED',
        notes: 'test',
        uiBadgeExpected: 'Verified',
      }),
    ).rejects.toThrow();
  });

  it('rejects invalid verification status', async () => {
    await db.insert(schema.claims).values({
      claimId: 'claim-check-002',
      claimText: 'Test',
      toolId: 'test',
    });

    await expect(
      db.insert(schema.claimAudits).values({
        claimId: 'claim-check-002',
        confidence: 'HIGH',
        verificationStatus: 'INVALID',
        notes: 'test',
        uiBadgeExpected: 'Verified',
      }),
    ).rejects.toThrow();
  });

  it('rejects artifact with size_bytes <= 0', async () => {
    await createJobWithEvent(db, {
      jobId: 'job-check-size',
      idempotencyKey: 'idem-check-size',
      userPrompt: 'Test',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await expect(
      db.insert(schema.artifacts).values({
        jobId: 'job-check-size',
        artifactUrl: 'https://example.com/v.mp4',
        storageKey: 's3://bucket/test',
        sha256: 'b'.repeat(64),
        contentType: 'video/mp4',
        sizeBytes: 0,
      }),
    ).rejects.toThrow();
  });

  it('rejects invalid safety review status', async () => {
    await createJobWithEvent(db, {
      jobId: 'job-check-safety',
      idempotencyKey: 'idem-check-safety',
      userPrompt: 'Test',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await expect(
      db.insert(schema.safetyReviews).values({
        jobId: 'job-check-safety',
        status: 'INVALID_STATUS',
      }),
    ).rejects.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Foreign key enforcement
// ═══════════════════════════════════════════════════════════════════════════

describe('Foreign key enforcement', () => {
  it('rejects event for non-existent job', async () => {
    await expect(
      db.insert(schema.videoJobEvents).values({
        jobId: 'nonexistent-job',
        eventType: 'test',
      }),
    ).rejects.toThrow();
  });

  it('rejects provider request for non-existent job', async () => {
    await expect(
      db.insert(schema.providerRequests).values({
        jobId: 'nonexistent-job',
        provider: 'runway',
        model: 'gen4.5',
        providerRequestKey: 'req-fk-001',
        requestPayload: {},
        status: 'submitted',
      }),
    ).rejects.toThrow();
  });

  it('rejects claim audit for non-existent claim', async () => {
    await expect(
      db.insert(schema.claimAudits).values({
        claimId: 'nonexistent-claim',
        confidence: 'HIGH',
        verificationStatus: 'VERIFIED',
        notes: 'test',
        uiBadgeExpected: 'Verified',
      }),
    ).rejects.toThrow();
  });

  it('cascades delete from video_jobs to events', async () => {
    await createJobWithEvent(db, {
      jobId: 'job-cascade-001',
      idempotencyKey: 'idem-cascade-001',
      userPrompt: 'Test cascade',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    // Delete job
    await db.delete(schema.videoJobs).where(eq(schema.videoJobs.jobId, 'job-cascade-001'));

    // Events should be gone
    const events = await db.select().from(schema.videoJobEvents)
      .where(eq(schema.videoJobEvents.jobId, 'job-cascade-001'));
    expect(events.length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Query helpers
// ═══════════════════════════════════════════════════════════════════════════

describe('Query helpers', () => {
  it('searches jobs by prompt with parameterized ILIKE', async () => {
    await createJobWithEvent(db, {
      jobId: 'job-search-001',
      idempotencyKey: 'idem-search-001',
      userPrompt: 'A beautiful sunset over the ocean',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    const results = await searchJobsByPrompt(db, 'sunset');
    expect(results.length).toBe(1);
    expect(results[0]!.jobId).toBe('job-search-001');
  });

  it('filters claims by status with parameterized query', async () => {
    await db.insert(schema.claims).values({
      claimId: 'claim-filter-001',
      claimText: 'Test filter',
      toolId: 'test',
    });
    await db.insert(schema.claimAudits).values({
      claimId: 'claim-filter-001',
      confidence: 'HIGH',
      verificationStatus: 'VERIFIED',
      notes: 'test',
      uiBadgeExpected: 'Verified',
    });

    const results = await filterClaimsByStatus(db, 'VERIFIED');
    expect(results.length).toBeGreaterThanOrEqual(1);
  });

  it('filters provider requests with parameterized query', async () => {
    await createJobWithEvent(db, {
      jobId: 'job-filter-pr',
      idempotencyKey: 'idem-filter-pr',
      userPrompt: 'Test',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });
    await submitProviderRequest(db, 'job-filter-pr', {
      jobId: 'job-filter-pr',
      provider: 'runway',
      model: 'gen4.5',
      providerRequestKey: 'req-filter-001',
      requestPayload: {},
      status: 'submitted',
    });

    const results = await filterProviderRequests(db, 'runway');
    expect(results.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Seed claims for proof
// ═══════════════════════════════════════════════════════════════════════════

describe('Seed claims for proof', () => {
  it('seeds 5 database-backed claims with sources and audits', async () => {
    await seedClaimsForProof(db);

    const allClaims = await db.select().from(schema.claims);
    expect(allClaims.length).toBeGreaterThanOrEqual(5);

    const allSources = await db.select().from(schema.claimSources);
    expect(allSources.length).toBeGreaterThanOrEqual(5);

    const allAudits = await db.select().from(schema.claimAudits);
    expect(allAudits.length).toBeGreaterThanOrEqual(5);
  });

  it('is idempotent -- running twice does not duplicate', async () => {
    await seedClaimsForProof(db);
    await seedClaimsForProof(db);

    const allClaims = await db.select().from(schema.claims);
    expect(allClaims.length).toBe(5);
  });
});

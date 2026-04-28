/**
 * tests/db-idempotency.test.ts -- Idempotency key tests
 *
 * Proves:
 *   - video_jobs.idempotency_key is unique (duplicate rejected)
 *   - provider_requests.provider_request_key is unique
 *   - artifacts.sha256 is unique (webhook + poller dedup)
 *   - proof_runs.run_id is unique
 *
 * AIM DRAG: All idempotency enforced at database level.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { eq } from 'drizzle-orm';
import * as schema from '../server/db/schema.js';
import {
  createJobWithEvent,
  submitProviderRequest,
  storeArtifactWithVerification,
  writeProofRunWithResults,
  getJobByIdempotencyKey,
  getArtifactBySha256,
} from '../server/db/repository.js';

const DATABASE_URL = process.env['DATABASE_URL'];
if (!DATABASE_URL) throw new Error('DATABASE_URL required for idempotency tests');

const pgClient = postgres(DATABASE_URL, { max: 5 });
const db = drizzle(pgClient, { schema });

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
}

beforeEach(async () => {
  await cleanAll();
  // Seed required providers for FK constraint
  await pgClient`INSERT INTO providers (provider_id, name) VALUES ('runway', 'Runway') ON CONFLICT DO NOTHING`;
  await pgClient`INSERT INTO providers (provider_id, name) VALUES ('test_provider', 'Test Provider') ON CONFLICT DO NOTHING`;
});

afterAll(async () => {
  await cleanAll();
  await pgClient`DELETE FROM providers`;
  await pgClient.end();
});

// ═══════════════════════════════════════════════════════════════════════════
// video_jobs.idempotency_key uniqueness
// ═══════════════════════════════════════════════════════════════════════════

describe('video_jobs.idempotency_key uniqueness', () => {
  it('allows first insert with idempotency key', async () => {
    const result = await createJobWithEvent(db, {
      jobId: 'idem-job-001',
      idempotencyKey: 'idem-key-unique-001',
      userPrompt: 'Test idempotency',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });
    expect(result.jobId).toBe('idem-job-001');
  });

  it('rejects duplicate idempotency key', async () => {
    await createJobWithEvent(db, {
      jobId: 'idem-job-002a',
      idempotencyKey: 'idem-key-dup-001',
      userPrompt: 'First insert',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await expect(
      createJobWithEvent(db, {
        jobId: 'idem-job-002b',
        idempotencyKey: 'idem-key-dup-001', // same key
        userPrompt: 'Duplicate insert',
        provider: 'runway',
        model: 'gen4.5',
        status: 'queued',
        decision: 'ALLOW',
      }),
    ).rejects.toThrow();
  });

  it('rejects duplicate job_id', async () => {
    await createJobWithEvent(db, {
      jobId: 'idem-job-003',
      idempotencyKey: 'idem-key-003a',
      userPrompt: 'First',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await expect(
      createJobWithEvent(db, {
        jobId: 'idem-job-003', // same job_id
        idempotencyKey: 'idem-key-003b',
        userPrompt: 'Duplicate',
        provider: 'runway',
        model: 'gen4.5',
        status: 'queued',
        decision: 'ALLOW',
      }),
    ).rejects.toThrow();
  });

  it('can look up job by idempotency key', async () => {
    await createJobWithEvent(db, {
      jobId: 'idem-job-004',
      idempotencyKey: 'idem-key-lookup-001',
      userPrompt: 'Lookup test',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    const job = await getJobByIdempotencyKey(db, 'idem-key-lookup-001');
    expect(job).not.toBeNull();
    expect(job!.jobId).toBe('idem-job-004');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// provider_requests.provider_request_key uniqueness
// ═══════════════════════════════════════════════════════════════════════════

describe('provider_requests.provider_request_key uniqueness', () => {
  it('rejects duplicate provider_request_key', async () => {
    await createJobWithEvent(db, {
      jobId: 'idem-pr-job-001',
      idempotencyKey: 'idem-pr-idem-001',
      userPrompt: 'Test',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await submitProviderRequest(db, 'idem-pr-job-001', {
      jobId: 'idem-pr-job-001',
      provider: 'runway',
      model: 'gen4.5',
      providerRequestKey: 'pr-key-dup-001',
      requestPayload: {},
      status: 'submitted',
    });

    // Create second job for the duplicate attempt
    await createJobWithEvent(db, {
      jobId: 'idem-pr-job-002',
      idempotencyKey: 'idem-pr-idem-002',
      userPrompt: 'Test 2',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await expect(
      submitProviderRequest(db, 'idem-pr-job-002', {
        jobId: 'idem-pr-job-002',
        provider: 'runway',
        model: 'gen4.5',
        providerRequestKey: 'pr-key-dup-001', // same key
        requestPayload: {},
        status: 'submitted',
      }),
    ).rejects.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// artifacts.sha256 uniqueness (webhook + poller dedup)
// ═══════════════════════════════════════════════════════════════════════════

describe('artifacts.sha256 uniqueness (webhook + poller dedup)', () => {
  it('rejects duplicate sha256 -- only one artifact record wins', async () => {
    await createJobWithEvent(db, {
      jobId: 'idem-art-job-001',
      idempotencyKey: 'idem-art-idem-001',
      userPrompt: 'Test',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await storeArtifactWithVerification(db, {
      jobId: 'idem-art-job-001',
      artifactUrl: 'https://cdn.example.com/v1.mp4',
      storageKey: 's3://bucket/art-001/v1.mp4',
      sha256: 'c'.repeat(64),
      contentType: 'video/mp4',
      sizeBytes: 500000,
    }, true, 'First write');

    // Second write with same sha256 should fail (webhook + poller dedup)
    await createJobWithEvent(db, {
      jobId: 'idem-art-job-002',
      idempotencyKey: 'idem-art-idem-002',
      userPrompt: 'Test 2',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await expect(
      storeArtifactWithVerification(db, {
        jobId: 'idem-art-job-002',
        artifactUrl: 'https://cdn.example.com/v2.mp4',
        storageKey: 's3://bucket/art-002/v2.mp4',
        sha256: 'c'.repeat(64), // same sha256
        contentType: 'video/mp4',
        sizeBytes: 500000,
      }, true, 'Duplicate write'),
    ).rejects.toThrow();
  });

  it('allows different sha256 values', async () => {
    await createJobWithEvent(db, {
      jobId: 'idem-art-job-003',
      idempotencyKey: 'idem-art-idem-003',
      userPrompt: 'Test',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    await storeArtifactWithVerification(db, {
      jobId: 'idem-art-job-003',
      artifactUrl: 'https://cdn.example.com/v3.mp4',
      storageKey: 's3://bucket/art-003/v3.mp4',
      sha256: 'd'.repeat(64),
      contentType: 'video/mp4',
      sizeBytes: 500000,
    }, true, 'Unique sha256');

    const art = await getArtifactBySha256(db, 'd'.repeat(64));
    expect(art).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// proof_runs.run_id uniqueness
// ═══════════════════════════════════════════════════════════════════════════

describe('proof_runs.run_id uniqueness', () => {
  it('rejects duplicate run_id', async () => {
    await writeProofRunWithResults(db, 'idem-run-001', 'ALLOW', [
      { gateName: 'test', rawExitCode: 0, normalizedExitCode: 0, verdict: 'PASS' },
    ]);

    await expect(
      writeProofRunWithResults(db, 'idem-run-001', 'ALLOW', [
        { gateName: 'build', rawExitCode: 0, normalizedExitCode: 0, verdict: 'PASS' },
      ]),
    ).rejects.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// proof_gate_results (run_id, gate_name) uniqueness
// ═══════════════════════════════════════════════════════════════════════════

describe('proof_gate_results (run_id, gate_name) uniqueness', () => {
  it('rejects duplicate gate for same run', async () => {
    await writeProofRunWithResults(db, 'idem-run-002', 'ALLOW', [
      { gateName: 'typecheck', rawExitCode: 0, normalizedExitCode: 0, verdict: 'PASS' },
    ]);

    // Try to insert another gate result with same run_id + gate_name
    await expect(
      db.insert(schema.proofGateResults).values({
        runId: 'idem-run-002',
        gateName: 'typecheck', // duplicate
        rawExitCode: 1,
        verdict: 'FAIL',
      }),
    ).rejects.toThrow();
  });
});

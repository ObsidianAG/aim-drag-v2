/**
 * tests/completed-job-verification.test.ts
 *
 * Regression test proving that a job CANNOT transition to 'completed'
 * without a verified artifact_verifications row linked to that job.
 *
 * FIX 5: Completed-job artifact verification guard
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from '../server/db/schema.js';
import {
  createJobWithEvent,
  transitionJobToCompleted,
  updateJobStatus,
  storeArtifactWithVerification,
  CompletedJobVerificationError,
} from '../server/db/repository.js';
import type { DbInstance } from '../server/db/repository.js';
import { sql } from 'drizzle-orm';

const DATABASE_URL = process.env.DATABASE_URL ?? 'postgresql://t2vrank:t2vrank_dev@localhost:5432/text2videorank';

let client: ReturnType<typeof postgres>;
let db: DbInstance;

beforeAll(async () => {
  client = postgres(DATABASE_URL);
  db = drizzle(client, { schema }) as unknown as DbInstance;
  // Seed required providers for FK constraint
  await db.execute(sql`INSERT INTO providers (provider_id, name) VALUES ('test_provider', 'Test Provider') ON CONFLICT DO NOTHING`);
  // Clean test data
  await db.execute(sql`DELETE FROM audit_log WHERE entity_id LIKE 'cjv-test-%'`);
  await db.execute(sql`DELETE FROM video_job_events WHERE job_id LIKE 'cjv-test-%'`);
  await db.execute(sql`DELETE FROM artifact_verifications WHERE job_id LIKE 'cjv-test-%'`);
  await db.execute(sql`DELETE FROM artifacts WHERE job_id LIKE 'cjv-test-%'`);
  await db.execute(sql`DELETE FROM video_jobs WHERE job_id LIKE 'cjv-test-%'`);
});

afterAll(async () => {
  await db.execute(sql`DELETE FROM audit_log WHERE entity_id LIKE 'cjv-test-%'`);
  await db.execute(sql`DELETE FROM video_job_events WHERE job_id LIKE 'cjv-test-%'`);
  await db.execute(sql`DELETE FROM artifact_verifications WHERE job_id LIKE 'cjv-test-%'`);
  await db.execute(sql`DELETE FROM artifacts WHERE job_id LIKE 'cjv-test-%'`);
  await db.execute(sql`DELETE FROM video_jobs WHERE job_id LIKE 'cjv-test-%'`);
  await client.end();
});

describe('FIX 5: Completed-job artifact verification guard', () => {
  it('REJECTS transition to completed when NO verified artifact exists (transitionJobToCompleted)', async () => {
    // Create a job
    await createJobWithEvent(db, {
      jobId: 'cjv-test-001',
      idempotencyKey: 'cjv-idem-001',
      userPrompt: 'test completed guard',
      provider: 'test_provider',
      model: 'test_model',
      status: 'verifying',
      decision: 'ALLOW',
    });

    // Attempt to transition to completed WITHOUT a verified artifact
    await expect(
      transitionJobToCompleted(db, 'cjv-test-001', 'ALLOW')
    ).rejects.toThrow(CompletedJobVerificationError);
  });

  it('REJECTS transition to completed via updateJobStatus when NO verified artifact exists', async () => {
    // Create a job
    await createJobWithEvent(db, {
      jobId: 'cjv-test-002',
      idempotencyKey: 'cjv-idem-002',
      userPrompt: 'test completed guard via updateJobStatus',
      provider: 'test_provider',
      model: 'test_model',
      status: 'verifying',
      decision: 'ALLOW',
    });

    // Attempt to transition to completed WITHOUT a verified artifact
    await expect(
      updateJobStatus(db, 'cjv-test-002', 'completed')
    ).rejects.toThrow(CompletedJobVerificationError);
  });

  it('REJECTS transition to completed when artifact exists but verified=false', async () => {
    // Create a job
    await createJobWithEvent(db, {
      jobId: 'cjv-test-003',
      idempotencyKey: 'cjv-idem-003',
      userPrompt: 'test completed guard with unverified artifact',
      provider: 'test_provider',
      model: 'test_model',
      status: 'verifying',
      decision: 'ALLOW',
    });

    // Store artifact with verified=false
    await storeArtifactWithVerification(
      db,
      {
        jobId: 'cjv-test-003',
        artifactUrl: 'https://example.com/video.mp4',
        storageKey: 'cjv-test-003/video.mp4',
        sha256: 'a'.repeat(64),
        contentType: 'video/mp4',
        sizeBytes: 1024,
      },
      false, // NOT verified
      'Verification pending',
    );

    // Attempt to transition to completed -- should fail because verified=false
    await expect(
      transitionJobToCompleted(db, 'cjv-test-003', 'ALLOW')
    ).rejects.toThrow(CompletedJobVerificationError);
  });

  it('ALLOWS transition to completed when verified artifact exists', async () => {
    // Create a job
    await createJobWithEvent(db, {
      jobId: 'cjv-test-004',
      idempotencyKey: 'cjv-idem-004',
      userPrompt: 'test completed guard with verified artifact',
      provider: 'test_provider',
      model: 'test_model',
      status: 'verifying',
      decision: 'ALLOW',
    });

    // Store artifact with verified=true
    await storeArtifactWithVerification(
      db,
      {
        jobId: 'cjv-test-004',
        artifactUrl: 'https://example.com/video2.mp4',
        storageKey: 'cjv-test-004/video.mp4',
        sha256: 'b'.repeat(64),
        contentType: 'video/mp4',
        sizeBytes: 2048,
      },
      true, // verified
      'SHA-256 matches',
    );

    // Transition to completed -- should succeed
    await expect(
      transitionJobToCompleted(db, 'cjv-test-004', 'ALLOW')
    ).resolves.toBeUndefined();
  });

  it('ALLOWS updateJobStatus to completed when verified artifact exists', async () => {
    // Create a job
    await createJobWithEvent(db, {
      jobId: 'cjv-test-005',
      idempotencyKey: 'cjv-idem-005',
      userPrompt: 'test updateJobStatus completed with verified artifact',
      provider: 'test_provider',
      model: 'test_model',
      status: 'verifying',
      decision: 'ALLOW',
    });

    // Store artifact with verified=true
    await storeArtifactWithVerification(
      db,
      {
        jobId: 'cjv-test-005',
        artifactUrl: 'https://example.com/video3.mp4',
        storageKey: 'cjv-test-005/video.mp4',
        sha256: 'c'.repeat(64),
        contentType: 'video/mp4',
        sizeBytes: 4096,
      },
      true,
      'SHA-256 matches',
    );

    // Transition to completed -- should succeed
    await expect(
      updateJobStatus(db, 'cjv-test-005', 'completed')
    ).resolves.toBeUndefined();
  });
});

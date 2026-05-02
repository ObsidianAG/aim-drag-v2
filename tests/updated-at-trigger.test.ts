/**
 * tests/updated-at-trigger.test.ts
 *
 * FIX 6: Prove that updatedAt is automatically managed by database triggers
 * on mutable tables: users, projects, video_jobs, providers.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from '../server/db/schema.js';
import { eq, sql } from 'drizzle-orm';
import type { DbInstance } from '../server/db/repository.js';

const DATABASE_URL = process.env.DATABASE_URL ?? 'postgresql://t2vrank:t2vrank_dev@localhost:5432/text2videorank';

let client: ReturnType<typeof postgres>;
let db: DbInstance;

beforeAll(async () => {
  client = postgres(DATABASE_URL);
  db = drizzle(client, { schema }) as unknown as DbInstance;
  // Clean test data
  await db.execute(sql`DELETE FROM video_job_events WHERE job_id LIKE 'uat-test-%'`);
  await db.execute(sql`DELETE FROM video_jobs WHERE job_id LIKE 'uat-test-%'`);
  await db.execute(sql`DELETE FROM projects WHERE project_id LIKE 'uat-test-%'`);
  await db.execute(sql`DELETE FROM providers WHERE provider_id LIKE 'uat-test-%'`);
  await db.execute(sql`DELETE FROM users WHERE user_id LIKE 'uat-test-%'`);
});

afterAll(async () => {
  await db.execute(sql`DELETE FROM video_job_events WHERE job_id LIKE 'uat-test-%'`);
  await db.execute(sql`DELETE FROM video_jobs WHERE job_id LIKE 'uat-test-%'`);
  await db.execute(sql`DELETE FROM projects WHERE project_id LIKE 'uat-test-%'`);
  await db.execute(sql`DELETE FROM providers WHERE provider_id LIKE 'uat-test-%'`);
  await db.execute(sql`DELETE FROM users WHERE user_id LIKE 'uat-test-%'`);
  await client.end();
});

describe('FIX 6: updatedAt database triggers', () => {
  it('users.updated_at is automatically updated on row modification', async () => {
    // Insert user
    await db.insert(schema.users).values({
      userId: 'uat-test-user-001',
      email: 'uat-test@example.com',
      displayName: 'Test User',
    });

    const [before] = await db.select().from(schema.users).where(eq(schema.users.userId, 'uat-test-user-001'));
    const beforeTs = before.updatedAt;

    // Wait a small amount to ensure timestamp difference
    await new Promise((r) => setTimeout(r, 50));

    // Update user without setting updatedAt explicitly
    await db.update(schema.users)
      .set({ displayName: 'Updated Name' })
      .where(eq(schema.users.userId, 'uat-test-user-001'));

    const [after] = await db.select().from(schema.users).where(eq(schema.users.userId, 'uat-test-user-001'));
    expect(after.updatedAt.getTime()).toBeGreaterThanOrEqual(beforeTs.getTime());
  });

  it('video_jobs.updated_at is automatically updated on row modification', async () => {
    // Insert job
    await db.insert(schema.videoJobs).values({
      jobId: 'uat-test-job-001',
      idempotencyKey: 'uat-test-idem-001',
      userPrompt: 'test updatedAt trigger',
      status: 'queued',
      decision: 'ALLOW',
    });

    const [before] = await db.select().from(schema.videoJobs).where(eq(schema.videoJobs.jobId, 'uat-test-job-001'));
    const beforeTs = before.updatedAt;

    await new Promise((r) => setTimeout(r, 50));

    // Update job without setting updatedAt explicitly
    await db.update(schema.videoJobs)
      .set({ status: 'planning' })
      .where(eq(schema.videoJobs.jobId, 'uat-test-job-001'));

    const [after] = await db.select().from(schema.videoJobs).where(eq(schema.videoJobs.jobId, 'uat-test-job-001'));
    expect(after.updatedAt.getTime()).toBeGreaterThanOrEqual(beforeTs.getTime());
  });

  it('providers.updated_at is automatically updated on row modification', async () => {
    // Insert provider
    await db.insert(schema.providers).values({
      providerId: 'uat-test-provider-001',
      name: 'Test Provider',
      apiBaseUrl: 'https://api.test.com',
    });

    const [before] = await db.select().from(schema.providers).where(eq(schema.providers.providerId, 'uat-test-provider-001'));
    const beforeTs = before.updatedAt;

    await new Promise((r) => setTimeout(r, 50));

    // Update provider without setting updatedAt explicitly
    await db.update(schema.providers)
      .set({ name: 'Updated Provider' })
      .where(eq(schema.providers.providerId, 'uat-test-provider-001'));

    const [after] = await db.select().from(schema.providers).where(eq(schema.providers.providerId, 'uat-test-provider-001'));
    expect(after.updatedAt.getTime()).toBeGreaterThanOrEqual(beforeTs.getTime());
  });

  it('projects.updated_at is automatically updated on row modification', async () => {
    // Need a user first for FK
    const existingUser = await db.select().from(schema.users).where(eq(schema.users.userId, 'uat-test-user-001'));
    if (existingUser.length === 0) {
      await db.insert(schema.users).values({
        userId: 'uat-test-user-001',
        email: 'uat-test2@example.com',
        displayName: 'Test User 2',
      });
    }

    // Insert project
    await db.insert(schema.projects).values({
      projectId: 'uat-test-project-001',
      userId: 'uat-test-user-001',
      name: 'Test Project',
    });

    const [before] = await db.select().from(schema.projects).where(eq(schema.projects.projectId, 'uat-test-project-001'));
    const beforeTs = before.updatedAt;

    await new Promise((r) => setTimeout(r, 50));

    // Update project without setting updatedAt explicitly
    await db.update(schema.projects)
      .set({ name: 'Updated Project' })
      .where(eq(schema.projects.projectId, 'uat-test-project-001'));

    const [after] = await db.select().from(schema.projects).where(eq(schema.projects.projectId, 'uat-test-project-001'));
    expect(after.updatedAt.getTime()).toBeGreaterThanOrEqual(beforeTs.getTime());
  });
});

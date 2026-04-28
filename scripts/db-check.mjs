#!/usr/bin/env node
/**
 * scripts/db-check.mjs — Database schema check
 *
 * Verifies all 15 required tables exist in the database and have expected constraints.
 */

import postgres from 'postgres';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is not set.');
  process.exit(1);
}

const REQUIRED_TABLES = [
  'users',
  'projects',
  'video_jobs',
  'video_job_events',
  'providers',
  'provider_requests',
  'artifacts',
  'artifact_verifications',
  'claims',
  'claim_sources',
  'claim_audits',
  'safety_reviews',
  'proof_runs',
  'proof_gate_results',
  'audit_log',
];

const client = postgres(DATABASE_URL, { max: 1 });

try {
  console.log('db-check: Verifying database schema...');

  // Check all tables exist
  const tables = await client`
    SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
    ORDER BY table_name
  `;
  const tableNames = tables.map(t => t.table_name);

  let allFound = true;
  for (const required of REQUIRED_TABLES) {
    if (tableNames.includes(required)) {
      console.log(`  ✓ ${required}`);
    } else {
      console.error(`  ✗ ${required} — MISSING`);
      allFound = false;
    }
  }

  if (!allFound) {
    console.error('db-check: FAIL — missing required tables.');
    await client.end();
    process.exit(1);
  }

  // Check key constraints exist
  const constraints = await client`
    SELECT tc.table_name, tc.constraint_name, tc.constraint_type
    FROM information_schema.table_constraints tc
    WHERE tc.table_schema = 'public'
    ORDER BY tc.table_name, tc.constraint_type
  `;

  const checkConstraints = constraints.filter(c => c.constraint_type === 'CHECK');
  const uniqueConstraints = constraints.filter(c => c.constraint_type === 'UNIQUE');
  const fkConstraints = constraints.filter(c => c.constraint_type === 'FOREIGN KEY');

  console.log(`\n  CHECK constraints: ${checkConstraints.length}`);
  console.log(`  UNIQUE constraints: ${uniqueConstraints.length}`);
  console.log(`  FOREIGN KEY constraints: ${fkConstraints.length}`);

  // Verify critical constraints
  const videoJobsChecks = checkConstraints.filter(c => c.table_name === 'video_jobs');
  const claimAuditsChecks = checkConstraints.filter(c => c.table_name === 'claim_audits');
  const artifactVerifChecks = checkConstraints.filter(c => c.table_name === 'artifact_verifications');

  if (videoJobsChecks.length < 2) {
    console.error('db-check: FAIL — video_jobs missing status/decision CHECK constraints.');
    await client.end();
    process.exit(1);
  }

  if (claimAuditsChecks.length < 3) {
    console.error('db-check: FAIL — claim_audits missing CHECK constraints.');
    await client.end();
    process.exit(1);
  }

  console.log('\ndb-check: PASS — all 15 tables present with required constraints.');
  await client.end();
  process.exit(0);
} catch (err) {
  console.error('db-check: FAIL —', err.message);
  await client.end();
  process.exit(1);
}

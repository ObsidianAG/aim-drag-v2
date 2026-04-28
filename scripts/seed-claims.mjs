#!/usr/bin/env node
/**
 * scripts/seed-claims.mjs -- Seed database-backed claims for proof
 *
 * Inserts claims, claim_sources, and claim_audits into the database.
 * Idempotent -- skips existing records.
 */

import postgres from 'postgres';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is not set.');
  process.exit(1);
}

const client = postgres(DATABASE_URL, { max: 1 });

const claimData = [
  {
    claimId: 'claim_db_001',
    claimText: 'PostgreSQL enforces CHECK constraints at the database level',
    toolId: 'postgresql_docs',
    sourceUrl: 'https://www.postgresql.org/docs/current/ddl-constraints.html',
    sourceTitle: 'PostgreSQL Documentation -- Constraints',
    confidence: 'HIGH',
    verificationStatus: 'VERIFIED',
    uiBadgeExpected: 'Verified',
    notes: 'Confirmed from official PostgreSQL documentation section 5.4',
  },
  {
    claimId: 'claim_db_002',
    claimText: 'Drizzle ORM uses parameterized queries preventing SQL injection',
    toolId: 'drizzle_docs',
    sourceUrl: 'https://orm.drizzle.team/docs/sql',
    sourceTitle: 'Drizzle ORM -- SQL Module Documentation',
    confidence: 'HIGH',
    verificationStatus: 'VERIFIED',
    uiBadgeExpected: 'Verified',
    notes: 'Drizzle ORM parameterizes all queries through postgres.js driver',
  },
  {
    claimId: 'claim_db_003',
    claimText: 'OWASP recommends parameterized queries as primary SQL injection defense',
    toolId: 'owasp_cheatsheet',
    sourceUrl: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
    sourceTitle: 'OWASP SQL Injection Prevention Cheat Sheet',
    confidence: 'HIGH',
    verificationStatus: 'VERIFIED',
    uiBadgeExpected: 'Verified',
    notes: 'Defense Option 1: Use of Prepared Statements (with Parameterized Queries)',
  },
  {
    claimId: 'claim_db_004',
    claimText: 'Drizzle-kit generate produces forward-only SQL migrations',
    toolId: 'drizzle_kit_docs',
    sourceUrl: 'https://orm.drizzle.team/docs/kit-overview',
    sourceTitle: 'Drizzle Kit -- Overview',
    confidence: 'HIGH',
    verificationStatus: 'VERIFIED',
    uiBadgeExpected: 'Verified',
    notes: 'drizzle-kit generate creates SQL migration files from schema diff',
  },
  {
    claimId: 'claim_db_005',
    claimText: 'Foreign key constraints enforce referential integrity between tables',
    toolId: 'postgresql_docs',
    sourceUrl: 'https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-FK',
    sourceTitle: 'PostgreSQL Documentation -- Foreign Keys',
    confidence: 'HIGH',
    verificationStatus: 'VERIFIED',
    uiBadgeExpected: 'Verified',
    notes: 'Section 5.4.5 documents foreign key constraint behavior',
  },
];

try {
  console.log('seed-claims: Seeding database-backed claims...');

  for (const c of claimData) {
    // Check if already exists
    const existing = await client`SELECT claim_id FROM claims WHERE claim_id = ${c.claimId}`;
    if (existing.length > 0) {
      console.log(`  ⊘ ${c.claimId} -- already exists, skipping`);
      continue;
    }

    await client.begin(async (tx) => {
      await tx`INSERT INTO claims (claim_id, claim_text, tool_id) VALUES (${c.claimId}, ${c.claimText}, ${c.toolId})`;
      await tx`INSERT INTO claim_sources (claim_id, source_url, source_title, retrieved_at) VALUES (${c.claimId}, ${c.sourceUrl}, ${c.sourceTitle}, NOW())`;
      await tx`INSERT INTO claim_audits (claim_id, confidence, verification_status, notes, ui_badge_expected) VALUES (${c.claimId}, ${c.confidence}, ${c.verificationStatus}, ${c.notes}, ${c.uiBadgeExpected})`;
    });

    console.log(`  ✓ ${c.claimId} -- inserted`);
  }

  console.log('seed-claims: Done.');
  await client.end();
  process.exit(0);
} catch (err) {
  console.error('seed-claims: FAIL --', err.message);
  await client.end();
  process.exit(1);
}

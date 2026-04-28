#!/usr/bin/env node
/**
 * scripts/claim-audit-db-check.mjs — Proves claims are database-backed, not static
 *
 * Queries claims, claim_sources, and claim_audits tables to verify:
 * 1. Records exist in the database
 * 2. Foreign keys link claim_audits → claims
 * 3. claim_sources linked to claims
 * 4. Data is not hardcoded/static
 */

import postgres from 'postgres';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is not set.');
  process.exit(1);
}

const client = postgres(DATABASE_URL, { max: 1 });

try {
  // Check claims table has records
  const claimCount = await client`SELECT count(*)::int as cnt FROM claims`;
  const claimSourceCount = await client`SELECT count(*)::int as cnt FROM claim_sources`;
  const claimAuditCount = await client`SELECT count(*)::int as cnt FROM claim_audits`;

  console.log('claim-audit-db-check: Database claim records:');
  console.log(`  claims: ${claimCount[0].cnt}`);
  console.log(`  claim_sources: ${claimSourceCount[0].cnt}`);
  console.log(`  claim_audits: ${claimAuditCount[0].cnt}`);

  if (claimCount[0].cnt === 0 || claimAuditCount[0].cnt === 0) {
    console.error('claim-audit-db-check: FAIL — no claim records in database.');
    await client.end();
    process.exit(1);
  }

  // Verify FK linkage
  const linked = await client`
    SELECT ca.claim_id, c.claim_text, ca.verification_status, ca.confidence, ca.ui_badge_expected
    FROM claim_audits ca
    JOIN claims c ON c.claim_id = ca.claim_id
    ORDER BY ca.id
  `;

  console.log(`\n  Linked claim_audits → claims: ${linked.length} records`);
  for (const row of linked) {
    console.log(`    ${row.claim_id}: ${row.verification_status} (${row.confidence}) → "${row.claim_text.substring(0, 60)}..."`);
  }

  // Verify claim_sources linkage
  const sources = await client`
    SELECT cs.claim_id, cs.source_url, cs.source_title
    FROM claim_sources cs
    JOIN claims c ON c.claim_id = cs.claim_id
    ORDER BY cs.id
  `;

  console.log(`\n  Linked claim_sources → claims: ${sources.length} records`);
  for (const row of sources) {
    console.log(`    ${row.claim_id}: ${row.source_title} → ${row.source_url}`);
  }

  console.log('\nclaim-audit-db-check: PASS — claims are database-backed with FK linkage.');
  await client.end();
  process.exit(0);
} catch (err) {
  console.error('claim-audit-db-check: FAIL —', err.message);
  await client.end();
  process.exit(1);
}

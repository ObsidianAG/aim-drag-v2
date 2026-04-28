#!/usr/bin/env node
/**
 * scripts/proof-package-db-check.mjs — Verifies PROOF_PACKAGE.md has database section
 */

import { readFileSync, existsSync } from 'node:fs';

const PROOF_PACKAGE_PATH = 'PROOF_PACKAGE.md';

if (!existsSync(PROOF_PACKAGE_PATH)) {
  console.error('proof-package-db-check: FAIL — PROOF_PACKAGE.md not found.');
  process.exit(1);
}

const content = readFileSync(PROOF_PACKAGE_PATH, 'utf-8');

const requiredSections = [
  'Database Provider',
  'Migration Strategy',
  'Schema Tables',
  'Constraint List',
  'Foreign Key List',
  'Unique Index List',
  'Transaction Map',
  'Idempotency Map',
  'SQL Injection Prevention',
  'Rollback Behavior',
];

let allFound = true;
for (const section of requiredSections) {
  const found = content.toLowerCase().includes(section.toLowerCase());
  if (found) {
    console.log(`  ✓ ${section}`);
  } else {
    console.error(`  ✗ ${section} — MISSING`);
    allFound = false;
  }
}

if (allFound) {
  console.log('\nproof-package-db-check: PASS — all required database sections present.');
  process.exit(0);
} else {
  console.error('\nproof-package-db-check: FAIL — missing required database sections.');
  process.exit(1);
}

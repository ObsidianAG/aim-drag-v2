#!/usr/bin/env node
/**
 * scripts/db-proof.mjs — Database proof runner
 *
 * Runs all database acceptance gates and writes proof logs.
 * Gates: db:generate, db:migrate:deploy, db:check, test:db, test:idempotency, test:sql-injection
 */

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const LOGS_DIR = resolve(process.cwd(), 'logs');
mkdirSync(LOGS_DIR, { recursive: true });

const gates = [
  { name: 'db-generate', cmd: 'pnpm db:generate' },
  { name: 'db-migrate-deploy', cmd: 'pnpm db:migrate:deploy' },
  { name: 'db-check', cmd: 'pnpm db:check' },
  { name: 'db-tests', cmd: 'pnpm test:db' },
  { name: 'idempotency-tests', cmd: 'pnpm test:idempotency' },
  { name: 'sql-injection-tests', cmd: 'pnpm test:sql-injection' },
];

let allPassed = true;
const results = [];

for (const gate of gates) {
  const logPath = resolve(LOGS_DIR, `${gate.name}.log`);
  const exitPath = resolve(LOGS_DIR, `${gate.name}.exit.txt`);

  let exitCode = 0;
  let output = '';

  try {
    output = execSync(gate.cmd, {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env },
      timeout: 60000,
    });
  } catch (err) {
    exitCode = err.status ?? 1;
    output = (err.stdout ?? '') + '\n' + (err.stderr ?? '');
  }

  writeFileSync(logPath, output);
  writeFileSync(exitPath, String(exitCode));

  const verdict = exitCode === 0 ? 'PASS' : 'FAIL';
  if (exitCode !== 0) allPassed = false;

  results.push({ gate: gate.name, exitCode, verdict });
  console.log(`  ${verdict === 'PASS' ? '✓' : '✗'} ${gate.name}: exit=${exitCode} ${verdict}`);
}

// Write summary
const summaryPath = resolve(LOGS_DIR, 'db-proof.log');
const summaryExitPath = resolve(LOGS_DIR, 'db-proof.exit.txt');
const summaryLines = [
  'Database Proof Summary',
  '='.repeat(40),
  ...results.map(r => `${r.gate}: exit=${r.exitCode} ${r.verdict}`),
  '',
  `Overall: ${allPassed ? 'ALL PASS' : 'SOME FAILED'}`,
];
writeFileSync(summaryPath, summaryLines.join('\n'));
writeFileSync(summaryExitPath, allPassed ? '0' : '1');

console.log(`\ndb-proof: ${allPassed ? 'ALL GATES PASSED' : 'SOME GATES FAILED'}`);
process.exit(allPassed ? 0 : 1);

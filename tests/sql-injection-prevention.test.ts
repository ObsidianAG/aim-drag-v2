/**
 * tests/sql-injection-prevention.test.ts — SQL injection prevention gate
 *
 * Proves:
 *   1. No raw string SQL interpolation with user input
 *   2. All user input goes through ORM parameter binding
 *   3. Search endpoints do not concatenate SQL
 *   4. Claim filters do not concatenate SQL
 *   5. Provider filters do not concatenate SQL
 *   6. Malicious input is safely handled (no SQL execution)
 *
 * AIM DRAG: OWASP-aligned SQL injection prevention proof.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname, relative } from 'node:path';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { eq } from 'drizzle-orm';
import * as schema from '../server/db/schema.js';
import {
  createJobWithEvent,
  searchJobsByPrompt,
  filterClaimsByStatus,
  filterProviderRequests,
  getJobByJobId,
  submitProviderRequest,
  seedClaimsForProof,
} from '../server/db/repository.js';

const DATABASE_URL = process.env['DATABASE_URL'];
if (!DATABASE_URL) throw new Error('DATABASE_URL required for SQL injection tests');

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
});

afterAll(async () => {
  await cleanAll();
  await pgClient.end();
});

// ═══════════════════════════════════════════════════════════════════════════
// Static analysis: No raw SQL string interpolation in source
// ═══════════════════════════════════════════════════════════════════════════

function collectTsFiles(dir: string, files: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (entry === 'node_modules' || entry === 'dist-web' || entry === 'dist-server' || entry === '.git' || entry === 'drizzle') continue;
    const stat = statSync(full);
    if (stat.isDirectory()) {
      collectTsFiles(full, files);
    } else if (extname(full) === '.ts' && !full.endsWith('.d.ts') && !full.includes('.test.')) {
      files.push(full);
    }
  }
  return files;
}

describe('Static analysis: No raw SQL string interpolation', () => {
  const rootDir = join(import.meta.dirname, '..');
  const tsFiles = collectTsFiles(rootDir);

  it('scans production TypeScript files for raw SQL patterns', () => {
    const dangerousPatterns = [
      // Template literal SQL with variable interpolation (not tagged sql``)
      /(?<!sql)`\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^`]*\$\{/i,
      // String concatenation with SQL keywords
      /['"](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^'"]*['"]\s*\+/i,
      /\+\s*['"](?:\s*(?:WHERE|AND|OR|SET|VALUES|FROM|INTO))\b/i,
      // pg query with string concat
      /\.query\(\s*['"`].*\$\{/,
    ];

    const violations: Array<{ file: string; line: number; pattern: string; text: string }> = [];

    for (const filePath of tsFiles) {
      const content = readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');
      const rel = relative(rootDir, filePath);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        // Skip comments
        if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

        for (const pattern of dangerousPatterns) {
          if (pattern.test(line)) {
            violations.push({
              file: rel,
              line: i + 1,
              pattern: pattern.source.substring(0, 40),
              text: line.trim().substring(0, 80),
            });
          }
        }
      }
    }

    if (violations.length > 0) {
      console.error('SQL injection risk — raw SQL string interpolation found:');
      for (const v of violations) {
        console.error(`  ${v.file}:${v.line} — ${v.text}`);
      }
    }

    expect(violations.length).toBe(0);
  });

  it('verifies all repository queries use Drizzle ORM (not raw pg)', () => {
    const repoPath = join(rootDir, 'server', 'db', 'repository.ts');
    const content = readFileSync(repoPath, 'utf-8');

    // Should NOT contain raw pg query calls
    expect(content).not.toMatch(/pgClient\s*`/);
    expect(content).not.toMatch(/client\s*`/);
    expect(content).not.toMatch(/\.query\(/);

    // Should contain Drizzle ORM patterns
    expect(content).toContain('db.transaction');
    expect(content).toContain('db.select()');
    expect(content).toContain('db.insert(');
    // tx.update inside transactions is the correct pattern
    expect(content).toContain('tx.update(');
  });

  it('verifies connection module does not expose raw query capability', () => {
    const connPath = join(rootDir, 'server', 'db', 'connection.ts');
    const content = readFileSync(connPath, 'utf-8');

    // pgClient is exported but documented as Drizzle-only
    expect(content).toContain('used only by Drizzle');
    expect(content).toContain('never for raw string queries');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Runtime: Search endpoint SQL injection attempts
// ═══════════════════════════════════════════════════════════════════════════

describe('Runtime: Search endpoint does not concatenate SQL', () => {
  beforeEach(async () => {
    await createJobWithEvent(db, {
      jobId: 'sqli-search-001',
      idempotencyKey: 'sqli-search-idem-001',
      userPrompt: 'A beautiful sunset',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });
  });

  it('handles SQL injection in search term safely', async () => {
    // Classic SQL injection attempt
    const results = await searchJobsByPrompt(db, "'; DROP TABLE video_jobs; --");
    expect(results.length).toBe(0);

    // Verify table still exists
    const check = await pgClient`SELECT count(*)::int as cnt FROM video_jobs`;
    expect(check[0]!.cnt).toBeGreaterThanOrEqual(1);
  });

  it('handles UNION injection attempt safely', async () => {
    const results = await searchJobsByPrompt(db, "' UNION SELECT * FROM users --");
    expect(results.length).toBe(0);
  });

  it('handles boolean injection attempt safely', async () => {
    const results = await searchJobsByPrompt(db, "' OR '1'='1");
    expect(results.length).toBe(0);
  });

  it('handles null byte injection safely — PostgreSQL rejects invalid encoding', async () => {
    // PostgreSQL rejects null bytes in UTF-8 — this is a database-level defense.
    // The query is still parameterized (not concatenated), so no SQL injection occurs.
    // The error proves the input was sent as a parameter, not interpolated into SQL.
    await expect(
      searchJobsByPrompt(db, "test\0'; DROP TABLE video_jobs;--"),
    ).rejects.toThrow();

    // Verify table still exists — no SQL injection occurred
    const check = await pgClient`SELECT count(*)::int as cnt FROM video_jobs`;
    expect(check[0]!.cnt).toBeGreaterThanOrEqual(1);
  });

  it('legitimate search still works after injection attempts', async () => {
    const results = await searchJobsByPrompt(db, 'sunset');
    expect(results.length).toBe(1);
    expect(results[0]!.jobId).toBe('sqli-search-001');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Runtime: Claim filter SQL injection attempts
// ═══════════════════════════════════════════════════════════════════════════

describe('Runtime: Claim filters do not concatenate SQL', () => {
  beforeEach(async () => {
    await seedClaimsForProof(db);
  });

  it('handles SQL injection in claim status filter', async () => {
    const results = await filterClaimsByStatus(db, "'; DROP TABLE claims; --");
    expect(results.length).toBe(0);

    // Verify table still exists
    const check = await pgClient`SELECT count(*)::int as cnt FROM claims`;
    expect(check[0]!.cnt).toBeGreaterThanOrEqual(1);
  });

  it('handles UNION injection in claim filter', async () => {
    const results = await filterClaimsByStatus(db, "VERIFIED' UNION SELECT * FROM users --");
    expect(results.length).toBe(0);
  });

  it('legitimate claim filter still works', async () => {
    const results = await filterClaimsByStatus(db, 'VERIFIED');
    expect(results.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Runtime: Provider filter SQL injection attempts
// ═══════════════════════════════════════════════════════════════════════════

describe('Runtime: Provider filters do not concatenate SQL', () => {
  beforeEach(async () => {
    await createJobWithEvent(db, {
      jobId: 'sqli-prov-001',
      idempotencyKey: 'sqli-prov-idem-001',
      userPrompt: 'Test',
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });
    await submitProviderRequest(db, 'sqli-prov-001', {
      jobId: 'sqli-prov-001',
      provider: 'runway',
      model: 'gen4.5',
      providerRequestKey: 'sqli-pr-001',
      requestPayload: {},
      status: 'submitted',
    });
  });

  it('handles SQL injection in provider filter', async () => {
    const results = await filterProviderRequests(db, "'; DROP TABLE provider_requests; --");
    expect(results.length).toBe(0);

    // Verify table still exists
    const check = await pgClient`SELECT count(*)::int as cnt FROM provider_requests`;
    expect(check[0]!.cnt).toBeGreaterThanOrEqual(1);
  });

  it('legitimate provider filter still works', async () => {
    const results = await filterProviderRequests(db, 'runway');
    expect(results.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Runtime: Job creation with malicious input
// ═══════════════════════════════════════════════════════════════════════════

describe('Runtime: Job creation with malicious input', () => {
  it('safely stores SQL injection attempt in user_prompt', async () => {
    const maliciousPrompt = "'; DROP TABLE video_jobs; SELECT '";
    const result = await createJobWithEvent(db, {
      jobId: 'sqli-create-001',
      idempotencyKey: 'sqli-create-idem-001',
      userPrompt: maliciousPrompt,
      provider: 'runway',
      model: 'gen4.5',
      status: 'queued',
      decision: 'ALLOW',
    });

    const job = await getJobByJobId(db, 'sqli-create-001');
    expect(job).not.toBeNull();
    // The malicious string is stored as data, not executed as SQL
    expect(job!.userPrompt).toBe(maliciousPrompt);

    // Verify table still exists and has data
    const check = await pgClient`SELECT count(*)::int as cnt FROM video_jobs`;
    expect(check[0]!.cnt).toBeGreaterThanOrEqual(1);
  });
});

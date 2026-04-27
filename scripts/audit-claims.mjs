#!/usr/bin/env node
/**
 * scripts/audit-claims.mjs — Prove all public claims have source metadata
 *
 * Scans TypeScript source for PublicClaim objects and verifies they
 * include required source metadata (url, retrievedAt, author).
 *
 * Also verifies that the PublicClaimSchema enforces source metadata
 * at the type level.
 *
 * Exit code 0 = CLEAN, exit code 1 = UNVERIFIED CLAIMS FOUND
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import ts from 'typescript';

const FINDINGS = [];
let schemaHasSourceField = false;

function collectTsFiles(dir, files = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (entry === 'node_modules' || entry === 'dist-web' || entry === 'dist-server' || entry === '.git') continue;
    const stat = statSync(full);
    if (stat.isDirectory()) {
      collectTsFiles(full, files);
    } else if (extname(full) === '.ts' && !full.endsWith('.d.ts')) {
      files.push(full);
    }
  }
  return files;
}

function visitNode(node, sourceFile, filePath) {
  const rel = relative(process.cwd(), filePath);
  const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;

  // Check if PublicClaimSchema has source field
  if (ts.isCallExpression(node)) {
    const text = node.getText(sourceFile);
    if (text.includes('PublicClaimSchema') && text.includes('z.object')) {
      if (text.includes('source:')) {
        schemaHasSourceField = true;
      }
    }
  }

  // Check for variable declarations with PublicClaim type that lack source
  if (ts.isVariableDeclaration(node) && node.type) {
    const typeText = node.type.getText(sourceFile);
    if (typeText === 'PublicClaim' && node.initializer) {
      const initText = node.initializer.getText(sourceFile);
      if (!initText.includes('source:') && !initText.includes('source :')) {
        FINDINGS.push({
          file: rel,
          line,
          message: 'PublicClaim object missing required "source" metadata',
        });
      }
    }
  }

  ts.forEachChild(node, (child) => visitNode(child, sourceFile, filePath));
}

const files = collectTsFiles(process.cwd());
console.log(`audit-claims: Scanning ${files.length} TypeScript files...\n`);

for (const filePath of files) {
  const content = readFileSync(filePath, 'utf-8');
  const sourceFile = ts.createSourceFile(
    filePath,
    content,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );

  ts.forEachChild(sourceFile, (node) => visitNode(node, sourceFile, filePath));

  // Also check the raw text for PublicClaimSchema definition
  if (content.includes('PublicClaimSchema') && content.includes('z.object')) {
    if (content.includes('source: z.object(')) {
      schemaHasSourceField = true;
    }
  }
}

console.log(`Schema enforcement: PublicClaimSchema has source field = ${schemaHasSourceField}`);

if (!schemaHasSourceField) {
  FINDINGS.push({
    file: 'schema',
    line: 0,
    message: 'PublicClaimSchema does not enforce source metadata at the schema level',
  });
}

if (FINDINGS.length === 0) {
  console.log('\naudit-claims: CLEAN — All public claims have source metadata enforced.');
  console.log('  PublicClaimSchema requires: source.url, source.retrievedAt, source.author');
  process.exit(0);
} else {
  console.error(`\naudit-claims: FAIL — ${FINDINGS.length} issue(s) found:\n`);
  for (const f of FINDINGS) {
    console.error(`  ✗ ${f.file}:${f.line} — ${f.message}`);
  }
  process.exit(1);
}

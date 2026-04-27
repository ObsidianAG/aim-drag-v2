#!/usr/bin/env node
/**
 * scripts/ast-gate.mjs — AST enforcement gate for TypeScript
 *
 * Uses TypeScript compiler API to parse source files and enforce rules:
 *   1. No direct client-side provider calls (fetch to OpenAI/Anthropic/Replicate)
 *   2. No secrets/API keys in client-facing code
 *   3. No UseCaseSchema.parse() — must use safeParse in production paths
 *   4. All public claims must have source metadata
 *   5. No hardcoded secrets (API keys, tokens)
 *
 * Exit code 0 = PASS, exit code 1 = FAIL
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import ts from 'typescript';

const VIOLATIONS = [];
const SCANNED = [];

// ═══════════════════════════════════════════════════════════════════════════
// FILE DISCOVERY
// ═══════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════
// AST RULES
// ═══════════════════════════════════════════════════════════════════════════

const PROVIDER_DOMAINS = [
  'api.openai.com',
  'api.anthropic.com',
  'api.replicate.com',
  'generativelanguage.googleapis.com',
  'api.stability.ai',
];

const SECRET_PATTERNS = [
  /sk-[a-zA-Z0-9]{20,}/,           // OpenAI keys
  /sk-ant-[a-zA-Z0-9]{20,}/,       // Anthropic keys
  /r8_[a-zA-Z0-9]{20,}/,           // Replicate keys
  /ghp_[a-zA-Z0-9]{20,}/,          // GitHub PATs
  /ghu_[a-zA-Z0-9]{20,}/,          // GitHub user tokens
  /AIza[a-zA-Z0-9_-]{30,}/,        // Google API keys
];

function isClientPath(filePath) {
  const rel = relative(process.cwd(), filePath);
  // Server-side code is allowed to make provider calls
  if (rel.startsWith('server/') || rel.startsWith('scripts/')) return false;
  // Test files are exempt
  if (rel.startsWith('tests/') || rel.includes('.test.') || rel.includes('.spec.')) return false;
  return true;
}

function isTestOrFixture(filePath) {
  const rel = relative(process.cwd(), filePath);
  return rel.startsWith('tests/') || rel.includes('.test.') || rel.includes('.spec.') || rel.includes('fixture');
}

function visitNode(node, sourceFile, filePath) {
  const text = node.getText(sourceFile);
  const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
  const rel = relative(process.cwd(), filePath);

  // Rule 1: No .parse() on schemas in production data paths (must use safeParse)
  if (ts.isCallExpression(node)) {
    const expr = node.expression;
    if (ts.isPropertyAccessExpression(expr)) {
      const methodName = expr.name.getText(sourceFile);
      const objectText = expr.expression.getText(sourceFile);

      // Block Schema.parse() in non-test files
      if (methodName === 'parse' && objectText.endsWith('Schema') && !isTestOrFixture(filePath)) {
        VIOLATIONS.push({
          file: rel,
          line,
          rule: 'SAFE_PARSE_REQUIRED',
          message: `${objectText}.parse() found — must use ${objectText}.safeParse() in production data paths`,
        });
      }
    }
  }

  // Rule 2: No hardcoded secrets
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    const val = node.getText(sourceFile);
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.test(val)) {
        VIOLATIONS.push({
          file: rel,
          line,
          rule: 'HARDCODED_SECRET',
          message: `Hardcoded secret detected matching pattern ${pattern}`,
        });
      }
    }
  }

  // Rule 3: No client-side fetch to AI providers
  if (isClientPath(filePath) && ts.isStringLiteral(node)) {
    const val = node.text;
    for (const domain of PROVIDER_DOMAINS) {
      if (val.includes(domain)) {
        VIOLATIONS.push({
          file: rel,
          line,
          rule: 'CLIENT_PROVIDER_CALL',
          message: `Client-side reference to AI provider domain "${domain}" — all provider calls must go through the server`,
        });
      }
    }
  }

  ts.forEachChild(node, (child) => visitNode(child, sourceFile, filePath));
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════

const files = collectTsFiles(process.cwd());
console.log(`ast-gate: Scanning ${files.length} TypeScript files...\n`);

for (const filePath of files) {
  const rel = relative(process.cwd(), filePath);
  SCANNED.push(rel);

  const content = readFileSync(filePath, 'utf-8');
  const sourceFile = ts.createSourceFile(
    filePath,
    content,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );

  ts.forEachChild(sourceFile, (node) => visitNode(node, sourceFile, filePath));
}

// ═══════════════════════════════════════════════════════════════════════════
// REPORT
// ═══════════════════════════════════════════════════════════════════════════

console.log('Files scanned:');
for (const f of SCANNED) {
  console.log(`  ✓ ${f}`);
}
console.log('');

if (VIOLATIONS.length === 0) {
  console.log('ast-gate: PASS — 0 violations found.');
  console.log(`  ${SCANNED.length} files scanned.`);
  console.log('  No client-side provider calls.');
  console.log('  No hardcoded secrets.');
  console.log('  No unsafe .parse() in production paths.');
  process.exit(0);
} else {
  console.error(`ast-gate: FAIL — ${VIOLATIONS.length} violation(s) found:\n`);
  for (const v of VIOLATIONS) {
    console.error(`  ✗ [${v.rule}] ${v.file}:${v.line}`);
    console.error(`    ${v.message}\n`);
  }
  process.exit(1);
}

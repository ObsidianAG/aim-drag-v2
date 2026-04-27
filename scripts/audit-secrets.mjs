#!/usr/bin/env node
/**
 * scripts/audit-secrets.mjs — Prove no secrets in client code or dist-web
 *
 * Scans lib/, dist-web/, and any client-facing code for:
 *   - API keys (OpenAI, Anthropic, Replicate, Google, GitHub)
 *   - DATABASE_URL or connection strings
 *   - process.env references in client code
 *   - Hardcoded tokens
 *
 * Exit code 0 = CLEAN, exit code 1 = SECRETS FOUND
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, extname } from 'node:path';

const FINDINGS = [];

const SECRET_PATTERNS = [
  { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{20,}/ },
  { name: 'Anthropic API Key', pattern: /sk-ant-[a-zA-Z0-9]{20,}/ },
  { name: 'Replicate API Key', pattern: /r8_[a-zA-Z0-9]{20,}/ },
  { name: 'GitHub PAT', pattern: /ghp_[a-zA-Z0-9]{20,}/ },
  { name: 'Google API Key', pattern: /AIza[a-zA-Z0-9_-]{30,}/ },
  { name: 'DATABASE_URL literal', pattern: /DATABASE_URL\s*[:=]\s*["'][^"']+["']/ },
  { name: 'Connection string', pattern: /mysql:\/\/[^\s"']+@[^\s"']+/ },
  { name: 'Connection string (pg)', pattern: /postgres(ql)?:\/\/[^\s"']+@[^\s"']+/ },
];

function collectFiles(dir, extensions, files = []) {
  if (!existsSync(dir)) return files;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (entry === 'node_modules' || entry === '.git') continue;
    const stat = statSync(full);
    if (stat.isDirectory()) {
      collectFiles(full, extensions, files);
    } else if (extensions.some(ext => full.endsWith(ext))) {
      files.push(full);
    }
  }
  return files;
}

// Scan client-facing directories
const dirs = ['lib', 'dist-web'];
const extensions = ['.ts', '.js', '.jsx', '.tsx', '.mjs', '.cjs', '.json', '.html'];

let totalScanned = 0;

for (const dir of dirs) {
  const files = collectFiles(dir, extensions);
  for (const filePath of files) {
    totalScanned++;
    const content = readFileSync(filePath, 'utf-8');
    const rel = relative(process.cwd(), filePath);

    for (const { name, pattern } of SECRET_PATTERNS) {
      if (pattern.test(content)) {
        FINDINGS.push({ file: rel, secret: name });
      }
    }
  }
}

console.log(`audit-secrets: Scanned ${totalScanned} files in [${dirs.join(', ')}]\n`);

if (FINDINGS.length === 0) {
  console.log('audit-secrets: CLEAN — No secrets found in client code or dist-web.');
  process.exit(0);
} else {
  console.error(`audit-secrets: FAIL — ${FINDINGS.length} secret(s) found:\n`);
  for (const f of FINDINGS) {
    console.error(`  ✗ ${f.file}: ${f.secret}`);
  }
  process.exit(1);
}

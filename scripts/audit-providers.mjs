#!/usr/bin/env node
/**
 * scripts/audit-providers.mjs -- Prove no direct client fetch to AI providers
 *
 * Scans lib/ and dist-web/ for any reference to AI provider endpoints.
 * Server code (server/) is ALLOWED to call providers.
 * Client code (lib/, dist-web/) is NOT.
 *
 * Exit code 0 = CLEAN, exit code 1 = PROVIDER CALLS FOUND
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, extname } from 'node:path';

const FINDINGS = [];

const PROVIDER_PATTERNS = [
  { name: 'OpenAI', pattern: /api\.openai\.com/ },
  { name: 'Anthropic', pattern: /api\.anthropic\.com/ },
  { name: 'Replicate', pattern: /api\.replicate\.com/ },
  { name: 'Google Generative AI', pattern: /generativelanguage\.googleapis\.com/ },
  { name: 'Stability AI', pattern: /api\.stability\.ai/ },
  { name: 'OpenAI SDK import', pattern: /from\s+['"]openai['"]/ },
  { name: 'Anthropic SDK import', pattern: /from\s+['"]@anthropic-ai\/sdk['"]/ },
  { name: 'Replicate SDK import', pattern: /from\s+['"]replicate['"]/ },
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

// Only scan client-facing directories
const dirs = ['lib', 'dist-web'];
const extensions = ['.ts', '.js', '.jsx', '.tsx', '.mjs', '.cjs'];

let totalScanned = 0;

for (const dir of dirs) {
  const files = collectFiles(dir, extensions);
  for (const filePath of files) {
    totalScanned++;
    const content = readFileSync(filePath, 'utf-8');
    const rel = relative(process.cwd(), filePath);

    for (const { name, pattern } of PROVIDER_PATTERNS) {
      if (pattern.test(content)) {
        FINDINGS.push({ file: rel, provider: name });
      }
    }
  }
}

console.log(`audit-providers: Scanned ${totalScanned} client-facing files in [${dirs.join(', ')}]\n`);

if (FINDINGS.length === 0) {
  console.log('audit-providers: CLEAN -- No direct client-side AI provider calls found.');
  process.exit(0);
} else {
  console.error(`audit-providers: FAIL -- ${FINDINGS.length} provider reference(s) found in client code:\n`);
  for (const f of FINDINGS) {
    console.error(`  ✗ ${f.file}: ${f.provider}`);
  }
  process.exit(1);
}

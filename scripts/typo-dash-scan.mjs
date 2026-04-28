#!/usr/bin/env node
/**
 * scripts/typo-dash-scan.mjs -- Typographic dash scan gate
 *
 * Scans package.json, tsconfig.json, scripts/, app/, components/, lib/, shared/, data/
 * for typographic dashes (en-dash U+2013, em-dash U+2014).
 *
 * Exit 0 = no typographic dashes found (PASS)
 * Exit 1 = typographic dashes found (FAIL)
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = process.cwd();

// Characters to scan for
const EN_DASH = '\u2013'; // U+2013
const EM_DASH = '\u2014'; // U+2014
const DASH_REGEX = /[\u2013\u2014]/g;

// Directories and files to scan
const SCAN_TARGETS = [
  'package.json',
  'tsconfig.json',
  'tsconfig.base.json',
  'tsconfig.build.json',
  'tsconfig.server.json',
  'tsconfig.test.json',
  'scripts',
  'app',
  'components',
  'lib',
  'shared',
  'data',
  'server',
];

// File extensions to scan
const SCAN_EXTENSIONS = new Set([
  '.json', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.md',
]);

function getFilesRecursive(dir) {
  const results = [];
  if (!existsSync(dir)) return results;

  const stat = statSync(dir);
  if (stat.isFile()) {
    results.push(dir);
    return results;
  }

  if (!stat.isDirectory()) return results;

  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    if (entry.isDirectory()) {
      results.push(...getFilesRecursive(fullPath));
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }
  return results;
}

let violations = [];

for (const target of SCAN_TARGETS) {
  const fullPath = join(ROOT, target);
  const files = getFilesRecursive(fullPath);

  for (const file of files) {
    const ext = file.slice(file.lastIndexOf('.'));
    if (!SCAN_EXTENSIONS.has(ext)) continue;

    let content;
    try {
      content = readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const matches = lines[i].match(DASH_REGEX);
      if (matches) {
        const relPath = relative(ROOT, file);
        for (const match of matches) {
          const charName = match === EN_DASH ? 'EN-DASH (U+2013)' : 'EM-DASH (U+2014)';
          violations.push({
            file: relPath,
            line: i + 1,
            char: charName,
            context: lines[i].trim().substring(0, 80),
          });
        }
      }
    }
  }
}

console.log('=== TYPOGRAPHIC DASH SCAN ===');
console.log(`Scanned targets: ${SCAN_TARGETS.join(', ')}`);
console.log(`Extensions: ${[...SCAN_EXTENSIONS].join(', ')}`);
console.log('');

if (violations.length === 0) {
  console.log('RESULT: PASS - No typographic dashes found');
  console.log('Exit code: 0');
  process.exit(0);
} else {
  console.log(`RESULT: FAIL - Found ${violations.length} typographic dash(es):`);
  console.log('');
  for (const v of violations) {
    console.log(`  ${v.file}:${v.line} [${v.char}]`);
    console.log(`    ${v.context}`);
  }
  console.log('');
  console.log('Exit code: 1');
  process.exit(1);
}

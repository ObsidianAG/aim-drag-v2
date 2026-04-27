#!/usr/bin/env node
/**
 * scripts/build-server.mjs — Build the custom Node server with esbuild
 *
 * Outputs a single file to dist-server/index.js.
 * Externalizes node: built-ins. Bundles everything else.
 */

import { build } from 'esbuild';
import { mkdirSync } from 'node:fs';

mkdirSync('dist-server', { recursive: true });

await build({
  entryPoints: ['server/index.ts'],
  outfile: 'dist-server/index.js',
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'esm',
  sourcemap: true,
  minify: false,
  external: ['node:*'],
  banner: {
    js: '// text2video-rank server — built by esbuild\n',
  },
});

console.log('build-server: dist-server/index.js written successfully.');

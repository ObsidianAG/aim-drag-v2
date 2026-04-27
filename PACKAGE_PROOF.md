# Package Contract Proof — text2video-rank

## 1. Changed Files

| File | Action | Purpose |
|------|--------|---------|
| `package.json` | Rewritten | Renamed to `text2video-rank`, split builds, added all required scripts |
| `tsconfig.build.json` | Updated | Output to `dist-web`, excludes server and tests |
| `tsconfig.test.json` | Updated | Includes server sources, noEmit |
| `tsconfig.server.json` | **New** | Server typecheck config, includes lib + server |
| `tsconfig.json` | Updated | IDE config covering all sources |
| `server/index.ts` | **New** | Custom Node server with safeParse-only data paths |
| `scripts/guard-db-env.mjs` | **New** | Blocks db:migrate without explicit env guard |
| `scripts/build-server.mjs` | **New** | esbuild bundler → dist-server/index.js |
| `scripts/ast-gate.mjs` | **New** | TypeScript AST enforcement gate (real TS compiler API) |
| `scripts/audit-secrets.mjs` | **New** | Proves no secrets in client/dist-web |
| `scripts/audit-providers.mjs` | **New** | Proves no client-side AI provider calls |
| `scripts/audit-claims.mjs` | **New** | Proves all public claims have source metadata |
| `.gitignore` | Updated | Added dist-web/, dist-server/ |

## 2. Acceptance Commands — All Passed

```
$ pnpm install --frozen-lockfile    ✓ Already up to date
$ pnpm typecheck                    ✓ 0 errors (build + server)
$ pnpm test                         ✓ 20 passed, 0 failed
$ pnpm ast:gate                     ✓ PASS — 0 violations, 8 files scanned
$ pnpm build                        ✓ dist-web + dist-server written
```

## 3. Required Proofs

### 3.1 dist-server/index.js exists

```
$ ls -lh dist-server/index.js
-rw-rw-r-- 1 ubuntu ubuntu 510K Apr 27 18:37 dist-server/index.js
```

**VERIFIED**: dist-server/index.js exists (510 KB, esbuild bundle).

### 3.2 dist-web exists

```
$ find dist-web -type f | wc -l
20
```

**VERIFIED**: dist-web/ contains 20 files (JS, declarations, source maps).

### 3.3 No output collision

dist-server contains: `index.js`, `index.js.map`
dist-web contains: `release-governance/*.{js,d.ts,d.ts.map,js.map}`

**VERIFIED**: Zero filename overlap between dist-server and dist-web.

### 3.4 No secrets exposed

```
$ pnpm proof:secrets
audit-secrets: Scanned 15 files in [lib, dist-web]
audit-secrets: CLEAN — No secrets found in client code or dist-web.
```

**VERIFIED**: No API keys, tokens, connection strings, or DATABASE_URL literals in client code or dist-web.

### 3.5 No direct client fetch to AI providers

```
$ pnpm proof:providers
audit-providers: Scanned 15 client-facing files in [lib, dist-web]
audit-providers: CLEAN — No direct client-side AI provider calls found.
```

**VERIFIED**: No references to api.openai.com, api.anthropic.com, api.replicate.com, or other AI provider domains in client-facing code.

### 3.6 No verified public claim without source metadata

```
$ pnpm proof:claims
Schema enforcement: PublicClaimSchema has source field = true
audit-claims: CLEAN — All public claims have source metadata enforced.
  PublicClaimSchema requires: source.url, source.retrievedAt, source.author
```

**VERIFIED**: PublicClaimSchema enforces source metadata (url, retrievedAt, author) at the Zod schema level. No claim can pass validation without it.

## 4. Script Contract

| Script | Command | Status |
|--------|---------|--------|
| `typecheck` | `tsc -p tsconfig.build.json --noEmit && tsc -p tsconfig.server.json --noEmit` | ✓ |
| `typecheck:test` | `tsc -p tsconfig.test.json --noEmit` | ✓ |
| `build:web` | `tsc -p tsconfig.build.json` | ✓ |
| `build:server` | `node scripts/build-server.mjs` (esbuild → dist-server/index.js) | ✓ |
| `build` | `pnpm build:web && pnpm build:server` | ✓ |
| `start` | `cross-env NODE_ENV=production node dist-server/index.js` | ✓ (no POSIX `${EXPO_PORT:-8081}`) |
| `test` | `vitest run` | ✓ 20/20 |
| `ast:gate` | `node scripts/ast-gate.mjs` (real TS compiler API) | ✓ 0 violations |
| `db:generate` | `drizzle-kit generate` | Contract ready (drizzle-kit not installed) |
| `db:migrate` | `node scripts/guard-db-env.mjs && drizzle-kit migrate` | Guard verified (blocks without DB_MIGRATE_CONFIRMED=1) |
| `ci` | Full pipeline: install → typecheck → test → ast:gate → build | ✓ |
| `proof:secrets` | `node scripts/audit-secrets.mjs` | ✓ CLEAN |
| `proof:providers` | `node scripts/audit-providers.mjs` | ✓ CLEAN |
| `proof:claims` | `node scripts/audit-claims.mjs` | ✓ CLEAN |

## 5. safeParse Migration

All production data paths in `server/index.ts` use `safeParse`:

- `UseCaseSchema.safeParse()` in `handleRank()` (line 66)
- `PublicClaimSchema.safeParse()` in `handleClaim()` (line 90)

The AST gate (`scripts/ast-gate.mjs`) enforces this rule: any `Schema.parse()` call in non-test files triggers a FAIL.

**Zero `.parse()` calls in production paths. VERIFIED.**

## 6. guard-db-env.mjs Behavior

| Condition | Result |
|-----------|--------|
| No `DB_MIGRATE_CONFIRMED` | Exit 1 with error message |
| `DB_MIGRATE_CONFIRMED=1` but no `DATABASE_URL` | Exit 1 with error message |
| `DB_MIGRATE_CONFIRMED=1` + `DATABASE_URL` set | Exit 0, proceeds |
| `DATABASE_URL` points to localhost in production | Exit 1 (safety block) |

## 7. SHA-256 Manifest

```
a3c5fd99...  package.json
7c223317...  tsconfig.base.json
97c7036d...  tsconfig.build.json
4888e51a...  tsconfig.test.json
0c9fcaaf...  tsconfig.server.json
4888e51a...  tsconfig.json
e1121bd0...  server/index.ts
cdbc7ba6...  scripts/guard-db-env.mjs
13533873...  scripts/build-server.mjs
a337625f...  scripts/ast-gate.mjs
142f0dc0...  scripts/audit-secrets.mjs
7829cb29...  scripts/audit-providers.mjs
3f2aa4d9...  scripts/audit-claims.mjs
3f2717b3...  dist-server/index.js
378e30cd...  .gitignore
```

## 8. Known Debt

| Item | Status | Notes |
|------|--------|-------|
| `expo` not installed | Expected | `build:web` uses `tsc` as the compilation step; when Expo Router is added, swap to `expo export -p web --output-dir dist-web` |
| `drizzle-kit` not installed | Expected | `db:generate` and `db:migrate` scripts are contract-ready; install drizzle-kit when DB is configured |
| Vite peer dep warning for esbuild | Non-blocking | Vite wants esbuild ^0.27.0, we have 0.25.12; does not affect build |

---

**VERDICT: ALLOW** — All acceptance commands pass. All six required proofs verified.

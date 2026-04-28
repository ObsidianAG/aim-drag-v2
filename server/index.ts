/**
 * server/index.ts -- Custom Node server for text2video-rank
 *
 * Production entry point. All AI provider calls happen server-side only.
 * No secrets are exposed to the client/dist-web bundle.
 *
 * SECURITY INVARIANTS:
 *   - No client-side provider calls (OpenAI, Anthropic, Replicate, etc.)
 *   - No secrets in dist-web
 *   - All public claims carry source metadata
 *   - safeParse everywhere in production data paths (never .parse())
 *   - Fail-closed: unknown state → FAIL_CLOSED
 *   - Every state transition needs CAS guard
 *   - No video becomes real until: generated, downloaded, hashed, stored, audited, shown with proof
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { z } from 'zod';
import {
  ReleaseStateMachine,
  ReleasePhase,
  ReleaseStage,
} from '../lib/release-governance/index.js';
import {
  handleCreateVideoJob,
  handleGetVideoJob,
  handleGetArtifact,
  extractJobIdFromPath,
  isArtifactPath,
} from './job-api.js';

// ═══════════════════════════════════════════════════════════════════════════
// SCHEMA DEFINITIONS -- safeParse only in production data paths
// ═══════════════════════════════════════════════════════════════════════════

/**
 * UseCaseSchema -- validated with safeParse (never .parse) in production.
 */
export const UseCaseSchema = z.object({
  id: z.string().uuid(),
  prompt: z.string().min(1).max(2000),
  model: z.enum(['text2video-v1', 'text2video-v2', 'text2video-rank']),
  parameters: z.object({
    duration: z.number().int().min(1).max(120),
    resolution: z.enum(['720p', '1080p', '4k']),
    fps: z.number().int().min(15).max(60),
  }),
});

export type UseCase = z.infer<typeof UseCaseSchema>;

/**
 * PublicClaimSchema -- every public claim MUST have source metadata.
 */
export const PublicClaimSchema = z.object({
  claim: z.string().min(1),
  source: z.object({
    url: z.string().url(),
    retrievedAt: z.string().datetime(),
    author: z.string().min(1),
  }),
  confidence: z.number().min(0).max(1),
  verified: z.boolean(),
});

export type PublicClaim = z.infer<typeof PublicClaimSchema>;

// ═══════════════════════════════════════════════════════════════════════════
// LEGACY REQUEST HANDLERS -- safeParse everywhere
// ═══════════════════════════════════════════════════════════════════════════

function handleRank(body: string): { status: number; body: string } {
  const parsed = UseCaseSchema.safeParse(JSON.parse(body));
  if (!parsed.success) {
    return {
      status: 400,
      body: JSON.stringify({
        error: 'VALIDATION_FAILED',
        issues: parsed.error.issues,
      }),
    };
  }

  const useCase = parsed.data;
  return {
    status: 200,
    body: JSON.stringify({
      id: useCase.id,
      rank: 1,
      model: useCase.model,
      status: 'queued',
    }),
  };
}

function handleClaim(body: string): { status: number; body: string } {
  const parsed = PublicClaimSchema.safeParse(JSON.parse(body));
  if (!parsed.success) {
    return {
      status: 400,
      body: JSON.stringify({
        error: 'CLAIM_VALIDATION_FAILED',
        issues: parsed.error.issues,
      }),
    };
  }

  return {
    status: 200,
    body: JSON.stringify({
      accepted: true,
      claim: parsed.data.claim,
      source: parsed.data.source,
    }),
  };
}

function handleHealth(): { status: number; body: string } {
  return {
    status: 200,
    body: JSON.stringify({
      status: 'healthy',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
    }),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// SERVER BOOTSTRAP
// ═══════════════════════════════════════════════════════════════════════════

const PORT = parseInt(process.env['PORT'] ?? '3000', 10);

function collectBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = req.url ?? '/';
  const method = req.method ?? 'GET';

  let result: { status: number; body: string };

  try {
    // ─── Health ─────────────────────────────────────────────────────
    if (url === '/health' && method === 'GET') {
      result = handleHealth();

    // ─── Legacy routes ──────────────────────────────────────────────
    } else if (url === '/api/rank' && method === 'POST') {
      const body = await collectBody(req);
      result = handleRank(body);
    } else if (url === '/api/claim' && method === 'POST') {
      const body = await collectBody(req);
      result = handleClaim(body);

    // ─── Video Job API ──────────────────────────────────────────────
    } else if (url === '/api/video-jobs' && method === 'POST') {
      const body = await collectBody(req);
      result = handleCreateVideoJob(body);
    } else if (url.startsWith('/api/video-jobs/') && method === 'GET') {
      const jobId = extractJobIdFromPath(url);
      if (!jobId) {
        result = { status: 400, body: JSON.stringify({ error: 'INVALID_PATH' }) };
      } else if (isArtifactPath(url)) {
        result = handleGetArtifact(jobId);
      } else {
        result = handleGetVideoJob(jobId);
      }

    // ─── 404 ────────────────────────────────────────────────────────
    } else {
      result = { status: 404, body: JSON.stringify({ error: 'NOT_FOUND' }) };
    }
  } catch (err) {
    result = {
      status: 500,
      body: JSON.stringify({ error: 'INTERNAL_ERROR' }),
    };
  }

  res.writeHead(result.status, { 'Content-Type': 'application/json' });
  res.end(result.body);
}

const server = createServer(handler);

server.listen(PORT, () => {
  console.log(`text2video-rank server listening on port ${PORT}`);
});

export { server };

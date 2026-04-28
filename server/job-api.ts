/**
 * server/job-api.ts -- Job API Routes for Text2VideoRank
 *
 * POST /api/video-jobs        -- create a video job
 * GET  /api/video-jobs/:jobId -- get job status
 * GET  /api/video-jobs/:jobId/artifact -- get artifact URL
 *
 * All routes use safeParse at entry boundary.
 * AIM DRAG: observe → decide → enforce → prove
 */

import { randomUUID } from 'node:crypto';
import {
  CreateVideoJobRequestSchema,
  VideoJobSchema,
} from './video-types.js';
import type { VideoJob, CreateVideoJobRequest } from './video-types.js';
import { selectProvider } from './provider-router.js';
import { storeJob, getJob, processJob, getEvidence } from './worker-pipeline.js';

// ═══════════════════════════════════════════════════════════════════════════
// ROUTE HANDLERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * POST /api/video-jobs -- Create a new video job.
 * Uses safeParse at entry boundary.
 */
export function handleCreateVideoJob(body: string): { status: number; body: string } {
  // safeParse at entry boundary -- never .parse()
  let rawBody: unknown;
  try {
    rawBody = JSON.parse(body);
  } catch {
    return {
      status: 400,
      body: JSON.stringify({ error: 'INVALID_JSON', message: 'Request body is not valid JSON' }),
    };
  }

  const parsed = CreateVideoJobRequestSchema.safeParse(rawBody);
  if (!parsed.success) {
    return {
      status: 400,
      body: JSON.stringify({
        error: 'VALIDATION_FAILED',
        issues: parsed.error.issues,
      }),
    };
  }

  const request = parsed.data;

  // Select provider
  const selection = selectProvider({
    qualityTier: request.qualityTier,
    aspectRatio: request.aspectRatio,
    durationSeconds: request.durationSeconds,
    needsAudio: false,
    needsEnterpriseControls: false,
    preferredProvider: request.preferredProvider,
  });

  // Create job
  const now = new Date().toISOString();
  const job: VideoJob = {
    jobId: randomUUID(),
    status: 'queued',
    provider: selection.provider,
    model: selection.model,
    userPrompt: request.prompt,
    rewrittenPrompt: '',
    decision: 'ALLOW',
    createdAt: now,
    updatedAt: now,
    casVersion: 0,
  };

  // Validate job with safeParse before storing
  const jobParsed = VideoJobSchema.safeParse(job);
  if (!jobParsed.success) {
    return {
      status: 500,
      body: JSON.stringify({
        error: 'INTERNAL_VALIDATION_FAILED',
        message: 'Job creation produced invalid data',
      }),
    };
  }

  storeJob(jobParsed.data);

  // Kick off async processing (fire and forget)
  void processJob(jobParsed.data.jobId);

  return {
    status: 201,
    body: JSON.stringify({
      jobId: jobParsed.data.jobId,
      status: jobParsed.data.status,
      provider: jobParsed.data.provider,
      model: jobParsed.data.model,
      createdAt: jobParsed.data.createdAt,
    }),
  };
}

/**
 * GET /api/video-jobs/:jobId -- Get job status.
 */
export function handleGetVideoJob(jobId: string): { status: number; body: string } {
  if (!jobId) {
    return {
      status: 400,
      body: JSON.stringify({ error: 'MISSING_JOB_ID' }),
    };
  }

  const job = getJob(jobId);
  if (!job) {
    return {
      status: 404,
      body: JSON.stringify({ error: 'JOB_NOT_FOUND', jobId }),
    };
  }

  const evidence = getEvidence(jobId);

  return {
    status: 200,
    body: JSON.stringify({
      jobId: job.jobId,
      status: job.status,
      provider: job.provider,
      model: job.model,
      decision: job.decision,
      artifactUrl: job.artifactUrl,
      artifactSha256: job.artifactSha256,
      createdAt: job.createdAt,
      updatedAt: job.updatedAt,
      hasEvidence: !!evidence,
    }),
  };
}

/**
 * GET /api/video-jobs/:jobId/artifact -- Get artifact URL.
 * Only returns artifact if job is completed with full proof chain.
 */
export function handleGetArtifact(jobId: string): { status: number; body: string } {
  if (!jobId) {
    return {
      status: 400,
      body: JSON.stringify({ error: 'MISSING_JOB_ID' }),
    };
  }

  const job = getJob(jobId);
  if (!job) {
    return {
      status: 404,
      body: JSON.stringify({ error: 'JOB_NOT_FOUND', jobId }),
    };
  }

  // AIM DRAG: No video becomes real until completed with proof
  if (job.status !== 'completed') {
    return {
      status: 409,
      body: JSON.stringify({
        error: 'JOB_NOT_COMPLETED',
        status: job.status,
        message: 'Artifact is only available after job is completed with full proof chain',
      }),
    };
  }

  const evidence = getEvidence(jobId);
  if (!evidence) {
    // Fail-closed: no evidence = no artifact
    return {
      status: 409,
      body: JSON.stringify({
        error: 'NO_EVIDENCE',
        message: 'Artifact cannot be served without evidence record (AIM DRAG policy)',
      }),
    };
  }

  if (!job.artifactUrl || !job.artifactSha256) {
    return {
      status: 409,
      body: JSON.stringify({
        error: 'ARTIFACT_MISSING',
        message: 'Artifact URL or hash is missing',
      }),
    };
  }

  return {
    status: 200,
    body: JSON.stringify({
      jobId: job.jobId,
      artifactUrl: job.artifactUrl,
      artifactSha256: job.artifactSha256,
      provider: job.provider,
      model: job.model,
      evidence: {
        storagePath: evidence.storagePath,
        finalDecision: evidence.finalDecision,
        createdAt: evidence.createdAt,
      },
    }),
  };
}

/**
 * Extract jobId from URL path.
 * Handles: /api/video-jobs/:jobId and /api/video-jobs/:jobId/artifact
 */
export function extractJobIdFromPath(path: string): string | null {
  const match = /^\/api\/video-jobs\/([^/]+)/.exec(path);
  return match?.[1] ?? null;
}

/**
 * Check if path is an artifact request.
 */
export function isArtifactPath(path: string): boolean {
  return /^\/api\/video-jobs\/[^/]+\/artifact$/.test(path);
}

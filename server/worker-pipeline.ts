/**
 * server/worker-pipeline.ts -- Async Worker Pipeline for Text2VideoRank
 *
 * Job processing: queue → plan → submit → poll → download → hash → store → audit → complete
 *
 * AIM DRAG RULES:
 *   - Each state transition is CAS-guarded
 *   - SHA-256 hash on every artifact
 *   - Evidence record for every job
 *   - No video becomes real until: generated, downloaded, hashed, stored, audited, shown with proof
 *   - Fail-closed: unknown state → FAIL_CLOSED
 */

import { createHash } from 'node:crypto';
import type {
  VideoJob,
  VideoJobStatus,
  EvidenceRecord,
  ClaimAudit,
  SafetyCheck,
} from './video-types.js';
import { VideoJobSchema, EvidenceRecordSchema } from './video-types.js';
import { planPrompt } from './vllm-planner.js';
import {
  selectProvider,
  getAdapter,
  recordProviderSuccess,
  recordProviderFailure,
} from './provider-router.js';
import { scanPromptSafety, safetyToDecision } from './safety-gate.js';
import { downloadArtifact, hashArtifact, storeArtifact, verifyStoredArtifact } from './artifact-storage.js';

// ═══════════════════════════════════════════════════════════════════════════
// VALID STATE TRANSITIONS
// ═══════════════════════════════════════════════════════════════════════════

const VALID_TRANSITIONS: Record<VideoJobStatus, readonly VideoJobStatus[]> = {
  queued: ['planning', 'failed'],
  planning: ['submitted', 'held', 'failed'],
  submitted: ['generating', 'failed'],
  generating: ['provider_completed', 'failed'],
  provider_completed: ['downloading', 'failed'],
  downloading: ['storing', 'failed'],
  storing: ['verifying', 'failed'],
  verifying: ['completed', 'held', 'failed'],
  completed: [],
  held: ['failed'],
  failed: [],
};

// ═══════════════════════════════════════════════════════════════════════════
// JOB STORE (in-memory for now)
// ═══════════════════════════════════════════════════════════════════════════

const jobStore = new Map<string, VideoJob>();
const evidenceStore = new Map<string, EvidenceRecord>();

export function getJob(jobId: string): VideoJob | undefined {
  return jobStore.get(jobId);
}

export function getAllJobs(): VideoJob[] {
  return Array.from(jobStore.values());
}

export function getEvidence(jobId: string): EvidenceRecord | undefined {
  return evidenceStore.get(jobId);
}

export function storeJob(job: VideoJob): void {
  jobStore.set(job.jobId, job);
}

/** Reset stores (for testing) */
export function resetStores(): void {
  jobStore.clear();
  evidenceStore.clear();
}

// ═══════════════════════════════════════════════════════════════════════════
// CAS-GUARDED STATE TRANSITION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Compare-and-swap state transition.
 * Only succeeds if:
 *   1. Job exists
 *   2. Current casVersion matches expectedVersion
 *   3. Transition is valid according to VALID_TRANSITIONS
 *
 * Returns updated job or error.
 */
export function casTransition(
  jobId: string,
  expectedVersion: number,
  newStatus: VideoJobStatus,
  updates?: Partial<Omit<VideoJob, 'jobId' | 'status' | 'casVersion' | 'createdAt'>>,
): { success: true; job: VideoJob } | { success: false; error: string } {
  const job = jobStore.get(jobId);
  if (!job) {
    return { success: false, error: `JOB_NOT_FOUND: ${jobId}` };
  }

  // CAS check
  if (job.casVersion !== expectedVersion) {
    return {
      success: false,
      error: `CAS_CONFLICT: expected version ${expectedVersion}, got ${job.casVersion}`,
    };
  }

  // Validate transition
  const allowed = VALID_TRANSITIONS[job.status];
  if (!allowed || !allowed.includes(newStatus)) {
    return {
      success: false,
      error: `INVALID_TRANSITION: ${job.status} → ${newStatus} is not allowed`,
    };
  }

  // Apply transition
  const updatedJob: VideoJob = {
    ...job,
    ...updates,
    status: newStatus,
    casVersion: job.casVersion + 1,
    updatedAt: new Date().toISOString(),
  };

  jobStore.set(jobId, updatedJob);
  return { success: true, job: updatedJob };
}

// ═══════════════════════════════════════════════════════════════════════════
// WORKER PIPELINE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Process a video job through the full pipeline:
 * queue → plan → submit → poll → download → hash → store → audit → complete
 *
 * Each step is CAS-guarded. Failures transition to 'failed'.
 */
export async function processJob(jobId: string): Promise<{
  success: boolean;
  job: VideoJob;
  evidence?: EvidenceRecord;
  error?: string;
}> {
  const job = jobStore.get(jobId);
  if (!job) {
    return { success: false, job: createFailedStub(jobId), error: 'JOB_NOT_FOUND' };
  }

  if (job.status !== 'queued') {
    return { success: false, job, error: `INVALID_START_STATE: expected queued, got ${job.status}` };
  }

  let currentJob = job;

  try {
    // ─── Step 1: Plan ───────────────────────────────────────────────
    const planResult = casTransition(jobId, currentJob.casVersion, 'planning');
    if (!planResult.success) return { success: false, job: currentJob, error: planResult.error };
    currentJob = planResult.job;

    const planOutput = planPrompt({
      userPrompt: currentJob.userPrompt,
      aspectRatio: '16:9',
      durationSeconds: 4,
      qualityTier: 'standard',
    });

    if (!planOutput.success) {
      const failResult = casTransition(jobId, currentJob.casVersion, 'failed');
      return { success: false, job: failResult.success ? failResult.job : currentJob, error: planOutput.error };
    }

    // Check safety decision
    if (planOutput.data.decision !== 'ALLOW') {
      const holdStatus: VideoJobStatus = planOutput.data.decision === 'HOLD' ? 'held' : 'failed';
      const holdResult = casTransition(jobId, currentJob.casVersion, holdStatus, {
        decision: planOutput.data.decision,
        rewrittenPrompt: planOutput.data.rewritten_prompt,
      });
      return {
        success: false,
        job: holdResult.success ? holdResult.job : currentJob,
        error: `SAFETY_${planOutput.data.decision}: ${planOutput.data.reason}`,
      };
    }

    // ─── Step 2: Submit to provider ─────────────────────────────────
    const submitResult = casTransition(jobId, currentJob.casVersion, 'submitted', {
      rewrittenPrompt: planOutput.data.rewritten_prompt,
      decision: 'ALLOW',
    });
    if (!submitResult.success) return { success: false, job: currentJob, error: submitResult.error };
    currentJob = submitResult.job;

    const adapter = getAdapter(currentJob.provider);
    const providerResponse = await adapter.submitJob({
      prompt: currentJob.rewrittenPrompt,
      aspectRatio: '16:9',
      durationSeconds: 4,
      qualityTier: 'standard',
      model: currentJob.model,
    });

    if (providerResponse.status !== 'accepted') {
      recordProviderFailure(currentJob.provider);
      const failResult = casTransition(jobId, currentJob.casVersion, 'failed');
      return { success: false, job: failResult.success ? failResult.job : currentJob, error: 'PROVIDER_REJECTED' };
    }

    // ─── Step 3: Generating ─────────────────────────────────────────
    const genResult = casTransition(jobId, currentJob.casVersion, 'generating', {
      providerJobId: providerResponse.providerJobId,
    });
    if (!genResult.success) return { success: false, job: currentJob, error: genResult.error };
    currentJob = genResult.job;

    // ─── Step 4: Poll for completion ────────────────────────────────
    const statusResponse = await adapter.pollStatus(providerResponse.providerJobId);

    if (statusResponse.status !== 'completed' || !statusResponse.artifactUrl) {
      recordProviderFailure(currentJob.provider);
      const failResult = casTransition(jobId, currentJob.casVersion, 'failed');
      return {
        success: false,
        job: failResult.success ? failResult.job : currentJob,
        error: `PROVIDER_${statusResponse.status.toUpperCase()}`,
      };
    }

    recordProviderSuccess(currentJob.provider);

    const completedResult = casTransition(jobId, currentJob.casVersion, 'provider_completed');
    if (!completedResult.success) return { success: false, job: currentJob, error: completedResult.error };
    currentJob = completedResult.job;

    // ─── Step 5: Download ───────────────────────────────────────────
    const dlResult = casTransition(jobId, currentJob.casVersion, 'downloading');
    if (!dlResult.success) return { success: false, job: currentJob, error: dlResult.error };
    currentJob = dlResult.job;

    const artifactData = await downloadArtifact(statusResponse.artifactUrl);

    // ─── Step 6: Hash ───────────────────────────────────────────────
    const sha256 = hashArtifact(artifactData);

    // ─── Step 7: Store ──────────────────────────────────────────────
    const storeResult = casTransition(jobId, currentJob.casVersion, 'storing', {
      artifactSha256: sha256,
    });
    if (!storeResult.success) return { success: false, job: currentJob, error: storeResult.error };
    currentJob = storeResult.job;

    const storagePath = await storeArtifact(jobId, artifactData, sha256);

    // ─── Step 8: Verify ─────────────────────────────────────────────
    const verifyResult = casTransition(jobId, currentJob.casVersion, 'verifying', {
      artifactUrl: storagePath,
    });
    if (!verifyResult.success) return { success: false, job: currentJob, error: verifyResult.error };
    currentJob = verifyResult.job;

    const verified = await verifyStoredArtifact(storagePath, sha256);
    if (!verified) {
      const failResult = casTransition(jobId, currentJob.casVersion, 'failed');
      return {
        success: false,
        job: failResult.success ? failResult.job : currentJob,
        error: 'ARTIFACT_VERIFICATION_FAILED: stored hash does not match',
      };
    }

    // ─── Step 9: Build evidence record ──────────────────────────────
    const evidence: EvidenceRecord = {
      jobId,
      originalPrompt: currentJob.userPrompt,
      rewrittenPrompt: currentJob.rewrittenPrompt,
      provider: currentJob.provider,
      model: currentJob.model,
      providerJobId: providerResponse.providerJobId,
      artifactSha256: sha256,
      storagePath,
      claimAuditResult: planOutput.data.claim_audit,
      safetyResult: planOutput.data.safety,
      finalDecision: 'ALLOW',
      createdAt: new Date().toISOString(),
    };

    // Validate evidence with safeParse
    const evidenceParsed = EvidenceRecordSchema.safeParse(evidence);
    if (!evidenceParsed.success) {
      const failResult = casTransition(jobId, currentJob.casVersion, 'failed');
      return {
        success: false,
        job: failResult.success ? failResult.job : currentJob,
        error: `EVIDENCE_VALIDATION_FAILED: ${evidenceParsed.error.message}`,
      };
    }

    evidenceStore.set(jobId, evidenceParsed.data);

    // ─── Step 10: Complete ──────────────────────────────────────────
    const completeResult = casTransition(jobId, currentJob.casVersion, 'completed');
    if (!completeResult.success) return { success: false, job: currentJob, error: completeResult.error };
    currentJob = completeResult.job;

    return { success: true, job: currentJob, evidence: evidenceParsed.data };
  } catch (err) {
    // AIM DRAG: Fail-closed on unknown errors
    const failResult = casTransition(jobId, currentJob.casVersion, 'failed');
    return {
      success: false,
      job: failResult.success ? failResult.job : currentJob,
      error: `PIPELINE_ERROR: ${err instanceof Error ? err.message : 'unknown error'}`,
    };
  }
}

function createFailedStub(jobId: string): VideoJob {
  return {
    jobId,
    status: 'failed',
    provider: 'fallback',
    model: 'none',
    userPrompt: '',
    rewrittenPrompt: '',
    decision: 'FAIL_CLOSED',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    casVersion: 0,
  };
}

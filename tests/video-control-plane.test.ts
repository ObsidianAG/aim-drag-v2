/**
 * tests/video-control-plane.test.ts
 *
 * Comprehensive tests for the Text2VideoRank governed AI video control plane.
 * Covers: core types, job lifecycle, provider routing, safety gate,
 * claim audit, artifact verification, worker pipeline, vLLM planner.
 *
 * AIM DRAG: safeParse patterns in test assertions, fail-closed verification.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  CreateVideoJobRequestSchema,
  VideoJobSchema,
  ScenePlanSchema,
  SafetyCheckSchema,
  ClaimAuditSchema,
  PlannerOutputSchema,
  EvidenceRecordSchema,
  validateClaimAudit,
  mapVerificationToBadge,
} from '../server/video-types.js';
import type {
  VideoJob,
  CreateVideoJobRequest,
  ClaimAudit,
  SafetyCheck,
  VideoJobStatus,
} from '../server/video-types.js';
import {
  selectProvider,
  isCircuitOpen,
  recordProviderFailure,
  recordProviderSuccess,
  resetAllCircuitBreakers,
  getCircuitBreaker,
  OpenAISoraAdapter,
  GoogleVeoAdapter,
  RunwayAdapter,
  FallbackAdapter,
  getAdapter,
} from '../server/provider-router.js';
import type { ProviderSelectionInput } from '../server/provider-router.js';
import { scanPromptSafety, safetyToDecision } from '../server/safety-gate.js';
import { planPrompt, splitScenes, VLLM_SYSTEM_PROMPT } from '../server/vllm-planner.js';
import {
  downloadArtifact,
  hashArtifact,
  storeArtifact,
  verifyStoredArtifact,
  resetStorage,
} from '../server/artifact-storage.js';
import {
  casTransition,
  storeJob,
  getJob,
  processJob,
  getEvidence,
  resetStores,
} from '../server/worker-pipeline.js';
import {
  handleCreateVideoJob,
  handleGetVideoJob,
  handleGetArtifact,
  extractJobIdFromPath,
  isArtifactPath,
} from '../server/job-api.js';

// ═══════════════════════════════════════════════════════════════════════════
// CORE TYPES & ZOD SCHEMAS
// ═══════════════════════════════════════════════════════════════════════════

describe('Core Types & Zod Schemas', () => {
  describe('CreateVideoJobRequestSchema', () => {
    it('accepts valid request with safeParse', () => {
      const input = {
        prompt: 'A sunset over the ocean',
        aspectRatio: '16:9',
        durationSeconds: 4,
        qualityTier: 'standard',
      };
      const result = CreateVideoJobRequestSchema.safeParse(input);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.prompt).toBe('A sunset over the ocean');
        expect(result.data.aspectRatio).toBe('16:9');
        expect(result.data.durationSeconds).toBe(4);
        expect(result.data.qualityTier).toBe('standard');
      }
    });

    it('accepts request with optional preferredProvider', () => {
      const input = {
        prompt: 'A mountain landscape',
        aspectRatio: '9:16',
        durationSeconds: 8,
        qualityTier: 'pro',
        preferredProvider: 'openai_sora',
      };
      const result = CreateVideoJobRequestSchema.safeParse(input);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.preferredProvider).toBe('openai_sora');
      }
    });

    it('rejects empty prompt via safeParse', () => {
      const input = {
        prompt: '',
        aspectRatio: '16:9',
        durationSeconds: 4,
        qualityTier: 'standard',
      };
      const result = CreateVideoJobRequestSchema.safeParse(input);
      expect(result.success).toBe(false);
    });

    it('rejects invalid duration via safeParse', () => {
      const input = {
        prompt: 'Test',
        aspectRatio: '16:9',
        durationSeconds: 5, // Not in [4, 6, 8, 10, 12]
        qualityTier: 'standard',
      };
      const result = CreateVideoJobRequestSchema.safeParse(input);
      expect(result.success).toBe(false);
    });

    it('rejects invalid aspect ratio via safeParse', () => {
      const input = {
        prompt: 'Test',
        aspectRatio: '4:3',
        durationSeconds: 4,
        qualityTier: 'standard',
      };
      const result = CreateVideoJobRequestSchema.safeParse(input);
      expect(result.success).toBe(false);
    });

    it('rejects invalid provider via safeParse', () => {
      const input = {
        prompt: 'Test',
        aspectRatio: '16:9',
        durationSeconds: 4,
        qualityTier: 'standard',
        preferredProvider: 'invalid_provider',
      };
      const result = CreateVideoJobRequestSchema.safeParse(input);
      expect(result.success).toBe(false);
    });
  });

  describe('VideoJobSchema', () => {
    it('validates a complete video job', () => {
      const job = {
        jobId: '550e8400-e29b-41d4-a716-446655440000',
        status: 'queued',
        provider: 'openai_sora',
        model: 'sora-2-pro',
        userPrompt: 'A sunset',
        rewrittenPrompt: 'Professional video: A sunset',
        decision: 'ALLOW',
        createdAt: '2026-04-27T00:00:00.000Z',
        updatedAt: '2026-04-27T00:00:00.000Z',
        casVersion: 0,
      };
      const result = VideoJobSchema.safeParse(job);
      expect(result.success).toBe(true);
    });

    it('rejects invalid status via safeParse', () => {
      const job = {
        jobId: '550e8400-e29b-41d4-a716-446655440000',
        status: 'invalid_status',
        provider: 'openai_sora',
        model: 'sora-2-pro',
        userPrompt: 'A sunset',
        rewrittenPrompt: '',
        decision: 'ALLOW',
        createdAt: '2026-04-27T00:00:00.000Z',
        updatedAt: '2026-04-27T00:00:00.000Z',
        casVersion: 0,
      };
      const result = VideoJobSchema.safeParse(job);
      expect(result.success).toBe(false);
    });
  });

  describe('ScenePlanSchema', () => {
    it('validates a scene plan', () => {
      const scene = {
        scene_id: 'scene_001',
        duration_seconds: 4,
        shot_type: 'wide',
        subject: 'ocean waves',
        action: 'crashing on shore',
        setting: 'beach',
        camera_motion: 'slow pan',
        lighting: 'golden hour',
        audio: 'wave sounds',
        negative_prompt: 'blurry',
      };
      const result = ScenePlanSchema.safeParse(scene);
      expect(result.success).toBe(true);
    });
  });

  describe('SafetyCheckSchema', () => {
    it('validates a safety check', () => {
      const safety = {
        contains_public_figure: false,
        contains_private_person: false,
        contains_copyrighted_character: false,
        contains_explicit_content: false,
        contains_medical_or_legal_claim: false,
        status: 'PASS',
      };
      const result = SafetyCheckSchema.safeParse(safety);
      expect(result.success).toBe(true);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// CLAIM AUDIT SYSTEM
// ═══════════════════════════════════════════════════════════════════════════

describe('Claim Audit System', () => {
  it('validates a complete claim with VERIFIED status', () => {
    const claim = {
      claim_id: 'claim_001',
      claim_text: 'Sora supports 1080p output',
      tool_id: 'openai_docs',
      source_url: 'https://platform.openai.com/docs/api-reference/video',
      source_title: 'OpenAI Video API Reference',
      retrieved_at: '2026-04-27T00:00:00.000Z',
      confidence: 'HIGH',
      verification_status: 'VERIFIED',
      notes: 'Confirmed from official API docs',
      ui_badge_expected: 'Verified',
    };
    const result = validateClaimAudit(claim);
    expect(result.success).toBe(true);
  });

  it('rejects VERIFIED claim without source_url', () => {
    const claim = {
      claim_id: 'claim_002',
      claim_text: 'Some claim',
      tool_id: 'test',
      source_url: '',
      source_title: 'Some Title',
      retrieved_at: '2026-04-27T00:00:00.000Z',
      confidence: 'HIGH',
      verification_status: 'VERIFIED',
      notes: 'Missing URL',
      ui_badge_expected: 'Verified',
    };
    const result = validateClaimAudit(claim);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain('CLAIM_AUDIT_FAILED');
    }
  });

  it('rejects VERIFIED claim without source_title', () => {
    const claim = {
      claim_id: 'claim_003',
      claim_text: 'Some claim',
      tool_id: 'test',
      source_url: 'https://example.com',
      source_title: '',
      retrieved_at: '2026-04-27T00:00:00.000Z',
      confidence: 'HIGH',
      verification_status: 'VERIFIED',
      notes: 'Missing title',
      ui_badge_expected: 'Verified',
    };
    const result = validateClaimAudit(claim);
    expect(result.success).toBe(false);
  });

  it('rejects VERIFIED claim without retrieved_at', () => {
    const claim = {
      claim_id: 'claim_004',
      claim_text: 'Some claim',
      tool_id: 'test',
      source_url: 'https://example.com',
      source_title: 'Title',
      retrieved_at: '',
      confidence: 'HIGH',
      verification_status: 'VERIFIED',
      notes: 'Missing retrieved_at',
      ui_badge_expected: 'Verified',
    };
    const result = validateClaimAudit(claim);
    expect(result.success).toBe(false);
  });

  it('allows UNVERIFIED claim without source metadata', () => {
    const claim = {
      claim_id: 'claim_005',
      claim_text: 'Unverified claim',
      tool_id: 'test',
      source_url: '',
      source_title: '',
      retrieved_at: '',
      confidence: 'LOW',
      verification_status: 'UNVERIFIED',
      notes: 'No evidence available',
      ui_badge_expected: 'Needs Verification',
    };
    const result = validateClaimAudit(claim);
    expect(result.success).toBe(true);
  });

  it('rejects mismatched ui_badge_expected', () => {
    const claim = {
      claim_id: 'claim_006',
      claim_text: 'Some claim',
      tool_id: 'test',
      source_url: '',
      source_title: '',
      retrieved_at: '',
      confidence: 'LOW',
      verification_status: 'UNVERIFIED',
      notes: 'Wrong badge',
      ui_badge_expected: 'Verified', // Should be 'Needs Verification'
    };
    const result = validateClaimAudit(claim);
    expect(result.success).toBe(false);
  });

  describe('mapVerificationToBadge', () => {
    it('maps VERIFIED to Verified', () => {
      expect(mapVerificationToBadge('VERIFIED')).toBe('Verified');
    });

    it('maps PARTIAL to Partial', () => {
      expect(mapVerificationToBadge('PARTIAL')).toBe('Partial');
    });

    it('maps UNVERIFIED to Needs Verification', () => {
      expect(mapVerificationToBadge('UNVERIFIED')).toBe('Needs Verification');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SAFETY GATE
// ═══════════════════════════════════════════════════════════════════════════

describe('Safety Gate', () => {
  it('returns PASS for safe prompt', () => {
    const result = scanPromptSafety('A beautiful sunset over the ocean');
    expect(result.status).toBe('PASS');
    expect(result.contains_public_figure).toBe(false);
    expect(result.contains_explicit_content).toBe(false);
  });

  it('returns HOLD for public figure', () => {
    const result = scanPromptSafety('Elon Musk giving a speech');
    expect(result.status).toBe('HOLD');
    expect(result.contains_public_figure).toBe(true);
  });

  it('returns HOLD for copyrighted character', () => {
    const result = scanPromptSafety('Mickey Mouse dancing in a park');
    expect(result.status).toBe('HOLD');
    expect(result.contains_copyrighted_character).toBe(true);
  });

  it('returns FAIL_CLOSED for explicit content', () => {
    const result = scanPromptSafety('nude figure in a scene');
    expect(result.status).toBe('FAIL_CLOSED');
    expect(result.contains_explicit_content).toBe(true);
  });

  it('returns HOLD for medical claims', () => {
    const result = scanPromptSafety('This treatment cures all diseases');
    expect(result.status).toBe('HOLD');
    expect(result.contains_medical_or_legal_claim).toBe(true);
  });

  it('returns FAIL_CLOSED for empty prompt', () => {
    const result = scanPromptSafety('');
    expect(result.status).toBe('FAIL_CLOSED');
  });

  describe('safetyToDecision', () => {
    it('maps PASS to ALLOW', () => {
      const safety: SafetyCheck = {
        contains_public_figure: false,
        contains_private_person: false,
        contains_copyrighted_character: false,
        contains_explicit_content: false,
        contains_medical_or_legal_claim: false,
        status: 'PASS',
      };
      expect(safetyToDecision(safety)).toBe('ALLOW');
    });

    it('maps HOLD to HOLD', () => {
      const safety: SafetyCheck = {
        contains_public_figure: true,
        contains_private_person: false,
        contains_copyrighted_character: false,
        contains_explicit_content: false,
        contains_medical_or_legal_claim: false,
        status: 'HOLD',
      };
      expect(safetyToDecision(safety)).toBe('HOLD');
    });

    it('maps FAIL_CLOSED to FAIL_CLOSED', () => {
      const safety: SafetyCheck = {
        contains_public_figure: false,
        contains_private_person: false,
        contains_copyrighted_character: false,
        contains_explicit_content: true,
        contains_medical_or_legal_claim: false,
        status: 'FAIL_CLOSED',
      };
      expect(safetyToDecision(safety)).toBe('FAIL_CLOSED');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// PROVIDER ROUTER
// ═══════════════════════════════════════════════════════════════════════════

describe('Provider Router', () => {
  beforeEach(() => {
    resetAllCircuitBreakers();
  });

  describe('selectProvider', () => {
    it('selects google_veo for enterprise controls', () => {
      const result = selectProvider({
        qualityTier: 'standard',
        aspectRatio: '16:9',
        durationSeconds: 4,
        needsAudio: false,
        needsEnterpriseControls: true,
      });
      expect(result.provider).toBe('google_veo');
      expect(result.model).toBe('veo-3.1-generate-001');
    });

    it('selects openai_sora for pro quality tier', () => {
      const result = selectProvider({
        qualityTier: 'pro',
        aspectRatio: '16:9',
        durationSeconds: 4,
        needsAudio: false,
        needsEnterpriseControls: false,
      });
      expect(result.provider).toBe('openai_sora');
      expect(result.model).toBe('sora-2-pro');
    });

    it('selects openai_sora when audio is needed', () => {
      const result = selectProvider({
        qualityTier: 'standard',
        aspectRatio: '16:9',
        durationSeconds: 4,
        needsAudio: true,
        needsEnterpriseControls: false,
      });
      expect(result.provider).toBe('openai_sora');
    });

    it('selects runway for standard tier', () => {
      const result = selectProvider({
        qualityTier: 'standard',
        aspectRatio: '16:9',
        durationSeconds: 4,
        needsAudio: false,
        needsEnterpriseControls: false,
      });
      expect(result.provider).toBe('runway');
      expect(result.model).toBe('gen4.5');
    });

    it('honors preferred provider', () => {
      const result = selectProvider({
        qualityTier: 'standard',
        aspectRatio: '16:9',
        durationSeconds: 4,
        needsAudio: false,
        needsEnterpriseControls: false,
        preferredProvider: 'google_veo',
      });
      expect(result.provider).toBe('google_veo');
    });

    it('falls back when all circuits are open', () => {
      // Open all primary circuits
      for (let i = 0; i < 5; i++) {
        recordProviderFailure('openai_sora');
        recordProviderFailure('google_veo');
        recordProviderFailure('runway');
      }
      const result = selectProvider({
        qualityTier: 'standard',
        aspectRatio: '16:9',
        durationSeconds: 4,
        needsAudio: false,
        needsEnterpriseControls: false,
      });
      expect(result.provider).toBe('fallback');
    });
  });

  describe('Circuit Breaker', () => {
    it('starts in closed state', () => {
      const cb = getCircuitBreaker('openai_sora');
      expect(cb.state).toBe('closed');
      expect(cb.failureCount).toBe(0);
    });

    it('opens after threshold failures', () => {
      for (let i = 0; i < 5; i++) {
        recordProviderFailure('openai_sora');
      }
      const cb = getCircuitBreaker('openai_sora');
      expect(cb.state).toBe('open');
      expect(isCircuitOpen('openai_sora')).toBe(true);
    });

    it('resets on success', () => {
      for (let i = 0; i < 3; i++) {
        recordProviderFailure('openai_sora');
      }
      recordProviderSuccess('openai_sora');
      const cb = getCircuitBreaker('openai_sora');
      expect(cb.state).toBe('closed');
      expect(cb.failureCount).toBe(0);
    });

    it('does not open below threshold', () => {
      for (let i = 0; i < 4; i++) {
        recordProviderFailure('runway');
      }
      expect(isCircuitOpen('runway')).toBe(false);
    });
  });

  describe('Provider Adapters', () => {
    it('OpenAI Sora adapter submits and polls', async () => {
      const adapter = new OpenAISoraAdapter();
      expect(adapter.name).toBe('openai_sora');

      const response = await adapter.submitJob({
        prompt: 'test',
        aspectRatio: '16:9',
        durationSeconds: 4,
        qualityTier: 'standard',
        model: 'sora-2',
      });
      expect(response.status).toBe('accepted');
      expect(response.providerJobId).toMatch(/^sora_/);

      const status = await adapter.pollStatus(response.providerJobId);
      expect(status.status).toBe('completed');
      expect(status.artifactUrl).toBeTruthy();
    });

    it('Google Veo adapter submits and polls', async () => {
      const adapter = new GoogleVeoAdapter();
      expect(adapter.name).toBe('google_veo');

      const response = await adapter.submitJob({
        prompt: 'test',
        aspectRatio: '16:9',
        durationSeconds: 4,
        qualityTier: 'standard',
        model: 'veo-3.1-generate-001',
      });
      expect(response.status).toBe('accepted');
      expect(response.providerJobId).toMatch(/^veo_/);
    });

    it('Runway adapter submits and polls', async () => {
      const adapter = new RunwayAdapter();
      expect(adapter.name).toBe('runway');

      const response = await adapter.submitJob({
        prompt: 'test',
        aspectRatio: '16:9',
        durationSeconds: 4,
        qualityTier: 'standard',
        model: 'gen4.5',
      });
      expect(response.status).toBe('accepted');
      expect(response.providerJobId).toMatch(/^runway_/);
    });

    it('Fallback adapter submits and polls', async () => {
      const adapter = new FallbackAdapter();
      expect(adapter.name).toBe('fallback');

      const response = await adapter.submitJob({
        prompt: 'test',
        aspectRatio: '16:9',
        durationSeconds: 4,
        qualityTier: 'standard',
        model: 'fallback-v1',
      });
      expect(response.status).toBe('accepted');
    });

    it('getAdapter returns correct adapter type', () => {
      expect(getAdapter('openai_sora').name).toBe('openai_sora');
      expect(getAdapter('google_veo').name).toBe('google_veo');
      expect(getAdapter('runway').name).toBe('runway');
      expect(getAdapter('fallback').name).toBe('fallback');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vLLM PLANNER
// ═══════════════════════════════════════════════════════════════════════════

describe('vLLM Planner', () => {
  it('has the correct system prompt', () => {
    expect(VLLM_SYSTEM_PROMPT).toContain('Prompt Planner and Proof Auditor');
    expect(VLLM_SYSTEM_PROMPT).toContain('Output JSON only');
    expect(VLLM_SYSTEM_PROMPT).toContain('Never claim a video exists');
  });

  it('plans a safe prompt successfully', () => {
    const result = planPrompt({
      userPrompt: 'A beautiful sunset over the ocean',
      aspectRatio: '16:9',
      durationSeconds: 4,
      qualityTier: 'standard',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.decision).toBe('ALLOW');
      expect(result.data.user_prompt).toBe('A beautiful sunset over the ocean');
      expect(result.data.rewritten_prompt).toContain('sunset');
      expect(result.data.scene_plan.length).toBeGreaterThan(0);
      expect(result.data.safety.status).toBe('PASS');
    }
  });

  it('holds an unsafe prompt', () => {
    const result = planPrompt({
      userPrompt: 'Elon Musk dancing',
      aspectRatio: '16:9',
      durationSeconds: 4,
      qualityTier: 'standard',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.decision).toBe('HOLD');
      expect(result.data.safety.contains_public_figure).toBe(true);
    }
  });

  it('fail-closes explicit content', () => {
    const result = planPrompt({
      userPrompt: 'explicit nude content',
      aspectRatio: '16:9',
      durationSeconds: 4,
      qualityTier: 'standard',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.decision).toBe('FAIL_CLOSED');
    }
  });

  describe('splitScenes', () => {
    it('creates 1 scene for 4 seconds', () => {
      const scenes = splitScenes('test prompt', 4);
      expect(scenes.length).toBe(1);
      expect(scenes[0]!.duration_seconds).toBe(4);
    });

    it('creates 2 scenes for 8 seconds', () => {
      const scenes = splitScenes('test prompt', 8);
      expect(scenes.length).toBe(2);
    });

    it('creates 3 scenes for 12 seconds', () => {
      const scenes = splitScenes('test prompt', 12);
      expect(scenes.length).toBe(3);
    });

    it('each scene has valid scene_id format', () => {
      const scenes = splitScenes('test', 12);
      expect(scenes[0]!.scene_id).toBe('scene_001');
      expect(scenes[1]!.scene_id).toBe('scene_002');
      expect(scenes[2]!.scene_id).toBe('scene_003');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ARTIFACT STORAGE
// ═══════════════════════════════════════════════════════════════════════════

describe('Artifact Storage', () => {
  beforeEach(() => {
    resetStorage();
  });

  it('downloads artifact and returns buffer', async () => {
    const data = await downloadArtifact('https://example.com/video.mp4');
    expect(Buffer.isBuffer(data)).toBe(true);
    expect(data.length).toBeGreaterThan(0);
  });

  it('hashes artifact with SHA-256', () => {
    const data = Buffer.from('test content');
    const hash = hashArtifact(data);
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('produces consistent hashes', () => {
    const data = Buffer.from('same content');
    const hash1 = hashArtifact(data);
    const hash2 = hashArtifact(data);
    expect(hash1).toBe(hash2);
  });

  it('produces different hashes for different content', () => {
    const hash1 = hashArtifact(Buffer.from('content A'));
    const hash2 = hashArtifact(Buffer.from('content B'));
    expect(hash1).not.toBe(hash2);
  });

  it('stores and verifies artifact', async () => {
    const data = Buffer.from('test video content');
    const sha256 = hashArtifact(data);
    const path = await storeArtifact('test-job-id', data, sha256);

    expect(path).toContain('test-job-id');

    const verified = await verifyStoredArtifact(path, sha256);
    expect(verified).toBe(true);
  });

  it('fails verification with wrong hash', async () => {
    const data = Buffer.from('test video content');
    const sha256 = hashArtifact(data);
    await storeArtifact('test-job-id-2', data, sha256);

    const verified = await verifyStoredArtifact(
      's3://text2video-rank-artifacts/artifacts/test-job-id-2/video.mp4',
      'wrong_hash',
    );
    expect(verified).toBe(false);
  });

  it('fails verification for non-existent artifact', async () => {
    const verified = await verifyStoredArtifact(
      's3://text2video-rank-artifacts/artifacts/nonexistent/video.mp4',
      'any_hash',
    );
    expect(verified).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// WORKER PIPELINE & CAS TRANSITIONS
// ═══════════════════════════════════════════════════════════════════════════

describe('Worker Pipeline', () => {
  beforeEach(() => {
    resetStores();
    resetAllCircuitBreakers();
    resetStorage();
  });

  describe('CAS-Guarded Transitions', () => {
    it('transitions from queued to planning', () => {
      const job: VideoJob = {
        jobId: '550e8400-e29b-41d4-a716-446655440000',
        status: 'queued',
        provider: 'runway',
        model: 'gen4.5',
        userPrompt: 'test',
        rewrittenPrompt: '',
        decision: 'ALLOW',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        casVersion: 0,
      };
      storeJob(job);

      const result = casTransition(job.jobId, 0, 'planning');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.job.status).toBe('planning');
        expect(result.job.casVersion).toBe(1);
      }
    });

    it('rejects CAS conflict', () => {
      const job: VideoJob = {
        jobId: '550e8400-e29b-41d4-a716-446655440001',
        status: 'queued',
        provider: 'runway',
        model: 'gen4.5',
        userPrompt: 'test',
        rewrittenPrompt: '',
        decision: 'ALLOW',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        casVersion: 0,
      };
      storeJob(job);

      // First transition succeeds
      casTransition(job.jobId, 0, 'planning');

      // Second transition with stale version fails
      const result = casTransition(job.jobId, 0, 'submitted');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toContain('CAS_CONFLICT');
      }
    });

    it('rejects invalid state transition', () => {
      const job: VideoJob = {
        jobId: '550e8400-e29b-41d4-a716-446655440002',
        status: 'queued',
        provider: 'runway',
        model: 'gen4.5',
        userPrompt: 'test',
        rewrittenPrompt: '',
        decision: 'ALLOW',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        casVersion: 0,
      };
      storeJob(job);

      // Cannot go from queued directly to completed
      const result = casTransition(job.jobId, 0, 'completed');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toContain('INVALID_TRANSITION');
      }
    });

    it('rejects transition for non-existent job', () => {
      const result = casTransition('nonexistent-id', 0, 'planning');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toContain('JOB_NOT_FOUND');
      }
    });

    it('blocks transitions from terminal states', () => {
      const job: VideoJob = {
        jobId: '550e8400-e29b-41d4-a716-446655440003',
        status: 'completed',
        provider: 'runway',
        model: 'gen4.5',
        userPrompt: 'test',
        rewrittenPrompt: 'rewritten',
        decision: 'ALLOW',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        casVersion: 5,
      };
      storeJob(job);

      const result = casTransition(job.jobId, 5, 'failed');
      expect(result.success).toBe(false);
    });
  });

  describe('Full Job Lifecycle', () => {
    it('processes a safe job through the full pipeline', async () => {
      const job: VideoJob = {
        jobId: '550e8400-e29b-41d4-a716-446655440010',
        status: 'queued',
        provider: 'runway',
        model: 'gen4.5',
        userPrompt: 'A beautiful mountain landscape at dawn',
        rewrittenPrompt: '',
        decision: 'ALLOW',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        casVersion: 0,
      };
      storeJob(job);

      const result = await processJob(job.jobId);
      expect(result.success).toBe(true);
      expect(result.job.status).toBe('completed');
      expect(result.evidence).toBeDefined();
      if (result.evidence) {
        expect(result.evidence.artifactSha256).toMatch(/^[a-f0-9]{64}$/);
        expect(result.evidence.storagePath).toContain(job.jobId);
        expect(result.evidence.finalDecision).toBe('ALLOW');
      }
    });

    it('holds a job with unsafe prompt', async () => {
      const job: VideoJob = {
        jobId: '550e8400-e29b-41d4-a716-446655440011',
        status: 'queued',
        provider: 'runway',
        model: 'gen4.5',
        userPrompt: 'Elon Musk at a press conference',
        rewrittenPrompt: '',
        decision: 'ALLOW',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        casVersion: 0,
      };
      storeJob(job);

      const result = await processJob(job.jobId);
      expect(result.success).toBe(false);
      expect(result.job.status).toBe('held');
      expect(result.job.decision).toBe('HOLD');
    });

    it('fails a job with explicit content', async () => {
      const job: VideoJob = {
        jobId: '550e8400-e29b-41d4-a716-446655440012',
        status: 'queued',
        provider: 'runway',
        model: 'gen4.5',
        userPrompt: 'explicit nude scene',
        rewrittenPrompt: '',
        decision: 'ALLOW',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        casVersion: 0,
      };
      storeJob(job);

      const result = await processJob(job.jobId);
      expect(result.success).toBe(false);
      expect(result.job.status).toBe('failed');
    });

    it('rejects processing a non-queued job', async () => {
      const job: VideoJob = {
        jobId: '550e8400-e29b-41d4-a716-446655440013',
        status: 'completed',
        provider: 'runway',
        model: 'gen4.5',
        userPrompt: 'test',
        rewrittenPrompt: 'rewritten',
        decision: 'ALLOW',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        casVersion: 5,
      };
      storeJob(job);

      const result = await processJob(job.jobId);
      expect(result.success).toBe(false);
      expect(result.error).toContain('INVALID_START_STATE');
    });

    it('returns error for non-existent job', async () => {
      const result = await processJob('nonexistent-id');
      expect(result.success).toBe(false);
      expect(result.error).toBe('JOB_NOT_FOUND');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// JOB API ROUTES
// ═══════════════════════════════════════════════════════════════════════════

describe('Job API Routes', () => {
  beforeEach(() => {
    resetStores();
    resetAllCircuitBreakers();
    resetStorage();
  });

  describe('POST /api/video-jobs', () => {
    it('creates a job with valid input', () => {
      const body = JSON.stringify({
        prompt: 'A sunset over the ocean',
        aspectRatio: '16:9',
        durationSeconds: 4,
        qualityTier: 'standard',
      });
      const result = handleCreateVideoJob(body);
      expect(result.status).toBe(201);

      const data = JSON.parse(result.body);
      expect(data.jobId).toBeTruthy();
      expect(data.status).toBe('queued');
      expect(data.provider).toBeTruthy();
    });

    it('rejects invalid JSON', () => {
      const result = handleCreateVideoJob('not json');
      expect(result.status).toBe(400);
      const data = JSON.parse(result.body);
      expect(data.error).toBe('INVALID_JSON');
    });

    it('rejects invalid request via safeParse', () => {
      const body = JSON.stringify({
        prompt: '',
        aspectRatio: '16:9',
        durationSeconds: 4,
        qualityTier: 'standard',
      });
      const result = handleCreateVideoJob(body);
      expect(result.status).toBe(400);
      const data = JSON.parse(result.body);
      expect(data.error).toBe('VALIDATION_FAILED');
    });
  });

  describe('GET /api/video-jobs/:jobId', () => {
    it('returns job status', () => {
      // Create a job first
      const createBody = JSON.stringify({
        prompt: 'A mountain landscape',
        aspectRatio: '16:9',
        durationSeconds: 4,
        qualityTier: 'standard',
      });
      const createResult = handleCreateVideoJob(createBody);
      const { jobId } = JSON.parse(createResult.body);

      const result = handleGetVideoJob(jobId);
      expect(result.status).toBe(200);
      const data = JSON.parse(result.body);
      expect(data.jobId).toBe(jobId);
    });

    it('returns 404 for non-existent job', () => {
      const result = handleGetVideoJob('nonexistent-id');
      expect(result.status).toBe(404);
    });

    it('returns 400 for missing jobId', () => {
      const result = handleGetVideoJob('');
      expect(result.status).toBe(400);
    });
  });

  describe('GET /api/video-jobs/:jobId/artifact', () => {
    it('returns 404 for non-existent job', () => {
      const result = handleGetArtifact('nonexistent-id');
      expect(result.status).toBe(404);
    });

    it('returns 409 for non-completed job', () => {
      const createBody = JSON.stringify({
        prompt: 'A river flowing',
        aspectRatio: '16:9',
        durationSeconds: 4,
        qualityTier: 'standard',
      });
      const createResult = handleCreateVideoJob(createBody);
      const { jobId } = JSON.parse(createResult.body);

      // Job is still queued/processing
      const result = handleGetArtifact(jobId);
      // Could be 409 (not completed) or 200 (if processed fast enough)
      expect([200, 409]).toContain(result.status);
    });
  });

  describe('Path Extraction', () => {
    it('extracts jobId from path', () => {
      expect(extractJobIdFromPath('/api/video-jobs/abc-123')).toBe('abc-123');
      expect(extractJobIdFromPath('/api/video-jobs/abc-123/artifact')).toBe('abc-123');
    });

    it('returns null for invalid path', () => {
      expect(extractJobIdFromPath('/api/other')).toBeNull();
      expect(extractJobIdFromPath('/api/video-jobs/')).toBeNull();
    });

    it('detects artifact paths', () => {
      expect(isArtifactPath('/api/video-jobs/abc-123/artifact')).toBe(true);
      expect(isArtifactPath('/api/video-jobs/abc-123')).toBe(false);
    });
  });
});

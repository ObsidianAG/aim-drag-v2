/**
 * server/video-types.ts -- Core types and Zod schemas for Text2VideoRank
 *
 * AIM DRAG RULES:
 *   - safeParse everywhere in production paths (never .parse())
 *   - Fail-closed: unknown state → FAIL_CLOSED
 *   - Every state transition needs CAS guard
 *   - No video becomes real until: generated, downloaded, hashed, stored, audited, shown with proof
 */

import { z } from 'zod';

// ═══════════════════════════════════════════════════════════════════════════
// ENUMS & LITERAL TYPES
// ═══════════════════════════════════════════════════════════════════════════

export const VIDEO_JOB_STATUSES = [
  'queued',
  'planning',
  'submitted',
  'generating',
  'provider_completed',
  'downloading',
  'storing',
  'verifying',
  'completed',
  'held',
  'failed',
] as const;

export const VIDEO_PROVIDERS = [
  'openai_sora',
  'google_veo',
  'runway',
  'fallback',
] as const;

export const ASPECT_RATIOS = ['16:9', '9:16', '1:1'] as const;
export const DURATIONS = [4, 6, 8, 10, 12] as const;
export const QUALITY_TIERS = ['draft', 'standard', 'pro'] as const;
export const RESOLUTIONS = ['720p', '1080p'] as const;
export const SHOT_TYPES = ['wide', 'medium', 'close-up', 'aerial', 'tracking'] as const;
export const DECISIONS = ['ALLOW', 'HOLD', 'FAIL_CLOSED'] as const;
export const SAFETY_STATUSES = ['PASS', 'HOLD', 'FAIL_CLOSED'] as const;
export const CONFIDENCE_LEVELS = ['LOW', 'MEDIUM', 'HIGH'] as const;
export const VERIFICATION_STATUSES = ['VERIFIED', 'PARTIAL', 'UNVERIFIED'] as const;
export const UI_BADGES = ['Verified', 'Partial', 'Needs Verification'] as const;
export const RISK_LEVELS = ['low', 'medium', 'high'] as const;

// ═══════════════════════════════════════════════════════════════════════════
// ZOD SCHEMAS
// ═══════════════════════════════════════════════════════════════════════════

/** CreateVideoJobRequest -- entry boundary schema, always safeParse */
export const CreateVideoJobRequestSchema = z.object({
  prompt: z.string().min(1).max(2000),
  aspectRatio: z.enum(ASPECT_RATIOS),
  durationSeconds: z.union([
    z.literal(4),
    z.literal(6),
    z.literal(8),
    z.literal(10),
    z.literal(12),
  ]),
  qualityTier: z.enum(QUALITY_TIERS),
  preferredProvider: z.enum(VIDEO_PROVIDERS).optional(),
});

export type CreateVideoJobRequest = z.infer<typeof CreateVideoJobRequestSchema>;

/** VideoJobStatus type */
export type VideoJobStatus = (typeof VIDEO_JOB_STATUSES)[number];

/** VideoProvider type */
export type VideoProvider = (typeof VIDEO_PROVIDERS)[number];

/** VideoJob -- full job record */
export const VideoJobSchema = z.object({
  jobId: z.string().uuid(),
  status: z.enum(VIDEO_JOB_STATUSES),
  provider: z.enum(VIDEO_PROVIDERS),
  model: z.string().min(1),
  userPrompt: z.string().min(1),
  rewrittenPrompt: z.string(),
  providerJobId: z.string().optional(),
  artifactUrl: z.string().optional(),
  artifactSha256: z.string().optional(),
  decision: z.enum(DECISIONS),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  /** CAS version for compare-and-swap state transitions */
  casVersion: z.number().int().min(0),
});

export type VideoJob = z.infer<typeof VideoJobSchema>;

/** ScenePlan -- structured shot spec from vLLM planner */
export const ScenePlanSchema = z.object({
  scene_id: z.string().min(1),
  duration_seconds: z.number().int().min(1).max(120),
  shot_type: z.enum(SHOT_TYPES),
  subject: z.string().min(1),
  action: z.string().min(1),
  setting: z.string().min(1),
  camera_motion: z.string(),
  lighting: z.string(),
  audio: z.string(),
  negative_prompt: z.string(),
});

export type ScenePlan = z.infer<typeof ScenePlanSchema>;

/** SafetyCheck -- prompt safety classification */
export const SafetyCheckSchema = z.object({
  contains_public_figure: z.boolean(),
  contains_private_person: z.boolean(),
  contains_copyrighted_character: z.boolean(),
  contains_explicit_content: z.boolean(),
  contains_medical_or_legal_claim: z.boolean(),
  status: z.enum(SAFETY_STATUSES),
});

export type SafetyCheck = z.infer<typeof SafetyCheckSchema>;

/** ClaimAudit -- evidence record for every claim */
export const ClaimAuditSchema = z.object({
  claim_id: z.string().min(1),
  claim_text: z.string().min(1),
  tool_id: z.string(),
  source_url: z.string(),
  source_title: z.string(),
  retrieved_at: z.string(),
  confidence: z.enum(CONFIDENCE_LEVELS),
  verification_status: z.enum(VERIFICATION_STATUSES),
  notes: z.string(),
  ui_badge_expected: z.enum(UI_BADGES),
});

export type ClaimAudit = z.infer<typeof ClaimAuditSchema>;

/** RecommendedProvider -- provider selection from planner */
export const RecommendedProviderSchema = z.object({
  provider: z.enum(['openai', 'google', 'runway', 'fallback'] as const),
  model: z.string().min(1),
  reason: z.string().min(1),
  risk: z.enum(RISK_LEVELS),
});

export type RecommendedProvider = z.infer<typeof RecommendedProviderSchema>;

/** GenerationParams -- video generation parameters */
export const GenerationParamsSchema = z.object({
  aspect_ratio: z.enum(ASPECT_RATIOS),
  resolution: z.enum(RESOLUTIONS),
  duration_seconds: z.number().int().min(1).max(120),
  quality_tier: z.enum(QUALITY_TIERS),
});

export type GenerationParams = z.infer<typeof GenerationParamsSchema>;

/** PlannerOutput -- full vLLM planner JSON shape */
export const PlannerOutputSchema = z.object({
  decision: z.enum(DECISIONS),
  reason: z.string(),
  user_prompt: z.string(),
  rewritten_prompt: z.string(),
  scene_plan: z.array(ScenePlanSchema),
  recommended_provider: RecommendedProviderSchema,
  generation_params: GenerationParamsSchema,
  safety: SafetyCheckSchema,
  claim_audit: z.array(ClaimAuditSchema),
});

export type PlannerOutput = z.infer<typeof PlannerOutputSchema>;

/** EvidenceRecord -- proof package for every job */
export const EvidenceRecordSchema = z.object({
  jobId: z.string().uuid(),
  originalPrompt: z.string(),
  rewrittenPrompt: z.string(),
  provider: z.enum(VIDEO_PROVIDERS),
  model: z.string(),
  providerJobId: z.string(),
  artifactSha256: z.string(),
  storagePath: z.string(),
  claimAuditResult: z.array(ClaimAuditSchema),
  safetyResult: SafetyCheckSchema,
  finalDecision: z.enum(DECISIONS),
  createdAt: z.string().datetime(),
});

export type EvidenceRecord = z.infer<typeof EvidenceRecordSchema>;

// ═══════════════════════════════════════════════════════════════════════════
// CLAIM AUDIT RULES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Validate a claim audit entry.
 * No claim is VERIFIED without source_url + source_title + retrieved_at.
 * Uses safeParse -- never .parse().
 */
export function validateClaimAudit(raw: unknown): {
  success: true;
  data: ClaimAudit;
} | {
  success: false;
  error: string;
} {
  const parsed = ClaimAuditSchema.safeParse(raw);
  if (!parsed.success) {
    return { success: false, error: parsed.error.message };
  }

  const claim = parsed.data;

  // AIM DRAG: No VERIFIED without full source metadata
  if (claim.verification_status === 'VERIFIED') {
    if (!claim.source_url || !claim.source_title || !claim.retrieved_at) {
      return {
        success: false,
        error: 'CLAIM_AUDIT_FAILED: VERIFIED status requires source_url, source_title, and retrieved_at',
      };
    }
  }

  // Map UI badge
  const expectedBadge = mapVerificationToBadge(claim.verification_status);
  if (claim.ui_badge_expected !== expectedBadge) {
    return {
      success: false,
      error: `CLAIM_AUDIT_FAILED: ui_badge_expected should be "${expectedBadge}" for verification_status "${claim.verification_status}"`,
    };
  }

  return { success: true, data: claim };
}

/** Map verification status to UI badge */
export function mapVerificationToBadge(
  status: 'VERIFIED' | 'PARTIAL' | 'UNVERIFIED',
): 'Verified' | 'Partial' | 'Needs Verification' {
  switch (status) {
    case 'VERIFIED':
      return 'Verified';
    case 'PARTIAL':
      return 'Partial';
    case 'UNVERIFIED':
      return 'Needs Verification';
  }
}

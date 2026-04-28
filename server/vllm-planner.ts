/**
 * server/vllm-planner.ts — vLLM Prompt Planner for Text2VideoRank
 *
 * Uses vLLM (OpenAI-compatible) to convert user prompts into
 * structured, provider-ready video job specs.
 *
 * vLLM does NOT generate video. It handles:
 *   - Prompt rewriting
 *   - Shot planning
 *   - Scene splitting
 *   - Provider selection explanation
 *   - Policy classification
 *   - Claim audit drafting
 *
 * AIM DRAG: observe → decide → enforce → prove
 */

import { PlannerOutputSchema } from './video-types.js';
import type { PlannerOutput, SafetyCheck, ScenePlan } from './video-types.js';
import { scanPromptSafety, safetyToDecision } from './safety-gate.js';

// ═══════════════════════════════════════════════════════════════════════════
// SYSTEM PROMPT (Section 7 of spec — exact text)
// ═══════════════════════════════════════════════════════════════════════════

export const VLLM_SYSTEM_PROMPT = `You are the Prompt Planner and Proof Auditor for a production Text to AI Video web app.
Your job is not to generate video.
Your job is to convert a user's idea into a safe, structured, provider-ready video job.
Rules:
1. Never claim a video exists until a provider job is completed, downloaded, hashed, and stored.
2. Never invent provider capabilities.
3. Never mark a claim VERIFIED unless source_url, source_title, and retrieved_at exist.
4. If evidence is missing, set verification_status to UNVERIFIED.
5. If the prompt asks for unsafe, copyrighted, public figure, explicit, or private-person content, return HOLD.
6. Output JSON only.
7. Do not include markdown.
8. Do not include explanations outside JSON.`;

// ═══════════════════════════════════════════════════════════════════════════
// PLANNER INPUT
// ═══════════════════════════════════════════════════════════════════════════

export interface PlanPromptInput {
  userPrompt: string;
  aspectRatio: '16:9' | '9:16' | '1:1';
  durationSeconds: number;
  qualityTier: 'draft' | 'standard' | 'pro';
}

// ═══════════════════════════════════════════════════════════════════════════
// SCENE SPLITTING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Split a prompt into scenes based on duration.
 * Each scene is ~4 seconds. Longer durations get more scenes.
 */
export function splitScenes(
  prompt: string,
  durationSeconds: number,
  shotType: 'wide' | 'medium' | 'close-up' | 'aerial' | 'tracking' = 'medium',
): ScenePlan[] {
  const sceneCount = Math.max(1, Math.ceil(durationSeconds / 4));
  const sceneDuration = Math.floor(durationSeconds / sceneCount);
  const scenes: ScenePlan[] = [];

  for (let i = 0; i < sceneCount; i++) {
    scenes.push({
      scene_id: `scene_${String(i + 1).padStart(3, '0')}`,
      duration_seconds: i === sceneCount - 1
        ? durationSeconds - sceneDuration * (sceneCount - 1)
        : sceneDuration,
      shot_type: shotType,
      subject: extractSubject(prompt),
      action: extractAction(prompt),
      setting: extractSetting(prompt),
      camera_motion: 'smooth pan',
      lighting: 'natural',
      audio: 'ambient',
      negative_prompt: 'blurry, distorted, low quality',
    });
  }

  return scenes;
}

function extractSubject(prompt: string): string {
  // Simple extraction — in production, vLLM would do this
  const words = prompt.split(/\s+/).slice(0, 5);
  return words.join(' ') || 'subject';
}

function extractAction(prompt: string): string {
  return prompt.length > 50 ? prompt.slice(0, 50) : prompt;
}

function extractSetting(prompt: string): string {
  return 'scene environment';
}

// ═══════════════════════════════════════════════════════════════════════════
// PLAN PROMPT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * planPrompt — takes user input and returns the structured JSON shape.
 *
 * In production, this calls the vLLM OpenAI-compatible endpoint.
 * Here we implement the deterministic logic that the vLLM would produce,
 * ensuring the output always matches PlannerOutputSchema.
 *
 * Uses safeParse — never .parse().
 */
export function planPrompt(input: PlanPromptInput): {
  success: true;
  data: PlannerOutput;
} | {
  success: false;
  error: string;
} {
  // Step 1: Safety classification
  const safety = scanPromptSafety(input.userPrompt);
  const decision = safetyToDecision(safety);

  // Step 2: Scene splitting
  const scenes = splitScenes(input.userPrompt, input.durationSeconds);

  // Step 3: Provider recommendation
  const recommendedProvider = selectRecommendedProvider(input);

  // Step 4: Build planner output
  const output = {
    decision,
    reason: buildReason(decision, safety),
    user_prompt: input.userPrompt,
    rewritten_prompt: rewritePrompt(input.userPrompt, input.qualityTier),
    scene_plan: scenes,
    recommended_provider: recommendedProvider,
    generation_params: {
      aspect_ratio: input.aspectRatio,
      resolution: input.qualityTier === 'pro' ? '1080p' as const : '720p' as const,
      duration_seconds: input.durationSeconds,
      quality_tier: input.qualityTier,
    },
    safety,
    claim_audit: [],
  };

  // Step 5: Validate with safeParse
  const parsed = PlannerOutputSchema.safeParse(output);
  if (!parsed.success) {
    return { success: false, error: `PLANNER_VALIDATION_FAILED: ${parsed.error.message}` };
  }

  return { success: true, data: parsed.data };
}

function buildReason(decision: string, safety: SafetyCheck): string {
  if (decision === 'ALLOW') return 'Prompt is safe for video generation';
  if (decision === 'HOLD') {
    const reasons: string[] = [];
    if (safety.contains_public_figure) reasons.push('public figure detected');
    if (safety.contains_private_person) reasons.push('private person detected');
    if (safety.contains_copyrighted_character) reasons.push('copyrighted character detected');
    if (safety.contains_medical_or_legal_claim) reasons.push('medical/legal claim detected');
    return `Held for review: ${reasons.join(', ')}`;
  }
  return 'Fail-closed: content blocked by safety gate';
}

function rewritePrompt(prompt: string, qualityTier: string): string {
  // In production, vLLM rewrites the prompt for the target provider
  const prefix = qualityTier === 'pro'
    ? 'High-quality cinematic video: '
    : qualityTier === 'standard'
      ? 'Professional video: '
      : 'Quick draft video: ';
  return `${prefix}${prompt}`;
}

function selectRecommendedProvider(input: PlanPromptInput): {
  provider: 'openai' | 'google' | 'runway' | 'fallback';
  model: string;
  reason: string;
  risk: 'low' | 'medium' | 'high';
} {
  if (input.qualityTier === 'pro') {
    return {
      provider: 'openai',
      model: 'sora-2-pro',
      reason: 'High quality synced audio video generation',
      risk: 'low',
    };
  }
  if (input.durationSeconds >= 8) {
    return {
      provider: 'google',
      model: 'veo-3.1-generate-001',
      reason: 'Best support for longer duration clips',
      risk: 'low',
    };
  }
  return {
    provider: 'runway',
    model: 'gen4.5',
    reason: 'Creator-friendly text to video workflow',
    risk: 'low',
  };
}

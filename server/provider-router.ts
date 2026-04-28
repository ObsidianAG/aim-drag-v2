/**
 * server/provider-router.ts -- Provider Router for Text2VideoRank
 *
 * Routes video jobs to: openai_sora, google_veo, runway, fallback
 * Each provider has a circuit breaker.
 * No real API calls -- interface + stub implementation.
 *
 * AIM DRAG: observe → decide → enforce → prove
 */

import type { VideoProvider } from './video-types.js';

// ═══════════════════════════════════════════════════════════════════════════
// PROVIDER SELECTION (Section 9 of spec)
// ═══════════════════════════════════════════════════════════════════════════

export interface ProviderSelectionInput {
  qualityTier: 'draft' | 'standard' | 'pro';
  aspectRatio: '16:9' | '9:16' | '1:1';
  durationSeconds: number;
  needsAudio: boolean;
  needsEnterpriseControls: boolean;
  preferredProvider?: VideoProvider | undefined;
}

export interface ProviderSelection {
  provider: VideoProvider;
  model: string;
  reason: string;
}

/**
 * selectProvider -- route each job to the best provider.
 * Exactly as specified in section 9 of the spec.
 */
export function selectProvider(input: ProviderSelectionInput): ProviderSelection {
  // Honor preferred provider if specified and circuit is not open
  if (input.preferredProvider && !isCircuitOpen(input.preferredProvider)) {
    return {
      provider: input.preferredProvider,
      model: getModelForProvider(input.preferredProvider, input.qualityTier),
      reason: `User preferred provider: ${input.preferredProvider}`,
    };
  }

  if (input.needsEnterpriseControls) {
    if (!isCircuitOpen('google_veo')) {
      return {
        provider: 'google_veo',
        model: 'veo-3.1-generate-001',
        reason: 'Enterprise Vertex AI integration and fixed quota controls',
      };
    }
  }

  if (input.qualityTier === 'pro' || input.needsAudio) {
    if (!isCircuitOpen('openai_sora')) {
      return {
        provider: 'openai_sora',
        model: 'sora-2-pro',
        reason: 'High quality synced audio video generation',
      };
    }
  }

  if (!isCircuitOpen('runway')) {
    return {
      provider: 'runway',
      model: 'gen4.5',
      reason: 'Creator-friendly text to video and image to video workflow',
    };
  }

  // Fallback when all circuits are open
  return {
    provider: 'fallback',
    model: 'fallback-v1',
    reason: 'All primary providers unavailable, using fallback',
  };
}

function getModelForProvider(provider: VideoProvider, qualityTier: string): string {
  switch (provider) {
    case 'openai_sora':
      return qualityTier === 'pro' ? 'sora-2-pro' : 'sora-2';
    case 'google_veo':
      return 'veo-3.1-generate-001';
    case 'runway':
      return 'gen4.5';
    case 'fallback':
      return 'fallback-v1';
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CIRCUIT BREAKER
// ═══════════════════════════════════════════════════════════════════════════

export interface CircuitBreakerState {
  provider: VideoProvider;
  state: 'closed' | 'open' | 'half_open';
  failureCount: number;
  lastFailureAt: string | null;
  openedAt: string | null;
  /** Threshold before circuit opens */
  failureThreshold: number;
  /** Milliseconds before half-open attempt */
  resetTimeoutMs: number;
}

const DEFAULT_FAILURE_THRESHOLD = 5;
const DEFAULT_RESET_TIMEOUT_MS = 60_000; // 1 minute

/** In-memory circuit breaker state per provider */
const circuitBreakers = new Map<VideoProvider, CircuitBreakerState>();

export function getCircuitBreaker(provider: VideoProvider): CircuitBreakerState {
  let cb = circuitBreakers.get(provider);
  if (!cb) {
    cb = {
      provider,
      state: 'closed',
      failureCount: 0,
      lastFailureAt: null,
      openedAt: null,
      failureThreshold: DEFAULT_FAILURE_THRESHOLD,
      resetTimeoutMs: DEFAULT_RESET_TIMEOUT_MS,
    };
    circuitBreakers.set(provider, cb);
  }
  return cb;
}

export function isCircuitOpen(provider: VideoProvider): boolean {
  const cb = getCircuitBreaker(provider);

  if (cb.state === 'closed') return false;

  if (cb.state === 'open' && cb.openedAt) {
    const elapsed = Date.now() - new Date(cb.openedAt).getTime();
    if (elapsed >= cb.resetTimeoutMs) {
      // Transition to half-open
      cb.state = 'half_open';
      return false; // Allow one attempt
    }
    return true;
  }

  // half_open allows one attempt
  return false;
}

export function recordProviderSuccess(provider: VideoProvider): void {
  const cb = getCircuitBreaker(provider);
  cb.state = 'closed';
  cb.failureCount = 0;
  cb.lastFailureAt = null;
  cb.openedAt = null;
}

export function recordProviderFailure(provider: VideoProvider): void {
  const cb = getCircuitBreaker(provider);
  cb.failureCount += 1;
  cb.lastFailureAt = new Date().toISOString();

  if (cb.failureCount >= cb.failureThreshold) {
    cb.state = 'open';
    cb.openedAt = new Date().toISOString();
  }
}

/** Reset all circuit breakers (for testing) */
export function resetAllCircuitBreakers(): void {
  circuitBreakers.clear();
}

// ═══════════════════════════════════════════════════════════════════════════
// PROVIDER ADAPTERS (Interface + Stub)
// ═══════════════════════════════════════════════════════════════════════════

export interface ProviderJobRequest {
  prompt: string;
  aspectRatio: '16:9' | '9:16' | '1:1';
  durationSeconds: number;
  qualityTier: 'draft' | 'standard' | 'pro';
  model: string;
}

export interface ProviderJobResponse {
  providerJobId: string;
  status: 'accepted' | 'rejected';
  estimatedCompletionMs?: number;
}

export interface ProviderStatusResponse {
  providerJobId: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  artifactUrl?: string;
  errorMessage?: string;
}

export interface ProviderAdapter {
  readonly name: VideoProvider;
  submitJob(request: ProviderJobRequest): Promise<ProviderJobResponse>;
  pollStatus(providerJobId: string): Promise<ProviderStatusResponse>;
}

// ─── OpenAI Sora Adapter (Stub) ─────────────────────────────────────────

export class OpenAISoraAdapter implements ProviderAdapter {
  readonly name: VideoProvider = 'openai_sora';

  async submitJob(request: ProviderJobRequest): Promise<ProviderJobResponse> {
    // Stub: In production, POST to api.openai.com/v1/video/generations
    return {
      providerJobId: `sora_${crypto.randomUUID()}`,
      status: 'accepted',
      estimatedCompletionMs: 120_000,
    };
  }

  async pollStatus(providerJobId: string): Promise<ProviderStatusResponse> {
    // Stub: In production, GET api.openai.com/v1/video/generations/{id}
    return {
      providerJobId,
      status: 'completed',
      artifactUrl: `https://stub.openai.com/videos/${providerJobId}.mp4`,
    };
  }
}

// ─── Google Veo Adapter (Stub) ──────────────────────────────────────────

export class GoogleVeoAdapter implements ProviderAdapter {
  readonly name: VideoProvider = 'google_veo';

  async submitJob(request: ProviderJobRequest): Promise<ProviderJobResponse> {
    // Stub: In production, POST to Vertex AI predict endpoint
    return {
      providerJobId: `veo_${crypto.randomUUID()}`,
      status: 'accepted',
      estimatedCompletionMs: 90_000,
    };
  }

  async pollStatus(providerJobId: string): Promise<ProviderStatusResponse> {
    // Stub: In production, GET Vertex AI operation status
    return {
      providerJobId,
      status: 'completed',
      artifactUrl: `https://stub.googleapis.com/videos/${providerJobId}.mp4`,
    };
  }
}

// ─── Runway Adapter (Stub) ──────────────────────────────────────────────

export class RunwayAdapter implements ProviderAdapter {
  readonly name: VideoProvider = 'runway';

  async submitJob(request: ProviderJobRequest): Promise<ProviderJobResponse> {
    // Stub: In production, POST to api.dev.runwayml.com/v1/text_to_video
    return {
      providerJobId: `runway_${crypto.randomUUID()}`,
      status: 'accepted',
      estimatedCompletionMs: 60_000,
    };
  }

  async pollStatus(providerJobId: string): Promise<ProviderStatusResponse> {
    // Stub: In production, GET api.dev.runwayml.com/v1/tasks/{id}
    return {
      providerJobId,
      status: 'completed',
      artifactUrl: `https://stub.runwayml.com/videos/${providerJobId}.mp4`,
    };
  }
}

// ─── Fallback Adapter (Stub) ────────────────────────────────────────────

export class FallbackAdapter implements ProviderAdapter {
  readonly name: VideoProvider = 'fallback';

  async submitJob(request: ProviderJobRequest): Promise<ProviderJobResponse> {
    return {
      providerJobId: `fallback_${crypto.randomUUID()}`,
      status: 'accepted',
      estimatedCompletionMs: 30_000,
    };
  }

  async pollStatus(providerJobId: string): Promise<ProviderStatusResponse> {
    return {
      providerJobId,
      status: 'completed',
      artifactUrl: `https://stub.fallback.local/videos/${providerJobId}.mp4`,
    };
  }
}

// ─── Adapter Registry ───────────────────────────────────────────────────

const adapters = new Map<VideoProvider, ProviderAdapter>();

export function getAdapter(provider: VideoProvider): ProviderAdapter {
  let adapter = adapters.get(provider);
  if (!adapter) {
    switch (provider) {
      case 'openai_sora':
        adapter = new OpenAISoraAdapter();
        break;
      case 'google_veo':
        adapter = new GoogleVeoAdapter();
        break;
      case 'runway':
        adapter = new RunwayAdapter();
        break;
      case 'fallback':
        adapter = new FallbackAdapter();
        break;
    }
    adapters.set(provider, adapter);
  }
  return adapter;
}

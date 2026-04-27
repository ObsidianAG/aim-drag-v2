// lib/release-governance/types.ts
// Python-Accurate Release Lifecycle Types

/**
 * ReleasePhase: Python's support status phases
 * Source: https://devguide.python.org/versions/
 *
 * feature    → Active development, new features accepted
 * prerelease → Beta/RC cycle, feature-frozen
 * bugfix     → After final release, accepting bug fixes only
 * security   → After bugfix window, security patches only
 * end_of_life → Frozen, no changes, tag-only
 */
export enum ReleasePhase {
  FEATURE = 'feature',
  PRERELEASE = 'prerelease',
  BUGFIX = 'bugfix',
  SECURITY = 'security',
  END_OF_LIFE = 'end_of_life',
}

/**
 * ReleaseStage: Development stages within phases
 *
 * pre_alpha → Before first alpha
 * alpha     → Alpha releases
 * beta      → Beta releases (feature freeze begins)
 * rc        → Release candidates (stricter review)
 * final     → Production release
 */
export enum ReleaseStage {
  PRE_ALPHA = 'pre_alpha',
  ALPHA = 'alpha',
  BETA = 'beta',
  RC = 'rc',
  FINAL = 'final',
}

/**
 * Python-Accurate Transition Rules:
 *
 * FEATURE + PRE_ALPHA → FEATURE + ALPHA     (start alpha)
 * FEATURE + ALPHA     → PRERELEASE + BETA   (feature freeze)
 * PRERELEASE + BETA   → PRERELEASE + RC     (RC cycle)
 * PRERELEASE + RC     → BUGFIX + FINAL      (full release)
 * BUGFIX + FINAL      → SECURITY + FINAL    (bugfix window closes)
 * SECURITY + FINAL    → END_OF_LIFE + FINAL (support ends)
 */

export interface ReleaseState {
  version: string;
  phase: ReleasePhase;
  stage: ReleaseStage;
  isFrozen: boolean;
  releaseManager: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface TransitionRecord {
  transitionId: string;
  version: string;
  fromPhase: ReleasePhase;
  toPhase: ReleasePhase;
  fromStage: ReleaseStage;
  toStage: ReleaseStage;
  actor: string;
  timestamp: Date;
  gateChecksum: string;
  evidenceHash: string;
}

export interface BetaGate {
  featureFreezeAcknowledged: boolean;
  allAlphaBlockersResolved: boolean;
  releaseNotesStarted: boolean;
  // AIM DRAG hardened (stricter than Python minimum)
  peerReviewRequired: boolean;
  bugIdLinked: boolean;
  rollbackProofExists: boolean;
}

export interface RCGate {
  allBetaBlockersResolved: boolean;
  peerReviewComplete: boolean;
  releaseNotesFinal: boolean;
  regressionTestsPassed: boolean;
  securityScanPassed: boolean;
  // AIM DRAG hardened
  commitSigned: boolean;
  artifactHashVerified: boolean;
}

export interface FinalGate {
  allRCBlockersResolved: boolean;
  releaseManagerApproval: boolean;
  tagSigned: boolean;
  artifactSigned: boolean;
  sbomGenerated: boolean;
  provenanceAttested: boolean;
  // AIM DRAG hardened
  sha256Verified: boolean;
  telemetryFresh: boolean;
  qneoEvidenceComplete: boolean;
}

export interface SecurityContext {
  actorMfaVerified: boolean;
  branchProtectionEnabled: boolean;
  requiredReviewsCount: number;
  signedCommitsRequired: boolean;
  forcePushBlocked: boolean;
}

export interface ReleaseAuthority {
  actorId: string;
  isReleaseManager: boolean;
  mfaEnabled: boolean;
  isAdmin: boolean;
  revokedAt: Date | null;
}

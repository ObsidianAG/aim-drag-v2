// lib/release-governance/index.ts
// Barrel export for release governance module

export {
  ReleasePhase,
  ReleaseStage,
  type ReleaseState,
  type TransitionRecord,
  type BetaGate,
  type RCGate,
  type FinalGate,
  type SecurityContext,
  type ReleaseAuthority,
} from './types.js';

export { ReleaseStateMachine } from './state-machine.js';

export { ReleaseAuthorityManager } from './authority-manager.js';

export {
  type SCMVerificationResult,
  verifySCMBranchProtection,
  type ArtifactVerificationResult,
  verifyArtifact,
  type TelemetryVerificationResult,
  verifyTelemetry,
  type QNEOVerificationResult,
  verifyQNEOEvidence,
} from './verifiers.js';

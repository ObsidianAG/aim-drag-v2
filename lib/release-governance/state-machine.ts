// lib/release-governance/state-machine.ts
// Python-Accurate Release State Machine

import { createHash, randomUUID } from 'node:crypto';
import {
  ReleasePhase,
  ReleaseStage,
  ReleaseState,
  TransitionRecord,
  BetaGate,
  RCGate,
  FinalGate,
  SecurityContext,
} from './types.js';

export class ReleaseStateMachine {
  private state: ReleaseState;
  private transitionHistory: TransitionRecord[] = [];

  constructor(version: string, releaseManager: string) {
    this.state = {
      version,
      phase: ReleasePhase.FEATURE,
      stage: ReleaseStage.PRE_ALPHA,
      isFrozen: false,
      releaseManager,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  get phase(): ReleasePhase {
    return this.state.phase;
  }

  get stage(): ReleaseStage {
    return this.state.stage;
  }

  get isFrozen(): boolean {
    return this.state.isFrozen;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TRANSITION: Feature → Alpha (still feature phase)
  // ═══════════════════════════════════════════════════════════════════════

  transitionToAlpha(
    actor: string,
    ctx: SecurityContext
  ): TransitionRecord {
    this.validateAuthority(actor, ctx);
    this.assertPhase(ReleasePhase.FEATURE);
    this.assertStage(ReleaseStage.PRE_ALPHA);

    const record = this.createTransitionRecord(
      actor,
      ReleasePhase.FEATURE,
      ReleasePhase.FEATURE,
      ReleaseStage.PRE_ALPHA,
      ReleaseStage.ALPHA,
      {}
    );

    this.state.stage = ReleaseStage.ALPHA;
    this.state.updatedAt = new Date();
    this.transitionHistory.push(record);

    return record;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TRANSITION: Alpha → Beta (enters PRERELEASE, feature freeze)
  // ═══════════════════════════════════════════════════════════════════════

  transitionToBeta(
    actor: string,
    gate: BetaGate,
    ctx: SecurityContext
  ): TransitionRecord {
    this.validateAuthority(actor, ctx);
    this.assertPhase(ReleasePhase.FEATURE);
    this.assertStage(ReleaseStage.ALPHA);
    this.validateBetaGate(gate);

    const record = this.createTransitionRecord(
      actor,
      ReleasePhase.FEATURE,
      ReleasePhase.PRERELEASE, // Phase changes: feature → prerelease
      ReleaseStage.ALPHA,
      ReleaseStage.BETA,
      gate
    );

    this.state.phase = ReleasePhase.PRERELEASE;
    this.state.stage = ReleaseStage.BETA;
    this.state.updatedAt = new Date();
    this.transitionHistory.push(record);

    return record;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TRANSITION: Beta → RC (stays PRERELEASE, stage changes)
  // Python: RC is still prerelease
  // ═══════════════════════════════════════════════════════════════════════

  transitionToRC(
    actor: string,
    gate: RCGate,
    ctx: SecurityContext
  ): TransitionRecord {
    this.validateAuthority(actor, ctx);
    this.assertPhase(ReleasePhase.PRERELEASE);
    this.assertStage(ReleaseStage.BETA);
    this.validateRCGate(gate);

    // CRITICAL: RC stays in PRERELEASE phase
    const record = this.createTransitionRecord(
      actor,
      ReleasePhase.PRERELEASE,
      ReleasePhase.PRERELEASE, // Phase stays prerelease
      ReleaseStage.BETA,
      ReleaseStage.RC,
      gate
    );

    this.state.phase = ReleasePhase.PRERELEASE; // Still prerelease
    this.state.stage = ReleaseStage.RC;
    this.state.updatedAt = new Date();
    this.transitionHistory.push(record);

    return record;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TRANSITION: RC → Final (enters BUGFIX, not security)
  // Python: bugfix mode starts after full release
  // ═══════════════════════════════════════════════════════════════════════

  transitionToFinal(
    actor: string,
    gate: FinalGate,
    ctx: SecurityContext
  ): TransitionRecord {
    this.validateAuthority(actor, ctx);
    this.assertPhase(ReleasePhase.PRERELEASE);
    this.assertStage(ReleaseStage.RC);
    this.validateFinalGate(gate);

    // CRITICAL: Final enters BUGFIX, not security
    const record = this.createTransitionRecord(
      actor,
      ReleasePhase.PRERELEASE,
      ReleasePhase.BUGFIX, // Phase changes: prerelease → bugfix
      ReleaseStage.RC,
      ReleaseStage.FINAL,
      gate
    );

    this.state.phase = ReleasePhase.BUGFIX; // Bugfix, not security
    this.state.stage = ReleaseStage.FINAL;
    this.state.updatedAt = new Date();
    this.transitionHistory.push(record);

    return record;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TRANSITION: Bugfix → Security (bugfix window closes)
  // Python: security begins after bugfix window ends
  // ═══════════════════════════════════════════════════════════════════════

  transitionToSecurity(
    actor: string,
    ctx: SecurityContext
  ): TransitionRecord {
    this.validateAuthority(actor, ctx);
    this.assertPhase(ReleasePhase.BUGFIX);
    this.assertStage(ReleaseStage.FINAL);

    const record = this.createTransitionRecord(
      actor,
      ReleasePhase.BUGFIX,
      ReleasePhase.SECURITY, // Phase changes: bugfix → security
      ReleaseStage.FINAL,
      ReleaseStage.FINAL,
      {}
    );

    this.state.phase = ReleasePhase.SECURITY;
    this.state.updatedAt = new Date();
    this.transitionHistory.push(record);

    return record;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TRANSITION: Security → EOL (support ends, branch frozen)
  // Python: release manager creates final tag, deletes branch, loses admin
  // ═══════════════════════════════════════════════════════════════════════

  transitionToEOL(
    actor: string,
    ctx: SecurityContext
  ): TransitionRecord {
    this.validateAuthority(actor, ctx);
    this.assertPhase(ReleasePhase.SECURITY);
    this.assertStage(ReleaseStage.FINAL);

    const record = this.createTransitionRecord(
      actor,
      ReleasePhase.SECURITY,
      ReleasePhase.END_OF_LIFE,
      ReleaseStage.FINAL,
      ReleaseStage.FINAL,
      {}
    );

    this.state.phase = ReleasePhase.END_OF_LIFE;
    this.state.isFrozen = true; // Critical: EOL is frozen
    this.state.updatedAt = new Date();
    this.transitionHistory.push(record);

    return record;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // VALIDATION HELPERS
  // ═══════════════════════════════════════════════════════════════════════

  private validateAuthority(actor: string, ctx: SecurityContext): void {
    if (!ctx.actorMfaVerified) {
      throw new Error('AUTHORITY_DENIED: MFA not verified');
    }
    if (!ctx.branchProtectionEnabled) {
      throw new Error('AUTHORITY_DENIED: Branch protection not enabled');
    }
    if (this.state.isFrozen) {
      throw new Error('AUTHORITY_DENIED: Release is frozen (EOL)');
    }
  }

  private assertPhase(expected: ReleasePhase): void {
    if (this.state.phase !== expected) {
      throw new Error(
        'INVALID_PHASE: Expected ' + expected + ', got ' + this.state.phase
      );
    }
  }

  private assertStage(expected: ReleaseStage): void {
    if (this.state.stage !== expected) {
      throw new Error(
        'INVALID_STAGE: Expected ' + expected + ', got ' + this.state.stage
      );
    }
  }

  private validateBetaGate(gate: BetaGate): void {
    // Python minimum: feature freeze
    if (!gate.featureFreezeAcknowledged) {
      throw new Error('BETA_GATE_FAILED: Feature freeze not acknowledged');
    }
    if (!gate.allAlphaBlockersResolved) {
      throw new Error('BETA_GATE_FAILED: Alpha blockers not resolved');
    }
    // AIM DRAG hardened (stricter than Python)
    if (!gate.peerReviewRequired) {
      throw new Error('BETA_GATE_FAILED: Peer review required (AIM DRAG policy)');
    }
    if (!gate.bugIdLinked) {
      throw new Error('BETA_GATE_FAILED: Bug ID not linked (AIM DRAG policy)');
    }
    if (!gate.rollbackProofExists) {
      throw new Error('BETA_GATE_FAILED: Rollback proof missing (AIM DRAG policy)');
    }
  }

  private validateRCGate(gate: RCGate): void {
    if (!gate.allBetaBlockersResolved) {
      throw new Error('RC_GATE_FAILED: Beta blockers not resolved');
    }
    if (!gate.peerReviewComplete) {
      throw new Error('RC_GATE_FAILED: Peer review not complete');
    }
    if (!gate.regressionTestsPassed) {
      throw new Error('RC_GATE_FAILED: Regression tests not passed');
    }
    if (!gate.securityScanPassed) {
      throw new Error('RC_GATE_FAILED: Security scan not passed');
    }
    if (!gate.commitSigned) {
      throw new Error('RC_GATE_FAILED: Commit not signed');
    }
  }

  private validateFinalGate(gate: FinalGate): void {
    if (!gate.allRCBlockersResolved) {
      throw new Error('FINAL_GATE_FAILED: RC blockers not resolved');
    }
    if (!gate.releaseManagerApproval) {
      throw new Error('FINAL_GATE_FAILED: Release manager approval missing');
    }
    if (!gate.tagSigned) {
      throw new Error('FINAL_GATE_FAILED: Tag not signed');
    }
    if (!gate.artifactSigned) {
      throw new Error('FINAL_GATE_FAILED: Artifact not signed');
    }
    if (!gate.sbomGenerated) {
      throw new Error('FINAL_GATE_FAILED: SBOM not generated');
    }
    if (!gate.provenanceAttested) {
      throw new Error('FINAL_GATE_FAILED: Provenance not attested');
    }
    // AIM DRAG requirements
    if (!gate.sha256Verified) {
      throw new Error('FINAL_GATE_FAILED: SHA-256 not verified (AIM DRAG policy)');
    }
    if (!gate.telemetryFresh) {
      throw new Error('FINAL_GATE_FAILED: Telemetry not fresh (AIM DRAG policy)');
    }
    if (!gate.qneoEvidenceComplete) {
      throw new Error('FINAL_GATE_FAILED: QNEO evidence not complete (AIM DRAG policy)');
    }
  }

  private createTransitionRecord(
    actor: string,
    fromPhase: ReleasePhase,
    toPhase: ReleasePhase,
    fromStage: ReleaseStage,
    toStage: ReleaseStage,
    gateData: unknown
  ): TransitionRecord {
    const gateChecksum = createHash('sha256')
      .update(JSON.stringify(gateData))
      .digest('hex');

    const evidencePayload = JSON.stringify({
      version: this.state.version,
      fromPhase,
      toPhase,
      fromStage,
      toStage,
      actor,
      timestamp: new Date().toISOString(),
      gateChecksum,
    });
    const evidenceHash = createHash('sha256')
      .update(evidencePayload)
      .digest('hex');

    return {
      transitionId: randomUUID(),
      version: this.state.version,
      fromPhase,
      toPhase,
      fromStage,
      toStage,
      actor,
      timestamp: new Date(),
      gateChecksum,
      evidenceHash,
    };
  }
}

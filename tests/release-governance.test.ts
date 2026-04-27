// tests/release-governance.test.ts
// Python-Accurate Release Governance Tests

import { describe, it, expect, beforeEach } from 'vitest';
import {
  ReleaseStateMachine,
  ReleasePhase,
  ReleaseStage,
  BetaGate,
  RCGate,
  FinalGate,
  SecurityContext,
  ReleaseAuthorityManager,
} from '../lib/release-governance/index.js';

// ═══════════════════════════════════════════════════════════════════════════
// TEST FIXTURES
// ═══════════════════════════════════════════════════════════════════════════

function makeStateMachine(): ReleaseStateMachine {
  return new ReleaseStateMachine('3.14.0', 'rm-alice');
}

function makeSecurityContext(): SecurityContext {
  return {
    actorMfaVerified: true,
    branchProtectionEnabled: true,
    requiredReviewsCount: 2,
    signedCommitsRequired: true,
    forcePushBlocked: true,
  };
}

function makeBetaGate(): BetaGate {
  return {
    featureFreezeAcknowledged: true,
    allAlphaBlockersResolved: true,
    releaseNotesStarted: true,
    peerReviewRequired: true,
    bugIdLinked: true,
    rollbackProofExists: true,
  };
}

function makeRCGate(): RCGate {
  return {
    allBetaBlockersResolved: true,
    peerReviewComplete: true,
    releaseNotesFinal: true,
    regressionTestsPassed: true,
    securityScanPassed: true,
    commitSigned: true,
    artifactHashVerified: true,
  };
}

function makeFinalGate(): FinalGate {
  return {
    allRCBlockersResolved: true,
    releaseManagerApproval: true,
    tagSigned: true,
    artifactSigned: true,
    sbomGenerated: true,
    provenanceAttested: true,
    sha256Verified: true,
    telemetryFresh: true,
    qneoEvidenceComplete: true,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// PYTHON-ACCURATE LIFECYCLE TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('ReleaseStateMachine', () => {
  describe('Python-Accurate Lifecycle Transitions', () => {
    it('initializes in FEATURE phase with PRE_ALPHA stage', () => {
      const sm = makeStateMachine();

      expect(sm.phase).toBe(ReleasePhase.FEATURE);
      expect(sm.stage).toBe(ReleaseStage.PRE_ALPHA);
      expect(sm.isFrozen).toBe(false);
    });

    it('transitions to ALPHA while staying in FEATURE phase', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();

      const record = sm.transitionToAlpha('rm-alice', ctx);

      expect(sm.phase).toBe(ReleasePhase.FEATURE);
      expect(sm.stage).toBe(ReleaseStage.ALPHA);
      expect(record.fromPhase).toBe(ReleasePhase.FEATURE);
      expect(record.toPhase).toBe(ReleasePhase.FEATURE);
      expect(record.fromStage).toBe(ReleaseStage.PRE_ALPHA);
      expect(record.toStage).toBe(ReleaseStage.ALPHA);
    });

    it('transitions to BETA and enters PRERELEASE phase (feature freeze)', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();

      sm.transitionToAlpha('rm-alice', ctx);
      const record = sm.transitionToBeta('rm-alice', makeBetaGate(), ctx);

      expect(sm.phase).toBe(ReleasePhase.PRERELEASE);
      expect(sm.stage).toBe(ReleaseStage.BETA);
      expect(record.fromPhase).toBe(ReleasePhase.FEATURE);
      expect(record.toPhase).toBe(ReleasePhase.PRERELEASE);
    });

    it('transitions to RC while STAYING in PRERELEASE phase', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();

      sm.transitionToAlpha('rm-alice', ctx);
      sm.transitionToBeta('rm-alice', makeBetaGate(), ctx);
      const record = sm.transitionToRC('rm-alice', makeRCGate(), ctx);

      // CRITICAL: RC is still PRERELEASE (Python-accurate)
      expect(sm.phase).toBe(ReleasePhase.PRERELEASE);
      expect(sm.stage).toBe(ReleaseStage.RC);
      expect(record.fromPhase).toBe(ReleasePhase.PRERELEASE);
      expect(record.toPhase).toBe(ReleasePhase.PRERELEASE);
      expect(record.fromStage).toBe(ReleaseStage.BETA);
      expect(record.toStage).toBe(ReleaseStage.RC);
    });

    it('transitions to FINAL and enters BUGFIX phase (not security)', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();

      sm.transitionToAlpha('rm-alice', ctx);
      sm.transitionToBeta('rm-alice', makeBetaGate(), ctx);
      sm.transitionToRC('rm-alice', makeRCGate(), ctx);
      const record = sm.transitionToFinal('rm-alice', makeFinalGate(), ctx);

      // CRITICAL: Final enters BUGFIX, not SECURITY (Python-accurate)
      expect(sm.phase).toBe(ReleasePhase.BUGFIX);
      expect(sm.stage).toBe(ReleaseStage.FINAL);
      expect(record.fromPhase).toBe(ReleasePhase.PRERELEASE);
      expect(record.toPhase).toBe(ReleasePhase.BUGFIX);
    });

    it('transitions from BUGFIX to SECURITY when bugfix window closes', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();

      sm.transitionToAlpha('rm-alice', ctx);
      sm.transitionToBeta('rm-alice', makeBetaGate(), ctx);
      sm.transitionToRC('rm-alice', makeRCGate(), ctx);
      sm.transitionToFinal('rm-alice', makeFinalGate(), ctx);

      const record = sm.transitionToSecurity('rm-alice', ctx);

      expect(sm.phase).toBe(ReleasePhase.SECURITY);
      expect(sm.stage).toBe(ReleaseStage.FINAL);
      expect(record.fromPhase).toBe(ReleasePhase.BUGFIX);
      expect(record.toPhase).toBe(ReleasePhase.SECURITY);
    });

    it('transitions from SECURITY to EOL and freezes branch', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();

      sm.transitionToAlpha('rm-alice', ctx);
      sm.transitionToBeta('rm-alice', makeBetaGate(), ctx);
      sm.transitionToRC('rm-alice', makeRCGate(), ctx);
      sm.transitionToFinal('rm-alice', makeFinalGate(), ctx);
      sm.transitionToSecurity('rm-alice', ctx);

      const record = sm.transitionToEOL('rm-alice', ctx);

      expect(sm.phase).toBe(ReleasePhase.END_OF_LIFE);
      expect(sm.isFrozen).toBe(true);
      expect(record.fromPhase).toBe(ReleasePhase.SECURITY);
      expect(record.toPhase).toBe(ReleasePhase.END_OF_LIFE);
    });
  });

  describe('Gate Enforcement', () => {
    it('rejects beta transition without feature freeze acknowledgment', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();
      const badGate = { ...makeBetaGate(), featureFreezeAcknowledged: false };

      sm.transitionToAlpha('rm-alice', ctx);

      expect(() => sm.transitionToBeta('rm-alice', badGate, ctx)).toThrow(
        /^BETA_GATE_FAILED: Feature freeze not acknowledged$/
      );
    });

    it('rejects RC transition without peer review', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();
      const badGate = { ...makeRCGate(), peerReviewComplete: false };

      sm.transitionToAlpha('rm-alice', ctx);
      sm.transitionToBeta('rm-alice', makeBetaGate(), ctx);

      expect(() => sm.transitionToRC('rm-alice', badGate, ctx)).toThrow(
        /^RC_GATE_FAILED: Peer review not complete$/
      );
    });

    it('rejects final transition without SHA-256 verification (AIM DRAG)', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();
      const badGate = { ...makeFinalGate(), sha256Verified: false };

      sm.transitionToAlpha('rm-alice', ctx);
      sm.transitionToBeta('rm-alice', makeBetaGate(), ctx);
      sm.transitionToRC('rm-alice', makeRCGate(), ctx);

      expect(() => sm.transitionToFinal('rm-alice', badGate, ctx)).toThrow(
        /^FINAL_GATE_FAILED: SHA-256 not verified \(AIM DRAG policy\)$/
      );
    });

    it('rejects final transition without QNEO evidence (AIM DRAG)', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();
      const badGate = { ...makeFinalGate(), qneoEvidenceComplete: false };

      sm.transitionToAlpha('rm-alice', ctx);
      sm.transitionToBeta('rm-alice', makeBetaGate(), ctx);
      sm.transitionToRC('rm-alice', makeRCGate(), ctx);

      expect(() => sm.transitionToFinal('rm-alice', badGate, ctx)).toThrow(
        /^FINAL_GATE_FAILED: QNEO evidence not complete \(AIM DRAG policy\)$/
      );
    });
  });

  describe('Authority Model', () => {
    it('rejects transition without MFA', () => {
      const sm = makeStateMachine();
      const badCtx = { ...makeSecurityContext(), actorMfaVerified: false };

      expect(() => sm.transitionToAlpha('rm-alice', badCtx)).toThrow(
        /^AUTHORITY_DENIED: MFA not verified$/
      );
    });

    it('rejects transition without branch protection', () => {
      const sm = makeStateMachine();
      const badCtx = {
        ...makeSecurityContext(),
        branchProtectionEnabled: false,
      };

      expect(() => sm.transitionToAlpha('rm-alice', badCtx)).toThrow(
        /^AUTHORITY_DENIED: Branch protection not enabled$/
      );
    });

    it('rejects all transitions after EOL (frozen)', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();

      // Full lifecycle
      sm.transitionToAlpha('rm-alice', ctx);
      sm.transitionToBeta('rm-alice', makeBetaGate(), ctx);
      sm.transitionToRC('rm-alice', makeRCGate(), ctx);
      sm.transitionToFinal('rm-alice', makeFinalGate(), ctx);
      sm.transitionToSecurity('rm-alice', ctx);
      sm.transitionToEOL('rm-alice', ctx);

      expect(sm.isFrozen).toBe(true);

      // Any transition should fail
      expect(() => sm.transitionToAlpha('rm-alice', ctx)).toThrow(
        /^AUTHORITY_DENIED: Release is frozen \(EOL\)$/
      );
    });
  });

  describe('Evidence Chain', () => {
    it('generates SHA-256 evidence hash for each transition', () => {
      const sm = makeStateMachine();
      const ctx = makeSecurityContext();

      const record = sm.transitionToAlpha('rm-alice', ctx);

      expect(record.evidenceHash).toMatch(/^[a-f0-9]{64}$/);
      expect(record.gateChecksum).toMatch(/^[a-f0-9]{64}$/);
      expect(record.transitionId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// AUTHORITY MANAGER TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('ReleaseAuthorityManager', () => {
  it('grants admin to release managers with MFA on active branches', () => {
    const mgr = new ReleaseAuthorityManager();
    const auth = mgr.registerAuthority('rm-alice', true, true);

    expect(auth.isAdmin).toBe(true);
    expect(auth.revokedAt).toBeNull();
    expect(mgr.hasAdminAuthority('rm-alice')).toBe(true);
  });

  it('denies admin to non-release-managers', () => {
    const mgr = new ReleaseAuthorityManager();
    const auth = mgr.registerAuthority('dev-bob', false, true);

    expect(auth.isAdmin).toBe(false);
    expect(mgr.hasAdminAuthority('dev-bob')).toBe(false);
  });

  it('denies admin without MFA', () => {
    const mgr = new ReleaseAuthorityManager();
    const auth = mgr.registerAuthority('rm-alice', true, false);

    expect(auth.isAdmin).toBe(false);
    expect(mgr.hasAdminAuthority('rm-alice')).toBe(false);
  });

  it('revokes all admin privileges on EOL transition', () => {
    const mgr = new ReleaseAuthorityManager();
    mgr.registerAuthority('rm-alice', true, true);
    mgr.registerAuthority('rm-bob', true, true);

    expect(mgr.hasAdminAuthority('rm-alice')).toBe(true);
    expect(mgr.hasAdminAuthority('rm-bob')).toBe(true);

    // Transition to EOL
    mgr.updatePhase(ReleasePhase.END_OF_LIFE);

    expect(mgr.hasAdminAuthority('rm-alice')).toBe(false);
    expect(mgr.hasAdminAuthority('rm-bob')).toBe(false);

    const aliceAuth = mgr.getAuthority('rm-alice');
    expect(aliceAuth?.revokedAt).not.toBeNull();
    expect(aliceAuth?.isAdmin).toBe(false);
  });

  it('does not grant admin when registering after EOL', () => {
    const mgr = new ReleaseAuthorityManager();
    mgr.updatePhase(ReleasePhase.END_OF_LIFE);

    const auth = mgr.registerAuthority('rm-new', true, true);
    expect(auth.isAdmin).toBe(false);
    expect(mgr.hasAdminAuthority('rm-new')).toBe(false);
  });
});

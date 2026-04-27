// lib/release-governance/authority-manager.ts
// Release Authority Model (Python DevGuide Aligned)

import { ReleasePhase, ReleaseAuthority } from './types.js';

/**
 * Python DevGuide Authority Rules:
 * - Release managers for active branches get admin privileges
 * - MFA required for org owners, repo admins, release managers
 * - After EOL: release manager creates final tag, deletes branch, loses admin
 */
export class ReleaseAuthorityManager {
  private authorities: Map<string, ReleaseAuthority> = new Map();
  private currentPhase: ReleasePhase = ReleasePhase.FEATURE;

  registerAuthority(
    actorId: string,
    isReleaseManager: boolean,
    mfaEnabled: boolean
  ): ReleaseAuthority {
    const authority: ReleaseAuthority = {
      actorId,
      isReleaseManager,
      mfaEnabled,
      isAdmin: isReleaseManager && mfaEnabled && this.isActiveBranch(),
      revokedAt: null,
    };

    this.authorities.set(actorId, authority);
    return authority;
  }

  updatePhase(phase: ReleasePhase): void {
    const previousPhase = this.currentPhase;
    this.currentPhase = phase;

    // Python: After EOL, release manager loses admin
    if (phase === ReleasePhase.END_OF_LIFE && previousPhase !== ReleasePhase.END_OF_LIFE) {
      this.revokeAllAdminPrivileges();
    }
  }

  getAuthority(actorId: string): ReleaseAuthority | undefined {
    return this.authorities.get(actorId);
  }

  hasAdminAuthority(actorId: string): boolean {
    const auth = this.authorities.get(actorId);
    if (!auth) return false;
    if (auth.revokedAt !== null) return false;
    if (!auth.mfaEnabled) return false;
    if (!auth.isReleaseManager) return false;
    if (!this.isActiveBranch()) return false;
    return true;
  }

  private isActiveBranch(): boolean {
    return this.currentPhase !== ReleasePhase.END_OF_LIFE;
  }

  private revokeAllAdminPrivileges(): void {
    for (const [, auth] of this.authorities) {
      if (auth.isAdmin) {
        auth.isAdmin = false;
        auth.revokedAt = new Date();
        this.authorities.set(auth.actorId, auth);
      }
    }
  }
}

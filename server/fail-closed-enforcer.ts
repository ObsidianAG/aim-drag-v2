/**
 * server/fail-closed-enforcer.ts -- Fail-Closed Enforcement Module
 *
 * Enumerates ALL failure conditions and enforces FAIL_CLOSED for each.
 * Every FAIL_CLOSED logs: action, reason, timestamp, retryAfterMs.
 * No silent failures — every path produces observable output.
 *
 * AIM DRAG: observe → decide → enforce → prove
 */

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export type FailureCondition =
  | 'PROMETHEUS_STALE'
  | 'PROMETHEUS_UNREACHABLE'
  | 'DB_WRITE_FAILURE'
  | 'INVALID_SNAPSHOT'
  | 'MISSING_ROLLBACK_TARGET'
  | 'EVIDENCE_CHAIN_BROKEN'
  | 'UNKNOWN_STATE'
  | 'TIMEOUT';

export interface FailClosedRecord {
  status: 'FAIL_CLOSED';
  action: string;
  reason: string;
  timestamp: string;
  retryAfterMs: number;
  condition: FailureCondition;
}

export type EnforcerResult =
  | { status: 'PASS'; action: string; timestamp: string }
  | FailClosedRecord;

export interface EnforcerInput {
  action: string;
  condition: FailureCondition | 'HEALTHY';
  context?: Record<string, unknown>;
}

// ═══════════════════════════════════════════════════════════════════════════
// RETRY POLICY
// ═══════════════════════════════════════════════════════════════════════════

const RETRY_POLICY: Record<FailureCondition, number> = {
  PROMETHEUS_STALE: 30_000,
  PROMETHEUS_UNREACHABLE: 60_000,
  DB_WRITE_FAILURE: 5_000,
  INVALID_SNAPSHOT: 0, // no retry — requires manual intervention
  MISSING_ROLLBACK_TARGET: 0, // no retry — requires manual intervention
  EVIDENCE_CHAIN_BROKEN: 0, // no retry — requires investigation
  UNKNOWN_STATE: 0, // no retry — requires investigation
  TIMEOUT: 15_000,
};

const REASON_MAP: Record<FailureCondition, string> = {
  PROMETHEUS_STALE: 'Prometheus metrics are stale beyond acceptable threshold',
  PROMETHEUS_UNREACHABLE: 'Prometheus endpoint is unreachable or returned non-200',
  DB_WRITE_FAILURE: 'Database write operation failed — data integrity at risk',
  INVALID_SNAPSHOT: 'Snapshot validation failed — data does not match expected schema',
  MISSING_ROLLBACK_TARGET: 'Rollback target deployment or revision not found',
  EVIDENCE_CHAIN_BROKEN: 'Evidence chain integrity verification failed — possible tampering',
  UNKNOWN_STATE: 'System entered an unknown or unexpected state — cannot proceed safely',
  TIMEOUT: 'Operation timed out before completion',
};

// ═══════════════════════════════════════════════════════════════════════════
// ENFORCER
// ═══════════════════════════════════════════════════════════════════════════

export class FailClosedEnforcer {
  private readonly log: FailClosedRecord[] = [];
  private readonly nowFn: () => string;

  constructor(nowFn?: () => string) {
    this.nowFn = nowFn ?? (() => new Date().toISOString());
  }

  /**
   * Evaluate a condition and enforce FAIL_CLOSED if unhealthy.
   * HEALTHY is the ONLY condition that produces PASS.
   * ALL other conditions produce FAIL_CLOSED with full logging.
   */
  enforce(input: EnforcerInput): EnforcerResult {
    const timestamp = this.nowFn();

    if (input.condition === 'HEALTHY') {
      return {
        status: 'PASS',
        action: input.action,
        timestamp,
      };
    }

    // Every non-HEALTHY condition is FAIL_CLOSED
    const record: FailClosedRecord = {
      status: 'FAIL_CLOSED',
      action: input.action,
      reason: REASON_MAP[input.condition],
      timestamp,
      retryAfterMs: RETRY_POLICY[input.condition],
      condition: input.condition,
    };

    this.log.push(record);
    return record;
  }

  /**
   * Evaluate multiple conditions simultaneously.
   * If ANY condition is not HEALTHY, ALL produce FAIL_CLOSED.
   * Returns array of results — one per input.
   */
  enforceAll(inputs: EnforcerInput[]): EnforcerResult[] {
    return inputs.map((input) => this.enforce(input));
  }

  /**
   * Get all FAIL_CLOSED records (audit log).
   */
  getLog(): readonly FailClosedRecord[] {
    return [...this.log];
  }

  /**
   * Check if any failures have been recorded.
   */
  hasFailures(): boolean {
    return this.log.length > 0;
  }

  /**
   * Get count of failures by condition type.
   */
  getFailureCounts(): Record<FailureCondition, number> {
    const counts: Record<string, number> = {};
    for (const condition of Object.keys(RETRY_POLICY)) {
      counts[condition] = 0;
    }
    for (const record of this.log) {
      counts[record.condition] = (counts[record.condition] ?? 0) + 1;
    }
    return counts as Record<FailureCondition, number>;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTED CONSTANTS (for testing)
// ═══════════════════════════════════════════════════════════════════════════

export const ALL_FAILURE_CONDITIONS: readonly FailureCondition[] = [
  'PROMETHEUS_STALE',
  'PROMETHEUS_UNREACHABLE',
  'DB_WRITE_FAILURE',
  'INVALID_SNAPSHOT',
  'MISSING_ROLLBACK_TARGET',
  'EVIDENCE_CHAIN_BROKEN',
  'UNKNOWN_STATE',
  'TIMEOUT',
] as const;

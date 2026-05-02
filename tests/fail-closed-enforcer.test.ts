/**
 * tests/fail-closed-enforcer.test.ts -- Gate 4: Fail-Closed Enforcer
 *
 * Validates that ALL failure conditions produce FAIL_CLOSED with proper logging.
 * No silent failures. Every path produces observable output.
 */
import { describe, it, expect } from 'vitest';
import {
  FailClosedEnforcer,
  ALL_FAILURE_CONDITIONS,
  type FailureCondition,
  type EnforcerInput,
} from '../server/fail-closed-enforcer.js';

// ═══════════════════════════════════════════════════════════════════════════
// FIXTURES
// ═══════════════════════════════════════════════════════════════════════════

const FIXED_TIMESTAMP = '2024-01-15T10:30:00.000Z';

function makeEnforcer(): FailClosedEnforcer {
  return new FailClosedEnforcer(() => FIXED_TIMESTAMP);
}

// ═══════════════════════════════════════════════════════════════════════════
// GATE 4 TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('Gate 4: Fail-Closed Enforcer', () => {
  describe('each failure condition individually → FAIL_CLOSED', () => {
    it('PROMETHEUS_STALE → FAIL_CLOSED', () => {
      const enforcer = makeEnforcer();
      const result = enforcer.enforce({
        action: 'check_metrics',
        condition: 'PROMETHEUS_STALE',
      });

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('stale');
        expect(result.retryAfterMs).toBe(30_000);
      }
    });

    it('PROMETHEUS_UNREACHABLE → FAIL_CLOSED', () => {
      const enforcer = makeEnforcer();
      const result = enforcer.enforce({
        action: 'fetch_metrics',
        condition: 'PROMETHEUS_UNREACHABLE',
      });

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('unreachable');
        expect(result.retryAfterMs).toBe(60_000);
      }
    });

    it('DB_WRITE_FAILURE → FAIL_CLOSED', () => {
      const enforcer = makeEnforcer();
      const result = enforcer.enforce({
        action: 'persist_decision',
        condition: 'DB_WRITE_FAILURE',
      });

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Database write');
        expect(result.retryAfterMs).toBe(5_000);
      }
    });

    it('INVALID_SNAPSHOT → FAIL_CLOSED', () => {
      const enforcer = makeEnforcer();
      const result = enforcer.enforce({
        action: 'validate_snapshot',
        condition: 'INVALID_SNAPSHOT',
      });

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Snapshot validation');
        expect(result.retryAfterMs).toBe(0);
      }
    });

    it('MISSING_ROLLBACK_TARGET → FAIL_CLOSED', () => {
      const enforcer = makeEnforcer();
      const result = enforcer.enforce({
        action: 'initiate_rollback',
        condition: 'MISSING_ROLLBACK_TARGET',
      });

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Rollback target');
        expect(result.retryAfterMs).toBe(0);
      }
    });

    it('EVIDENCE_CHAIN_BROKEN → FAIL_CLOSED', () => {
      const enforcer = makeEnforcer();
      const result = enforcer.enforce({
        action: 'verify_evidence',
        condition: 'EVIDENCE_CHAIN_BROKEN',
      });

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Evidence chain');
        expect(result.retryAfterMs).toBe(0);
      }
    });

    it('UNKNOWN_STATE → FAIL_CLOSED (not ALLOW, not HOLD)', () => {
      const enforcer = makeEnforcer();
      const result = enforcer.enforce({
        action: 'state_evaluation',
        condition: 'UNKNOWN_STATE',
      });

      expect(result.status).toBe('FAIL_CLOSED');
      expect(result.status).not.toBe('PASS');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('unknown');
        expect(result.retryAfterMs).toBe(0);
      }
    });

    it('TIMEOUT → FAIL_CLOSED', () => {
      const enforcer = makeEnforcer();
      const result = enforcer.enforce({
        action: 'wait_for_response',
        condition: 'TIMEOUT',
      });

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('timed out');
        expect(result.retryAfterMs).toBe(15_000);
      }
    });
  });

  describe('FAIL_CLOSED record structure', () => {
    it('contains action, reason, timestamp, retryAfterMs', () => {
      const enforcer = makeEnforcer();
      const result = enforcer.enforce({
        action: 'test_action',
        condition: 'DB_WRITE_FAILURE',
      });

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result).toHaveProperty('action', 'test_action');
        expect(result).toHaveProperty('reason');
        expect(result).toHaveProperty('timestamp', FIXED_TIMESTAMP);
        expect(result).toHaveProperty('retryAfterMs');
        expect(typeof result.reason).toBe('string');
        expect(result.reason.length).toBeGreaterThan(0);
        expect(typeof result.retryAfterMs).toBe('number');
        expect(result.retryAfterMs).toBeGreaterThanOrEqual(0);
      }
    });

    it('all failure conditions have non-empty reason strings', () => {
      const enforcer = makeEnforcer();

      for (const condition of ALL_FAILURE_CONDITIONS) {
        const result = enforcer.enforce({ action: `test_${condition}`, condition });
        expect(result.status).toBe('FAIL_CLOSED');
        if (result.status === 'FAIL_CLOSED') {
          expect(result.reason.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('UNKNOWN_STATE → FAIL_CLOSED (not ALLOW, not HOLD)', () => {
    it('unknown state never produces PASS', () => {
      const enforcer = makeEnforcer();
      const result = enforcer.enforce({
        action: 'unknown_evaluation',
        condition: 'UNKNOWN_STATE',
      });

      // Must be FAIL_CLOSED, never anything else
      expect(result.status).toBe('FAIL_CLOSED');
      expect((result as { status: string }).status).not.toBe('PASS');
      expect((result as { status: string }).status).not.toBe('HOLD');
      expect((result as { status: string }).status).not.toBe('ALLOW');
    });
  });

  describe('multiple simultaneous failures', () => {
    it('all produce FAIL_CLOSED', () => {
      const enforcer = makeEnforcer();

      const inputs: EnforcerInput[] = ALL_FAILURE_CONDITIONS.map((condition) => ({
        action: `multi_${condition}`,
        condition,
      }));

      const results = enforcer.enforceAll(inputs);

      expect(results.length).toBe(ALL_FAILURE_CONDITIONS.length);
      for (const result of results) {
        expect(result.status).toBe('FAIL_CLOSED');
      }
    });

    it('all failures are logged', () => {
      const enforcer = makeEnforcer();

      const inputs: EnforcerInput[] = ALL_FAILURE_CONDITIONS.map((condition) => ({
        action: `multi_${condition}`,
        condition,
      }));

      enforcer.enforceAll(inputs);
      const log = enforcer.getLog();

      expect(log.length).toBe(ALL_FAILURE_CONDITIONS.length);
      expect(enforcer.hasFailures()).toBe(true);
    });
  });

  describe('no silent swallowing of errors', () => {
    it('every failure path returns a result (not void/undefined)', () => {
      const enforcer = makeEnforcer();

      for (const condition of ALL_FAILURE_CONDITIONS) {
        const result = enforcer.enforce({ action: `check_${condition}`, condition });
        expect(result).toBeDefined();
        expect(result).not.toBeNull();
        expect(result.status).toBeDefined();
        expect(result.status).toBe('FAIL_CLOSED');
      }
    });

    it('HEALTHY is the only path that produces PASS', () => {
      const enforcer = makeEnforcer();

      const healthyResult = enforcer.enforce({
        action: 'health_check',
        condition: 'HEALTHY',
      });
      expect(healthyResult.status).toBe('PASS');

      // All others must be FAIL_CLOSED
      for (const condition of ALL_FAILURE_CONDITIONS) {
        const result = enforcer.enforce({ action: `verify_${condition}`, condition });
        expect(result.status).toBe('FAIL_CLOSED');
      }
    });

    it('failure count tracking works correctly', () => {
      const enforcer = makeEnforcer();

      enforcer.enforce({ action: 'a', condition: 'TIMEOUT' });
      enforcer.enforce({ action: 'b', condition: 'TIMEOUT' });
      enforcer.enforce({ action: 'c', condition: 'DB_WRITE_FAILURE' });

      const counts = enforcer.getFailureCounts();
      expect(counts.TIMEOUT).toBe(2);
      expect(counts.DB_WRITE_FAILURE).toBe(1);
      expect(counts.PROMETHEUS_STALE).toBe(0);
    });
  });
});

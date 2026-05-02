/**
 * tests/evidence-chain.test.ts -- Gate 3: SHA-256 Evidence Chain
 *
 * Validates chain integrity, immutability, FAIL_CLOSED on missing fields,
 * and deterministic hash computation.
 */
import { describe, it, expect } from 'vitest';
import { EvidenceChain, type EvidenceRecord } from '../server/evidence-chain.js';

// ═══════════════════════════════════════════════════════════════════════════
// FIXTURES
// ═══════════════════════════════════════════════════════════════════════════

const FIXED_TIMESTAMP = '2024-01-15T10:30:00.000Z';

function makeValidInput(overrides?: Record<string, unknown>) {
  return {
    traceId: 'trace-abc-123',
    policyVersion: 'v2.1.0',
    artifactLineage: 'sha256:deadbeef1234567890',
    timestamp: FIXED_TIMESTAMP,
    action: 'rollback_initiated',
    decision: 'APPROVED',
    metadata: { reason: 'burn rate exceeded threshold' },
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// GATE 3 TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('Gate 3: SHA-256 Evidence Chain', () => {
  describe('create evidence record', () => {
    it('creates record with valid SHA-256 hash', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);
      const result = chain.append(makeValidInput());

      expect(result.status).toBe('OK');
      if (result.status === 'OK') {
        expect(result.record.hash).toMatch(/^[a-f0-9]{64}$/);
        expect(result.record.traceId).toBe('trace-abc-123');
        expect(result.record.policyVersion).toBe('v2.1.0');
        expect(result.record.artifactLineage).toBe('sha256:deadbeef1234567890');
        expect(result.record.previousHash).toBeNull(); // first record
      }
    });

    it('first record has null previousHash', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);
      const result = chain.append(makeValidInput());

      if (result.status === 'OK') {
        expect(result.record.previousHash).toBeNull();
      }
    });
  });

  describe('chain 3+ records', () => {
    it('each record references previous hash', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);

      const r1 = chain.append(makeValidInput({ traceId: 'trace-1' }));
      const r2 = chain.append(makeValidInput({ traceId: 'trace-2' }));
      const r3 = chain.append(makeValidInput({ traceId: 'trace-3' }));

      expect(r1.status).toBe('OK');
      expect(r2.status).toBe('OK');
      expect(r3.status).toBe('OK');

      if (r1.status === 'OK' && r2.status === 'OK' && r3.status === 'OK') {
        expect(r1.record.previousHash).toBeNull();
        expect(r2.record.previousHash).toBe(r1.record.hash);
        expect(r3.record.previousHash).toBe(r2.record.hash);
      }
    });

    it('chain length is correct', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);

      chain.append(makeValidInput({ traceId: 'trace-1' }));
      chain.append(makeValidInput({ traceId: 'trace-2' }));
      chain.append(makeValidInput({ traceId: 'trace-3' }));

      expect(chain.length).toBe(3);
    });
  });

  describe('verify valid chain', () => {
    it('valid chain passes verification', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);

      chain.append(makeValidInput({ traceId: 'trace-1' }));
      chain.append(makeValidInput({ traceId: 'trace-2' }));
      chain.append(makeValidInput({ traceId: 'trace-3' }));

      const result = chain.verify();
      expect(result.status).toBe('VALID');
      if (result.status === 'VALID') {
        expect(result.length).toBe(3);
      }
    });
  });

  describe('tamper detection', () => {
    it('tamper with middle record → chain verification FAILS', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);

      chain.append(makeValidInput({ traceId: 'trace-1' }));
      chain.append(makeValidInput({ traceId: 'trace-2' }));
      chain.append(makeValidInput({ traceId: 'trace-3' }));

      // Get records and tamper with middle one
      const records = chain.getRecords() as EvidenceRecord[];
      const tampered = [...records];
      tampered[1] = { ...tampered[1]!, decision: 'TAMPERED' };

      const result = EvidenceChain.verifyChain(tampered);
      expect(result.status).toBe('INVALID');
      if (result.status === 'INVALID') {
        expect(result.brokenAtIndex).toBe(1);
        expect(result.reason).toContain('Hash mismatch');
      }
    });

    it('tamper with first record hash → breaks chain at index 1', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);

      chain.append(makeValidInput({ traceId: 'trace-1' }));
      chain.append(makeValidInput({ traceId: 'trace-2' }));

      const records = chain.getRecords() as EvidenceRecord[];
      const tampered = [...records];
      tampered[0] = { ...tampered[0]!, hash: 'aaaa'.repeat(16) };

      const result = EvidenceChain.verifyChain(tampered);
      expect(result.status).toBe('INVALID');
    });
  });

  describe('FAIL_CLOSED on missing fields', () => {
    it('missing trace_id → FAIL_CLOSED', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);
      const input = makeValidInput();
      delete (input as Record<string, unknown>).traceId;

      const result = chain.append(input);
      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('traceId');
      }
    });

    it('missing policy_version → FAIL_CLOSED', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);
      const input = makeValidInput();
      delete (input as Record<string, unknown>).policyVersion;

      const result = chain.append(input);
      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('policyVersion');
      }
    });

    it('empty trace_id → FAIL_CLOSED', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);
      const result = chain.append(makeValidInput({ traceId: '' }));
      expect(result.status).toBe('FAIL_CLOSED');
    });

    it('empty policy_version → FAIL_CLOSED', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);
      const result = chain.append(makeValidInput({ policyVersion: '' }));
      expect(result.status).toBe('FAIL_CLOSED');
    });

    it('null input → FAIL_CLOSED', () => {
      const chain = new EvidenceChain(() => FIXED_TIMESTAMP);
      const result = chain.append(null);
      expect(result.status).toBe('FAIL_CLOSED');
    });
  });

  describe('deterministic hash computation', () => {
    it('same input produces same hash', () => {
      const chain1 = new EvidenceChain(() => FIXED_TIMESTAMP);
      const chain2 = new EvidenceChain(() => FIXED_TIMESTAMP);

      const input = makeValidInput();
      const r1 = chain1.append(input);
      const r2 = chain2.append(input);

      if (r1.status === 'OK' && r2.status === 'OK') {
        expect(r1.record.hash).toBe(r2.record.hash);
      }
    });

    it('different input produces different hash', () => {
      const chain1 = new EvidenceChain(() => FIXED_TIMESTAMP);
      const chain2 = new EvidenceChain(() => FIXED_TIMESTAMP);

      const r1 = chain1.append(makeValidInput({ traceId: 'trace-A' }));
      const r2 = chain2.append(makeValidInput({ traceId: 'trace-B' }));

      if (r1.status === 'OK' && r2.status === 'OK') {
        expect(r1.record.hash).not.toBe(r2.record.hash);
      }
    });

    it('computeHash is a pure function', () => {
      const data = {
        previousHash: null,
        traceId: 'trace-123',
        policyVersion: 'v1.0.0',
        artifactLineage: 'sha256:abc',
        timestamp: FIXED_TIMESTAMP,
        action: 'test',
        decision: 'PASS',
        metadata: {},
      };

      const hash1 = EvidenceChain.computeHash(data);
      const hash2 = EvidenceChain.computeHash(data);
      const hash3 = EvidenceChain.computeHash(data);

      expect(hash1).toBe(hash2);
      expect(hash2).toBe(hash3);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });
  });
});

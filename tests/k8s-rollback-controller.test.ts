/**
 * tests/k8s-rollback-controller.test.ts -- Gate 2: K8s Rollback Controller
 *
 * Validates typed API pattern (no kubectl exec), dry-run mode,
 * evidence recording, CAS guard, and FAIL_CLOSED behavior.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  K8sRollbackController,
  type K8sClient,
  type DeploymentSpec,
  type RollbackTarget,
} from '../server/k8s-rollback-controller.js';

// ═══════════════════════════════════════════════════════════════════════════
// FIXTURES
// ═══════════════════════════════════════════════════════════════════════════

const FIXED_TIMESTAMP = '2024-01-15T10:30:00.000Z';

function makeDeploymentSpec(overrides?: Partial<DeploymentSpec>): DeploymentSpec {
  return {
    name: 'api-server',
    namespace: 'production',
    revision: 5,
    image: 'registry.io/api:v2.3.0',
    replicas: 3,
    resourceVersion: 'rv-12345',
    ...overrides,
  };
}

function makeTarget(overrides?: Partial<RollbackTarget>): RollbackTarget {
  return {
    deploymentName: 'api-server',
    namespace: 'production',
    targetRevision: 4,
    expectedCurrentRevision: 5,
    ...overrides,
  };
}

function makeMockClient(overrides?: Partial<K8sClient>): K8sClient {
  return {
    get: async ({ name, namespace }) => makeDeploymentSpec({ name, namespace, revision: 5 }),
    getRevision: async ({ name, namespace, revision }) =>
      makeDeploymentSpec({ name, namespace, revision, image: `registry.io/api:v2.2.0` }),
    update: async ({ spec }) => spec,
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// GATE 2 TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('Gate 2: K8s Rollback Controller', () => {
  describe('successful rollback with dry-run', () => {
    it('records action with before/after state', async () => {
      const client = makeMockClient();
      const controller = new K8sRollbackController(client, () => FIXED_TIMESTAMP);

      const result = await controller.rollback(makeTarget(), true);

      expect(result.status).toBe('OK');
      if (result.status === 'OK') {
        expect(result.record.dryRun).toBe(true);
        expect(result.record.timestamp).toBe(FIXED_TIMESTAMP);
        expect(result.record.beforeState.revision).toBe(5);
        expect(result.record.afterState.revision).toBe(4);
        expect(result.record.beforeState.image).toBe('registry.io/api:v2.3.0');
        expect(result.record.afterState.image).toBe('registry.io/api:v2.2.0');
        expect(result.record.target.deploymentName).toBe('api-server');
        expect(result.record.target.namespace).toBe('production');
      }
    });

    it('produces valid SHA-256 hash of action record', async () => {
      const client = makeMockClient();
      const controller = new K8sRollbackController(client, () => FIXED_TIMESTAMP);

      const result = await controller.rollback(makeTarget(), true);

      expect(result.status).toBe('OK');
      if (result.status === 'OK') {
        expect(result.record.sha256).toMatch(/^[a-f0-9]{64}$/);
        expect(K8sRollbackController.verifyRecord(result.record)).toBe(true);
      }
    });

    it('stores record in controller history', async () => {
      const client = makeMockClient();
      const controller = new K8sRollbackController(client, () => FIXED_TIMESTAMP);

      await controller.rollback(makeTarget(), true);
      const records = controller.getRecords();

      expect(records.length).toBe(1);
      expect(records[0]!.dryRun).toBe(true);
    });
  });

  describe('target not found → FAIL_CLOSED', () => {
    it('returns FAIL_CLOSED when deployment does not exist', async () => {
      const client = makeMockClient({
        get: async () => null,
      });
      const controller = new K8sRollbackController(client, () => FIXED_TIMESTAMP);

      const result = await controller.rollback(makeTarget(), true);

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Target not found');
        expect(result.reason).toContain('production/api-server');
      }
    });
  });

  describe('state mismatch (CAS guard) → FAIL_CLOSED', () => {
    it('rejects when current revision differs from expected', async () => {
      const client = makeMockClient({
        get: async ({ name, namespace }) =>
          makeDeploymentSpec({ name, namespace, revision: 6 }), // revision 6, not 5
      });
      const controller = new K8sRollbackController(client, () => FIXED_TIMESTAMP);

      const result = await controller.rollback(makeTarget(), true);

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('State mismatch');
        expect(result.reason).toContain('CAS guard');
        expect(result.reason).toContain('expected revision 5');
        expect(result.reason).toContain('found 6');
      }
    });
  });

  describe('target revision not found → FAIL_CLOSED', () => {
    it('rejects when historical revision does not exist', async () => {
      const client = makeMockClient({
        getRevision: async () => null,
      });
      const controller = new K8sRollbackController(client, () => FIXED_TIMESTAMP);

      const result = await controller.rollback(makeTarget(), true);

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Target revision 4 not found');
      }
    });
  });

  describe('update failure → FAIL_CLOSED', () => {
    it('rejects when update returns null (dry-run fails)', async () => {
      const client = makeMockClient({
        update: async () => null,
      });
      const controller = new K8sRollbackController(client, () => FIXED_TIMESTAMP);

      const result = await controller.rollback(makeTarget(), true);

      expect(result.status).toBe('FAIL_CLOSED');
      if (result.status === 'FAIL_CLOSED') {
        expect(result.reason).toContain('Rollback apply failed');
        expect(result.reason).toContain('dryRun=true');
      }
    });
  });

  describe('evidence recording with SHA-256', () => {
    it('SHA-256 is deterministic for same input', async () => {
      const client = makeMockClient();
      const controller1 = new K8sRollbackController(client, () => FIXED_TIMESTAMP);
      const controller2 = new K8sRollbackController(client, () => FIXED_TIMESTAMP);

      const result1 = await controller1.rollback(makeTarget(), true);
      const result2 = await controller2.rollback(makeTarget(), true);

      if (result1.status === 'OK' && result2.status === 'OK') {
        // Same inputs → same SHA-256 (deterministic)
        expect(result1.record.sha256).toBe(result2.record.sha256);
      }
    });

    it('tampered record fails verification', async () => {
      const client = makeMockClient();
      const controller = new K8sRollbackController(client, () => FIXED_TIMESTAMP);

      const result = await controller.rollback(makeTarget(), true);

      if (result.status === 'OK') {
        // Tamper with the record
        const tampered = { ...result.record, beforeState: { ...result.record.beforeState, revision: 99 } };
        expect(K8sRollbackController.verifyRecord(tampered)).toBe(false);
      }
    });
  });

  describe('no kubectl exec in implementation', () => {
    it('implementation file contains no kubectl/exec/spawn/shell patterns', () => {
      const implPath = resolve(__dirname, '../server/k8s-rollback-controller.ts');
      const content = readFileSync(implPath, 'utf-8');

      expect(content).not.toContain('kubectl');
      expect(content).not.toContain('child_process');
      expect(content).not.toContain('execSync');
      expect(content).not.toContain('spawnSync');
      expect(content).not.toContain('exec(');
      expect(content).not.toContain('spawn(');
      expect(content).not.toContain('shell:');
    });
  });
});

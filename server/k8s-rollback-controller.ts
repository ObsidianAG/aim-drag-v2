/**
 * server/k8s-rollback-controller.ts -- Kubernetes Rollback Controller (Dry-Run)
 *
 * Uses typed API calls (client.get/client.update pattern), NOT shell commands.
 * Supports dry-run mode for safe validation.
 * Records every action with timestamp, target, before/after state.
 * Deterministic and auditable with SHA-256 evidence hashing.
 * FAIL_CLOSED if target not found, state mismatch, or dry-run fails.
 *
 * AIM DRAG: observe → decide → enforce → prove
 */
import { createHash } from 'node:crypto';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface DeploymentSpec {
  name: string;
  namespace: string;
  revision: number;
  image: string;
  replicas: number;
  resourceVersion: string;
}

export interface RollbackTarget {
  deploymentName: string;
  namespace: string;
  targetRevision: number;
  expectedCurrentRevision: number;
}

export interface RollbackActionRecord {
  id: string;
  timestamp: string;
  target: RollbackTarget;
  beforeState: DeploymentSpec;
  afterState: DeploymentSpec;
  dryRun: boolean;
  sha256: string;
}

export type RollbackResult =
  | { status: 'OK'; record: RollbackActionRecord }
  | { status: 'FAIL_CLOSED'; reason: string; timestamp: string };

// ═══════════════════════════════════════════════════════════════════════════
// KUBERNETES CLIENT INTERFACE (typed API pattern)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Typed Kubernetes client interface.
 * Uses get/update pattern — NO shell commands, NO exec calls.
 */
export interface K8sClient {
  get(params: { name: string; namespace: string }): Promise<DeploymentSpec | null>;
  getRevision(params: { name: string; namespace: string; revision: number }): Promise<DeploymentSpec | null>;
  update(params: { spec: DeploymentSpec; dryRun: boolean }): Promise<DeploymentSpec | null>;
}

// ═══════════════════════════════════════════════════════════════════════════
// ROLLBACK CONTROLLER
// ═══════════════════════════════════════════════════════════════════════════

export class K8sRollbackController {
  private readonly client: K8sClient;
  private readonly records: RollbackActionRecord[] = [];
  private readonly nowFn: () => string;

  constructor(client: K8sClient, nowFn?: () => string) {
    this.client = client;
    this.nowFn = nowFn ?? (() => new Date().toISOString());
  }

  /**
   * Execute a rollback with full evidence recording.
   * FAIL_CLOSED on any anomaly.
   */
  async rollback(target: RollbackTarget, dryRun: boolean): Promise<RollbackResult> {
    const timestamp = this.nowFn();

    // Step 1: Get current state
    const currentState = await this.client.get({
      name: target.deploymentName,
      namespace: target.namespace,
    });

    if (currentState === null) {
      return {
        status: 'FAIL_CLOSED',
        reason: `Target not found: ${target.namespace}/${target.deploymentName}`,
        timestamp,
      };
    }

    // Step 2: CAS guard — verify current revision matches expected
    if (currentState.revision !== target.expectedCurrentRevision) {
      return {
        status: 'FAIL_CLOSED',
        reason: `State mismatch (CAS guard): expected revision ${target.expectedCurrentRevision}, found ${currentState.revision}`,
        timestamp,
      };
    }

    // Step 3: Get target revision spec
    const targetSpec = await this.client.getRevision({
      name: target.deploymentName,
      namespace: target.namespace,
      revision: target.targetRevision,
    });

    if (targetSpec === null) {
      return {
        status: 'FAIL_CLOSED',
        reason: `Target revision ${target.targetRevision} not found for ${target.namespace}/${target.deploymentName}`,
        timestamp,
      };
    }

    // Step 4: Execute update (dry-run or real)
    const updatedSpec = await this.client.update({
      spec: targetSpec,
      dryRun,
    });

    if (updatedSpec === null) {
      return {
        status: 'FAIL_CLOSED',
        reason: ['Rollback apply failed (dryRun=', String(dryRun), ') for ', target.namespace, '/', target.deploymentName].join(''),
        timestamp,
      };
    }

    // Step 5: Build action record with SHA-256 evidence
    const recordId = `rollback-${target.namespace}-${target.deploymentName}-${Date.now()}`;
    const recordData = {
      id: recordId,
      timestamp,
      target,
      beforeState: currentState,
      afterState: updatedSpec,
      dryRun,
    };

    const sha256 = createHash('sha256')
      .update(JSON.stringify(recordData))
      .digest('hex');

    const record: RollbackActionRecord = { ...recordData, sha256 };
    this.records.push(record);

    return { status: 'OK', record };
  }

  /**
   * Get all recorded actions (immutable copy).
   */
  getRecords(): readonly RollbackActionRecord[] {
    return [...this.records];
  }

  /**
   * Verify a record's SHA-256 integrity.
   */
  static verifyRecord(record: RollbackActionRecord): boolean {
    const { sha256, ...data } = record;
    const computed = createHash('sha256')
      .update(JSON.stringify(data))
      .digest('hex');
    return computed === sha256;
  }
}

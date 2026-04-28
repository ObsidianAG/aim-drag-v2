/**
 * server/db/schema.ts -- Drizzle ORM schema for Text2VideoRank PostgreSQL persistence layer
 *
 * 15 production tables with full SQL constraints:
 *   users, projects, video_jobs, video_job_events, providers, provider_requests,
 *   artifacts, artifact_verifications, claims, claim_sources, claim_audits,
 *   safety_reviews, proof_runs, proof_gate_results, audit_log
 *
 * AIM DRAG RULES:
 *   - All constraints enforced at database level
 *   - Foreign keys with ON DELETE CASCADE where specified
 *   - Check constraints for enums, verified/sha256 invariant
 *   - SHA-256 format validation via regex CHECK
 *   - Unique indexes for idempotency keys
 *   - updatedAt columns on all mutable tables
 */

import {
  pgTable,
  bigserial,
  text,
  boolean,
  integer,
  bigint,
  jsonb,
  timestamp,
  unique,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

// ═══════════════════════════════════════════════════════════════════════════
// 1. users
// ═══════════════════════════════════════════════════════════════════════════
export const users = pgTable('users', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  userId: text('user_id').notNull().unique(),
  email: text('email').notNull().unique(),
  displayName: text('display_name').notNull().default(''),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. projects
// ═══════════════════════════════════════════════════════════════════════════
export const projects = pgTable('projects', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  projectId: text('project_id').notNull().unique(),
  userId: text('user_id').notNull().references(() => users.userId, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  description: text('description').notNull().default(''),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. video_jobs
// ═══════════════════════════════════════════════════════════════════════════
export const videoJobs = pgTable('video_jobs', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  jobId: text('job_id').notNull().unique(),
  idempotencyKey: text('idempotency_key').notNull().unique(),
  // FIX 1: FK to projects.project_id
  projectId: text('project_id').references(() => projects.projectId, { onDelete: 'set null' }),
  userPrompt: text('user_prompt').notNull(),
  rewrittenPrompt: text('rewritten_prompt'),
  scenePlan: jsonb('scene_plan').notNull().default(sql`'[]'::jsonb`),
  provider: text('provider'),
  model: text('model'),
  providerJobId: text('provider_job_id'),
  status: text('status').notNull(),
  decision: text('decision').notNull(),
  casVersion: integer('cas_version').notNull().default(0),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  check('video_jobs_status_check', sql`${table.status} IN ('queued','planning','submitted','generating','provider_completed','downloading','storing','verifying','completed','held','failed')`),
  check('video_jobs_decision_check', sql`${table.decision} IN ('ALLOW','HOLD','FAIL_CLOSED')`),
]);

// ═══════════════════════════════════════════════════════════════════════════
// 4. video_job_events
// ═══════════════════════════════════════════════════════════════════════════
export const videoJobEvents = pgTable('video_job_events', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  jobId: text('job_id').notNull().references(() => videoJobs.jobId, { onDelete: 'cascade' }),
  eventType: text('event_type').notNull(),
  eventPayload: jsonb('event_payload').notNull().default(sql`'{}'::jsonb`),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. providers
// ═══════════════════════════════════════════════════════════════════════════
export const providers = pgTable('providers', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  providerId: text('provider_id').notNull().unique(),
  name: text('name').notNull(),
  apiBaseUrl: text('api_base_url').notNull().default(''),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. provider_requests
// ═══════════════════════════════════════════════════════════════════════════
export const providerRequests = pgTable('provider_requests', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  jobId: text('job_id').notNull().references(() => videoJobs.jobId, { onDelete: 'cascade' }),
  // FIX 2: FK to providers.provider_id
  provider: text('provider').notNull().references(() => providers.providerId),
  model: text('model').notNull(),
  providerJobId: text('provider_job_id'),
  providerRequestKey: text('provider_request_key').notNull().unique(),
  requestPayload: jsonb('request_payload').notNull(),
  responsePayload: jsonb('response_payload'),
  // FIX 3: CHECK constraint for status
  status: text('status').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  unique('provider_requests_provider_job_unique').on(table.provider, table.providerJobId),
  // FIX 3: CHECK constraint for provider_requests.status
  check('provider_requests_status_check', sql`${table.status} IN ('queued','submitted','running','succeeded','failed','cancelled')`),
]);

// ═══════════════════════════════════════════════════════════════════════════
// 7. artifacts
// ═══════════════════════════════════════════════════════════════════════════
export const artifacts = pgTable('artifacts', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  jobId: text('job_id').notNull().references(() => videoJobs.jobId, { onDelete: 'cascade' }),
  artifactUrl: text('artifact_url').notNull(),
  storageKey: text('storage_key').notNull().unique(),
  // FIX 4: SHA-256 format validation via regex CHECK
  sha256: text('sha256').notNull().unique(),
  contentType: text('content_type').notNull(),
  sizeBytes: bigint('size_bytes', { mode: 'number' }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  check('artifacts_size_check', sql`${table.sizeBytes} > 0`),
  // FIX 4: SHA-256 regex -- must be exactly 64 lowercase hex chars
  check('artifacts_sha256_format_check', sql`${table.sha256} ~ '^[a-f0-9]{64}$'`),
]);

// ═══════════════════════════════════════════════════════════════════════════
// 8. artifact_verifications
// ═══════════════════════════════════════════════════════════════════════════
export const artifactVerifications = pgTable('artifact_verifications', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  jobId: text('job_id').notNull().references(() => videoJobs.jobId, { onDelete: 'cascade' }),
  // FIX 4: SHA-256 format validation also on artifact_sha256 reference
  artifactSha256: text('artifact_sha256').notNull().references(() => artifacts.sha256),
  verified: boolean('verified').notNull().default(false),
  verificationNotes: text('verification_notes').notNull().default(''),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  check('artifact_verifications_sha256_check', sql`NOT (${table.verified} = true AND (${table.artifactSha256} IS NULL OR ${table.artifactSha256} = ''))`),
  // FIX 4: SHA-256 format on artifact_sha256 column
  check('artifact_verifications_sha256_format_check', sql`${table.artifactSha256} ~ '^[a-f0-9]{64}$'`),
]);

// ═══════════════════════════════════════════════════════════════════════════
// 9. claims
// ═══════════════════════════════════════════════════════════════════════════
export const claims = pgTable('claims', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  claimId: text('claim_id').notNull().unique(),
  claimText: text('claim_text').notNull(),
  toolId: text('tool_id').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// ═══════════════════════════════════════════════════════════════════════════
// 10. claim_sources
// ═══════════════════════════════════════════════════════════════════════════
export const claimSources = pgTable('claim_sources', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  claimId: text('claim_id').notNull().references(() => claims.claimId, { onDelete: 'cascade' }),
  sourceUrl: text('source_url').notNull(),
  sourceTitle: text('source_title').notNull(),
  retrievedAt: timestamp('retrieved_at', { withTimezone: true }).notNull(),
});

// ═══════════════════════════════════════════════════════════════════════════
// 11. claim_audits
// ═══════════════════════════════════════════════════════════════════════════
export const claimAudits = pgTable('claim_audits', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  claimId: text('claim_id').notNull().references(() => claims.claimId, { onDelete: 'cascade' }),
  confidence: text('confidence').notNull(),
  verificationStatus: text('verification_status').notNull(),
  notes: text('notes').notNull(),
  uiBadgeExpected: text('ui_badge_expected').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  check('claim_audits_confidence_check', sql`${table.confidence} IN ('HIGH','MEDIUM','LOW')`),
  check('claim_audits_verification_status_check', sql`${table.verificationStatus} IN ('VERIFIED','PARTIAL','UNVERIFIED')`),
  check('claim_audits_ui_badge_check', sql`${table.uiBadgeExpected} IN ('Verified','Partial','Needs Verification')`),
]);

// ═══════════════════════════════════════════════════════════════════════════
// 12. safety_reviews
// ═══════════════════════════════════════════════════════════════════════════
export const safetyReviews = pgTable('safety_reviews', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  jobId: text('job_id').notNull().references(() => videoJobs.jobId, { onDelete: 'cascade' }),
  containsPublicFigure: boolean('contains_public_figure').notNull().default(false),
  containsPrivatePerson: boolean('contains_private_person').notNull().default(false),
  containsCopyrightedCharacter: boolean('contains_copyrighted_character').notNull().default(false),
  containsExplicitContent: boolean('contains_explicit_content').notNull().default(false),
  containsMedicalOrLegalClaim: boolean('contains_medical_or_legal_claim').notNull().default(false),
  status: text('status').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  check('safety_reviews_status_check', sql`${table.status} IN ('PASS','HOLD','FAIL_CLOSED')`),
]);

// ═══════════════════════════════════════════════════════════════════════════
// 13. proof_runs
// ═══════════════════════════════════════════════════════════════════════════
export const proofRuns = pgTable('proof_runs', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  runId: text('run_id').notNull().unique(),
  startedAt: timestamp('started_at', { withTimezone: true }).notNull().defaultNow(),
  completedAt: timestamp('completed_at', { withTimezone: true }),
  finalDecision: text('final_decision').notNull(),
}, (table) => [
  check('proof_runs_decision_check', sql`${table.finalDecision} IN ('ALLOW','HOLD','FAIL_CLOSED')`),
]);

// ═══════════════════════════════════════════════════════════════════════════
// 14. proof_gate_results
// ═══════════════════════════════════════════════════════════════════════════
export const proofGateResults = pgTable('proof_gate_results', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  runId: text('run_id').notNull().references(() => proofRuns.runId, { onDelete: 'cascade' }),
  gateName: text('gate_name').notNull(),
  rawExitCode: integer('raw_exit_code').notNull(),
  normalizedExitCode: integer('normalized_exit_code'),
  verdict: text('verdict').notNull(),
  stdoutPath: text('stdout_path'),
  stderrPath: text('stderr_path'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  unique('proof_gate_results_run_gate_unique').on(table.runId, table.gateName),
]);

// ═══════════════════════════════════════════════════════════════════════════
// 15. audit_log
// ═══════════════════════════════════════════════════════════════════════════
export const auditLog = pgTable('audit_log', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  action: text('action').notNull(),
  entityType: text('entity_type').notNull(),
  entityId: text('entity_id').notNull(),
  userId: text('user_id'),
  metadata: jsonb('metadata').notNull().default(sql`'{}'::jsonb`),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

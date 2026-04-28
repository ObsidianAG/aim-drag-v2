CREATE TABLE "artifact_verifications" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"job_id" text NOT NULL,
	"artifact_sha256" text NOT NULL,
	"verified" boolean DEFAULT false NOT NULL,
	"verification_notes" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "artifact_verifications_sha256_check" CHECK (NOT ("artifact_verifications"."verified" = true AND ("artifact_verifications"."artifact_sha256" IS NULL OR "artifact_verifications"."artifact_sha256" = '')))
);
--> statement-breakpoint
CREATE TABLE "artifacts" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"job_id" text NOT NULL,
	"artifact_url" text NOT NULL,
	"storage_key" text NOT NULL,
	"sha256" text NOT NULL,
	"content_type" text NOT NULL,
	"size_bytes" bigint NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "artifacts_storage_key_unique" UNIQUE("storage_key"),
	CONSTRAINT "artifacts_sha256_unique" UNIQUE("sha256"),
	CONSTRAINT "artifacts_size_check" CHECK ("artifacts"."size_bytes" > 0)
);
--> statement-breakpoint
CREATE TABLE "audit_log" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"action" text NOT NULL,
	"entity_type" text NOT NULL,
	"entity_id" text NOT NULL,
	"user_id" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "claim_audits" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"claim_id" text NOT NULL,
	"confidence" text NOT NULL,
	"verification_status" text NOT NULL,
	"notes" text NOT NULL,
	"ui_badge_expected" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "claim_audits_confidence_check" CHECK ("claim_audits"."confidence" IN ('HIGH','MEDIUM','LOW')),
	CONSTRAINT "claim_audits_verification_status_check" CHECK ("claim_audits"."verification_status" IN ('VERIFIED','PARTIAL','UNVERIFIED')),
	CONSTRAINT "claim_audits_ui_badge_check" CHECK ("claim_audits"."ui_badge_expected" IN ('Verified','Partial','Needs Verification'))
);
--> statement-breakpoint
CREATE TABLE "claim_sources" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"claim_id" text NOT NULL,
	"source_url" text NOT NULL,
	"source_title" text NOT NULL,
	"retrieved_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "claims" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"claim_id" text NOT NULL,
	"claim_text" text NOT NULL,
	"tool_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "claims_claim_id_unique" UNIQUE("claim_id")
);
--> statement-breakpoint
CREATE TABLE "projects" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"project_id" text NOT NULL,
	"user_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "projects_project_id_unique" UNIQUE("project_id")
);
--> statement-breakpoint
CREATE TABLE "proof_gate_results" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"run_id" text NOT NULL,
	"gate_name" text NOT NULL,
	"raw_exit_code" integer NOT NULL,
	"normalized_exit_code" integer,
	"verdict" text NOT NULL,
	"stdout_path" text,
	"stderr_path" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "proof_gate_results_run_gate_unique" UNIQUE("run_id","gate_name")
);
--> statement-breakpoint
CREATE TABLE "proof_runs" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"run_id" text NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	"final_decision" text NOT NULL,
	CONSTRAINT "proof_runs_run_id_unique" UNIQUE("run_id"),
	CONSTRAINT "proof_runs_decision_check" CHECK ("proof_runs"."final_decision" IN ('ALLOW','HOLD','FAIL_CLOSED'))
);
--> statement-breakpoint
CREATE TABLE "provider_requests" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"job_id" text NOT NULL,
	"provider" text NOT NULL,
	"model" text NOT NULL,
	"provider_job_id" text,
	"provider_request_key" text NOT NULL,
	"request_payload" jsonb NOT NULL,
	"response_payload" jsonb,
	"status" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "provider_requests_provider_request_key_unique" UNIQUE("provider_request_key"),
	CONSTRAINT "provider_requests_provider_job_unique" UNIQUE("provider","provider_job_id")
);
--> statement-breakpoint
CREATE TABLE "providers" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"provider_id" text NOT NULL,
	"name" text NOT NULL,
	"api_base_url" text DEFAULT '' NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "providers_provider_id_unique" UNIQUE("provider_id")
);
--> statement-breakpoint
CREATE TABLE "safety_reviews" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"job_id" text NOT NULL,
	"contains_public_figure" boolean DEFAULT false NOT NULL,
	"contains_private_person" boolean DEFAULT false NOT NULL,
	"contains_copyrighted_character" boolean DEFAULT false NOT NULL,
	"contains_explicit_content" boolean DEFAULT false NOT NULL,
	"contains_medical_or_legal_claim" boolean DEFAULT false NOT NULL,
	"status" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "safety_reviews_status_check" CHECK ("safety_reviews"."status" IN ('PASS','HOLD','FAIL_CLOSED'))
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"email" text NOT NULL,
	"display_name" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_user_id_unique" UNIQUE("user_id"),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "video_job_events" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"job_id" text NOT NULL,
	"event_type" text NOT NULL,
	"event_payload" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "video_jobs" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"job_id" text NOT NULL,
	"idempotency_key" text NOT NULL,
	"project_id" text,
	"user_prompt" text NOT NULL,
	"rewritten_prompt" text,
	"scene_plan" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"provider" text,
	"model" text,
	"provider_job_id" text,
	"status" text NOT NULL,
	"decision" text NOT NULL,
	"cas_version" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "video_jobs_job_id_unique" UNIQUE("job_id"),
	CONSTRAINT "video_jobs_idempotency_key_unique" UNIQUE("idempotency_key"),
	CONSTRAINT "video_jobs_status_check" CHECK ("video_jobs"."status" IN ('queued','planning','submitted','generating','provider_completed','downloading','storing','verifying','completed','held','failed')),
	CONSTRAINT "video_jobs_decision_check" CHECK ("video_jobs"."decision" IN ('ALLOW','HOLD','FAIL_CLOSED'))
);
--> statement-breakpoint
ALTER TABLE "artifact_verifications" ADD CONSTRAINT "artifact_verifications_job_id_video_jobs_job_id_fk" FOREIGN KEY ("job_id") REFERENCES "public"."video_jobs"("job_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "artifact_verifications" ADD CONSTRAINT "artifact_verifications_artifact_sha256_artifacts_sha256_fk" FOREIGN KEY ("artifact_sha256") REFERENCES "public"."artifacts"("sha256") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "artifacts" ADD CONSTRAINT "artifacts_job_id_video_jobs_job_id_fk" FOREIGN KEY ("job_id") REFERENCES "public"."video_jobs"("job_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "claim_audits" ADD CONSTRAINT "claim_audits_claim_id_claims_claim_id_fk" FOREIGN KEY ("claim_id") REFERENCES "public"."claims"("claim_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "claim_sources" ADD CONSTRAINT "claim_sources_claim_id_claims_claim_id_fk" FOREIGN KEY ("claim_id") REFERENCES "public"."claims"("claim_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "projects" ADD CONSTRAINT "projects_user_id_users_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("user_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proof_gate_results" ADD CONSTRAINT "proof_gate_results_run_id_proof_runs_run_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."proof_runs"("run_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "provider_requests" ADD CONSTRAINT "provider_requests_job_id_video_jobs_job_id_fk" FOREIGN KEY ("job_id") REFERENCES "public"."video_jobs"("job_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "safety_reviews" ADD CONSTRAINT "safety_reviews_job_id_video_jobs_job_id_fk" FOREIGN KEY ("job_id") REFERENCES "public"."video_jobs"("job_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "video_job_events" ADD CONSTRAINT "video_job_events_job_id_video_jobs_job_id_fk" FOREIGN KEY ("job_id") REFERENCES "public"."video_jobs"("job_id") ON DELETE cascade ON UPDATE no action;
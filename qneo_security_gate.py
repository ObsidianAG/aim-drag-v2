"""
qneo_security_gate.py — QNEO Security Gate for A.I.M D.R.A.G

The QNEO gate is the final decision authority for every AI-generated patch.
It evaluates the complete security evidence and produces one of four decisions:

    ALLOW       — All 8 conditions met: safe to merge
    HOLD        — Any of 6 conditions triggered: needs investigation
    FAIL_CLOSED — Any of 9 conditions triggered: block everything
    ROLLBACK    — Any of 5 conditions triggered: revert deployed patch

CORE RULE:
    AI can help find and fix vulnerabilities, but AIM DRAG must treat every
    AI-generated patch as hostile until scanners, AST gates, tests, re-scans,
    human review, and QNEO prove it safe.

    No evidence bundle, no merge.
    No QNEO evidence → no customer-visible output.

Production code — no mocks, no placeholders, no simulation.
"""

from __future__ import annotations

import enum
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from secure_coding_gate import (
    ASTGateResult,
    HumanSecurityReview,
    LLMReviewResult,
    PatchAnalysis,
    PipelineStepResult,
    SARIFBundle,
    SecurityEvidenceBundle,
    TestExecutionResult,
    compute_sha256,
    is_cwe_mapping_vague,
    validate_cwe_mapping,
)

logger = logging.getLogger("aim_drag.qneo_security_gate")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — QNEO DECISION TYPES
# ═══════════════════════════════════════════════════════════════════════════════

class QNEODecision(enum.Enum):
    """QNEO control decision — the four possible outcomes."""
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    FAIL_CLOSED = "FAIL_CLOSED"
    ROLLBACK = "ROLLBACK"


class QNEOConditionCategory(enum.Enum):
    """Category of a QNEO condition evaluation."""
    ALLOW_CONDITION = "allow_condition"
    HOLD_TRIGGER = "hold_trigger"
    FAIL_CLOSED_TRIGGER = "fail_closed_trigger"
    ROLLBACK_TRIGGER = "rollback_trigger"


@dataclass(frozen=True)
class QNEOConditionResult:
    """Result of evaluating a single QNEO condition."""
    condition_id: str
    condition_name: str
    category: QNEOConditionCategory
    satisfied: bool
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — QNEO STATE VECTOR FOR SECURE CODING
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class QNEOSecurityStateVector:
    """
    Complete state vector for QNEO secure coding gate evaluation.
    Every field must be present — incomplete vector = FAIL_CLOSED.
    """
    # Pipeline evidence
    pipeline_id: str
    evidence_bundle: Optional[SecurityEvidenceBundle] = None

    # Scanner state
    scanner_output_present: bool = False
    sarif_bundle: Optional[SARIFBundle] = None
    scanner_findings_resolved: bool = False

    # AST gate state
    ast_gate_present: bool = False
    ast_gate_result: Optional[ASTGateResult] = None

    # Test state
    tests_passed: bool = False
    test_result: Optional[TestExecutionResult] = None

    # Re-scan state
    patched_code_rescanned: bool = False
    rescan_sarif_bundle: Optional[SARIFBundle] = None

    # Patch analysis
    patch_analysis: Optional[PatchAnalysis] = None
    patch_is_minimal: bool = False

    # CWE state
    cwe_mapping: List[int] = field(default_factory=list)
    cwe_classification_correct: bool = False

    # LLM review state
    llm_review: Optional[LLMReviewResult] = None

    # Human review state
    human_review: Optional[HumanSecurityReview] = None
    human_reviewer_signed_off: bool = False

    # Post-deployment state (for ROLLBACK evaluation)
    post_merge_new_high_risk_issue: bool = False
    runtime_exploit_behavior_detected: bool = False
    qneo_risk_risen_after_deployment: bool = False
    incident_linked_to_ai_patch: bool = False
    patch_evidence_not_reconstructable: bool = False

    # Evidence hash
    evidence_hash_present: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipeline_id": self.pipeline_id,
            "scanner_output_present": self.scanner_output_present,
            "scanner_findings_resolved": self.scanner_findings_resolved,
            "ast_gate_present": self.ast_gate_present,
            "ast_gate_passed": self.ast_gate_result.passed if self.ast_gate_result else False,
            "tests_passed": self.tests_passed,
            "patched_code_rescanned": self.patched_code_rescanned,
            "patch_is_minimal": self.patch_is_minimal,
            "cwe_classification_correct": self.cwe_classification_correct,
            "human_reviewer_signed_off": self.human_reviewer_signed_off,
            "evidence_hash_present": self.evidence_hash_present,
            "post_merge_new_high_risk_issue": self.post_merge_new_high_risk_issue,
            "runtime_exploit_behavior_detected": self.runtime_exploit_behavior_detected,
            "qneo_risk_risen_after_deployment": self.qneo_risk_risen_after_deployment,
            "incident_linked_to_ai_patch": self.incident_linked_to_ai_patch,
            "patch_evidence_not_reconstructable": self.patch_evidence_not_reconstructable,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — QNEO DECISION RECORD
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class QNEODecisionRecord:
    """Audit record for a QNEO security gate decision."""
    decision_id: str
    decision: QNEODecision
    pipeline_id: str
    trace_id: str
    timestamp: str
    conditions_evaluated: List[QNEOConditionResult]
    reasons: List[str]
    policy_version: str
    policy_snapshot: str
    actor_identity: str
    evidence_bundle_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "decision": self.decision.value,
            "pipeline_id": self.pipeline_id,
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "reasons": self.reasons,
            "policy_version": self.policy_version,
            "conditions_count": len(self.conditions_evaluated),
            "evidence_bundle_hash": self.evidence_bundle_hash,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — QNEO SECURITY GATE (The Decision Authority)
# ═══════════════════════════════════════════════════════════════════════════════

class QNEOSecurityGate:
    """
    QNEO Security Gate — the final decision authority for AI-generated patches.

    Decision priority (highest to lowest):
        1. FAIL_CLOSED — any of 9 conditions → block immediately
        2. ROLLBACK    — any of 5 conditions → revert deployed patch
        3. HOLD        — any of 6 conditions → needs investigation
        4. ALLOW       — all 8 conditions met → safe to merge

    ALLOW requires ALL 8 conditions to be true.
    HOLD, FAIL_CLOSED, ROLLBACK require ANY of their conditions to be true.
    FAIL_CLOSED takes priority over all other decisions.

    Policy rules:
        No evidence bundle → no merge
        No scanner output → FAIL_CLOSED
        No AST gate → FAIL_CLOSED
        No re-scan → FAIL_CLOSED
        No human review → FAIL_CLOSED
        No evidence hash → FAIL_CLOSED
    """

    POLICY_VERSION = "aim-drag-qneo-v1.0"

    POLICY_RULES = [
        "No evidence bundle → no merge",
        "No scanner output → FAIL_CLOSED",
        "No AST gate → FAIL_CLOSED",
        "No re-scan → FAIL_CLOSED",
        "No human review → FAIL_CLOSED",
        "No evidence hash → FAIL_CLOSED",
        "LLM review is useful but NOT authoritative",
        "Every AI patch treated as hostile until proven safe",
        "Scanner output, AST enforcement, tests, re-scan, human review, and QNEO evidence = decision boundary",
    ]

    def __init__(self) -> None:
        self._decisions: List[QNEODecisionRecord] = []

    @property
    def decisions(self) -> List[QNEODecisionRecord]:
        return list(self._decisions)

    # ── FAIL_CLOSED Conditions (9 conditions) ────────────────────────────

    def _evaluate_fail_closed_conditions(
        self,
        sv: QNEOSecurityStateVector,
    ) -> List[QNEOConditionResult]:
        """
        Evaluate all 9 FAIL_CLOSED conditions.
        Any single trigger = FAIL_CLOSED.
        """
        results: List[QNEOConditionResult] = []

        # FC-1: Scanner output is missing
        results.append(QNEOConditionResult(
            condition_id="FC-1",
            condition_name="scanner_output_missing",
            category=QNEOConditionCategory.FAIL_CLOSED_TRIGGER,
            satisfied=not sv.scanner_output_present,
            description="Scanner output is missing",
        ))

        # FC-2: AST gate is missing
        results.append(QNEOConditionResult(
            condition_id="FC-2",
            condition_name="ast_gate_missing",
            category=QNEOConditionCategory.FAIL_CLOSED_TRIGGER,
            satisfied=not sv.ast_gate_present,
            description="AST gate is missing",
        ))

        # FC-3: Patched code is not re-scanned
        results.append(QNEOConditionResult(
            condition_id="FC-3",
            condition_name="patched_code_not_rescanned",
            category=QNEOConditionCategory.FAIL_CLOSED_TRIGGER,
            satisfied=not sv.patched_code_rescanned,
            description="Patched code is not re-scanned",
        ))

        # FC-4: LLM patch disables validation
        llm_disables_validation = (
            sv.llm_review is not None and sv.llm_review.disables_validation
        )
        results.append(QNEOConditionResult(
            condition_id="FC-4",
            condition_name="llm_patch_disables_validation",
            category=QNEOConditionCategory.FAIL_CLOSED_TRIGGER,
            satisfied=llm_disables_validation,
            description="LLM patch disables validation",
        ))

        # FC-5: LLM patch suppresses tests
        llm_suppresses_tests = (
            sv.llm_review is not None and sv.llm_review.suppresses_tests
        )
        results.append(QNEOConditionResult(
            condition_id="FC-5",
            condition_name="llm_patch_suppresses_tests",
            category=QNEOConditionCategory.FAIL_CLOSED_TRIGGER,
            satisfied=llm_suppresses_tests,
            description="LLM patch suppresses tests",
        ))

        # FC-6: LLM patch removes logging or audit
        llm_removes_logging = (
            sv.llm_review is not None and sv.llm_review.removes_logging_or_audit
        )
        results.append(QNEOConditionResult(
            condition_id="FC-6",
            condition_name="llm_patch_removes_logging",
            category=QNEOConditionCategory.FAIL_CLOSED_TRIGGER,
            satisfied=llm_removes_logging,
            description="LLM patch removes logging or audit",
        ))

        # FC-7: Unsafe calls appear without waiver
        unsafe_without_waiver = False
        if sv.ast_gate_result is not None:
            for v in sv.ast_gate_result.violations:
                if v.waiver_eligible and not v.waiver_present and v.is_blocked:
                    unsafe_without_waiver = True
                    break
        results.append(QNEOConditionResult(
            condition_id="FC-7",
            condition_name="unsafe_calls_without_waiver",
            category=QNEOConditionCategory.FAIL_CLOSED_TRIGGER,
            satisfied=unsafe_without_waiver,
            description="Unsafe calls appear without waiver",
        ))

        # FC-8: Manual security review is missing
        manual_review_missing = not sv.human_reviewer_signed_off
        results.append(QNEOConditionResult(
            condition_id="FC-8",
            condition_name="manual_security_review_missing",
            category=QNEOConditionCategory.FAIL_CLOSED_TRIGGER,
            satisfied=manual_review_missing,
            description="Manual security review is missing",
        ))

        # FC-9: QNEO evidence hash is missing
        results.append(QNEOConditionResult(
            condition_id="FC-9",
            condition_name="qneo_evidence_hash_missing",
            category=QNEOConditionCategory.FAIL_CLOSED_TRIGGER,
            satisfied=not sv.evidence_hash_present,
            description="QNEO evidence hash is missing",
        ))

        return results

    # ── ROLLBACK Conditions (5 conditions) ───────────────────────────────

    def _evaluate_rollback_conditions(
        self,
        sv: QNEOSecurityStateVector,
    ) -> List[QNEOConditionResult]:
        """
        Evaluate all 5 ROLLBACK conditions.
        Any single trigger = ROLLBACK.
        """
        results: List[QNEOConditionResult] = []

        # RB-1: Post-merge scanner detects a new high-risk issue
        results.append(QNEOConditionResult(
            condition_id="RB-1",
            condition_name="post_merge_new_high_risk_issue",
            category=QNEOConditionCategory.ROLLBACK_TRIGGER,
            satisfied=sv.post_merge_new_high_risk_issue,
            description="Post-merge scanner detects a new high-risk issue",
        ))

        # RB-2: Runtime telemetry shows exploit-like behavior
        results.append(QNEOConditionResult(
            condition_id="RB-2",
            condition_name="runtime_exploit_behavior",
            category=QNEOConditionCategory.ROLLBACK_TRIGGER,
            satisfied=sv.runtime_exploit_behavior_detected,
            description="Runtime telemetry shows exploit-like behavior",
        ))

        # RB-3: QNEO risk rises after deployment
        results.append(QNEOConditionResult(
            condition_id="RB-3",
            condition_name="qneo_risk_risen_after_deployment",
            category=QNEOConditionCategory.ROLLBACK_TRIGGER,
            satisfied=sv.qneo_risk_risen_after_deployment,
            description="QNEO risk rises after deployment",
        ))

        # RB-4: Incident links to an AI-generated patch
        results.append(QNEOConditionResult(
            condition_id="RB-4",
            condition_name="incident_linked_to_ai_patch",
            category=QNEOConditionCategory.ROLLBACK_TRIGGER,
            satisfied=sv.incident_linked_to_ai_patch,
            description="Incident links to an AI-generated patch",
        ))

        # RB-5: Patch evidence cannot be reconstructed
        results.append(QNEOConditionResult(
            condition_id="RB-5",
            condition_name="patch_evidence_not_reconstructable",
            category=QNEOConditionCategory.ROLLBACK_TRIGGER,
            satisfied=sv.patch_evidence_not_reconstructable,
            description="Patch evidence cannot be reconstructed",
        ))

        return results

    # ── HOLD Conditions (6 conditions) ───────────────────────────────────

    def _evaluate_hold_conditions(
        self,
        sv: QNEOSecurityStateVector,
    ) -> List[QNEOConditionResult]:
        """
        Evaluate all 6 HOLD conditions.
        Any single trigger = HOLD.
        """
        results: List[QNEOConditionResult] = []

        # H-1: LLM reports extra issues without scanner support
        llm_extra_issues = (
            sv.llm_review is not None
            and sv.llm_review.extra_issues_without_scanner_support
        )
        results.append(QNEOConditionResult(
            condition_id="H-1",
            condition_name="llm_extra_issues_without_scanner_support",
            category=QNEOConditionCategory.HOLD_TRIGGER,
            satisfied=llm_extra_issues,
            description="LLM reports extra issues without scanner support",
        ))

        # H-2: Scanner and LLM disagree
        scanner_llm_disagree = (
            sv.llm_review is not None
            and not sv.llm_review.agrees_with_scanners
        )
        results.append(QNEOConditionResult(
            condition_id="H-2",
            condition_name="scanner_llm_disagree",
            category=QNEOConditionCategory.HOLD_TRIGGER,
            satisfied=scanner_llm_disagree,
            description="Scanner and LLM disagree",
        ))

        # H-3: CWE mapping is vague
        cwe_vague = is_cwe_mapping_vague(sv.cwe_mapping)
        results.append(QNEOConditionResult(
            condition_id="H-3",
            condition_name="cwe_mapping_vague",
            category=QNEOConditionCategory.HOLD_TRIGGER,
            satisfied=cwe_vague,
            description="CWE mapping is vague",
        ))

        # H-4: Patch changes unrelated code
        changes_unrelated = (
            sv.patch_analysis is not None
            and sv.patch_analysis.changes_unrelated_code
        )
        results.append(QNEOConditionResult(
            condition_id="H-4",
            condition_name="patch_changes_unrelated_code",
            category=QNEOConditionCategory.HOLD_TRIGGER,
            satisfied=changes_unrelated,
            description="Patch changes unrelated code",
        ))

        # H-5: False positive needs expert review
        false_positive_needs_review = False
        if sv.sarif_bundle is not None:
            for r in sv.sarif_bundle.all_results:
                if r.false_positive and not r.false_positive_justification:
                    false_positive_needs_review = True
                    break
        results.append(QNEOConditionResult(
            condition_id="H-5",
            condition_name="false_positive_needs_expert_review",
            category=QNEOConditionCategory.HOLD_TRIGGER,
            satisfied=false_positive_needs_review,
            description="False positive needs expert review",
        ))

        # H-6: Fix removes functionality without proof
        removes_functionality = (
            sv.llm_review is not None
            and sv.llm_review.removes_functionality_without_proof
        )
        results.append(QNEOConditionResult(
            condition_id="H-6",
            condition_name="fix_removes_functionality_without_proof",
            category=QNEOConditionCategory.HOLD_TRIGGER,
            satisfied=removes_functionality,
            description="Fix removes functionality without proof",
        ))

        return results

    # ── ALLOW Conditions (8 conditions) ──────────────────────────────────

    def _evaluate_allow_conditions(
        self,
        sv: QNEOSecurityStateVector,
    ) -> List[QNEOConditionResult]:
        """
        Evaluate all 8 ALLOW conditions.
        ALL must be satisfied for ALLOW.
        """
        results: List[QNEOConditionResult] = []

        # A-1: Scanner findings are resolved or documented as false positives
        results.append(QNEOConditionResult(
            condition_id="A-1",
            condition_name="scanner_findings_resolved",
            category=QNEOConditionCategory.ALLOW_CONDITION,
            satisfied=sv.scanner_findings_resolved,
            description="Scanner findings are resolved or documented as false positives",
        ))

        # A-2: AST gate passes
        ast_passes = (
            sv.ast_gate_result is not None and sv.ast_gate_result.passed
        )
        results.append(QNEOConditionResult(
            condition_id="A-2",
            condition_name="ast_gate_passes",
            category=QNEOConditionCategory.ALLOW_CONDITION,
            satisfied=ast_passes,
            description="AST gate passes",
        ))

        # A-3: Tests pass
        results.append(QNEOConditionResult(
            condition_id="A-3",
            condition_name="tests_pass",
            category=QNEOConditionCategory.ALLOW_CONDITION,
            satisfied=sv.tests_passed,
            description="Tests pass",
        ))

        # A-4: Patched code is re-scanned
        results.append(QNEOConditionResult(
            condition_id="A-4",
            condition_name="patched_code_rescanned",
            category=QNEOConditionCategory.ALLOW_CONDITION,
            satisfied=sv.patched_code_rescanned,
            description="Patched code is re-scanned",
        ))

        # A-5: Patch is minimal
        results.append(QNEOConditionResult(
            condition_id="A-5",
            condition_name="patch_is_minimal",
            category=QNEOConditionCategory.ALLOW_CONDITION,
            satisfied=sv.patch_is_minimal,
            description="Patch is minimal",
        ))

        # A-6: CWE classification is correct
        results.append(QNEOConditionResult(
            condition_id="A-6",
            condition_name="cwe_classification_correct",
            category=QNEOConditionCategory.ALLOW_CONDITION,
            satisfied=sv.cwe_classification_correct,
            description="CWE classification is correct",
        ))

        # A-7: Human reviewer signs off
        results.append(QNEOConditionResult(
            condition_id="A-7",
            condition_name="human_reviewer_signs_off",
            category=QNEOConditionCategory.ALLOW_CONDITION,
            satisfied=sv.human_reviewer_signed_off,
            description="Human reviewer signs off",
        ))

        # A-8: QNEO evidence bundle is complete
        evidence_complete = (
            sv.evidence_bundle is not None
            and sv.evidence_bundle.is_complete()
        )
        results.append(QNEOConditionResult(
            condition_id="A-8",
            condition_name="qneo_evidence_bundle_complete",
            category=QNEOConditionCategory.ALLOW_CONDITION,
            satisfied=evidence_complete,
            description="QNEO evidence bundle is complete",
        ))

        return results

    # ── Main Evaluation ──────────────────────────────────────────────────

    def evaluate(
        self,
        state_vector: QNEOSecurityStateVector,
        trace_id: Optional[str] = None,
        actor_identity: str = "system",
    ) -> QNEODecisionRecord:
        """
        Evaluate the complete state vector and produce a QNEO decision.

        Decision priority:
            1. FAIL_CLOSED — any of 9 conditions triggered
            2. ROLLBACK    — any of 5 conditions triggered
            3. HOLD        — any of 6 conditions triggered
            4. ALLOW       — all 8 conditions satisfied

        This is the single decision point. All paths converge here.
        """
        if trace_id is None:
            trace_id = str(uuid.uuid4())

        all_conditions: List[QNEOConditionResult] = []
        reasons: List[str] = []

        # Evaluate FAIL_CLOSED conditions (highest priority)
        fc_conditions = self._evaluate_fail_closed_conditions(state_vector)
        all_conditions.extend(fc_conditions)
        fc_triggered = [c for c in fc_conditions if c.satisfied]

        # Evaluate ROLLBACK conditions
        rb_conditions = self._evaluate_rollback_conditions(state_vector)
        all_conditions.extend(rb_conditions)
        rb_triggered = [c for c in rb_conditions if c.satisfied]

        # Evaluate HOLD conditions
        hold_conditions = self._evaluate_hold_conditions(state_vector)
        all_conditions.extend(hold_conditions)
        hold_triggered = [c for c in hold_conditions if c.satisfied]

        # Evaluate ALLOW conditions
        allow_conditions = self._evaluate_allow_conditions(state_vector)
        all_conditions.extend(allow_conditions)
        allow_satisfied = [c for c in allow_conditions if c.satisfied]
        allow_unsatisfied = [c for c in allow_conditions if not c.satisfied]

        # Decision logic: priority order
        if fc_triggered:
            decision = QNEODecision.FAIL_CLOSED
            reasons = [f"{c.condition_id}: {c.description}" for c in fc_triggered]
        elif rb_triggered:
            decision = QNEODecision.ROLLBACK
            reasons = [f"{c.condition_id}: {c.description}" for c in rb_triggered]
        elif hold_triggered:
            decision = QNEODecision.HOLD
            reasons = [f"{c.condition_id}: {c.description}" for c in hold_triggered]
        elif len(allow_satisfied) == len(allow_conditions):
            decision = QNEODecision.ALLOW
            reasons = ["All 8 ALLOW conditions satisfied"]
        else:
            # Not all ALLOW conditions met and no explicit HOLD/FC/RB trigger
            # Default to FAIL_CLOSED (fail-closed by design)
            decision = QNEODecision.FAIL_CLOSED
            reasons = [
                f"ALLOW condition not met — {c.condition_id}: {c.description}"
                for c in allow_unsatisfied
            ]

        # Compute evidence bundle hash
        evidence_hash = ""
        if state_vector.evidence_bundle is not None:
            evidence_hash = state_vector.evidence_bundle.compute_bundle_hash()

        # Build policy snapshot
        policy_snapshot = json.dumps({
            "policy_version": self.POLICY_VERSION,
            "rules": self.POLICY_RULES,
            "conditions_evaluated": len(all_conditions),
            "fc_triggered": len(fc_triggered),
            "rb_triggered": len(rb_triggered),
            "hold_triggered": len(hold_triggered),
            "allow_satisfied": f"{len(allow_satisfied)}/{len(allow_conditions)}",
        })

        # Build decision record
        record = QNEODecisionRecord(
            decision_id=str(uuid.uuid4()),
            decision=decision,
            pipeline_id=state_vector.pipeline_id,
            trace_id=trace_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            conditions_evaluated=all_conditions,
            reasons=reasons,
            policy_version=self.POLICY_VERSION,
            policy_snapshot=policy_snapshot,
            actor_identity=actor_identity,
            evidence_bundle_hash=evidence_hash,
        )

        self._decisions.append(record)

        logger.info(
            f"QNEO decision: {decision.value} for pipeline {state_vector.pipeline_id} "
            f"(trace_id={trace_id}): {reasons}"
        )

        return record

    # ── Convenience: Build State Vector from Pipeline ────────────────────

    @staticmethod
    def build_state_vector_from_pipeline(
        pipeline_id: str,
        evidence_bundle: Optional[SecurityEvidenceBundle] = None,
        sarif_bundle: Optional[SARIFBundle] = None,
        rescan_sarif_bundle: Optional[SARIFBundle] = None,
        ast_gate_result: Optional[ASTGateResult] = None,
        test_result: Optional[TestExecutionResult] = None,
        llm_review: Optional[LLMReviewResult] = None,
        human_review: Optional[HumanSecurityReview] = None,
        patch_analysis: Optional[PatchAnalysis] = None,
        cwe_mapping: Optional[List[int]] = None,
        # Post-deployment signals
        post_merge_new_high_risk_issue: bool = False,
        runtime_exploit_behavior_detected: bool = False,
        qneo_risk_risen_after_deployment: bool = False,
        incident_linked_to_ai_patch: bool = False,
        patch_evidence_not_reconstructable: bool = False,
    ) -> QNEOSecurityStateVector:
        """
        Build a QNEOSecurityStateVector from pipeline components.
        """
        # Scanner state
        scanner_output_present = sarif_bundle is not None and sarif_bundle.has_output()
        scanner_findings_resolved = (
            sarif_bundle is not None and sarif_bundle.findings_resolved()
        )

        # AST gate state
        ast_gate_present = ast_gate_result is not None

        # Test state
        tests_passed = test_result is not None and test_result.passed

        # Re-scan state
        patched_code_rescanned = rescan_sarif_bundle is not None and rescan_sarif_bundle.has_output()

        # Patch analysis
        patch_is_minimal = patch_analysis is not None and patch_analysis.is_minimal

        # CWE state
        actual_cwe_mapping = cwe_mapping or []
        cwe_valid, _ = validate_cwe_mapping(actual_cwe_mapping)
        cwe_classification_correct = cwe_valid and not is_cwe_mapping_vague(actual_cwe_mapping)

        # Human review
        human_reviewer_signed_off = (
            human_review is not None
            and human_review.approved
            and human_review.is_valid()
        )

        # Evidence hash
        evidence_hash_present = (
            evidence_bundle is not None
            and bool(evidence_bundle.compute_bundle_hash())
        )

        return QNEOSecurityStateVector(
            pipeline_id=pipeline_id,
            evidence_bundle=evidence_bundle,
            scanner_output_present=scanner_output_present,
            sarif_bundle=sarif_bundle,
            scanner_findings_resolved=scanner_findings_resolved,
            ast_gate_present=ast_gate_present,
            ast_gate_result=ast_gate_result,
            tests_passed=tests_passed,
            test_result=test_result,
            patched_code_rescanned=patched_code_rescanned,
            rescan_sarif_bundle=rescan_sarif_bundle,
            patch_analysis=patch_analysis,
            patch_is_minimal=patch_is_minimal,
            cwe_mapping=actual_cwe_mapping,
            cwe_classification_correct=cwe_classification_correct,
            llm_review=llm_review,
            human_review=human_review,
            human_reviewer_signed_off=human_reviewer_signed_off,
            post_merge_new_high_risk_issue=post_merge_new_high_risk_issue,
            runtime_exploit_behavior_detected=runtime_exploit_behavior_detected,
            qneo_risk_risen_after_deployment=qneo_risk_risen_after_deployment,
            incident_linked_to_ai_patch=incident_linked_to_ai_patch,
            patch_evidence_not_reconstructable=patch_evidence_not_reconstructable,
            evidence_hash_present=evidence_hash_present,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — INTEGRATED PIPELINE EXECUTOR
# ═══════════════════════════════════════════════════════════════════════════════

class SecureCodingGateExecutor:
    """
    Integrated executor that runs the full 11-step secure coding pipeline
    and produces a QNEO decision.

    This is the top-level entry point for the A.I.M D.R.A.G secure coding gate.
    """

    def __init__(self) -> None:
        self._qneo_gate = QNEOSecurityGate()

    @property
    def qneo_gate(self) -> QNEOSecurityGate:
        return self._qneo_gate

    def execute_gate(
        self,
        pipeline_id: str,
        evidence_bundle: Optional[SecurityEvidenceBundle] = None,
        sarif_bundle: Optional[SARIFBundle] = None,
        rescan_sarif_bundle: Optional[SARIFBundle] = None,
        ast_gate_result: Optional[ASTGateResult] = None,
        test_result: Optional[TestExecutionResult] = None,
        llm_review: Optional[LLMReviewResult] = None,
        human_review: Optional[HumanSecurityReview] = None,
        patch_analysis: Optional[PatchAnalysis] = None,
        cwe_mapping: Optional[List[int]] = None,
        # Post-deployment signals
        post_merge_new_high_risk_issue: bool = False,
        runtime_exploit_behavior_detected: bool = False,
        qneo_risk_risen_after_deployment: bool = False,
        incident_linked_to_ai_patch: bool = False,
        patch_evidence_not_reconstructable: bool = False,
        # Trace
        trace_id: Optional[str] = None,
        actor_identity: str = "system",
    ) -> QNEODecisionRecord:
        """
        Execute the QNEO gate with the given pipeline evidence.
        Returns the QNEO decision record.
        """
        state_vector = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id=pipeline_id,
            evidence_bundle=evidence_bundle,
            sarif_bundle=sarif_bundle,
            rescan_sarif_bundle=rescan_sarif_bundle,
            ast_gate_result=ast_gate_result,
            test_result=test_result,
            llm_review=llm_review,
            human_review=human_review,
            patch_analysis=patch_analysis,
            cwe_mapping=cwe_mapping,
            post_merge_new_high_risk_issue=post_merge_new_high_risk_issue,
            runtime_exploit_behavior_detected=runtime_exploit_behavior_detected,
            qneo_risk_risen_after_deployment=qneo_risk_risen_after_deployment,
            incident_linked_to_ai_patch=incident_linked_to_ai_patch,
            patch_evidence_not_reconstructable=patch_evidence_not_reconstructable,
        )

        return self._qneo_gate.evaluate(
            state_vector=state_vector,
            trace_id=trace_id,
            actor_identity=actor_identity,
        )

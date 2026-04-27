"""
test_qneo_security_gate.py — Comprehensive tests for the QNEO Security Gate.

Tests prove all gate decisions:
    - ALLOW:       All 8 conditions satisfied → merge allowed
    - HOLD:        Any of 6 conditions triggered → needs investigation
    - FAIL_CLOSED: Any of 9 conditions triggered → block everything
    - ROLLBACK:    Any of 5 conditions triggered → revert deployed patch

Every condition is tested individually and in combination.
"""

import hashlib
import json
import unittest
from datetime import datetime, timezone

from secure_coding_gate import (
    ASTEnforcementEngine,
    ASTGateResult,
    ASTViolation,
    ASTViolationSeverity,
    HumanSecurityReview,
    LLMReviewResult,
    PatchAnalysis,
    SARIFBundle,
    SARIFResult,
    SARIFToolRun,
    SecurityEvidenceBundle,
    TestExecutionResult,
    analyze_patch,
    compute_sha256,
)

from qneo_security_gate import (
    QNEOConditionCategory,
    QNEOConditionResult,
    QNEODecision,
    QNEODecisionRecord,
    QNEOSecurityGate,
    QNEOSecurityStateVector,
    SecureCodingGateExecutor,
)


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _make_valid_evidence_bundle() -> SecurityEvidenceBundle:
    """Create a valid evidence bundle with all 15 fields."""
    return SecurityEvidenceBundle(
        input_hash=_sha256("original"),
        output_hash=_sha256("patched"),
        prompt_hash=_sha256("prompt"),
        model_id="gpt-5",
        model_temperature=0.0,
        scanner_versions={"semgrep": "1.50.0"},
        SARIF_bundle_hash=_sha256("sarif"),
        AST_gate_result="PASS",
        test_result_hash=_sha256("tests"),
        CWE_mapping=[89, 79],
        risk_rating="high",
        manual_reviewer="security-lead@example.com",
        patch_diff_hash=_sha256("diff"),
        QNEO_decision="ALLOW",
        merge_commit_sha="",
    )


def _make_clean_ast_result() -> ASTGateResult:
    """AST gate result with no violations."""
    return ASTGateResult(passed=True, violations=[], files_scanned=1)


def _make_failed_ast_result() -> ASTGateResult:
    """AST gate result with blocking violations."""
    return ASTGateResult(
        passed=False,
        violations=[
            ASTViolation(
                rule_id="AST-001",
                rule_name="ban_parse_at_boundaries",
                description="Ban .parse at boundaries",
                file_path="app.py",
                line_number=10,
                code_snippet="json.loads(data)",
                severity=ASTViolationSeverity.CRITICAL,
                waiver_eligible=False,
                waiver_present=False,
            ),
        ],
        files_scanned=1,
    )


def _make_ast_result_with_unwaived_unsafe() -> ASTGateResult:
    """AST gate result with waiver-eligible but unwaived violation."""
    return ASTGateResult(
        passed=False,
        violations=[
            ASTViolation(
                rule_id="AST-006",
                rule_name="ban_unsafe_c_calls",
                description="Ban unsafe C/C++ calls unless waiver",
                file_path="native.py",
                line_number=5,
                code_snippet="strcpy(dest, src)",
                severity=ASTViolationSeverity.CRITICAL,
                waiver_eligible=True,
                waiver_present=False,
            ),
        ],
        files_scanned=1,
    )


def _make_resolved_sarif_bundle() -> SARIFBundle:
    """SARIF bundle with all findings resolved."""
    r1 = SARIFResult(
        rule_id="R1", message="Issue", level="error",
        file_path="a.py", start_line=1, end_line=1,
        cwe_ids=[89],
        false_positive=True,
        false_positive_justification="Verified safe",
    )
    return SARIFBundle(runs=[SARIFToolRun("semgrep", "1.50.0", [r1])])


def _make_unresolved_sarif_bundle() -> SARIFBundle:
    """SARIF bundle with unresolved findings."""
    r1 = SARIFResult(
        rule_id="R1", message="SQL Injection", level="error",
        file_path="a.py", start_line=1, end_line=1,
        cwe_ids=[89],
    )
    return SARIFBundle(runs=[SARIFToolRun("semgrep", "1.50.0", [r1])])


def _make_sarif_with_unjustified_fp() -> SARIFBundle:
    """SARIF bundle with false positive lacking justification."""
    r1 = SARIFResult(
        rule_id="R1", message="Issue", level="error",
        file_path="a.py", start_line=1, end_line=1,
        cwe_ids=[89],
        false_positive=True,
        false_positive_justification="",  # No justification
    )
    return SARIFBundle(runs=[SARIFToolRun("semgrep", "1.50.0", [r1])])


def _make_empty_sarif_bundle() -> SARIFBundle:
    """SARIF bundle with a run but no findings."""
    return SARIFBundle(runs=[SARIFToolRun("semgrep", "1.50.0", [])])


def _make_passing_tests() -> TestExecutionResult:
    return TestExecutionResult(
        passed=True, total_tests=42, passed_tests=42,
        failed_tests=0, error_tests=0, skipped_tests=0,
        execution_time_seconds=10.0, test_output="All passed",
    )


def _make_failing_tests() -> TestExecutionResult:
    return TestExecutionResult(
        passed=False, total_tests=42, passed_tests=38,
        failed_tests=3, error_tests=1, skipped_tests=0,
        execution_time_seconds=10.0, test_output="4 failures",
    )


def _make_clean_llm_review() -> LLMReviewResult:
    return LLMReviewResult(
        model_id="gpt-5", model_temperature=0.0,
        prompt_hash=_sha256("prompt"),
        agrees_with_scanners=True,
    )


def _make_approved_human_review() -> HumanSecurityReview:
    return HumanSecurityReview(
        reviewer_identity="security-lead@example.com",
        approved=True,
        reviewed_evidence_hash=_sha256("evidence"),
    )


def _make_minimal_patch_analysis() -> PatchAnalysis:
    return PatchAnalysis(
        original_source="def foo():\n    return 1\n",
        patched_source="def foo():\n    return 2\n",
        patch_diff="- return 1\n+ return 2",
        is_minimal=True,
        changes_unrelated_code=False,
        lines_added=1,
        lines_removed=1,
        files_changed=1,
    )


def _make_non_minimal_patch_analysis() -> PatchAnalysis:
    return PatchAnalysis(
        original_source="a\n" * 100,
        patched_source="b\n" * 100,
        patch_diff="massive diff",
        is_minimal=False,
        changes_unrelated_code=False,
        lines_added=100,
        lines_removed=100,
        files_changed=1,
    )


def _make_unrelated_changes_patch() -> PatchAnalysis:
    return PatchAnalysis(
        original_source="original",
        patched_source="patched",
        patch_diff="diff",
        is_minimal=True,
        changes_unrelated_code=True,
        lines_added=5,
        lines_removed=3,
        files_changed=1,
    )


def _build_allow_state_vector() -> QNEOSecurityStateVector:
    """Build a state vector that should result in ALLOW."""
    return QNEOSecurityGate.build_state_vector_from_pipeline(
        pipeline_id="test-pipeline-allow",
        evidence_bundle=_make_valid_evidence_bundle(),
        sarif_bundle=_make_resolved_sarif_bundle(),
        rescan_sarif_bundle=_make_empty_sarif_bundle(),
        ast_gate_result=_make_clean_ast_result(),
        test_result=_make_passing_tests(),
        llm_review=_make_clean_llm_review(),
        human_review=_make_approved_human_review(),
        patch_analysis=_make_minimal_patch_analysis(),
        cwe_mapping=[89, 79],
    )


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: ALLOW CONDITIONS (8 conditions — ALL must be satisfied)
# ═══════════════════════════════════════════════════════════════════════════════

class TestQNEOAllow(unittest.TestCase):
    """Tests proving ALLOW requires all 8 conditions to be satisfied."""

    def setUp(self):
        self.gate = QNEOSecurityGate()

    def test_allow_all_conditions_met(self):
        """ALLOW when all 8 conditions are satisfied."""
        sv = _build_allow_state_vector()
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.ALLOW)
        self.assertIn("All 8 ALLOW conditions satisfied", record.reasons)

    def test_allow_condition_a1_scanner_findings_resolved(self):
        """A-1: Scanner findings must be resolved."""
        sv = _build_allow_state_vector()
        # Verify the condition is checked
        allow_conditions = self.gate._evaluate_allow_conditions(sv)
        a1 = next(c for c in allow_conditions if c.condition_id == "A-1")
        self.assertTrue(a1.satisfied)

    def test_allow_condition_a2_ast_gate_passes(self):
        """A-2: AST gate must pass."""
        sv = _build_allow_state_vector()
        allow_conditions = self.gate._evaluate_allow_conditions(sv)
        a2 = next(c for c in allow_conditions if c.condition_id == "A-2")
        self.assertTrue(a2.satisfied)

    def test_allow_condition_a3_tests_pass(self):
        """A-3: Tests must pass."""
        sv = _build_allow_state_vector()
        allow_conditions = self.gate._evaluate_allow_conditions(sv)
        a3 = next(c for c in allow_conditions if c.condition_id == "A-3")
        self.assertTrue(a3.satisfied)

    def test_allow_condition_a4_patched_code_rescanned(self):
        """A-4: Patched code must be re-scanned."""
        sv = _build_allow_state_vector()
        allow_conditions = self.gate._evaluate_allow_conditions(sv)
        a4 = next(c for c in allow_conditions if c.condition_id == "A-4")
        self.assertTrue(a4.satisfied)

    def test_allow_condition_a5_patch_is_minimal(self):
        """A-5: Patch must be minimal."""
        sv = _build_allow_state_vector()
        allow_conditions = self.gate._evaluate_allow_conditions(sv)
        a5 = next(c for c in allow_conditions if c.condition_id == "A-5")
        self.assertTrue(a5.satisfied)

    def test_allow_condition_a6_cwe_classification_correct(self):
        """A-6: CWE classification must be correct."""
        sv = _build_allow_state_vector()
        allow_conditions = self.gate._evaluate_allow_conditions(sv)
        a6 = next(c for c in allow_conditions if c.condition_id == "A-6")
        self.assertTrue(a6.satisfied)

    def test_allow_condition_a7_human_reviewer_signs_off(self):
        """A-7: Human reviewer must sign off."""
        sv = _build_allow_state_vector()
        allow_conditions = self.gate._evaluate_allow_conditions(sv)
        a7 = next(c for c in allow_conditions if c.condition_id == "A-7")
        self.assertTrue(a7.satisfied)

    def test_allow_condition_a8_evidence_bundle_complete(self):
        """A-8: QNEO evidence bundle must be complete."""
        sv = _build_allow_state_vector()
        allow_conditions = self.gate._evaluate_allow_conditions(sv)
        a8 = next(c for c in allow_conditions if c.condition_id == "A-8")
        self.assertTrue(a8.satisfied)

    def test_not_allow_when_scanner_findings_unresolved(self):
        """Not ALLOW when scanner findings are unresolved (A-1 fails)."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_unresolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertNotEqual(record.decision, QNEODecision.ALLOW)

    def test_not_allow_when_tests_fail(self):
        """Not ALLOW when tests fail (A-3 fails)."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_failing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertNotEqual(record.decision, QNEODecision.ALLOW)

    def test_not_allow_when_patch_not_minimal(self):
        """Not ALLOW when patch is not minimal (A-5 fails)."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_non_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertNotEqual(record.decision, QNEODecision.ALLOW)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: HOLD CONDITIONS (6 conditions — ANY triggers HOLD)
# ═══════════════════════════════════════════════════════════════════════════════

class TestQNEOHold(unittest.TestCase):
    """Tests proving HOLD is triggered by any of 6 conditions."""

    def setUp(self):
        self.gate = QNEOSecurityGate()

    def _make_hold_sv(self, **overrides) -> QNEOSecurityStateVector:
        """Build a state vector that would ALLOW except for the override."""
        defaults = dict(
            pipeline_id="test-hold",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        defaults.update(overrides)
        return QNEOSecurityGate.build_state_vector_from_pipeline(**defaults)

    def test_hold_h1_llm_extra_issues_without_scanner_support(self):
        """H-1: HOLD when LLM reports extra issues without scanner support."""
        llm = LLMReviewResult(
            model_id="gpt-5", model_temperature=0.0,
            prompt_hash=_sha256("p"),
            agrees_with_scanners=True,
            extra_issues_without_scanner_support=True,
        )
        sv = self._make_hold_sv(llm_review=llm)
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.HOLD)
        self.assertTrue(any("H-1" in r for r in record.reasons))

    def test_hold_h2_scanner_llm_disagree(self):
        """H-2: HOLD when scanner and LLM disagree."""
        llm = LLMReviewResult(
            model_id="gpt-5", model_temperature=0.0,
            prompt_hash=_sha256("p"),
            agrees_with_scanners=False,
        )
        sv = self._make_hold_sv(llm_review=llm)
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.HOLD)
        self.assertTrue(any("H-2" in r for r in record.reasons))

    def test_hold_h3_cwe_mapping_vague(self):
        """H-3: HOLD when CWE mapping is vague."""
        sv = self._make_hold_sv(cwe_mapping=[20])  # Only broad category
        record = self.gate.evaluate(sv)
        # Should not be ALLOW due to vague CWE (triggers H-3 and fails A-6)
        self.assertNotEqual(record.decision, QNEODecision.ALLOW)

    def test_hold_h4_patch_changes_unrelated_code(self):
        """H-4: HOLD when patch changes unrelated code."""
        sv = self._make_hold_sv(patch_analysis=_make_unrelated_changes_patch())
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.HOLD)
        self.assertTrue(any("H-4" in r for r in record.reasons))

    def test_hold_h5_false_positive_needs_expert_review(self):
        """H-5: HOLD when false positive needs expert review."""
        sv = self._make_hold_sv(sarif_bundle=_make_sarif_with_unjustified_fp())
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.HOLD)
        self.assertTrue(any("H-5" in r for r in record.reasons))

    def test_hold_h6_fix_removes_functionality_without_proof(self):
        """H-6: HOLD when fix removes functionality without proof."""
        llm = LLMReviewResult(
            model_id="gpt-5", model_temperature=0.0,
            prompt_hash=_sha256("p"),
            agrees_with_scanners=True,
            removes_functionality_without_proof=True,
        )
        sv = self._make_hold_sv(llm_review=llm)
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.HOLD)
        self.assertTrue(any("H-6" in r for r in record.reasons))


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: FAIL_CLOSED CONDITIONS (9 conditions — ANY triggers FAIL_CLOSED)
# ═══════════════════════════════════════════════════════════════════════════════

class TestQNEOFailClosed(unittest.TestCase):
    """Tests proving FAIL_CLOSED is triggered by any of 9 conditions."""

    def setUp(self):
        self.gate = QNEOSecurityGate()

    def test_fc1_scanner_output_missing(self):
        """FC-1: FAIL_CLOSED when scanner output is missing."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-fc1",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=None,  # No scanner output
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)
        self.assertTrue(any("FC-1" in r for r in record.reasons))

    def test_fc2_ast_gate_missing(self):
        """FC-2: FAIL_CLOSED when AST gate is missing."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-fc2",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=None,  # No AST gate
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)
        self.assertTrue(any("FC-2" in r for r in record.reasons))

    def test_fc3_patched_code_not_rescanned(self):
        """FC-3: FAIL_CLOSED when patched code is not re-scanned."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-fc3",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=None,  # No re-scan
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)
        self.assertTrue(any("FC-3" in r for r in record.reasons))

    def test_fc4_llm_patch_disables_validation(self):
        """FC-4: FAIL_CLOSED when LLM patch disables validation."""
        llm = LLMReviewResult(
            model_id="gpt-5", model_temperature=0.0,
            prompt_hash=_sha256("p"),
            agrees_with_scanners=True,
            disables_validation=True,
        )
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-fc4",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=llm,
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)
        self.assertTrue(any("FC-4" in r for r in record.reasons))

    def test_fc5_llm_patch_suppresses_tests(self):
        """FC-5: FAIL_CLOSED when LLM patch suppresses tests."""
        llm = LLMReviewResult(
            model_id="gpt-5", model_temperature=0.0,
            prompt_hash=_sha256("p"),
            agrees_with_scanners=True,
            suppresses_tests=True,
        )
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-fc5",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=llm,
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)
        self.assertTrue(any("FC-5" in r for r in record.reasons))

    def test_fc6_llm_patch_removes_logging(self):
        """FC-6: FAIL_CLOSED when LLM patch removes logging or audit."""
        llm = LLMReviewResult(
            model_id="gpt-5", model_temperature=0.0,
            prompt_hash=_sha256("p"),
            agrees_with_scanners=True,
            removes_logging_or_audit=True,
        )
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-fc6",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=llm,
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)
        self.assertTrue(any("FC-6" in r for r in record.reasons))

    def test_fc7_unsafe_calls_without_waiver(self):
        """FC-7: FAIL_CLOSED when unsafe calls appear without waiver."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-fc7",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_ast_result_with_unwaived_unsafe(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)
        self.assertTrue(any("FC-7" in r for r in record.reasons))

    def test_fc8_manual_security_review_missing(self):
        """FC-8: FAIL_CLOSED when manual security review is missing."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-fc8",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=None,  # No human review
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)
        self.assertTrue(any("FC-8" in r for r in record.reasons))

    def test_fc9_qneo_evidence_hash_missing(self):
        """FC-9: FAIL_CLOSED when QNEO evidence hash is missing."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-fc9",
            evidence_bundle=None,  # No evidence bundle → no hash
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)
        self.assertTrue(any("FC-9" in r for r in record.reasons))

    def test_fail_closed_takes_priority_over_hold(self):
        """FAIL_CLOSED must take priority over HOLD."""
        llm = LLMReviewResult(
            model_id="gpt-5", model_temperature=0.0,
            prompt_hash=_sha256("p"),
            agrees_with_scanners=False,  # H-2 trigger
            disables_validation=True,    # FC-4 trigger
        )
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-priority",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=llm,
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)

    def test_fail_closed_takes_priority_over_rollback(self):
        """FAIL_CLOSED must take priority over ROLLBACK."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-priority-2",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=None,  # FC-1 trigger
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
            post_merge_new_high_risk_issue=True,  # RB-1 trigger
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)

    def test_multiple_fc_conditions(self):
        """Multiple FAIL_CLOSED conditions should all be reported."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-multi-fc",
            evidence_bundle=None,       # FC-9
            sarif_bundle=None,          # FC-1
            rescan_sarif_bundle=None,   # FC-3
            ast_gate_result=None,       # FC-2
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=None,          # FC-8
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)
        # Multiple FC reasons should be present
        fc_reasons = [r for r in record.reasons if r.startswith("FC-")]
        self.assertGreaterEqual(len(fc_reasons), 3)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: ROLLBACK CONDITIONS (5 conditions — ANY triggers ROLLBACK)
# ═══════════════════════════════════════════════════════════════════════════════

class TestQNEORollback(unittest.TestCase):
    """Tests proving ROLLBACK is triggered by any of 5 conditions."""

    def setUp(self):
        self.gate = QNEOSecurityGate()

    def _make_rollback_sv(self, **overrides) -> QNEOSecurityStateVector:
        """Build a state vector that would ALLOW except for rollback triggers."""
        defaults = dict(
            pipeline_id="test-rollback",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        defaults.update(overrides)
        return QNEOSecurityGate.build_state_vector_from_pipeline(**defaults)

    def test_rb1_post_merge_new_high_risk_issue(self):
        """RB-1: ROLLBACK when post-merge scanner detects new high-risk issue."""
        sv = self._make_rollback_sv(post_merge_new_high_risk_issue=True)
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.ROLLBACK)
        self.assertTrue(any("RB-1" in r for r in record.reasons))

    def test_rb2_runtime_exploit_behavior(self):
        """RB-2: ROLLBACK when runtime telemetry shows exploit-like behavior."""
        sv = self._make_rollback_sv(runtime_exploit_behavior_detected=True)
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.ROLLBACK)
        self.assertTrue(any("RB-2" in r for r in record.reasons))

    def test_rb3_qneo_risk_risen_after_deployment(self):
        """RB-3: ROLLBACK when QNEO risk rises after deployment."""
        sv = self._make_rollback_sv(qneo_risk_risen_after_deployment=True)
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.ROLLBACK)
        self.assertTrue(any("RB-3" in r for r in record.reasons))

    def test_rb4_incident_linked_to_ai_patch(self):
        """RB-4: ROLLBACK when incident links to AI-generated patch."""
        sv = self._make_rollback_sv(incident_linked_to_ai_patch=True)
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.ROLLBACK)
        self.assertTrue(any("RB-4" in r for r in record.reasons))

    def test_rb5_patch_evidence_not_reconstructable(self):
        """RB-5: ROLLBACK when patch evidence cannot be reconstructed."""
        sv = self._make_rollback_sv(patch_evidence_not_reconstructable=True)
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.ROLLBACK)
        self.assertTrue(any("RB-5" in r for r in record.reasons))

    def test_rollback_takes_priority_over_hold(self):
        """ROLLBACK must take priority over HOLD."""
        llm = LLMReviewResult(
            model_id="gpt-5", model_temperature=0.0,
            prompt_hash=_sha256("p"),
            agrees_with_scanners=False,  # H-2 trigger
        )
        sv = self._make_rollback_sv(
            llm_review=llm,
            post_merge_new_high_risk_issue=True,  # RB-1 trigger
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.ROLLBACK)

    def test_multiple_rollback_conditions(self):
        """Multiple ROLLBACK conditions should all be reported."""
        sv = self._make_rollback_sv(
            post_merge_new_high_risk_issue=True,
            runtime_exploit_behavior_detected=True,
            incident_linked_to_ai_patch=True,
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.ROLLBACK)
        rb_reasons = [r for r in record.reasons if r.startswith("RB-")]
        self.assertGreaterEqual(len(rb_reasons), 3)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: DECISION PRIORITY
# ═══════════════════════════════════════════════════════════════════════════════

class TestQNEODecisionPriority(unittest.TestCase):
    """Tests proving decision priority: FAIL_CLOSED > ROLLBACK > HOLD > ALLOW."""

    def setUp(self):
        self.gate = QNEOSecurityGate()

    def test_priority_fc_over_rb_over_hold(self):
        """FAIL_CLOSED > ROLLBACK > HOLD in priority."""
        # Trigger all three
        llm = LLMReviewResult(
            model_id="gpt-5", model_temperature=0.0,
            prompt_hash=_sha256("p"),
            agrees_with_scanners=False,   # H-2
            disables_validation=True,     # FC-4
        )
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-priority",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=llm,
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
            post_merge_new_high_risk_issue=True,  # RB-1
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)

    def test_default_fail_closed_when_no_conditions_met(self):
        """Default to FAIL_CLOSED when no ALLOW conditions met and no explicit triggers."""
        sv = QNEOSecurityStateVector(pipeline_id="test-empty")
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: DECISION RECORD
# ═══════════════════════════════════════════════════════════════════════════════

class TestQNEODecisionRecord(unittest.TestCase):
    """Tests for QNEO decision record structure."""

    def setUp(self):
        self.gate = QNEOSecurityGate()

    def test_record_has_all_fields(self):
        """Decision record must contain all required fields."""
        sv = _build_allow_state_vector()
        record = self.gate.evaluate(sv, trace_id="test-trace-123")

        self.assertTrue(record.decision_id)
        self.assertEqual(record.decision, QNEODecision.ALLOW)
        self.assertEqual(record.pipeline_id, "test-pipeline-allow")
        self.assertEqual(record.trace_id, "test-trace-123")
        self.assertTrue(record.timestamp)
        self.assertTrue(len(record.conditions_evaluated) > 0)
        self.assertTrue(len(record.reasons) > 0)
        self.assertEqual(record.policy_version, "aim-drag-qneo-v1.0")
        self.assertTrue(record.policy_snapshot)
        self.assertEqual(record.actor_identity, "system")

    def test_record_to_dict(self):
        """Decision record to_dict must include key fields."""
        sv = _build_allow_state_vector()
        record = self.gate.evaluate(sv)
        d = record.to_dict()
        self.assertIn("decision_id", d)
        self.assertIn("decision", d)
        self.assertIn("pipeline_id", d)
        self.assertIn("trace_id", d)
        self.assertIn("reasons", d)
        self.assertIn("policy_version", d)

    def test_decisions_are_recorded(self):
        """Gate must maintain a list of all decisions."""
        sv = _build_allow_state_vector()
        self.gate.evaluate(sv)
        self.gate.evaluate(sv)
        self.assertEqual(len(self.gate.decisions), 2)

    def test_conditions_count(self):
        """All conditions (8+6+9+5 = 28) must be evaluated."""
        sv = _build_allow_state_vector()
        record = self.gate.evaluate(sv)
        self.assertEqual(len(record.conditions_evaluated), 28)

    def test_policy_snapshot_contains_rules(self):
        """Policy snapshot must contain the policy rules."""
        sv = _build_allow_state_vector()
        record = self.gate.evaluate(sv)
        snapshot = json.loads(record.policy_snapshot)
        self.assertIn("policy_version", snapshot)
        self.assertIn("rules", snapshot)
        self.assertIn("conditions_evaluated", snapshot)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: SECURE CODING GATE EXECUTOR
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecureCodingGateExecutor(unittest.TestCase):
    """Tests for the integrated SecureCodingGateExecutor."""

    def test_executor_allow(self):
        """Executor must return ALLOW when all conditions met."""
        executor = SecureCodingGateExecutor()
        record = executor.execute_gate(
            pipeline_id="test-exec-allow",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        self.assertEqual(record.decision, QNEODecision.ALLOW)

    def test_executor_fail_closed(self):
        """Executor must return FAIL_CLOSED when scanner output missing."""
        executor = SecureCodingGateExecutor()
        record = executor.execute_gate(
            pipeline_id="test-exec-fc",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=None,
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)

    def test_executor_rollback(self):
        """Executor must return ROLLBACK when post-deployment issue detected."""
        executor = SecureCodingGateExecutor()
        record = executor.execute_gate(
            pipeline_id="test-exec-rb",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
            post_merge_new_high_risk_issue=True,
        )
        self.assertEqual(record.decision, QNEODecision.ROLLBACK)

    def test_executor_hold(self):
        """Executor must return HOLD when LLM disagrees with scanners."""
        llm = LLMReviewResult(
            model_id="gpt-5", model_temperature=0.0,
            prompt_hash=_sha256("p"),
            agrees_with_scanners=False,
        )
        executor = SecureCodingGateExecutor()
        record = executor.execute_gate(
            pipeline_id="test-exec-hold",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=llm,
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        self.assertEqual(record.decision, QNEODecision.HOLD)

    def test_executor_records_decisions(self):
        """Executor must record all decisions in the gate."""
        executor = SecureCodingGateExecutor()
        executor.execute_gate(
            pipeline_id="test-1",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        self.assertEqual(len(executor.qneo_gate.decisions), 1)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: STATE VECTOR CONSTRUCTION
# ═══════════════════════════════════════════════════════════════════════════════

class TestStateVectorConstruction(unittest.TestCase):
    """Tests for QNEOSecurityStateVector construction from pipeline components."""

    def test_build_from_pipeline_complete(self):
        """State vector built from complete pipeline must have all fields set."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-sv",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        self.assertTrue(sv.scanner_output_present)
        self.assertTrue(sv.scanner_findings_resolved)
        self.assertTrue(sv.ast_gate_present)
        self.assertTrue(sv.tests_passed)
        self.assertTrue(sv.patched_code_rescanned)
        self.assertTrue(sv.patch_is_minimal)
        self.assertTrue(sv.cwe_classification_correct)
        self.assertTrue(sv.human_reviewer_signed_off)
        self.assertTrue(sv.evidence_hash_present)

    def test_build_from_pipeline_empty(self):
        """State vector built from empty pipeline must have all fields False."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-empty",
        )
        self.assertFalse(sv.scanner_output_present)
        self.assertFalse(sv.ast_gate_present)
        self.assertFalse(sv.tests_passed)
        self.assertFalse(sv.patched_code_rescanned)
        self.assertFalse(sv.patch_is_minimal)
        self.assertFalse(sv.human_reviewer_signed_off)
        self.assertFalse(sv.evidence_hash_present)

    def test_state_vector_to_dict(self):
        """State vector to_dict must include all key fields."""
        sv = _build_allow_state_vector()
        d = sv.to_dict()
        self.assertIn("pipeline_id", d)
        self.assertIn("scanner_output_present", d)
        self.assertIn("ast_gate_present", d)
        self.assertIn("tests_passed", d)
        self.assertIn("patched_code_rescanned", d)
        self.assertIn("human_reviewer_signed_off", d)
        self.assertIn("evidence_hash_present", d)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):
    """Tests for edge cases and boundary conditions."""

    def setUp(self):
        self.gate = QNEOSecurityGate()

    def test_empty_state_vector_fails_closed(self):
        """Empty state vector must result in FAIL_CLOSED."""
        sv = QNEOSecurityStateVector(pipeline_id="empty")
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)

    def test_auto_generated_trace_id(self):
        """Trace ID must be auto-generated if not provided."""
        sv = QNEOSecurityStateVector(pipeline_id="test")
        record = self.gate.evaluate(sv)
        self.assertTrue(record.trace_id)
        self.assertGreater(len(record.trace_id), 0)

    def test_custom_trace_id(self):
        """Custom trace ID must be preserved."""
        sv = QNEOSecurityStateVector(pipeline_id="test")
        record = self.gate.evaluate(sv, trace_id="custom-trace-123")
        self.assertEqual(record.trace_id, "custom-trace-123")

    def test_custom_actor_identity(self):
        """Custom actor identity must be preserved."""
        sv = QNEOSecurityStateVector(pipeline_id="test")
        record = self.gate.evaluate(sv, actor_identity="ci-bot")
        self.assertEqual(record.actor_identity, "ci-bot")

    def test_unapproved_human_review_triggers_fc8(self):
        """Unapproved human review must trigger FC-8."""
        review = HumanSecurityReview(
            reviewer_identity="reviewer@example.com",
            approved=False,
            reviewed_evidence_hash=_sha256("evidence"),
        )
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-unapproved",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=_make_clean_llm_review(),
            human_review=review,
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        self.assertEqual(record.decision, QNEODecision.FAIL_CLOSED)

    def test_no_llm_review_still_evaluates(self):
        """Missing LLM review should not crash — LLM conditions default to safe."""
        sv = QNEOSecurityGate.build_state_vector_from_pipeline(
            pipeline_id="test-no-llm",
            evidence_bundle=_make_valid_evidence_bundle(),
            sarif_bundle=_make_resolved_sarif_bundle(),
            rescan_sarif_bundle=_make_empty_sarif_bundle(),
            ast_gate_result=_make_clean_ast_result(),
            test_result=_make_passing_tests(),
            llm_review=None,
            human_review=_make_approved_human_review(),
            patch_analysis=_make_minimal_patch_analysis(),
            cwe_mapping=[89, 79],
        )
        record = self.gate.evaluate(sv)
        # Should still reach a decision (ALLOW since LLM conditions don't trigger)
        self.assertIn(record.decision, [QNEODecision.ALLOW, QNEODecision.HOLD, QNEODecision.FAIL_CLOSED])


if __name__ == "__main__":
    unittest.main()

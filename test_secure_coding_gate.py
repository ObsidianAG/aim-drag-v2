"""
test_secure_coding_gate.py — Comprehensive tests for the A.I.M D.R.A.G
Secure Coding Pipeline, AST Enforcement Engine, Pattern Enforcement Engine,
SARIF Aggregation, and Security Evidence Bundles.

Tests prove:
    - 11-step pipeline operates in correct order
    - Real AST enforcement catches security violations via ast.NodeVisitor
    - Pattern enforcement catches banned patterns in non-Python source
    - SARIF aggregation produces valid SARIF 2.1.0 documents
    - Security evidence bundle validates all 15 required fields
    - CWE 2025 Top 25 registry is complete and correct per MITRE
    - Patch analysis uses difflib.unified_diff for minimality
    - SHA-256 validation is strict hex
    - Step 11 accepts actual QNEO decision parameter
    - All prior steps must pass before step 11 proceeds
    - Rescan compares original vs patched SARIF
    - test_output_hash is included in TestExecutionResult.compute_hash
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
    CWE_2025_TOP_25,
    CWEEntry,
    HumanSecurityReview,
    LLMReviewResult,
    PatchAnalysis,
    PatternEnforcementEngine,
    PipelineStep,
    PipelineStepResult,
    PIPELINE_STEP_ORDER,
    PythonSecurityVisitor,
    SARIFAggregator,
    SARIFBundle,
    SARIFResult,
    SARIFToolRun,
    SecureCodingPipeline,
    SecurityEvidenceBundle,
    TestExecutionResult,
    analyze_patch,
    classify_cwe_priority,
    compute_sha256,
    get_cwe_entry,
    is_cwe_mapping_vague,
    is_sha256,
    validate_cwe_exists,
    validate_cwe_mapping,
)


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _make_clean_source() -> str:
    """Source code with no violations."""
    return '''
def add(a: int, b: int) -> int:
    """Add two integers safely."""
    return a + b

def greet(name: str) -> str:
    """Greet a user by name."""
    if not name:
        raise ValueError("Name is required")
    return f"Hello, {name}"
'''


def _make_vulnerable_source() -> str:
    """Source code with multiple AST violations."""
    return '''
import os
import subprocess
import json
import hashlib
import pickle
import requests

def parse_user_input(data):
    return json.loads(data)

def run_command(cmd):
    os.system(cmd)

def fetch_url(url):
    return requests.get(url)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def load_object(data):
    return pickle.loads(data)

def execute_query(cursor, query):
    cursor.execute(query)
'''


def _make_patched_source() -> str:
    """Patched source code (clean) — minimal change from _make_clean_source."""
    return '''
def add(a: int, b: int) -> int:
    """Add two integers safely."""
    return a + b

def greet(name: str) -> str:
    """Greet a user by name."""
    if not name:
        raise ValueError("Name must be provided")
    return f"Hello, {name}"
'''


def _make_sarif_results() -> list:
    """Create sample SARIF results for testing."""
    return [
        SARIFResult(
            rule_id="PY001",
            message="SQL injection vulnerability detected",
            level="error",
            file_path="app.py",
            start_line=10,
            end_line=10,
            cwe_ids=[89],
        ),
        SARIFResult(
            rule_id="PY002",
            message="Cross-site scripting vulnerability",
            level="warning",
            file_path="app.py",
            start_line=25,
            end_line=25,
            cwe_ids=[79],
        ),
    ]


def _make_resolved_sarif_results() -> list:
    """Create SARIF results that are all resolved."""
    r1 = SARIFResult(
        rule_id="PY001",
        message="SQL injection vulnerability detected",
        level="error",
        file_path="app.py",
        start_line=10,
        end_line=10,
        cwe_ids=[89],
        false_positive=True,
        false_positive_justification="Parameterized query used — verified by reviewer",
    )
    r2 = SARIFResult(
        rule_id="PY002",
        message="Cross-site scripting vulnerability",
        level="warning",
        file_path="app.py",
        start_line=25,
        end_line=25,
        cwe_ids=[79],
        suppressed=True,
    )
    return [r1, r2]


def _make_valid_evidence_bundle() -> SecurityEvidenceBundle:
    """Create a valid security evidence bundle with all 15 fields."""
    return SecurityEvidenceBundle(
        input_hash=_sha256("original source"),
        output_hash=_sha256("patched source"),
        prompt_hash=_sha256("fix the vulnerability"),
        model_id="gpt-5",
        model_temperature=0.0,
        scanner_versions={"semgrep": "1.50.0", "bandit": "1.7.5"},
        SARIF_bundle_hash=_sha256("sarif bundle content"),
        AST_gate_result="PASS",
        test_result_hash=_sha256("test results"),
        CWE_mapping=[89, 79],
        risk_rating="high",
        manual_reviewer="security-lead@example.com",
        patch_diff_hash=_sha256("patch diff"),
        QNEO_decision="ALLOW",
        merge_commit_sha="",
    )


def _make_test_result(passed: bool = True) -> TestExecutionResult:
    """Create a test execution result."""
    return TestExecutionResult(
        passed=passed,
        total_tests=42,
        passed_tests=42 if passed else 38,
        failed_tests=0 if passed else 3,
        error_tests=0 if passed else 1,
        skipped_tests=0,
        execution_time_seconds=12.5,
        test_output="All tests passed" if passed else "4 tests failed",
    )


def _make_llm_review(clean: bool = True) -> LLMReviewResult:
    """Create an LLM review result."""
    return LLMReviewResult(
        model_id="gpt-5",
        model_temperature=0.0,
        prompt_hash=_sha256("review prompt"),
        agrees_with_scanners=True,
        disables_validation=not clean,
        suppresses_tests=not clean,
    )


def _make_human_review(approved: bool = True) -> HumanSecurityReview:
    """Create a human security review."""
    return HumanSecurityReview(
        reviewer_identity="security-lead@example.com",
        approved=approved,
        reviewed_evidence_hash=_sha256("evidence"),
        comments="Reviewed and approved" if approved else "Issues found",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# CWE REGISTRY TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCWERegistry(unittest.TestCase):
    """Tests for the CWE 2025 Top 25 registry."""

    def test_registry_has_exactly_25_entries(self):
        """Registry must have exactly 25 entries per MITRE 2025 Top 25."""
        self.assertEqual(len(CWE_2025_TOP_25), 25)

    def test_registry_contains_exact_mitre_2025_top_25(self):
        """Registry must contain exactly the MITRE 2025 Top 25 CWE IDs."""
        expected = {
            79, 89, 352, 862, 787, 22, 416, 125, 78, 94,
            120, 434, 476, 121, 502, 122, 863, 20, 284, 200,
            306, 918, 77, 639, 770,
        }
        actual = set(CWE_2025_TOP_25.keys())
        self.assertEqual(actual, expected)

    def test_registry_does_not_contain_removed_cwes(self):
        """Registry must NOT contain CWE-119, 798, 276, 269."""
        removed = {119, 798, 276, 269}
        for cwe_id in removed:
            self.assertNotIn(cwe_id, CWE_2025_TOP_25,
                             f"CWE-{cwe_id} should not be in 2025 Top 25")

    def test_kev_listed_flags_per_mitre_table(self):
        """KEV flags must match MITRE 2025 table."""
        # CWEs with 0 CVEs in KEV per MITRE table → kev_listed=False
        self.assertFalse(CWE_2025_TOP_25[352].kev_listed, "CWE-352 has 0 KEV CVEs")
        self.assertFalse(CWE_2025_TOP_25[862].kev_listed, "CWE-862 has 0 KEV CVEs")
        self.assertFalse(CWE_2025_TOP_25[918].kev_listed, "CWE-918 has 0 KEV CVEs")
        self.assertFalse(CWE_2025_TOP_25[120].kev_listed, "CWE-120 has 0 KEV CVEs")
        # CWE-77 has 2 CVEs in KEV → kev_listed=True
        self.assertTrue(CWE_2025_TOP_25[77].kev_listed, "CWE-77 has 2 KEV CVEs")

    def test_get_cwe_entry_found(self):
        entry = get_cwe_entry(79)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.cwe_id, 79)
        self.assertEqual(entry.identifier, "CWE-79")

    def test_get_cwe_entry_not_found(self):
        entry = get_cwe_entry(99999)
        self.assertIsNone(entry)

    def test_validate_cwe_exists_accepts_non_top25(self):
        """validate_cwe_exists should accept valid CWEs outside Top 25."""
        valid, issues = validate_cwe_exists([772, 362, 665])
        self.assertTrue(valid)
        self.assertEqual(len(issues), 0)

    def test_validate_cwe_exists_rejects_invalid(self):
        """validate_cwe_exists should reject non-positive integers."""
        valid, issues = validate_cwe_exists([-1, 0])
        self.assertFalse(valid)
        self.assertEqual(len(issues), 2)

    def test_classify_cwe_priority(self):
        """classify_cwe_priority separates top_25, kev_linked, other."""
        result = classify_cwe_priority([89, 79, 772, 362])
        self.assertIn(89, result["top_25"])
        self.assertIn(79, result["top_25"])
        self.assertIn(89, result["kev_linked"])
        self.assertIn(772, result["other"])
        self.assertIn(362, result["other"])

    def test_validate_cwe_mapping_does_not_reject_non_top25(self):
        """validate_cwe_mapping should NOT reject valid non-Top-25 CWEs."""
        valid, issues = validate_cwe_mapping([772, 362, 665, 686])
        self.assertTrue(valid)
        self.assertEqual(len(issues), 0)

    def test_is_cwe_mapping_vague(self):
        self.assertTrue(is_cwe_mapping_vague([]))
        self.assertTrue(is_cwe_mapping_vague([20]))
        self.assertTrue(is_cwe_mapping_vague([20, 200]))
        self.assertFalse(is_cwe_mapping_vague([89]))
        self.assertFalse(is_cwe_mapping_vague([20, 89]))

    def test_all_entries_have_valid_severity(self):
        valid_severities = {"critical", "high", "medium", "low"}
        for cwe_id, entry in CWE_2025_TOP_25.items():
            self.assertIn(entry.severity, valid_severities,
                          f"CWE-{cwe_id} has invalid severity: {entry.severity}")


# ═══════════════════════════════════════════════════════════════════════════════
# SHA-256 VALIDATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSHA256Validation(unittest.TestCase):
    """Tests for strict SHA-256 hex validation."""

    def test_valid_sha256(self):
        h = _sha256("test")
        self.assertTrue(is_sha256(h))

    def test_rejects_non_hex_chars(self):
        """Must reject 'z' * 64 — not valid hex."""
        self.assertFalse(is_sha256("z" * 64))

    def test_rejects_uppercase(self):
        """Must reject uppercase hex."""
        self.assertFalse(is_sha256("A" * 64))

    def test_rejects_wrong_length(self):
        self.assertFalse(is_sha256("abcdef"))
        self.assertFalse(is_sha256("a" * 63))
        self.assertFalse(is_sha256("a" * 65))

    def test_rejects_empty(self):
        self.assertFalse(is_sha256(""))

    def test_evidence_bundle_rejects_invalid_hash(self):
        """SecurityEvidenceBundle.validate must reject 'z' * 64."""
        bundle = _make_valid_evidence_bundle()
        bundle.input_hash = "z" * 64
        errors = bundle.validate()
        self.assertTrue(any("input_hash" in e for e in errors))


# ═══════════════════════════════════════════════════════════════════════════════
# SARIF TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSARIF(unittest.TestCase):
    """Tests for SARIF evidence format."""

    def test_sarif_result_to_dict(self):
        result = SARIFResult(
            rule_id="PY001",
            message="Test finding",
            level="error",
            file_path="test.py",
            start_line=1,
            end_line=1,
            cwe_ids=[89],
        )
        d = result.to_sarif_dict()
        self.assertEqual(d["ruleId"], "PY001")
        self.assertEqual(d["level"], "error")

    def test_sarif_bundle_hash_is_deterministic(self):
        results = _make_sarif_results()
        agg = SARIFAggregator()
        agg.add_tool_run("semgrep", "1.50.0", results)
        bundle = agg.build_bundle()
        h1 = bundle.compute_hash()
        h2 = bundle.compute_hash()
        self.assertEqual(h1, h2)
        self.assertTrue(is_sha256(h1))

    def test_sarif_bundle_unresolved_results(self):
        results = _make_sarif_results()
        agg = SARIFAggregator()
        agg.add_tool_run("semgrep", "1.50.0", results)
        bundle = agg.build_bundle()
        self.assertEqual(len(bundle.unresolved_results), 2)
        self.assertEqual(len(bundle.error_results), 1)
        self.assertEqual(len(bundle.warning_results), 1)

    def test_sarif_bundle_resolved(self):
        results = _make_resolved_sarif_results()
        agg = SARIFAggregator()
        agg.add_tool_run("semgrep", "1.50.0", results)
        bundle = agg.build_bundle()
        self.assertTrue(bundle.findings_resolved())

    def test_sarif_bundle_cwe_ids(self):
        results = _make_sarif_results()
        agg = SARIFAggregator()
        agg.add_tool_run("semgrep", "1.50.0", results)
        bundle = agg.build_bundle()
        self.assertEqual(bundle.all_cwe_ids, [79, 89])

    def test_sarif_aggregator_clear(self):
        agg = SARIFAggregator()
        agg.add_tool_run("semgrep", "1.50.0", _make_sarif_results())
        agg.clear()
        bundle = agg.build_bundle()
        self.assertEqual(len(bundle.runs), 0)


# ═══════════════════════════════════════════════════════════════════════════════
# PATTERN ENFORCEMENT ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestPatternEnforcementEngine(unittest.TestCase):
    """Tests for the regex-based pattern enforcement engine."""

    def test_clean_source_passes(self):
        engine = PatternEnforcementEngine()
        result = engine.scan_source(_make_clean_source())
        self.assertTrue(result.passed)
        self.assertEqual(len(result.blocking_violations), 0)

    def test_vulnerable_source_fails(self):
        engine = PatternEnforcementEngine()
        result = engine.scan_source(_make_vulnerable_source())
        self.assertFalse(result.passed)
        self.assertGreater(len(result.blocking_violations), 0)

    def test_subprocess_list_form_allowed(self):
        """Pattern engine: subprocess without shell=True should pass rule 8."""
        engine = PatternEnforcementEngine()
        source = '''
import subprocess
result = subprocess.run(["git", "status"], check=True)
'''
        result = engine.scan_source(source)
        rule_8_violations = [v for v in result.violations if v.rule_id == "AST-008"]
        self.assertEqual(len(rule_8_violations), 0,
                         "List-form subprocess.run should not trigger AST-008")

    def test_subprocess_shell_true_blocked(self):
        """Pattern engine: subprocess with shell=True must be blocked."""
        engine = PatternEnforcementEngine()
        source = '''
import subprocess
subprocess.run(cmd, shell=True)
'''
        result = engine.scan_source(source)
        rule_8_violations = [v for v in result.violations if v.rule_id == "AST-008"]
        self.assertGreater(len(rule_8_violations), 0,
                           "subprocess.run(shell=True) must trigger AST-008")

    def test_waiver_eligible_rule(self):
        engine = PatternEnforcementEngine(waivers={"AST-006": "Approved by security team"})
        source = 'ctypes.cdll.LoadLibrary("test.so")  # SECURITY_WAIVER: AST-006'
        result = engine.scan_source(source)
        waived = result.waived_violations
        self.assertGreater(len(waived), 0)

    def test_scan_multiple_files(self):
        engine = PatternEnforcementEngine()
        files = {
            "clean.py": _make_clean_source(),
            "vuln.py": _make_vulnerable_source(),
        }
        result = engine.scan_multiple_files(files)
        self.assertFalse(result.passed)
        self.assertEqual(result.files_scanned, 2)


# ═══════════════════════════════════════════════════════════════════════════════
# AST ENFORCEMENT ENGINE TESTS (Real ast.NodeVisitor)
# ═══════════════════════════════════════════════════════════════════════════════

class TestASTEnforcementEngine(unittest.TestCase):
    """Tests for the real AST enforcement engine using ast.parse + NodeVisitor."""

    def test_clean_source_passes(self):
        engine = ASTEnforcementEngine()
        result = engine.scan_source(_make_clean_source())
        self.assertTrue(result.passed)
        self.assertEqual(len(result.blocking_violations), 0)

    def test_detects_eval(self):
        engine = ASTEnforcementEngine()
        source = 'result = eval(user_input)\n'
        result = engine.scan_source(source)
        self.assertFalse(result.passed)
        rule_ids = {v.rule_id for v in result.blocking_violations}
        self.assertIn("AST-001", rule_ids)

    def test_detects_exec(self):
        engine = ASTEnforcementEngine()
        source = 'exec(user_code)\n'
        result = engine.scan_source(source)
        self.assertFalse(result.passed)
        rule_ids = {v.rule_id for v in result.blocking_violations}
        self.assertIn("AST-001", rule_ids)

    def test_detects_pickle_loads(self):
        engine = ASTEnforcementEngine()
        source = 'import pickle\ndata = pickle.loads(raw)\n'
        result = engine.scan_source(source)
        self.assertFalse(result.passed)
        rule_ids = {v.rule_id for v in result.blocking_violations}
        self.assertIn("AST-001", rule_ids)

    def test_detects_os_system(self):
        engine = ASTEnforcementEngine()
        source = 'import os\nos.system("rm -rf /")\n'
        result = engine.scan_source(source)
        self.assertFalse(result.passed)
        rule_ids = {v.rule_id for v in result.blocking_violations}
        self.assertIn("AST-008", rule_ids)

    def test_detects_subprocess_shell_true(self):
        engine = ASTEnforcementEngine()
        source = 'import subprocess\nsubprocess.run(cmd, shell=True)\n'
        result = engine.scan_source(source)
        self.assertFalse(result.passed)
        rule_ids = {v.rule_id for v in result.blocking_violations}
        self.assertIn("AST-008", rule_ids)

    def test_allows_subprocess_list_form(self):
        """subprocess.run with list args and no shell=True must be allowed."""
        engine = ASTEnforcementEngine()
        source = 'import subprocess\nsubprocess.run(["git", "status"], check=True)\n'
        result = engine.scan_source(source)
        rule_8_violations = [v for v in result.violations if v.rule_id == "AST-008"]
        self.assertEqual(len(rule_8_violations), 0,
                         "List-form subprocess.run should not trigger AST-008")

    def test_allows_yaml_safe_load(self):
        """yaml.safe_load must NOT be banned."""
        engine = ASTEnforcementEngine()
        source = 'import yaml\ndata = yaml.safe_load(content)\n'
        result = engine.scan_source(source)
        rule_1_violations = [v for v in result.violations if v.rule_id == "AST-001"]
        self.assertEqual(len(rule_1_violations), 0,
                         "yaml.safe_load should not be banned")

    def test_bans_yaml_load_without_safeloader(self):
        """yaml.load without SafeLoader must be banned."""
        engine = ASTEnforcementEngine()
        source = 'import yaml\ndata = yaml.load(content)\n'
        result = engine.scan_source(source)
        rule_1_violations = [v for v in result.violations if v.rule_id == "AST-001"]
        self.assertGreater(len(rule_1_violations), 0,
                           "yaml.load without SafeLoader must be banned")

    def test_allows_yaml_load_with_safeloader(self):
        """yaml.load(content, Loader=yaml.SafeLoader) must be allowed."""
        engine = ASTEnforcementEngine()
        source = 'import yaml\ndata = yaml.load(content, Loader=yaml.SafeLoader)\n'
        result = engine.scan_source(source)
        rule_1_violations = [v for v in result.violations if v.rule_id == "AST-001"]
        self.assertEqual(len(rule_1_violations), 0,
                         "yaml.load with SafeLoader should be allowed")

    def test_detects_hashlib_md5(self):
        engine = ASTEnforcementEngine()
        source = 'import hashlib\nh = hashlib.md5(data)\n'
        result = engine.scan_source(source)
        rule_ids = {v.rule_id for v in result.blocking_violations}
        self.assertIn("AST-007", rule_ids)

    def test_detects_requests_get(self):
        engine = ASTEnforcementEngine()
        source = 'import requests\nrequests.get(url)\n'
        result = engine.scan_source(source)
        rule_ids = {v.rule_id for v in result.blocking_violations}
        self.assertIn("AST-004", rule_ids)

    def test_detects_cursor_execute(self):
        engine = ASTEnforcementEngine()
        source = 'cursor.execute(query)\n'
        result = engine.scan_source(source)
        rule_ids = {v.rule_id for v in result.blocking_violations}
        self.assertIn("AST-003", rule_ids)

    def test_does_not_flag_string_containing_dangerous_call(self):
        """AST engine should NOT flag strings/docstrings containing dangerous patterns."""
        engine = ASTEnforcementEngine()
        source = '''
def safe_function():
    """Do not call subprocess.run(user_input, shell=True)"""
    message = "do not call eval(user_input)"
    return message
'''
        result = engine.scan_source(source)
        self.assertTrue(result.passed,
                        "Strings/docstrings should not trigger violations")

    def test_falls_back_to_pattern_for_non_python(self):
        """Non-Python source should fall back to pattern engine."""
        engine = ASTEnforcementEngine()
        source = '{{ this is not valid python }}'
        result = engine.scan_source(source)
        # Should not crash — falls back to pattern scan
        self.assertIsInstance(result, ASTGateResult)

    def test_scan_multiple_files(self):
        engine = ASTEnforcementEngine()
        files = {
            "clean.py": _make_clean_source(),
            "vuln.py": 'import os\nos.system("bad")\n',
        }
        result = engine.scan_multiple_files(files)
        self.assertFalse(result.passed)
        self.assertEqual(result.files_scanned, 2)


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY EVIDENCE BUNDLE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityEvidenceBundle(unittest.TestCase):
    """Tests for the security evidence bundle."""

    def test_valid_bundle_passes_validation(self):
        bundle = _make_valid_evidence_bundle()
        errors = bundle.validate()
        self.assertEqual(errors, [])
        self.assertTrue(bundle.is_complete())

    def test_invalid_hash_fails_validation(self):
        bundle = _make_valid_evidence_bundle()
        bundle.input_hash = "not_a_hash"
        errors = bundle.validate()
        self.assertTrue(any("input_hash" in e for e in errors))

    def test_z64_hash_fails_validation(self):
        """'z' * 64 must be rejected by strict SHA-256 validation."""
        bundle = _make_valid_evidence_bundle()
        bundle.input_hash = "z" * 64
        errors = bundle.validate()
        self.assertTrue(any("input_hash" in e for e in errors))

    def test_invalid_qneo_decision_fails(self):
        bundle = _make_valid_evidence_bundle()
        bundle.QNEO_decision = "PENDING"
        errors = bundle.validate()
        self.assertTrue(any("QNEO_decision" in e for e in errors))

    def test_valid_qneo_decisions(self):
        for decision in ("ALLOW", "HOLD", "FAIL_CLOSED", "ROLLBACK"):
            bundle = _make_valid_evidence_bundle()
            bundle.QNEO_decision = decision
            errors = bundle.validate()
            self.assertEqual(errors, [], f"Decision '{decision}' should be valid")

    def test_bundle_hash_is_deterministic(self):
        bundle = _make_valid_evidence_bundle()
        h1 = bundle.compute_bundle_hash()
        h2 = bundle.compute_bundle_hash()
        self.assertEqual(h1, h2)
        self.assertTrue(is_sha256(h1))

    def test_missing_model_id_fails(self):
        bundle = _make_valid_evidence_bundle()
        bundle.model_id = ""
        errors = bundle.validate()
        self.assertTrue(any("model_id" in e for e in errors))

    def test_temperature_out_of_range_fails(self):
        bundle = _make_valid_evidence_bundle()
        bundle.model_temperature = 3.0
        errors = bundle.validate()
        self.assertTrue(any("model_temperature" in e for e in errors))


# ═══════════════════════════════════════════════════════════════════════════════
# TEST EXECUTION RESULT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestTestExecutionResult(unittest.TestCase):
    """Tests for TestExecutionResult."""

    def test_compute_hash_is_deterministic(self):
        result = _make_test_result()
        h1 = result.compute_hash()
        h2 = result.compute_hash()
        self.assertEqual(h1, h2)
        self.assertTrue(is_sha256(h1))

    def test_compute_hash_includes_test_output(self):
        """Different test_output must produce different hashes (Issue #11)."""
        r1 = TestExecutionResult(
            passed=True, total_tests=10, passed_tests=10,
            failed_tests=0, error_tests=0, skipped_tests=0,
            execution_time_seconds=1.0, test_output="output A",
        )
        r2 = TestExecutionResult(
            passed=True, total_tests=10, passed_tests=10,
            failed_tests=0, error_tests=0, skipped_tests=0,
            execution_time_seconds=1.0, test_output="output B",
        )
        self.assertNotEqual(r1.compute_hash(), r2.compute_hash(),
                            "Different test_output must produce different hashes")

    def test_different_results_different_hash(self):
        r1 = _make_test_result(passed=True)
        r2 = _make_test_result(passed=False)
        self.assertNotEqual(r1.compute_hash(), r2.compute_hash())


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH ANALYSIS TESTS (difflib.unified_diff)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPatchAnalysis(unittest.TestCase):
    """Tests for patch analysis using difflib.unified_diff."""

    def test_minimal_patch_detected(self):
        original = _make_clean_source()
        patched = _make_patched_source()
        analysis = analyze_patch(original, patched)
        self.assertTrue(analysis.is_minimal)
        self.assertFalse(analysis.changes_unrelated_code)

    def test_patch_diff_uses_unified_format(self):
        """Patch diff must use unified diff format (Issue #12)."""
        original = "line1\nline2\nline3\n"
        patched = "line1\nmodified\nline3\n"
        analysis = analyze_patch(original, patched)
        # Unified diff contains --- and +++ headers
        self.assertIn("---", analysis.patch_diff)
        self.assertIn("+++", analysis.patch_diff)
        self.assertIn("@@", analysis.patch_diff)

    def test_identical_source_produces_empty_diff(self):
        source = _make_clean_source()
        analysis = analyze_patch(source, source)
        self.assertTrue(analysis.is_minimal)
        self.assertEqual(analysis.lines_added, 0)
        self.assertEqual(analysis.lines_removed, 0)

    def test_large_change_not_minimal(self):
        original = "\n".join(f"line {i}" for i in range(100))
        patched = "\n".join(f"changed {i}" for i in range(100))
        analysis = analyze_patch(original, patched)
        self.assertFalse(analysis.is_minimal)

    def test_hash_properties(self):
        analysis = analyze_patch("original\n", "patched\n")
        self.assertTrue(is_sha256(analysis.input_hash))
        self.assertTrue(is_sha256(analysis.output_hash))
        self.assertTrue(is_sha256(analysis.diff_hash))

    def test_single_line_insert_is_minimal(self):
        """A single line insert should be detected as minimal (difflib handles this)."""
        original = "line1\nline2\nline3\n"
        patched = "line1\nline2\nnew_line\nline3\n"
        analysis = analyze_patch(original, patched)
        self.assertTrue(analysis.is_minimal)
        self.assertEqual(analysis.lines_added, 1)
        self.assertEqual(analysis.lines_removed, 0)


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineSteps(unittest.TestCase):
    """Tests for the 11-step pipeline."""

    def test_pipeline_step_order(self):
        self.assertEqual(len(PIPELINE_STEP_ORDER), 11)
        self.assertEqual(PIPELINE_STEP_ORDER[0], PipelineStep.AI_PATCH_PROPOSED)
        self.assertEqual(PIPELINE_STEP_ORDER[10], PipelineStep.QNEO_RETURNS_DECISION)

    def test_step_01_records_correctly(self):
        pipeline = SecureCodingPipeline()
        result = pipeline.step_01_ai_patch_proposed(
            original_source=_make_clean_source(),
            patched_source=_make_patched_source(),
            model_id="gpt-5",
            prompt="Fix the vulnerability",
        )
        self.assertTrue(result.completed)
        self.assertTrue(result.passed)
        self.assertEqual(result.step, PipelineStep.AI_PATCH_PROPOSED)

    def test_step_02_normalizes_and_hashes(self):
        pipeline = SecureCodingPipeline()
        pipeline.step_01_ai_patch_proposed(
            _make_clean_source(), _make_patched_source(), "gpt-5", "fix"
        )
        result = pipeline.step_02_source_normalized_and_hashed()
        self.assertTrue(result.completed)
        self.assertTrue(result.passed)
        self.assertIn("input_hash", result.evidence)
        self.assertIn("output_hash", result.evidence)
        self.assertTrue(is_sha256(result.evidence["input_hash"]))

    def test_step_02_fails_without_step_01(self):
        pipeline = SecureCodingPipeline()
        result = pipeline.step_02_source_normalized_and_hashed()
        self.assertFalse(result.completed)
        self.assertFalse(result.passed)

    def _run_full_pipeline(self, qneo_decision: str = "ALLOW") -> SecureCodingPipeline:
        """Helper: run all 11 steps with clean data."""
        pipeline = SecureCodingPipeline()

        # Step 1
        pipeline.step_01_ai_patch_proposed(
            _make_clean_source(), _make_patched_source(), "gpt-5", "fix"
        )
        # Step 2
        pipeline.step_02_source_normalized_and_hashed()
        # Step 3
        pipeline.step_03_static_scanners_run([
            ("semgrep", "1.50.0", _make_resolved_sarif_results()),
        ])
        # Step 4
        pipeline.step_04_sarif_results_aggregated()
        # Step 5
        pipeline.step_05_ast_policy_gate_runs()
        # Step 6
        pipeline.step_06_llm_reviews_scanner_evidence(_make_llm_review(clean=True))
        # Step 7
        pipeline.step_07_minimal_patch_generated()
        # Step 8
        pipeline.step_08_tests_run(_make_test_result(passed=True))
        # Step 9 — clean rescan (no findings)
        pipeline.step_09_patched_code_rescanned([
            ("semgrep", "1.50.0", []),
        ])
        # Step 10
        pipeline.step_10_human_security_review(_make_human_review(approved=True))
        # Step 11
        pipeline.step_11_qneo_returns_decision(qneo_decision)

        return pipeline

    def test_full_pipeline_passes(self):
        pipeline = self._run_full_pipeline("ALLOW")
        summary = pipeline.get_pipeline_summary()
        self.assertEqual(summary["steps_completed"], 11)
        self.assertTrue(summary["all_steps_passed"])

    def test_step_11_accepts_qneo_decision_parameter(self):
        """Step 11 must accept actual QNEO decision parameter (Issue #3)."""
        pipeline = self._run_full_pipeline("HOLD")
        bundle = pipeline.evidence_bundle
        self.assertIsNotNone(bundle)
        self.assertEqual(bundle.QNEO_decision, "HOLD")

    def test_step_11_rejects_invalid_qneo_decision(self):
        """Step 11 must reject invalid QNEO decisions."""
        pipeline = SecureCodingPipeline()
        pipeline.step_01_ai_patch_proposed(
            _make_clean_source(), _make_patched_source(), "gpt-5", "fix"
        )
        pipeline.step_02_source_normalized_and_hashed()
        pipeline.step_03_static_scanners_run([
            ("semgrep", "1.50.0", _make_resolved_sarif_results()),
        ])
        pipeline.step_04_sarif_results_aggregated()
        pipeline.step_05_ast_policy_gate_runs()
        pipeline.step_06_llm_reviews_scanner_evidence(_make_llm_review())
        pipeline.step_07_minimal_patch_generated()
        pipeline.step_08_tests_run(_make_test_result())
        pipeline.step_09_patched_code_rescanned([("semgrep", "1.50.0", [])])
        pipeline.step_10_human_security_review(_make_human_review())
        result = pipeline.step_11_qneo_returns_decision("PENDING")
        self.assertFalse(result.passed)
        self.assertTrue(any("PENDING" in e for e in result.errors))

    def test_step_11_blocks_when_prior_steps_failed(self):
        """Step 11 must fail if any prior step failed (Issue #4)."""
        pipeline = SecureCodingPipeline()
        pipeline.step_01_ai_patch_proposed(
            _make_clean_source(), _make_patched_source(), "gpt-5", "fix"
        )
        pipeline.step_02_source_normalized_and_hashed()
        pipeline.step_03_static_scanners_run([
            ("semgrep", "1.50.0", _make_sarif_results()),  # unresolved findings
        ])
        pipeline.step_04_sarif_results_aggregated()
        pipeline.step_05_ast_policy_gate_runs()
        # Step 6: LLM disagrees with scanners → fails
        bad_llm = _make_llm_review(clean=False)
        pipeline.step_06_llm_reviews_scanner_evidence(bad_llm)
        pipeline.step_07_minimal_patch_generated()
        # Step 8: tests fail
        pipeline.step_08_tests_run(_make_test_result(passed=False))
        pipeline.step_09_patched_code_rescanned([("semgrep", "1.50.0", [])])
        pipeline.step_10_human_security_review(_make_human_review(approved=False))
        result = pipeline.step_11_qneo_returns_decision("ALLOW")
        self.assertFalse(result.passed)
        self.assertTrue(any("Prior pipeline steps failed" in e for e in result.errors))

    def test_step_11_blocks_when_steps_missing(self):
        """Step 11 must fail if prior steps are missing."""
        pipeline = SecureCodingPipeline()
        pipeline.step_01_ai_patch_proposed(
            _make_clean_source(), _make_patched_source(), "gpt-5", "fix"
        )
        # Skip steps 2-10
        result = pipeline.step_11_qneo_returns_decision("ALLOW")
        self.assertFalse(result.passed)
        self.assertTrue(any("Missing pipeline steps" in e for e in result.errors))


# ═══════════════════════════════════════════════════════════════════════════════
# RESCAN COMPARISON TESTS (Issue #5)
# ═══════════════════════════════════════════════════════════════════════════════

class TestRescanComparison(unittest.TestCase):
    """Tests for step 9 rescan comparison logic."""

    def _setup_pipeline_to_step_8(self) -> SecureCodingPipeline:
        """Run pipeline through step 8."""
        pipeline = SecureCodingPipeline()
        pipeline.step_01_ai_patch_proposed(
            _make_clean_source(), _make_patched_source(), "gpt-5", "fix"
        )
        pipeline.step_02_source_normalized_and_hashed()
        pipeline.step_03_static_scanners_run([
            ("semgrep", "1.50.0", _make_resolved_sarif_results()),
        ])
        pipeline.step_04_sarif_results_aggregated()
        pipeline.step_05_ast_policy_gate_runs()
        pipeline.step_06_llm_reviews_scanner_evidence(_make_llm_review())
        pipeline.step_07_minimal_patch_generated()
        pipeline.step_08_tests_run(_make_test_result())
        return pipeline

    def test_clean_rescan_passes(self):
        pipeline = self._setup_pipeline_to_step_8()
        result = pipeline.step_09_patched_code_rescanned([
            ("semgrep", "1.50.0", []),
        ])
        self.assertTrue(result.passed)

    def test_rescan_blocks_new_errors(self):
        pipeline = self._setup_pipeline_to_step_8()
        new_error = SARIFResult(
            rule_id="NEW001", message="New error", level="error",
            file_path="app.py", start_line=5, end_line=5, cwe_ids=[89],
        )
        result = pipeline.step_09_patched_code_rescanned([
            ("semgrep", "1.50.0", [new_error]),
        ])
        self.assertFalse(result.passed)
        self.assertTrue(any("error-level" in e for e in result.errors))

    def test_rescan_blocks_new_unwaived_warnings(self):
        pipeline = self._setup_pipeline_to_step_8()
        new_warning = SARIFResult(
            rule_id="NEW002", message="New warning", level="warning",
            file_path="app.py", start_line=10, end_line=10, cwe_ids=[79],
        )
        result = pipeline.step_09_patched_code_rescanned([
            ("semgrep", "1.50.0", [new_warning]),
        ])
        self.assertFalse(result.passed)
        self.assertTrue(any("warning-level" in e for e in result.errors))

    def test_rescan_allows_waived_warnings(self):
        pipeline = self._setup_pipeline_to_step_8()
        waived_warning = SARIFResult(
            rule_id="NEW002", message="Waived warning", level="warning",
            file_path="app.py", start_line=10, end_line=10, cwe_ids=[79],
            waived=True,
        )
        result = pipeline.step_09_patched_code_rescanned([
            ("semgrep", "1.50.0", [waived_warning]),
        ])
        # No unwaived warnings, but the waived warning is still a finding
        # Check that no warning-level error was raised
        warning_errors = [e for e in result.errors if "warning-level" in e]
        self.assertEqual(len(warning_errors), 0)

    def test_rescan_blocks_new_top25_cwe(self):
        """Rescan must block if new Top 25 CWE appears."""
        pipeline = self._setup_pipeline_to_step_8()
        # Original scan had CWE-89, 79 (resolved). Rescan introduces CWE-502.
        new_finding = SARIFResult(
            rule_id="NEW003", message="Deserialization issue", level="error",
            file_path="app.py", start_line=15, end_line=15, cwe_ids=[502],
        )
        result = pipeline.step_09_patched_code_rescanned([
            ("semgrep", "1.50.0", [new_finding]),
        ])
        self.assertFalse(result.passed)
        self.assertTrue(any("Top 25" in e for e in result.errors))

    def test_rescan_fails_with_no_results(self):
        pipeline = self._setup_pipeline_to_step_8()
        result = pipeline.step_09_patched_code_rescanned([])
        self.assertFalse(result.completed)


# ═══════════════════════════════════════════════════════════════════════════════
# HUMAN REVIEW TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestHumanReview(unittest.TestCase):
    """Tests for human security review."""

    def test_valid_review(self):
        review = _make_human_review(approved=True)
        self.assertTrue(review.is_valid())

    def test_invalid_review_no_identity(self):
        review = HumanSecurityReview(
            reviewer_identity="",
            approved=True,
            reviewed_evidence_hash=_sha256("evidence"),
        )
        self.assertFalse(review.is_valid())

    def test_invalid_review_no_evidence_hash(self):
        review = HumanSecurityReview(
            reviewer_identity="reviewer@example.com",
            approved=True,
            reviewed_evidence_hash="",
        )
        self.assertFalse(review.is_valid())


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE SUMMARY TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineSummary(unittest.TestCase):
    """Tests for pipeline summary."""

    def test_summary_structure(self):
        pipeline = SecureCodingPipeline()
        pipeline.step_01_ai_patch_proposed(
            _make_clean_source(), _make_patched_source(), "gpt-5", "fix"
        )
        summary = pipeline.get_pipeline_summary()
        self.assertIn("pipeline_id", summary)
        self.assertIn("steps_completed", summary)
        self.assertIn("step_results", summary)
        self.assertEqual(summary["steps_completed"], 1)


if __name__ == "__main__":
    unittest.main()

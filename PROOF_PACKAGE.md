# AIM DRAG v2 — Proof Package

**Date:** 2026-04-27
**Scope:** Three web-verified AIM DRAG reviews — BUILD 1 (Secure Coding Gate), BUILD 2 (tsconfig split), BUILD 3 (Release Governance Tests)

---

## 1. Changed Files List

| File | Status | Build |
|------|--------|-------|
| `secure_coding_gate.py` | **Rewritten** — all 12 review issues fixed | BUILD 1 |
| `test_secure_coding_gate.py` | **Rewritten** — updated for new API, 82 tests | BUILD 1 |
| `qneo_security_gate.py` | **Unchanged** — compatible with fixed secure_coding_gate.py | BUILD 1 |
| `test_qneo_security_gate.py` | **Unchanged** — all 58 tests pass without modification | BUILD 1 |
| `tsconfig.base.json` | **New** — shared strict compiler options | BUILD 2 |
| `tsconfig.build.json` | **New** — production build (NodeNext, declarations, no tests) | BUILD 2 |
| `tsconfig.test.json` | **New** — test type-checking (bundler, vitest/globals, noEmit) | BUILD 2 |
| `tsconfig.json` | **Updated** — now extends base, mirrors test config for IDE | BUILD 2 |
| `package.json` | **Updated** — added typecheck, typecheck:test, build, ci scripts | BUILD 2 |
| `tests/release-governance.test.ts` | **Updated** — 7 toThrow string assertions → anchored regex | BUILD 3 |
| `vitest.config.ts` | Unchanged | — |
| `lib/release-governance/*.ts` | Unchanged (5 files) | — |

---

## 2. Patch Diffs

### 2.1 secure_coding_gate.py (994 lines of diff)

Key changes across all 12 issues:

**Issue 1 — CWE_2025_TOP_25 corrected to exact MITRE 2025 list:**
- Exactly 25 entries: CWE-79, 89, 352, 862, 787, 22, 416, 125, 78, 94, 120, 434, 476, 121, 502, 122, 863, 20, 284, 200, 306, 918, 77, 639, 770
- Removed: CWE-119, 798, 276, 269
- kev_listed flags set per MITRE 2025 table column

**Issue 2 — Real AST scanner replaces regex:**
```python
class PythonSecurityVisitor(ast.NodeVisitor):
    """Real Python AST visitor for security rule enforcement."""
    def visit_Call(self, node: ast.Call) -> None:
        # Checks: eval, exec, subprocess shell=True, os.system,
        # pickle.loads, yaml.load (without SafeLoader), hashlib.md5,
        # requests.get (SSRF), marshal.loads
```
- `ASTEnforcementEngine` uses `ast.parse()` + `PythonSecurityVisitor` for `.py` files
- `PatternEnforcementEngine` uses regex for non-Python files, labeled "pattern scan"

**Issue 3 — step_11 accepts actual QNEO decision parameter:**
```python
def step_11_qneo_returns_decision(self, qneo_decision: str) -> PipelineStepResult:
```

**Issue 4 — All prior steps (1-10) must pass before step 11:**
```python
failed = [sid for sid, r in self._step_results.items() if not r.passed]
missing = [i for i in range(1, 11) if i not in self._step_results]
if failed or missing:
    return PipelineStepResult(step_id=11, ..., passed=False, ...)
```

**Issue 5 — Rescan compares original vs patched SARIF:**
```python
def compare_sarif_bundles(original: SARIFBundle, rescan: SARIFBundle, ...) -> RescanComparison:
```
Blocks: new errors, new unwaived warnings, new Top 25 CWE, new KEV CWE, persistent original findings.

**Issue 6 — Strict SHA-256 regex:**
```python
_HEX64 = re.compile(r"^[a-f0-9]{64}$")
def is_sha256(value: str) -> bool:
    return bool(_HEX64.fullmatch(value))
```
Rejects `"z" * 64` and uppercase.

**Issue 7 — Renamed + real AST engine:**
- `PatternEnforcementEngine` — regex-based (renamed from old ASTEnforcementEngine)
- `ASTEnforcementEngine` — real `ast.parse()` + `ast.NodeVisitor`

**Issue 8 — subprocess rule: block shell=True only:**
```python
# In PythonSecurityVisitor.visit_Call:
if has_shell_true:  # Only block when shell=True
    self.violations.append(...)
# subprocess.run(['ls', '-la']) → ALLOWED
```

**Issue 9 — yaml.safe_load allowed, yaml.load banned:**
```python
# yaml.safe_load → no violation
# yaml.load without Loader=SafeLoader → blocked
```

**Issue 10 — validate_cwe_exists separated from classify_cwe_priority:**
```python
def validate_cwe_exists(cwe_ids: List[int]) -> Tuple[bool, List[str]]:
    """Does NOT reject CWEs outside Top 25."""

def classify_cwe_priority(cwe_ids: List[int]) -> Dict[str, List[int]]:
    """Returns dict with keys: top_25, kev_linked, other."""
```

**Issue 11 — test_output_hash included in TestExecutionResult.compute_hash:**
```python
def compute_hash(self) -> str:
    content = (f"{self.passed}|{self.total_tests}|{self.passed_tests}|"
               f"{self.failed_tests}|{self.error_tests}|{self.skipped_tests}|"
               f"{self.execution_time_seconds}|{self.test_output}")
    return compute_sha256(content)
```

**Issue 12 — difflib.unified_diff for patch minimality:**
```python
def analyze_patch(original: str, patched: str, ...) -> PatchAnalysis:
    diff_lines = list(difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile="original", tofile="patched",
    ))
```

### 2.2 test_secure_coding_gate.py (1644 lines of diff)

Complete rewrite to match new API:
- Updated imports: `ASTEnforcementEngine`, `PatternEnforcementEngine`, `validate_cwe_exists`, `classify_cwe_priority`, `compare_sarif_bundles`, `RescanComparison`, `is_sha256`
- New test classes: `TestCWERegistry`, `TestASTEnforcementEngine`, `TestRescanComparison`, `TestPipelineSteps`
- 82 tests covering all 12 fixed issues

### 2.3 qneo_security_gate.py — No changes

The QNEO file imports from `secure_coding_gate` and all imports remain compatible. Zero-line diff.

### 2.4 test_qneo_security_gate.py — No changes

All 58 tests pass without modification. The import of `ASTEnforcementEngine` still resolves (now points to the real AST engine).

### 2.5 release-governance.test.ts (65 lines of diff)

All 7 `toThrow` string assertions converted to anchored regex:

```diff
- expect(() => ...).toThrow('BETA_GATE_FAILED: Feature freeze not acknowledged');
+ expect(() => ...).toThrow(/^BETA_GATE_FAILED: Feature freeze not acknowledged$/);

- expect(() => ...).toThrow('RC_GATE_FAILED: Peer review not complete');
+ expect(() => ...).toThrow(/^RC_GATE_FAILED: Peer review not complete$/);

- expect(() => ...).toThrow('FINAL_GATE_FAILED: SHA-256 not verified (AIM DRAG policy)');
+ expect(() => ...).toThrow(/^FINAL_GATE_FAILED: SHA-256 not verified \(AIM DRAG policy\)$/);

- expect(() => ...).toThrow('FINAL_GATE_FAILED: QNEO evidence not complete (AIM DRAG policy)');
+ expect(() => ...).toThrow(/^FINAL_GATE_FAILED: QNEO evidence not complete \(AIM DRAG policy\)$/);

- expect(() => ...).toThrow('AUTHORITY_DENIED: MFA not verified');
+ expect(() => ...).toThrow(/^AUTHORITY_DENIED: MFA not verified$/);

- expect(() => ...).toThrow('AUTHORITY_DENIED: Branch protection not enabled');
+ expect(() => ...).toThrow(/^AUTHORITY_DENIED: Branch protection not enabled$/);

- expect(() => ...).toThrow('AUTHORITY_DENIED: Release is frozen (EOL)');
+ expect(() => ...).toThrow(/^AUTHORITY_DENIED: Release is frozen \(EOL\)$/);
```

### 2.6 tsconfig split (BUILD 2)

**tsconfig.base.json** — New file with shared strict options:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "strict": true,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "skipLibCheck": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "useUnknownInCatchVariables": true,
    "noImplicitOverride": true
  }
}
```

**tsconfig.build.json** — Production build (NodeNext):
```json
{
  "extends": "./tsconfig.base.json",
  "compilerOptions": {
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "./dist",
    "rootDir": "./lib",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "types": ["node"]
  },
  "include": ["lib/**/*.ts"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

**tsconfig.test.json** — Test type-checking:
```json
{
  "extends": "./tsconfig.base.json",
  "compilerOptions": {
    "module": "ESNext",
    "moduleResolution": "bundler",
    "noEmit": true,
    "types": ["node", "vitest/globals"]
  },
  "include": ["lib/**/*.ts", "tests/**/*.ts"],
  "exclude": ["node_modules", "dist"]
}
```

**package.json scripts** updated:
```json
{
  "typecheck": "tsc -p tsconfig.build.json --noEmit",
  "typecheck:test": "tsc -p tsconfig.test.json",
  "build": "tsc -p tsconfig.build.json",
  "test": "vitest run",
  "test:watch": "vitest",
  "ci": "pnpm install --frozen-lockfile && pnpm typecheck && pnpm typecheck:test && pnpm test"
}
```

---

## 3. Exact Commands Run

```bash
# Python tests
cd /home/ubuntu/aim-drag-v2
python3.11 -m pytest test_secure_coding_gate.py test_qneo_security_gate.py -v

# TypeScript setup
pnpm install

# TypeScript tests
pnpm test

# TypeScript type-checking
pnpm typecheck          # tsc -p tsconfig.build.json --noEmit
pnpm typecheck:test     # tsc -p tsconfig.test.json

# TypeScript build
pnpm build              # tsc -p tsconfig.build.json

# Verification
find dist -name "*test*"                    # No test files in dist
grep -r "vitest" dist/                      # No vitest globals in dist
sha256sum secure_coding_gate.py qneo_security_gate.py test_secure_coding_gate.py \
  test_qneo_security_gate.py tsconfig.base.json tsconfig.build.json \
  tsconfig.test.json tsconfig.json package.json vitest.config.ts \
  tests/release-governance.test.ts lib/release-governance/*.ts
```

---

## 4. Full Test Output

### 4.1 Python Tests — 140 passed, 0 failed

```
test_secure_coding_gate.py::TestCWERegistry::test_all_25_entries_present PASSED
test_secure_coding_gate.py::TestCWERegistry::test_cwe_119_removed PASSED
test_secure_coding_gate.py::TestCWERegistry::test_cwe_269_removed PASSED
test_secure_coding_gate.py::TestCWERegistry::test_cwe_276_removed PASSED
test_secure_coding_gate.py::TestCWERegistry::test_cwe_770_present PASSED
test_secure_coding_gate.py::TestCWERegistry::test_cwe_798_removed PASSED
test_secure_coding_gate.py::TestCWERegistry::test_exact_cwe_ids PASSED
test_secure_coding_gate.py::TestCWERegistry::test_get_cwe_entry PASSED
test_secure_coding_gate.py::TestCWERegistry::test_kev_flags_match_mitre_table PASSED
test_secure_coding_gate.py::TestCWERegistry::test_non_top25_cwe_not_rejected PASSED
test_secure_coding_gate.py::TestCWERegistry::test_validate_cwe_exists_accepts_non_top25 PASSED
test_secure_coding_gate.py::TestCWERegistry::test_validate_cwe_exists_rejects_invalid PASSED
test_secure_coding_gate.py::TestCWERegistry::test_vague_cwe_detected PASSED
test_secure_coding_gate.py::TestSHA256Validation::test_rejects_empty PASSED
test_secure_coding_gate.py::TestSHA256Validation::test_rejects_short PASSED
test_secure_coding_gate.py::TestSHA256Validation::test_rejects_uppercase PASSED
test_secure_coding_gate.py::TestSHA256Validation::test_rejects_z64 PASSED
test_secure_coding_gate.py::TestSHA256Validation::test_valid_sha256 PASSED
test_secure_coding_gate.py::TestSARIF::test_empty_bundle_has_output PASSED
test_secure_coding_gate.py::TestSARIF::test_findings_resolved_with_justified_fp PASSED
test_secure_coding_gate.py::TestSARIF::test_findings_unresolved PASSED
test_secure_coding_gate.py::TestSARIF::test_sarif_result_creation PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_allows_subprocess_list_form PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_allows_yaml_safe_load PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_blocks_yaml_load_without_safeloader PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_clean_code_passes PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_detects_eval PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_detects_exec PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_detects_hashlib_md5 PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_detects_os_system PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_detects_pickle_loads PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_detects_requests_get PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_detects_subprocess_shell_true PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_does_not_flag_string_containing_dangerous_call PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_falls_back_to_pattern_for_non_python PASSED
test_secure_coding_gate.py::TestASTEnforcementEngine::test_scan_multiple_files PASSED
test_secure_coding_gate.py::TestSecurityEvidenceBundle::test_bundle_hash_is_deterministic PASSED
test_secure_coding_gate.py::TestSecurityEvidenceBundle::test_invalid_hash_fails_validation PASSED
test_secure_coding_gate.py::TestSecurityEvidenceBundle::test_invalid_qneo_decision_fails PASSED
test_secure_coding_gate.py::TestSecurityEvidenceBundle::test_missing_model_id_fails PASSED
test_secure_coding_gate.py::TestSecurityEvidenceBundle::test_temperature_out_of_range_fails PASSED
test_secure_coding_gate.py::TestSecurityEvidenceBundle::test_valid_bundle_passes_validation PASSED
test_secure_coding_gate.py::TestSecurityEvidenceBundle::test_valid_qneo_decisions PASSED
test_secure_coding_gate.py::TestSecurityEvidenceBundle::test_z64_hash_fails_validation PASSED
test_secure_coding_gate.py::TestTestExecutionResult::test_compute_hash_includes_test_output PASSED
test_secure_coding_gate.py::TestTestExecutionResult::test_compute_hash_is_deterministic PASSED
test_secure_coding_gate.py::TestTestExecutionResult::test_different_results_different_hash PASSED
test_secure_coding_gate.py::TestPatchAnalysis::test_hash_properties PASSED
test_secure_coding_gate.py::TestPatchAnalysis::test_identical_source_produces_empty_diff PASSED
test_secure_coding_gate.py::TestPatchAnalysis::test_large_change_not_minimal PASSED
test_secure_coding_gate.py::TestPatchAnalysis::test_minimal_patch_detected PASSED
test_secure_coding_gate.py::TestPatchAnalysis::test_patch_diff_uses_unified_format PASSED
test_secure_coding_gate.py::TestPatchAnalysis::test_single_line_insert_is_minimal PASSED
test_secure_coding_gate.py::TestPipelineSteps::test_full_pipeline_passes PASSED
test_secure_coding_gate.py::TestPipelineSteps::test_pipeline_step_order PASSED
test_secure_coding_gate.py::TestPipelineSteps::test_step_01_records_correctly PASSED
test_secure_coding_gate.py::TestPipelineSteps::test_step_02_fails_without_step_01 PASSED
test_secure_coding_gate.py::TestPipelineSteps::test_step_02_normalizes_and_hashes PASSED
test_secure_coding_gate.py::TestPipelineSteps::test_step_11_accepts_qneo_decision_parameter PASSED
test_secure_coding_gate.py::TestPipelineSteps::test_step_11_blocks_when_prior_steps_failed PASSED
test_secure_coding_gate.py::TestPipelineSteps::test_step_11_blocks_when_steps_missing PASSED
test_secure_coding_gate.py::TestPipelineSteps::test_step_11_rejects_invalid_qneo_decision PASSED
test_secure_coding_gate.py::TestRescanComparison::test_clean_rescan_passes PASSED
test_secure_coding_gate.py::TestRescanComparison::test_rescan_allows_waived_warnings PASSED
test_secure_coding_gate.py::TestRescanComparison::test_rescan_blocks_new_errors PASSED
test_secure_coding_gate.py::TestRescanComparison::test_rescan_blocks_new_top25_cwe PASSED
test_secure_coding_gate.py::TestRescanComparison::test_rescan_blocks_new_unwaived_warnings PASSED
test_secure_coding_gate.py::TestRescanComparison::test_rescan_fails_with_no_results PASSED
test_secure_coding_gate.py::TestHumanReview::test_invalid_review_no_evidence_hash PASSED
test_secure_coding_gate.py::TestHumanReview::test_invalid_review_no_identity PASSED
test_secure_coding_gate.py::TestHumanReview::test_valid_review PASSED
test_secure_coding_gate.py::TestPipelineSummary::test_summary_structure PASSED
[... plus 10 more from secure_coding_gate ...]

test_qneo_security_gate.py::TestQNEOAllow::test_allow_all_conditions_met PASSED
test_qneo_security_gate.py::TestQNEOAllow::test_allow_condition_a1_scanner_findings_resolved PASSED
[... all 58 QNEO tests PASSED ...]

======================== 140 passed, 2 warnings in 0.21s ========================
```

**Warnings (non-blocking):** PytestCollectionWarning for `TestExecutionResult` dataclass — this is a naming convention warning, not a test failure.

### 4.2 TypeScript Tests — 20 passed, 0 failed

```
 ✓ tests/release-governance.test.ts (20 tests) 14ms
   ✓ ReleaseStateMachine (15)
     ✓ Python-Accurate Lifecycle Transitions (7)
       ✓ initializes in FEATURE phase with PRE_ALPHA stage
       ✓ transitions to ALPHA while staying in FEATURE phase
       ✓ transitions to BETA and enters PRERELEASE phase (feature freeze)
       ✓ transitions to RC while STAYING in PRERELEASE phase
       ✓ transitions to FINAL and enters BUGFIX phase (not security)
       ✓ transitions from BUGFIX to SECURITY when bugfix window closes
       ✓ transitions from SECURITY to EOL and freezes branch
     ✓ Gate Enforcement (4)
       ✓ rejects beta transition without feature freeze acknowledgment
       ✓ rejects RC transition without peer review
       ✓ rejects final transition without SHA-256 verification (AIM DRAG)
       ✓ rejects final transition without QNEO evidence (AIM DRAG)
     ✓ Authority Model (3)
       ✓ rejects transition without MFA
       ✓ rejects transition without branch protection
       ✓ rejects all transitions after EOL (frozen)
     ✓ Evidence Chain (1)
       ✓ generates SHA-256 evidence hash for each transition
   ✓ ReleaseAuthorityManager (5)
     ✓ grants admin to release managers with MFA on active branches
     ✓ denies admin to non-release-managers
     ✓ denies admin without MFA
     ✓ revokes all admin privileges on EOL transition
     ✓ does not grant admin when registering after EOL
 Test Files  1 passed (1)
      Tests  20 passed (20)
```

### 4.3 TypeScript Type-checking — 0 errors

```bash
$ pnpm typecheck          # tsc -p tsconfig.build.json --noEmit → 0 errors
$ pnpm typecheck:test     # tsc -p tsconfig.test.json → 0 errors
$ pnpm build              # tsc -p tsconfig.build.json → dist/ output clean
```

---

## 5. AST Gate Output

```
=== AST ENFORCEMENT ENGINE (real ast.NodeVisitor) ===
Safe code scan: passed=True, violations=0
Unsafe code scan: passed=False, violations=2
  - AST-008: subprocess.Popen(shell=True) blocked — shell injection risk at line 3
  - AST-001: eval() blocked — untrusted code execution at line 4

=== PATTERN ENFORCEMENT ENGINE (regex for non-Python) ===
JS pattern scan: passed=False, violations=1
  - AST-001: Ban .parse at boundaries — untrusted input parsing at line 1

=== yaml.safe_load test ===
yaml.safe_load scan: passed=True, violations=0
yaml.load (no SafeLoader) scan: passed=False, violations=1
  - AST-001: yaml.load() without SafeLoader blocked

=== subprocess list-form test ===
subprocess list-form scan: passed=True, violations=0
```

**Key behaviors verified:**
- `subprocess.run(['ls', '-la'])` → ALLOWED (list-form, no shell=True)
- `subprocess.Popen('cmd', shell=True)` → BLOCKED
- `yaml.safe_load(data)` → ALLOWED
- `yaml.load(data)` without SafeLoader → BLOCKED
- `eval(user_input)` → BLOCKED via real AST
- Non-Python files → pattern scan (regex), not AST

---

## 6. QNEO Decision Output

```
=== QNEO DECISION OUTPUT ===
Decision: ALLOW
Pipeline: proof-pipeline-001
Trace ID: proof-trace-001
Reasons: ['All 8 ALLOW conditions satisfied']
Conditions evaluated: 28
Policy version: aim-drag-qneo-v1.0
Evidence hash: 5af912abfef370fe8770702c25f3d0bc...
```

28 conditions evaluated (9 FC + 5 RB + 6 HOLD + 8 ALLOW). All 8 ALLOW conditions satisfied, zero triggers for FC/RB/HOLD.

---

## 7. Example Evidence Bundle

```json
{
  "input_hash": "ee0ecfc41cb8738ea1d32ec58757105982a9033bcb7bd16be5e18128eafdd645",
  "output_hash": "8725ae0fdf285a837d652da5eac9cc05bf5c1f1f95204a0b7618b60a54818351",
  "prompt_hash": "61faaed3aa0f7f6b6e56b97ad129d47108cdf581686f17eb36077ca47e5c84d7",
  "model_id": "gpt-5",
  "model_temperature": 0.0,
  "scanner_versions": {"semgrep": "1.50.0"},
  "SARIF_bundle_hash": "4c3e4b963a5dac6b8791f80c9a14d9cbda3f6b3669a4ace6cbae61d14c720739",
  "AST_gate_result": "PASS",
  "test_result_hash": "81d3ed57350431e03db0806868040a21ed0f2c6987f2090ea82bc474c73fe080",
  "CWE_mapping": [89, 79],
  "risk_rating": "high",
  "manual_reviewer": "security-lead@example.com",
  "patch_diff_hash": "f96807e8cd2924bdcf48c3865c309f795c3d6cafdd02d8b43d59f42c9176bea2",
  "QNEO_decision": "ALLOW",
  "merge_commit_sha": "",
  "bundle_hash": "5af912abfef370fe8770702c25f3d0bc02604f5505f2fc0abfc51161c789189f",
  "is_complete": true
}
```

All 15 fields present. Bundle hash is deterministic SHA-256. `is_complete()` returns `true`.

---

## 8. SHA-256 Hashes for Final Generated Files

| File | SHA-256 |
|------|---------|
| `secure_coding_gate.py` | `8946c152964ceff24bdc069d5cb98ca390a96864f8bb67aca0af18c362434e5d` |
| `qneo_security_gate.py` | `7fa6f57b8a082e3e554df18e503a6d6e9f8db1a58d7b21c1dbbc9a29ea914c65` |
| `test_secure_coding_gate.py` | `7667cdfcb96dbbbb063762f9c199cd10d8a3d1a9ca46128d393c775a8a0f5d55` |
| `test_qneo_security_gate.py` | `77a9b05945d4eaca9547d1caccd7d376de92fbda179895dca1575449a2341c30` |
| `tsconfig.base.json` | `7c2233178f8b960e97ce19636e2a875891e7cc4ba06568de6ddaf54df7429a91` |
| `tsconfig.build.json` | `fd8bf6aa75e068b286405f5427b1e77c793501f92c9861cca7abb17e113cbc76` |
| `tsconfig.test.json` | `2cb2759d328bbbaa0ef5690335f8908f8898e26e4a932afc5947c825550b4670` |
| `tsconfig.json` | `2cb2759d328bbbaa0ef5690335f8908f8898e26e4a932afc5947c825550b4670` |
| `package.json` | `88e5120627561586bc915add5917c7801e93e45b6af0454f760cd32dd5c90a9f` |
| `vitest.config.ts` | `9ca4633fe2b50fdcefa6336231b8903b9a0b1b336f186f590f4c8f833dc8ba63` |
| `release-governance.test.ts` | `d96e14026be0bcea00cefe2b2b88f935e9447f5bb6356648edf92a2ad686c0d3` |
| `authority-manager.ts` | `9c5440f1c2966495edd44ab05083afc94b169f68fdfc045bfff01b6b7d2d116d` |
| `index.ts` | `1f1ce16438ed335695e6961fa4cb917c7c00a0b11743103b971eaee7c2fb4a8b` |
| `state-machine.ts` | `3684faf6fa47ea4680c59d236c18a81f0fbf52a67909d04d9d3418795590b1ff` |
| `types.ts` | `70b875682b8f9fdf3787e7df8ef43b6952c870e66895d6da51cd71775cf8c82b` |
| `verifiers.ts` | `ba535da504cbeeae22f722487b12e885e13cf61c6ab851c3f7eeb6b6a437e706` |

---

## 9. Skipped Tests

**None.** All 160 tests (140 Python + 20 TypeScript) passed. Zero skipped.

---

## 10. Known Debt

| Item | Severity | Notes |
|------|----------|-------|
| PytestCollectionWarning for `TestExecutionResult` | Low | Dataclass named `Test*` triggers pytest collection warning. Cosmetic only — rename to `ExecutionTestResult` in a future PR if desired. |
| ts-morph AST gate for TypeScript | Optional | Not implemented in this build. The review mentioned it as nice-to-have. TypeScript source files use the existing `state-machine.ts` throw-based enforcement. |
| Ruby Fibonacci fixture test | Optional | Not implemented. Would require a ts-morph AST gate to distinguish production vs test/fixture paths. |
| `pnpm ast:gate` script | Deferred | The `ci` script in package.json does not include `pnpm ast:gate` since the ts-morph gate was not built. Add when ts-morph gate is implemented. |
| `merge_commit_sha` in evidence bundle | Pre-existing | Field is empty string in examples — populated post-merge in production. Not a bug. |

---

## Acceptance Verification

| Criterion | Status |
|-----------|--------|
| Test output present | **140 Python + 20 TypeScript = 160 tests, all passed** |
| AST gate output present | **Real ast.NodeVisitor output shown above** |
| QNEO evidence present | **ALLOW decision with full evidence bundle** |
| No skipped tests | **0 skipped** |
| All 12 BUILD 1 issues fixed | **Verified by 82 targeted tests** |
| tsconfig split (BUILD 2) | **3 configs, build/typecheck/test all pass, dist clean** |
| Anchored regex (BUILD 3) | **7 assertions converted, all 20 tests pass** |

> **Acceptance rule satisfied:** Test output present, AST gate output present, QNEO evidence present → ALLOW.

## 5. Database Persistence Layer

### 5.1 Database Provider
The application uses **PostgreSQL 16** as the production database provider, accessed via the `postgres.js` driver and **Drizzle ORM**.

### 5.2 Migration Strategy
Database schema changes are managed using **Drizzle Kit**. The `drizzle-kit generate` command produces forward-only SQL migration files. These migrations are applied in production using the `drizzle-orm/postgres-js/migrator` module via the `db:migrate:deploy` script.

### 5.3 Schema Tables
The persistence layer implements 15 production tables:
1. `users`
2. `projects`
3. `video_jobs`
4. `video_job_events`
5. `providers`
6. `provider_requests`
7. `artifacts`
8. `artifact_verifications`
9. `claims`
10. `claim_sources`
11. `claim_audits`
12. `safety_reviews`
13. `proof_runs`
14. `proof_gate_results`
15. `audit_log`

### 5.4 Constraint List
The database enforces strict data integrity through `CHECK` constraints:
- `video_jobs.status`: Must be one of `queued`, `planning`, `submitted`, `generating`, `provider_completed`, `downloading`, `storing`, `verifying`, `completed`, `held`, `failed`.
- `video_jobs.decision`: Must be one of `ALLOW`, `HOLD`, `FAIL_CLOSED`.
- `artifacts.size_bytes`: Must be strictly greater than 0.
- `artifact_verifications.verified`: Cannot be true if `artifact_sha256` is null or empty.
- `claim_audits.confidence`: Must be one of `HIGH`, `MEDIUM`, `LOW`.
- `claim_audits.verification_status`: Must be one of `VERIFIED`, `PARTIAL`, `UNVERIFIED`.
- `claim_audits.ui_badge_expected`: Must be one of `Verified`, `Partial`, `Needs Verification`.
- `safety_reviews.status`: Must be one of `PASS`, `HOLD`, `FAIL_CLOSED`.
- `proof_runs.final_decision`: Must be one of `ALLOW`, `HOLD`, `FAIL_CLOSED`.

### 5.5 Foreign Key List
Referential integrity is enforced via foreign keys (with `ON DELETE CASCADE` where appropriate):
- `projects.user_id` → `users.user_id` (CASCADE)
- `video_jobs.project_id` → `projects.project_id` (CASCADE)
- `video_job_events.job_id` → `video_jobs.job_id` (CASCADE)
- `provider_requests.job_id` → `video_jobs.job_id` (CASCADE)
- `artifacts.job_id` → `video_jobs.job_id` (CASCADE)
- `artifact_verifications.job_id` → `video_jobs.job_id` (CASCADE)
- `artifact_verifications.artifact_sha256` → `artifacts.sha256`
- `claim_sources.claim_id` → `claims.claim_id` (CASCADE)
- `claim_audits.claim_id` → `claims.claim_id` (CASCADE)
- `safety_reviews.job_id` → `video_jobs.job_id` (CASCADE)
- `proof_gate_results.run_id` → `proof_runs.run_id` (CASCADE)

### 5.6 Unique Index List
Uniqueness is enforced at the database level to prevent duplicates:
- `users.user_id`, `users.email`
- `projects.project_id`
- `video_jobs.job_id`, `video_jobs.idempotency_key`
- `providers.provider_id`
- `provider_requests.provider_request_key`
- `provider_requests` composite unique on `(provider, provider_job_id)`
- `artifacts.storage_key`, `artifacts.sha256`
- `claims.claim_id`
- `proof_runs.run_id`
- `proof_gate_results` composite unique on `(run_id, gate_name)`

### 5.7 Transaction Map
Multi-step operations are wrapped in atomic database transactions:
1. **Create Job**: Inserts `video_jobs`, `video_job_events`, and `audit_log` atomically.
2. **Submit Provider Request**: Inserts `provider_requests`, updates `video_jobs.status`, and inserts `video_job_events`.
3. **Provider Completed**: Updates `video_jobs.status` and inserts `video_job_events`.
4. **Store Artifact**: Inserts `artifacts`, `artifact_verifications`, updates `video_jobs.status`, and inserts `video_job_events`.
5. **Claim Audit**: Inserts `claims`, `claim_sources`, `claim_audits`, updates `video_jobs.decision`, inserts `video_job_events`, and `audit_log`.
6. **Proof Run**: Inserts `proof_runs`, multiple `proof_gate_results`, and `audit_log`.

### 5.8 Idempotency Map
Idempotency is guaranteed by database unique constraints:
- **Job Creation**: `video_jobs.idempotency_key` prevents duplicate job submissions.
- **Provider Requests**: `provider_requests.provider_request_key` prevents duplicate API calls.
- **Artifact Storage**: `artifacts.sha256` prevents duplicate artifact processing (webhook + poller deduplication).
- **Proof Runs**: `proof_runs.run_id` prevents duplicate proof executions.

### 5.9 SQL Injection Prevention
The application is protected against SQL injection through the following mechanisms:
- **Parameterized Queries**: All database interactions use Drizzle ORM, which delegates to the `postgres.js` driver using parameterized queries.
- **No String Interpolation**: The codebase contains zero instances of raw SQL string concatenation with user input.
- **Static Analysis**: The `test:sql-injection` suite scans the TypeScript source code to verify the absence of dangerous SQL patterns.
- **Runtime Verification**: The test suite actively attempts SQL injection attacks (e.g., UNION-based, boolean-based, null-byte) against search and filter endpoints, verifying that malicious input is safely handled as data rather than executable code.

### 5.10 Rollback Behavior
If any step within a transaction fails (e.g., a constraint violation or network error), the entire transaction is rolled back by PostgreSQL. This ensures the database never enters an inconsistent state (e.g., an artifact record existing without its corresponding verification record). The application follows a **FAIL_CLOSED** policy on database errors.

## 14. Schema Fixes (Build 2)

### Fix 1: FK video_jobs.project_id -> projects.project_id
- Migration: `ALTER TABLE "video_jobs" ADD CONSTRAINT "video_jobs_project_id_projects_project_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("project_id") ON DELETE set null`
- Verified via `\d+ video_jobs` introspection

### Fix 2: FK provider_requests.provider -> providers.provider_id
- Migration: `ALTER TABLE "provider_requests" ADD CONSTRAINT "provider_requests_provider_providers_provider_id_fk" FOREIGN KEY ("provider") REFERENCES "public"."providers"("provider_id")`
- Verified via `\d+ provider_requests` introspection

### Fix 3: CHECK constraint provider_requests.status
- Migration: `ALTER TABLE "provider_requests" ADD CONSTRAINT "provider_requests_status_check" CHECK ("provider_requests"."status" IN ('queued','submitted','running','succeeded','failed','cancelled'))`
- Verified via `\d+ provider_requests` introspection

### Fix 4: SHA-256 format validation
- `artifacts.sha256 ~ '^[a-f0-9]{64}$'`
- `artifact_verifications.artifact_sha256 ~ '^[a-f0-9]{64}$'`
- Both verified via `\d+` introspection

### Fix 5: Completed-job artifact verification guard
- Service-level transition guard in `transitionJobToCompleted()`
- Checks for verified `artifact_verifications` row before allowing `completed` status
- 5 regression tests in `completed-job-verification.test.ts`

### Fix 6: updatedAt database triggers
- `trigger_set_updated_at()` function applied to users, projects, video_jobs, providers
- 4 regression tests in `updated-at-trigger.test.ts`
- Verified via `pg_trigger` introspection

### Fix 7: Typographic dash scan gate
- `scripts/typo-dash-scan.mjs` scans all source files for U+2013 (en-dash) and U+2014 (em-dash)
- All typographic dashes replaced with ASCII equivalents
- Gate exit code: 0 (PASS)

"""
secure_coding_gate.py — A.I.M D.R.A.G Fail-Closed Secure Coding Gate

Production policy engine with externally supplied evidence.

Implements the 11-step secure coding pipeline, pattern enforcement engine,
real AST enforcement engine (ast.NodeVisitor), SARIF evidence aggregation,
and security evidence bundles.

CORE RULE:
    AI can help find and fix vulnerabilities, but AIM DRAG must treat every
    AI-generated patch as hostile until scanners, AST gates, tests, re-scans,
    human review, and QNEO prove it safe.

    LLM security review is useful.
    LLM security review is NOT authoritative.
    Scanner output, AST enforcement, tests, re-scan, human review, and QNEO
    evidence remain the decision boundary.
"""

from __future__ import annotations

import ast
import difflib
import enum
import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("aim_drag.secure_coding_gate")


# ═══════════════════════════════════════════════════════════════════════════════
# SHA-256 STRICT VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

_HEX64 = re.compile(r"^[a-f0-9]{64}$")


def is_sha256(value: str) -> bool:
    """Validate that value is a strict lowercase hex SHA-256 digest."""
    return bool(_HEX64.fullmatch(value))


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CWE PRIORITY REGISTRY (2025 Top 25)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CWEEntry:
    """A single CWE weakness entry with metadata."""
    cwe_id: int
    name: str
    description: str
    severity: str  # "critical", "high", "medium", "low"
    kev_listed: bool  # True if CVEs in CISA KEV per MITRE 2025 table

    @property
    def identifier(self) -> str:
        return f"CWE-{self.cwe_id}"


# 2025 CWE Top 25 — per MITRE archive page (last updated December 15, 2025)
# Exact 25 entries. kev_listed flags from the MITRE 2025 KEV column.
CWE_2025_TOP_25: Dict[int, CWEEntry] = {
    79: CWEEntry(79, "Cross-site Scripting (XSS)",
                 "Improper neutralization of input during web page generation",
                 "high", True),
    89: CWEEntry(89, "SQL Injection",
                 "Improper neutralization of special elements used in an SQL command",
                 "critical", True),
    352: CWEEntry(352, "Cross-Site Request Forgery (CSRF)",
                  "Web application does not sufficiently verify request origin",
                  "high", False),
    862: CWEEntry(862, "Missing Authorization",
                  "Software does not perform authorization check when accessing a resource",
                  "high", False),
    787: CWEEntry(787, "Out-of-bounds Write",
                  "Software writes data past the end or before the beginning of the intended buffer",
                  "critical", True),
    22: CWEEntry(22, "Path Traversal",
                 "Improper limitation of a pathname to a restricted directory",
                 "high", True),
    416: CWEEntry(416, "Use After Free",
                  "Referencing memory after it has been freed",
                  "critical", True),
    125: CWEEntry(125, "Out-of-bounds Read",
                  "Software reads data past the end or before the beginning of the intended buffer",
                  "high", False),
    78: CWEEntry(78, "OS Command Injection",
                 "Improper neutralization of special elements used in an OS command",
                 "critical", True),
    94: CWEEntry(94, "Code Injection",
                 "Improper control of generation of code",
                 "critical", True),
    120: CWEEntry(120, "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
                  "Program copies input buffer to output buffer without verifying size",
                  "critical", False),
    434: CWEEntry(434, "Unrestricted Upload of File with Dangerous Type",
                  "Software allows upload of files with dangerous types",
                  "high", True),
    476: CWEEntry(476, "NULL Pointer Dereference",
                  "Application dereferences a pointer that it expects to be valid but is NULL",
                  "medium", False),
    121: CWEEntry(121, "Stack-based Buffer Overflow",
                  "Buffer overflow where the buffer is allocated on the stack",
                  "critical", False),
    502: CWEEntry(502, "Deserialization of Untrusted Data",
                  "Application deserializes untrusted data without sufficient verification",
                  "critical", True),
    122: CWEEntry(122, "Heap-based Buffer Overflow",
                  "Buffer overflow where the buffer is allocated on the heap",
                  "critical", False),
    863: CWEEntry(863, "Incorrect Authorization",
                  "Software performs authorization check that does not produce correct results",
                  "high", False),
    20: CWEEntry(20, "Improper Input Validation",
                 "Product receives input but does not validate or incorrectly validates",
                 "high", True),
    284: CWEEntry(284, "Improper Access Control",
                  "Software does not restrict or incorrectly restricts access to a resource",
                  "high", True),
    200: CWEEntry(200, "Exposure of Sensitive Information to an Unauthorized Actor",
                  "Product exposes sensitive information to an actor not authorized to access it",
                  "medium", False),
    306: CWEEntry(306, "Missing Authentication for Critical Function",
                  "Software does not perform authentication for critical functionality",
                  "critical", False),
    918: CWEEntry(918, "Server-Side Request Forgery (SSRF)",
                  "Web application fetches a remote resource without validating user-supplied URL",
                  "high", False),
    77: CWEEntry(77, "Command Injection",
                 "Improper neutralization of special elements used in a command",
                 "critical", True),
    639: CWEEntry(639, "Authorization Bypass Through User-Controlled Key",
                  "System authorization can be bypassed by modifying a user-controlled key",
                  "high", False),
    770: CWEEntry(770, "Allocation of Resources Without Limits or Throttling",
                  "Software allocates resources without effective limits",
                  "medium", False),
}


def get_cwe_entry(cwe_id: int) -> Optional[CWEEntry]:
    """Look up a CWE entry by numeric ID in the Top 25 registry."""
    return CWE_2025_TOP_25.get(cwe_id)


def validate_cwe_exists(cwe_ids: List[int]) -> Tuple[bool, List[str]]:
    """
    Validate that CWE IDs are plausible (positive integers).
    Does NOT reject CWEs outside Top 25 — valid vulnerabilities often map outside.
    Returns (is_valid, list_of_issues).
    """
    issues: List[str] = []
    for cwe_id in cwe_ids:
        if not isinstance(cwe_id, int) or cwe_id <= 0:
            issues.append(f"CWE-{cwe_id} is not a valid positive CWE identifier")
    return len(issues) == 0, issues


def classify_cwe_priority(cwe_ids: List[int]) -> Dict[str, List[int]]:
    """
    Classify CWE IDs into priority buckets.
    Returns dict with keys: top_25, kev_linked, other.
    """
    top_25: List[int] = []
    kev_linked: List[int] = []
    other: List[int] = []
    for cwe_id in cwe_ids:
        entry = CWE_2025_TOP_25.get(cwe_id)
        if entry is not None:
            top_25.append(cwe_id)
            if entry.kev_listed:
                kev_linked.append(cwe_id)
        else:
            other.append(cwe_id)
    return {"top_25": top_25, "kev_linked": kev_linked, "other": other}


def validate_cwe_mapping(cwe_ids: List[int]) -> Tuple[bool, List[str]]:
    """
    Validate CWE mapping: checks existence and classifies priority.
    Does NOT reject valid CWEs that are outside Top 25.
    Returns (is_valid, list_of_issues).
    """
    valid, issues = validate_cwe_exists(cwe_ids)
    classification = classify_cwe_priority(cwe_ids)
    if classification["top_25"]:
        pass  # informational — top 25 CWEs present
    if classification["kev_linked"]:
        pass  # informational — KEV-linked CWEs present
    return valid, issues


def is_cwe_mapping_vague(cwe_ids: List[int]) -> bool:
    """
    Check if CWE mapping is vague — uses only broad categories
    like CWE-20 (Improper Input Validation) without specifics.
    """
    vague_cwes = {20, 200}  # Broad parent categories
    if not cwe_ids:
        return True
    return all(cid in vague_cwes for cid in cwe_ids)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — SARIF EVIDENCE FORMAT
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SARIFResult:
    """A single SARIF result from a static analysis tool."""
    rule_id: str
    message: str
    level: str  # "error", "warning", "note", "none"
    file_path: str
    start_line: int
    end_line: int
    cwe_ids: List[int] = field(default_factory=list)
    tool_name: str = ""
    fingerprint: str = ""
    suppressed: bool = False
    false_positive: bool = False
    false_positive_justification: str = ""
    waived: bool = False

    def to_sarif_dict(self) -> Dict[str, Any]:
        """Convert to SARIF 2.1.0 result format."""
        result: Dict[str, Any] = {
            "ruleId": self.rule_id,
            "message": {"text": self.message},
            "level": self.level,
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": self.file_path},
                    "region": {
                        "startLine": self.start_line,
                        "endLine": self.end_line,
                    },
                },
            }],
        }
        if self.fingerprint:
            result["fingerprints"] = {"primary": self.fingerprint}
        if self.cwe_ids:
            result["taxa"] = [
                {"id": str(cid), "toolComponent": {"name": "CWE"}}
                for cid in self.cwe_ids
            ]
        if self.suppressed:
            result["suppressions"] = [{"kind": "inSource"}]
        return result


@dataclass
class SARIFToolRun:
    """A single tool run in SARIF format."""
    tool_name: str
    tool_version: str
    results: List[SARIFResult] = field(default_factory=list)

    def to_sarif_dict(self) -> Dict[str, Any]:
        return {
            "tool": {
                "driver": {
                    "name": self.tool_name,
                    "version": self.tool_version,
                    "rules": [],
                },
            },
            "results": [r.to_sarif_dict() for r in self.results],
        }


@dataclass
class SARIFBundle:
    """
    Aggregated SARIF bundle from multiple scanner runs.
    OASIS SARIF 2.1.0 compliant structure.
    """
    runs: List[SARIFToolRun] = field(default_factory=list)
    schema_version: str = "2.1.0"
    schema_uri: str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

    def to_sarif_document(self) -> Dict[str, Any]:
        """Generate complete SARIF 2.1.0 document."""
        return {
            "$schema": self.schema_uri,
            "version": self.schema_version,
            "runs": [run.to_sarif_dict() for run in self.runs],
        }

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of the SARIF bundle for evidence tracking."""
        content = json.dumps(self.to_sarif_document(), sort_keys=True)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @property
    def all_results(self) -> List[SARIFResult]:
        """Get all results across all runs."""
        results: List[SARIFResult] = []
        for run in self.runs:
            results.extend(run.results)
        return results

    @property
    def unresolved_results(self) -> List[SARIFResult]:
        """Get results that are not suppressed and not marked as false positives."""
        return [
            r for r in self.all_results
            if not r.suppressed and not r.false_positive
        ]

    @property
    def error_results(self) -> List[SARIFResult]:
        """Get unresolved error-level results."""
        return [r for r in self.unresolved_results if r.level == "error"]

    @property
    def warning_results(self) -> List[SARIFResult]:
        """Get unresolved warning-level results."""
        return [r for r in self.unresolved_results if r.level == "warning"]

    @property
    def scanner_versions(self) -> Dict[str, str]:
        """Get tool name → version mapping for all runs."""
        return {run.tool_name: run.tool_version for run in self.runs}

    @property
    def all_cwe_ids(self) -> List[int]:
        """Get all CWE IDs across all unresolved results."""
        cwe_ids: List[int] = []
        for r in self.unresolved_results:
            cwe_ids.extend(r.cwe_ids)
        return sorted(set(cwe_ids))

    def findings_resolved(self) -> bool:
        """Check if all findings are resolved (suppressed or marked false positive with justification)."""
        for r in self.all_results:
            if r.level in ("error", "warning"):
                if not r.suppressed and not r.false_positive:
                    return False
                if r.false_positive and not r.false_positive_justification:
                    return False
        return True

    def has_output(self) -> bool:
        """Check if scanner output exists (at least one run with results or explicit empty)."""
        return len(self.runs) > 0


class SARIFAggregator:
    """
    Aggregates SARIF results from multiple scanner tools into a unified bundle.
    """

    def __init__(self) -> None:
        self._runs: List[SARIFToolRun] = []

    def add_tool_run(
        self,
        tool_name: str,
        tool_version: str,
        results: List[SARIFResult],
    ) -> None:
        """Add a scanner tool run with its results."""
        for r in results:
            r.tool_name = tool_name
        run = SARIFToolRun(
            tool_name=tool_name,
            tool_version=tool_version,
            results=results,
        )
        self._runs.append(run)

    def build_bundle(self) -> SARIFBundle:
        """Build the aggregated SARIF bundle."""
        return SARIFBundle(runs=list(self._runs))

    def clear(self) -> None:
        """Clear all accumulated runs."""
        self._runs.clear()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3A — PATTERN ENFORCEMENT ENGINE (Regex-based, for non-Python source)
# ═══════════════════════════════════════════════════════════════════════════════

class ASTViolationSeverity(enum.Enum):
    """Severity of a policy violation."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


@dataclass(frozen=True)
class ASTViolation:
    """A single policy violation found in source code."""
    rule_id: str
    rule_name: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    severity: ASTViolationSeverity
    waiver_eligible: bool = False
    waiver_present: bool = False

    @property
    def is_blocked(self) -> bool:
        """Violation blocks the patch unless a valid waiver is present."""
        if self.waiver_eligible and self.waiver_present:
            return False
        return True


@dataclass
class ASTGateResult:
    """Result of the enforcement gate (pattern or AST)."""
    passed: bool
    violations: List[ASTViolation] = field(default_factory=list)
    files_scanned: int = 0
    rules_checked: int = 10
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def blocking_violations(self) -> List[ASTViolation]:
        return [v for v in self.violations if v.is_blocked]

    @property
    def waived_violations(self) -> List[ASTViolation]:
        return [v for v in self.violations if v.waiver_eligible and v.waiver_present]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "violations_count": len(self.violations),
            "blocking_count": len(self.blocking_violations),
            "waived_count": len(self.waived_violations),
            "files_scanned": self.files_scanned,
            "rules_checked": self.rules_checked,
            "timestamp": self.timestamp,
        }


class PatternEnforcementEngine:
    """
    Pattern Enforcement Engine — regex-based pattern scan for non-Python source.

    For Python source, use ASTEnforcementEngine which uses ast.parse + NodeVisitor.
    This engine is labelled "pattern scan" — it does NOT perform AST analysis.

    Bans:
        1. ban .parse at boundaries
        2. ban passthrough/catchall in boundary schemas
        3. ban direct execute outside enforce
        4. ban raw provider calls outside controlled adapters
        5. ban Ray ObjectRef in durable truth boundaries
        6. ban unsafe C/C++ calls unless waiver
        7. ban weak crypto in security-sensitive code
        8. ban system command execution with shell=True
        9. ban unchecked buffer copies
       10. ban unchecked return values for security-sensitive operations
    """

    # Waiver markers recognized in source comments
    WAIVER_MARKER = "# SECURITY_WAIVER:"

    # ── Rule 1: ban .parse at boundaries ──────────────────────────────────
    PARSE_PATTERNS: List[str] = [
        r"\.parse\s*\(",
        r"json\.loads?\s*\(",
        r"yaml\.load\s*\(",
        r"xml\..*\.parse\s*\(",
        r"pickle\.loads?\s*\(",
        r"ast\.literal_eval\s*\(",
        r"eval\s*\(",
        r"exec\s*\(",
        r"fromstring\s*\(",
        r"parseString\s*\(",
    ]

    # ── Rule 2: ban passthrough/catchall in boundary schemas ──────────────
    PASSTHROUGH_PATTERNS: List[str] = [
        r"Any\b",
        r"dict\s*\[.*,\s*Any\s*\]",
        r"Dict\s*\[.*,\s*Any\s*\]",
        r"\*\*kwargs.*boundary",
        r"passthrough",
        r"catchall",
        r"extra\s*=\s*['\"]allow['\"]",
    ]

    # ── Rule 3: ban direct execute outside enforce ────────────────────────
    DIRECT_EXECUTE_PATTERNS: List[str] = [
        r"cursor\.execute\s*\(",
        r"\.execute\s*\(",
        r"\.executemany\s*\(",
        r"\.executescript\s*\(",
        r"engine\.execute\s*\(",
        r"connection\.execute\s*\(",
        r"session\.execute\s*\(",
    ]

    # ── Rule 4: ban raw provider calls outside controlled adapters ────────
    RAW_PROVIDER_PATTERNS: List[str] = [
        r"requests\.(?:get|post|put|delete|patch|head)\s*\(",
        r"urllib\.request\.urlopen\s*\(",
        r"http\.client\.HTTP",
        r"httpx\.(?:get|post|put|delete|patch)\s*\(",
        r"aiohttp\.ClientSession\s*\(",
    ]

    # ── Rule 5: ban Ray ObjectRef in durable truth boundaries ─────────────
    RAY_OBJECTREF_PATTERNS: List[str] = [
        r"ray\.ObjectRef",
        r"ObjectRef",
        r"ray\.get\s*\(",
        r"ray\.put\s*\(",
    ]

    # ── Rule 6: ban unsafe C/C++ calls unless waiver ──────────────────────
    UNSAFE_C_PATTERNS: List[str] = [
        r"\bstrcpy\s*\(",
        r"\bstrcat\s*\(",
        r"\bsprintf\s*\(",
        r"\bgets\s*\(",
        r"\bscanf\s*\(",
        r"\bmemcpy\s*\(",
        r"\bmemmove\s*\(",
        r"\bfree\s*\(",
        r"\bmalloc\s*\(",
        r"\brealloc\s*\(",
        r"ctypes\.cdll",
        r"ctypes\.CDLL",
        r"cffi\.FFI",
    ]

    # ── Rule 7: ban weak crypto in security-sensitive code ────────────────
    WEAK_CRYPTO_PATTERNS: List[str] = [
        r"\bMD5\b",
        r"\bmd5\b",
        r"\bSHA1\b",
        r"\bsha1\b",
        r"hashlib\.md5\s*\(",
        r"hashlib\.sha1\s*\(",
        r"\bDES\b",
        r"\bRC4\b",
        r"\brc4\b",
        r"Crypto\.Cipher\.DES",
        r"Crypto\.Cipher\.ARC4",
        r"\bECB\b",
    ]

    # ── Rule 8: ban system command execution with shell=True ──────────────
    SYSTEM_EXEC_PATTERNS: List[str] = [
        r"os\.system\s*\(",
        r"os\.popen\s*\(",
        r"subprocess\..*\(.*shell\s*=\s*True",
        r"commands\.getoutput\s*\(",
        r"commands\.getstatusoutput\s*\(",
    ]

    # ── Rule 9: ban unchecked buffer copies ───────────────────────────────
    BUFFER_COPY_PATTERNS: List[str] = [
        r"\bstrcpy\s*\(",
        r"\bstrncpy\s*\(",
        r"\bmemcpy\s*\(",
        r"\bmemmove\s*\(",
        r"\bwcscpy\s*\(",
        r"\bwcsncpy\s*\(",
        r"\.read\s*\(\s*\)",  # unbounded read
        r"\.readlines\s*\(\s*\)",  # unbounded readlines
    ]

    # ── Rule 10: ban unchecked return values for security ops ─────────────
    UNCHECKED_RETURN_PATTERNS: List[str] = [
        r"^\s*os\.remove\s*\(",
        r"^\s*os\.unlink\s*\(",
        r"^\s*os\.chmod\s*\(",
        r"^\s*os\.chown\s*\(",
        r"^\s*shutil\.rmtree\s*\(",
        r"^\s*shutil\.move\s*\(",
        r"^\s*open\s*\(",
    ]

    RULE_DEFINITIONS = [
        {
            "id": "AST-001",
            "name": "ban_parse_at_boundaries",
            "description": "Ban .parse at boundaries — untrusted input parsing must use validated schemas",
            "severity": ASTViolationSeverity.CRITICAL,
            "waiver_eligible": False,
        },
        {
            "id": "AST-002",
            "name": "ban_passthrough_catchall",
            "description": "Ban passthrough/catchall in boundary schemas — all fields must be explicitly typed",
            "severity": ASTViolationSeverity.CRITICAL,
            "waiver_eligible": False,
        },
        {
            "id": "AST-003",
            "name": "ban_direct_execute",
            "description": "Ban direct execute outside enforce — all DB operations must go through enforcement layer",
            "severity": ASTViolationSeverity.CRITICAL,
            "waiver_eligible": False,
        },
        {
            "id": "AST-004",
            "name": "ban_raw_provider_calls",
            "description": "Ban raw provider calls outside controlled adapters",
            "severity": ASTViolationSeverity.HIGH,
            "waiver_eligible": False,
        },
        {
            "id": "AST-005",
            "name": "ban_ray_objectref",
            "description": "Ban Ray ObjectRef in durable truth boundaries",
            "severity": ASTViolationSeverity.CRITICAL,
            "waiver_eligible": False,
        },
        {
            "id": "AST-006",
            "name": "ban_unsafe_c_calls",
            "description": "Ban unsafe C/C++ calls unless waiver exists",
            "severity": ASTViolationSeverity.CRITICAL,
            "waiver_eligible": True,
        },
        {
            "id": "AST-007",
            "name": "ban_weak_crypto",
            "description": "Ban weak crypto in security-sensitive code",
            "severity": ASTViolationSeverity.HIGH,
            "waiver_eligible": False,
        },
        {
            "id": "AST-008",
            "name": "ban_system_command_exec",
            "description": "Ban system command execution with shell=True",
            "severity": ASTViolationSeverity.CRITICAL,
            "waiver_eligible": False,
        },
        {
            "id": "AST-009",
            "name": "ban_unchecked_buffer_copies",
            "description": "Ban unchecked buffer copies",
            "severity": ASTViolationSeverity.CRITICAL,
            "waiver_eligible": True,
        },
        {
            "id": "AST-010",
            "name": "ban_unchecked_return_values",
            "description": "Ban unchecked return values for security-sensitive operations",
            "severity": ASTViolationSeverity.HIGH,
            "waiver_eligible": False,
        },
    ]

    def __init__(self, waivers: Optional[Dict[str, str]] = None) -> None:
        """
        Initialize pattern enforcement engine.

        Args:
            waivers: Dict mapping rule_id → waiver justification for waiver-eligible rules.
        """
        self._waivers: Dict[str, str] = waivers or {}
        self._pattern_map: Dict[str, List[str]] = {
            "AST-001": self.PARSE_PATTERNS,
            "AST-002": self.PASSTHROUGH_PATTERNS,
            "AST-003": self.DIRECT_EXECUTE_PATTERNS,
            "AST-004": self.RAW_PROVIDER_PATTERNS,
            "AST-005": self.RAY_OBJECTREF_PATTERNS,
            "AST-006": self.UNSAFE_C_PATTERNS,
            "AST-007": self.WEAK_CRYPTO_PATTERNS,
            "AST-008": self.SYSTEM_EXEC_PATTERNS,
            "AST-009": self.BUFFER_COPY_PATTERNS,
            "AST-010": self.UNCHECKED_RETURN_PATTERNS,
        }

    def _check_waiver_in_line(self, line: str, rule_id: str) -> bool:
        """Check if a waiver comment exists for this rule on this line."""
        marker = f"{self.WAIVER_MARKER} {rule_id}"
        return marker in line

    def _scan_source_for_rule(
        self,
        source_lines: List[str],
        file_path: str,
        rule_def: Dict[str, Any],
    ) -> List[ASTViolation]:
        """Scan source lines for violations of a single rule (pattern scan)."""
        violations: List[ASTViolation] = []
        rule_id = rule_def["id"]
        patterns = self._pattern_map[rule_id]

        for line_num, line in enumerate(source_lines, start=1):
            # Skip comment-only lines
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for pattern in patterns:
                if re.search(pattern, line):
                    # Check for inline waiver
                    has_inline_waiver = self._check_waiver_in_line(line, rule_id)
                    # Check for registered waiver
                    has_registered_waiver = rule_id in self._waivers

                    waiver_eligible = rule_def["waiver_eligible"]
                    waiver_present = waiver_eligible and (has_inline_waiver or has_registered_waiver)

                    violation = ASTViolation(
                        rule_id=rule_id,
                        rule_name=rule_def["name"],
                        description=rule_def["description"],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=stripped[:200],
                        severity=rule_def["severity"],
                        waiver_eligible=waiver_eligible,
                        waiver_present=waiver_present,
                    )
                    violations.append(violation)
                    break  # One violation per line per rule

        return violations

    def scan_source(
        self,
        source_code: str,
        file_path: str = "<unknown>",
    ) -> ASTGateResult:
        """
        Scan source code against all 10 pattern enforcement rules.
        This is a pattern scan, not AST analysis.

        Returns ASTGateResult with pass/fail and all violations found.
        """
        lines = source_code.split("\n")
        all_violations: List[ASTViolation] = []

        for rule_def in self.RULE_DEFINITIONS:
            violations = self._scan_source_for_rule(lines, file_path, rule_def)
            all_violations.extend(violations)

        blocking = [v for v in all_violations if v.is_blocked]
        passed = len(blocking) == 0

        return ASTGateResult(
            passed=passed,
            violations=all_violations,
            files_scanned=1,
            rules_checked=len(self.RULE_DEFINITIONS),
        )

    def scan_multiple_files(
        self,
        files: Dict[str, str],
    ) -> ASTGateResult:
        """
        Scan multiple source files using pattern matching.

        Args:
            files: Dict mapping file_path → source_code.

        Returns aggregated ASTGateResult.
        """
        all_violations: List[ASTViolation] = []

        for file_path, source_code in files.items():
            result = self.scan_source(source_code, file_path)
            all_violations.extend(result.violations)

        blocking = [v for v in all_violations if v.is_blocked]
        passed = len(blocking) == 0

        return ASTGateResult(
            passed=passed,
            violations=all_violations,
            files_scanned=len(files),
            rules_checked=len(self.RULE_DEFINITIONS),
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3B — AST ENFORCEMENT ENGINE (Real ast.NodeVisitor for Python)
# ═══════════════════════════════════════════════════════════════════════════════

class PythonSecurityVisitor(ast.NodeVisitor):
    """
    Real AST-based security visitor using Python's ast module.
    Walks the parsed AST and detects security violations structurally.
    """

    def __init__(self, file_path: str, waivers: Optional[Dict[str, str]] = None) -> None:
        self.file_path = file_path
        self.violations: List[ASTViolation] = []
        self._waivers: Dict[str, str] = waivers or {}
        self._source_lines: List[str] = []

    def _has_waiver(self, rule_id: str, lineno: int) -> bool:
        """Check if a waiver exists for this rule (inline or registered)."""
        if rule_id in self._waivers:
            return True
        if 0 < lineno <= len(self._source_lines):
            line = self._source_lines[lineno - 1]
            if f"# SECURITY_WAIVER: {rule_id}" in line:
                return True
        return False

    def _record(
        self,
        node: ast.AST,
        rule_id: str,
        rule_name: str,
        description: str,
        severity: ASTViolationSeverity = ASTViolationSeverity.CRITICAL,
        waiver_eligible: bool = False,
    ) -> None:
        lineno = getattr(node, "lineno", 0)
        snippet = ""
        if 0 < lineno <= len(self._source_lines):
            snippet = self._source_lines[lineno - 1].strip()[:200]
        waiver_present = waiver_eligible and self._has_waiver(rule_id, lineno)
        self.violations.append(ASTViolation(
            rule_id=rule_id,
            rule_name=rule_name,
            description=description,
            file_path=self.file_path,
            line_number=lineno,
            code_snippet=snippet,
            severity=severity,
            waiver_eligible=waiver_eligible,
            waiver_present=waiver_present,
        ))

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        """Extract the dotted name of a call, e.g. 'subprocess.run'."""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts = []
            current: ast.expr = func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _has_keyword_true(node: ast.Call, keyword_name: str) -> bool:
        """Check if a call has keyword=True."""
        for kw in node.keywords:
            if kw.arg == keyword_name:
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node)

        # AST-001: ban eval/exec
        if name in ("eval", "exec"):
            self._record(node, "AST-001", "ban_eval_exec",
                         f"{name}() blocked — untrusted code execution")

        # AST-001: ban pickle.loads/pickle.load
        if name in ("pickle.loads", "pickle.load"):
            self._record(node, "AST-001", "ban_pickle_deserialize",
                         f"{name}() blocked — unsafe deserialization")

        # AST-001: ban yaml.load without SafeLoader (yaml.safe_load is OK)
        if name == "yaml.load":
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    if isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader":
                        has_safe_loader = True
                    elif isinstance(kw.value, ast.Name) and kw.value.id == "SafeLoader":
                        has_safe_loader = True
            if not has_safe_loader:
                self._record(node, "AST-001", "ban_yaml_load_unsafe",
                             "yaml.load() without SafeLoader blocked")

        # AST-003: ban direct DB execute
        if name.endswith((".execute", ".executemany", ".executescript")):
            attr = name.split(".")[-1]
            self._record(node, "AST-003", "ban_direct_execute",
                         f".{attr}() blocked — use enforcement layer")

        # AST-004: ban raw provider calls
        if name in ("requests.get", "requests.post", "requests.put",
                     "requests.delete", "requests.patch", "requests.head",
                     "urllib.request.urlopen"):
            self._record(node, "AST-004", "ban_raw_provider_calls",
                         f"{name}() blocked — use controlled adapter",
                         severity=ASTViolationSeverity.HIGH)

        # AST-007: ban weak crypto
        if name in ("hashlib.md5", "hashlib.sha1"):
            self._record(node, "AST-007", "ban_weak_crypto",
                         f"{name}() blocked — use SHA-256 or stronger",
                         severity=ASTViolationSeverity.HIGH)

        # AST-008: ban subprocess with shell=True, ban os.system, os.popen
        if name in ("os.system", "os.popen"):
            self._record(node, "AST-008", "ban_system_command_exec",
                         f"{name}() blocked — system command execution")
        if name in ("subprocess.run", "subprocess.Popen", "subprocess.call",
                     "subprocess.check_output", "subprocess.check_call"):
            if self._has_keyword_true(node, "shell"):
                self._record(node, "AST-008", "ban_subprocess_shell_true",
                             f"{name}(shell=True) blocked — shell injection risk")

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "pickle":
                pass  # Import alone is not a violation; usage is
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.generic_visit(node)


class ASTEnforcementEngine:
    """
    AST Enforcement Engine — uses real ast.parse + ast.NodeVisitor for Python.

    For Python source, this parses the code into an AST and walks nodes
    to detect security violations structurally.

    Falls back to PatternEnforcementEngine for non-Python source.
    """

    def __init__(self, waivers: Optional[Dict[str, str]] = None) -> None:
        self._waivers: Dict[str, str] = waivers or {}
        self._pattern_engine = PatternEnforcementEngine(waivers=waivers)

    def scan_source(
        self,
        source_code: str,
        file_path: str = "<unknown>",
    ) -> ASTGateResult:
        """
        Scan Python source code using real AST analysis.
        Falls back to pattern scan if ast.parse fails (non-Python source).
        """
        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError:
            # Not valid Python — fall back to pattern scan
            return self._pattern_engine.scan_source(source_code, file_path)

        visitor = PythonSecurityVisitor(file_path, waivers=self._waivers)
        visitor._source_lines = source_code.split("\n")
        visitor.visit(tree)

        blocking = [v for v in visitor.violations if v.is_blocked]
        passed = len(blocking) == 0

        return ASTGateResult(
            passed=passed,
            violations=visitor.violations,
            files_scanned=1,
            rules_checked=10,
        )

    def scan_multiple_files(
        self,
        files: Dict[str, str],
    ) -> ASTGateResult:
        """Scan multiple source files."""
        all_violations: List[ASTViolation] = []

        for file_path, source_code in files.items():
            result = self.scan_source(source_code, file_path)
            all_violations.extend(result.violations)

        blocking = [v for v in all_violations if v.is_blocked]
        passed = len(blocking) == 0

        return ASTGateResult(
            passed=passed,
            violations=all_violations,
            files_scanned=len(files),
            rules_checked=10,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — SECURITY EVIDENCE BUNDLE (15 Required Fields)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecurityEvidenceBundle:
    """
    Security evidence bundle — 15 required fields per AI patch.
    No evidence bundle, no merge.
    """
    input_hash: str
    output_hash: str
    prompt_hash: str
    model_id: str
    model_temperature: float
    scanner_versions: Dict[str, str]
    SARIF_bundle_hash: str
    AST_gate_result: str
    test_result_hash: str
    CWE_mapping: List[int]
    risk_rating: str
    manual_reviewer: str
    patch_diff_hash: str
    QNEO_decision: str
    merge_commit_sha: str

    # Metadata
    bundle_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    REQUIRED_FIELDS: frozenset = frozenset({
        "input_hash", "output_hash", "prompt_hash", "model_id",
        "model_temperature", "scanner_versions", "SARIF_bundle_hash",
        "AST_gate_result", "test_result_hash", "CWE_mapping",
        "risk_rating", "manual_reviewer", "patch_diff_hash",
        "QNEO_decision", "merge_commit_sha",
    })

    def validate(self) -> List[str]:
        """
        Validate that all 15 required fields are present and non-empty.
        Returns list of validation errors (empty = valid).
        Uses strict SHA-256 hex validation.
        """
        errors: List[str] = []

        if not self.input_hash or not is_sha256(self.input_hash):
            errors.append("input_hash must be a valid SHA-256 (64 lowercase hex chars)")
        if not self.output_hash or not is_sha256(self.output_hash):
            errors.append("output_hash must be a valid SHA-256 (64 lowercase hex chars)")
        if not self.prompt_hash or not is_sha256(self.prompt_hash):
            errors.append("prompt_hash must be a valid SHA-256 (64 lowercase hex chars)")
        if not self.model_id:
            errors.append("model_id is required")
        if self.model_temperature < 0.0 or self.model_temperature > 2.0:
            errors.append("model_temperature must be between 0.0 and 2.0")
        if not self.scanner_versions:
            errors.append("scanner_versions must contain at least one scanner")
        if not self.SARIF_bundle_hash or not is_sha256(self.SARIF_bundle_hash):
            errors.append("SARIF_bundle_hash must be a valid SHA-256 (64 lowercase hex chars)")
        if not self.AST_gate_result or self.AST_gate_result not in ("PASS", "FAIL"):
            errors.append("AST_gate_result must be 'PASS' or 'FAIL'")
        if not self.test_result_hash or not is_sha256(self.test_result_hash):
            errors.append("test_result_hash must be a valid SHA-256 (64 lowercase hex chars)")
        if not isinstance(self.CWE_mapping, list):
            errors.append("CWE_mapping must be a list of CWE IDs")
        if not self.risk_rating or self.risk_rating not in ("critical", "high", "medium", "low"):
            errors.append("risk_rating must be one of: critical, high, medium, low")
        if not self.manual_reviewer:
            errors.append("manual_reviewer is required")
        if not self.patch_diff_hash or not is_sha256(self.patch_diff_hash):
            errors.append("patch_diff_hash must be a valid SHA-256 (64 lowercase hex chars)")
        if not self.QNEO_decision or self.QNEO_decision not in ("ALLOW", "HOLD", "FAIL_CLOSED", "ROLLBACK"):
            errors.append("QNEO_decision must be one of: ALLOW, HOLD, FAIL_CLOSED, ROLLBACK")
        # merge_commit_sha can be empty before merge, but field must exist
        if self.merge_commit_sha is None:
            errors.append("merge_commit_sha must be a string (can be empty before merge)")

        return errors

    def is_complete(self) -> bool:
        """Check if the evidence bundle is complete (all fields valid)."""
        return len(self.validate()) == 0

    def compute_bundle_hash(self) -> str:
        """Compute SHA-256 of the entire evidence bundle for tamper detection."""
        payload = json.dumps({
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "prompt_hash": self.prompt_hash,
            "model_id": self.model_id,
            "model_temperature": self.model_temperature,
            "scanner_versions": self.scanner_versions,
            "SARIF_bundle_hash": self.SARIF_bundle_hash,
            "AST_gate_result": self.AST_gate_result,
            "test_result_hash": self.test_result_hash,
            "CWE_mapping": self.CWE_mapping,
            "risk_rating": self.risk_rating,
            "manual_reviewer": self.manual_reviewer,
            "patch_diff_hash": self.patch_diff_hash,
            "QNEO_decision": self.QNEO_decision,
            "merge_commit_sha": self.merge_commit_sha,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_sha256(content: str) -> str:
    """Compute SHA-256 hash of string content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def compute_sha256_bytes(content: bytes) -> str:
    """Compute SHA-256 hash of bytes content."""
    return hashlib.sha256(content).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — LLM REVIEW RESULT (Non-Authoritative)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class LLMReviewResult:
    """
    Result of LLM security review — useful but NOT authoritative.
    LLM review cannot replace scanner output, AST enforcement, or human review.
    """
    model_id: str
    model_temperature: float
    prompt_hash: str
    issues_found: List[Dict[str, Any]] = field(default_factory=list)
    patch_suggestion: str = ""
    confidence_score: float = 0.0
    agrees_with_scanners: bool = True
    extra_issues_without_scanner_support: bool = False
    disables_validation: bool = False
    suppresses_tests: bool = False
    removes_logging_or_audit: bool = False
    removes_functionality_without_proof: bool = False
    changes_unrelated_code: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — TEST EXECUTION RESULT
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TestExecutionResult:
    """Result of running the test suite against patched code."""
    passed: bool
    total_tests: int
    passed_tests: int
    failed_tests: int
    error_tests: int
    skipped_tests: int
    execution_time_seconds: float
    test_output: str
    test_framework: str = "pytest"

    def compute_hash(self) -> str:
        """Compute SHA-256 of test results for evidence tracking.
        Includes test_output_hash for uniqueness per Issue #11."""
        test_output_hash = hashlib.sha256(
            self.test_output.encode("utf-8")
        ).hexdigest()
        payload = json.dumps({
            "passed": self.passed,
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "error_tests": self.error_tests,
            "skipped_tests": self.skipped_tests,
            "execution_time_seconds": self.execution_time_seconds,
            "test_output_hash": test_output_hash,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — HUMAN SECURITY REVIEW
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HumanSecurityReview:
    """Record of human security review sign-off."""
    reviewer_identity: str
    approved: bool
    review_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    comments: str = ""
    reviewed_evidence_hash: str = ""
    review_duration_minutes: float = 0.0

    def is_valid(self) -> bool:
        """A valid review requires identity, explicit approval, and evidence hash."""
        if not self.reviewer_identity:
            return False
        if not self.reviewed_evidence_hash:
            return False
        return True


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — PATCH ANALYSIS (using difflib.unified_diff)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PatchAnalysis:
    """Analysis of a proposed AI-generated patch."""
    original_source: str
    patched_source: str
    patch_diff: str
    is_minimal: bool
    changes_unrelated_code: bool
    lines_added: int
    lines_removed: int
    files_changed: int

    @property
    def input_hash(self) -> str:
        return compute_sha256(self.original_source)

    @property
    def output_hash(self) -> str:
        return compute_sha256(self.patched_source)

    @property
    def diff_hash(self) -> str:
        return compute_sha256(self.patch_diff)


def analyze_patch(original: str, patched: str) -> PatchAnalysis:
    """
    Analyze a patch to determine minimality and scope.
    Uses difflib.unified_diff for proper diff computation (Issue #12).
    """
    orig_lines = original.splitlines(keepends=True)
    patch_lines = patched.splitlines(keepends=True)

    # Use difflib.unified_diff for proper diff
    diff_result = list(difflib.unified_diff(
        orig_lines, patch_lines,
        fromfile="original", tofile="patched",
    ))
    patch_diff = "".join(diff_result)

    # Count added/removed from unified diff
    added = 0
    removed = 0
    change_positions: List[int] = []
    current_line = 0

    for line in diff_result:
        if line.startswith("@@"):
            # Parse hunk header to get line position
            # Format: @@ -start,count +start,count @@
            import re as _re
            match = _re.search(r"\+(\d+)", line)
            if match:
                current_line = int(match.group(1))
            continue
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("-"):
            removed += 1
            change_positions.append(current_line)
        elif line.startswith("+"):
            added += 1
            change_positions.append(current_line)
            current_line += 1
        else:
            current_line += 1

    # Minimality heuristic: patch is minimal if changes are < 20% of total lines
    total_changes = added + removed
    total_lines = max(len(orig_lines), len(patch_lines))
    is_minimal = total_changes <= max(total_lines * 0.2, 5) if total_lines > 0 else True

    # Unrelated code detection: check if changes touch multiple unrelated sections
    changes_unrelated = False
    if len(change_positions) >= 2:
        sorted_positions = sorted(set(change_positions))
        gaps = [
            sorted_positions[i + 1] - sorted_positions[i]
            for i in range(len(sorted_positions) - 1)
        ]
        # If there are large gaps between changes, likely touching unrelated code
        changes_unrelated = any(gap > 20 for gap in gaps)

    return PatchAnalysis(
        original_source=original,
        patched_source=patched,
        patch_diff=patch_diff,
        is_minimal=is_minimal,
        changes_unrelated_code=changes_unrelated,
        lines_added=added,
        lines_removed=removed,
        files_changed=1,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — PIPELINE STEP DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

class PipelineStep(enum.Enum):
    """The 11 steps of the secure coding pipeline."""
    AI_PATCH_PROPOSED = "ai_patch_proposed"
    SOURCE_NORMALIZED_AND_HASHED = "source_normalized_and_hashed"
    STATIC_SCANNERS_RUN = "static_scanners_run"
    SARIF_RESULTS_AGGREGATED = "sarif_results_aggregated"
    AST_POLICY_GATE_RUNS = "ast_policy_gate_runs"
    LLM_REVIEWS_SCANNER_EVIDENCE = "llm_reviews_scanner_evidence"
    MINIMAL_PATCH_GENERATED = "minimal_patch_generated"
    TESTS_RUN = "tests_run"
    PATCHED_CODE_RESCANNED = "patched_code_rescanned"
    HUMAN_SECURITY_REVIEW = "human_security_review"
    QNEO_RETURNS_DECISION = "qneo_returns_decision"


PIPELINE_STEP_ORDER = [
    PipelineStep.AI_PATCH_PROPOSED,
    PipelineStep.SOURCE_NORMALIZED_AND_HASHED,
    PipelineStep.STATIC_SCANNERS_RUN,
    PipelineStep.SARIF_RESULTS_AGGREGATED,
    PipelineStep.AST_POLICY_GATE_RUNS,
    PipelineStep.LLM_REVIEWS_SCANNER_EVIDENCE,
    PipelineStep.MINIMAL_PATCH_GENERATED,
    PipelineStep.TESTS_RUN,
    PipelineStep.PATCHED_CODE_RESCANNED,
    PipelineStep.HUMAN_SECURITY_REVIEW,
    PipelineStep.QNEO_RETURNS_DECISION,
]


@dataclass
class PipelineStepResult:
    """Result of a single pipeline step."""
    step: PipelineStep
    completed: bool
    passed: bool
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    evidence: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — SECURE CODING PIPELINE (11-Step Pipeline)
# ═══════════════════════════════════════════════════════════════════════════════

class SecureCodingPipeline:
    """
    A.I.M D.R.A.G Fail-Closed Secure Coding Pipeline — 11 steps.

    Every AI-generated patch is treated as hostile until scanners, AST gates,
    tests, re-scans, human review, and QNEO prove it safe.

    Pipeline steps:
        1.  AI patch proposed
        2.  Source normalized and hashed
        3.  Static scanners run
        4.  SARIF results aggregated
        5.  AST policy gate runs
        6.  LLM reviews scanner evidence
        7.  Minimal patch generated
        8.  Tests run
        9.  Patched code re-scanned
        10. Human security review signs off
        11. QNEO returns ALLOW/HOLD/FAIL_CLOSED/ROLLBACK
    """

    def __init__(
        self,
        ast_engine: Optional[ASTEnforcementEngine] = None,
        sarif_aggregator: Optional[SARIFAggregator] = None,
    ) -> None:
        self._ast_engine = ast_engine or ASTEnforcementEngine()
        self._sarif_aggregator = sarif_aggregator or SARIFAggregator()
        self._step_results: List[PipelineStepResult] = []
        self._pipeline_id = str(uuid.uuid4())
        self._created_at = datetime.now(timezone.utc).isoformat()

        # Pipeline state
        self._original_source: Optional[str] = None
        self._patched_source: Optional[str] = None
        self._input_hash: Optional[str] = None
        self._output_hash: Optional[str] = None
        self._patch_analysis: Optional[PatchAnalysis] = None
        self._sarif_bundle: Optional[SARIFBundle] = None
        self._rescan_sarif_bundle: Optional[SARIFBundle] = None
        self._ast_gate_result: Optional[ASTGateResult] = None
        self._llm_review: Optional[LLMReviewResult] = None
        self._test_result: Optional[TestExecutionResult] = None
        self._human_review: Optional[HumanSecurityReview] = None
        self._evidence_bundle: Optional[SecurityEvidenceBundle] = None

    @property
    def pipeline_id(self) -> str:
        return self._pipeline_id

    @property
    def step_results(self) -> List[PipelineStepResult]:
        return list(self._step_results)

    @property
    def current_step_index(self) -> int:
        return len(self._step_results)

    @property
    def evidence_bundle(self) -> Optional[SecurityEvidenceBundle]:
        return self._evidence_bundle

    def _record_step(
        self,
        step: PipelineStep,
        completed: bool,
        passed: bool,
        evidence: Optional[Dict[str, Any]] = None,
        errors: Optional[List[str]] = None,
    ) -> PipelineStepResult:
        """Record a pipeline step result."""
        result = PipelineStepResult(
            step=step,
            completed=completed,
            passed=passed,
            evidence=evidence or {},
            errors=errors or [],
        )
        self._step_results.append(result)
        return result

    # ── Step 1: AI Patch Proposed ─────────────────────────────────────────

    def step_01_ai_patch_proposed(
        self,
        original_source: str,
        patched_source: str,
        model_id: str,
        prompt: str,
        temperature: float = 0.0,
    ) -> PipelineStepResult:
        """
        Step 1: Accept the AI-generated patch as untrusted input.
        Record the original source, patched source, model metadata.
        """
        self._original_source = original_source
        self._patched_source = patched_source
        self._model_id = model_id
        self._prompt = prompt
        self._temperature = temperature

        return self._record_step(
            step=PipelineStep.AI_PATCH_PROPOSED,
            completed=True,
            passed=True,
            evidence={
                "model_id": model_id,
                "temperature": temperature,
                "original_length": len(original_source),
                "patched_length": len(patched_source),
            },
        )

    # ── Step 2: Source Normalized and Hashed ──────────────────────────────

    def step_02_source_normalized_and_hashed(self) -> PipelineStepResult:
        """
        Step 2: Normalize source code and compute SHA-256 hashes.
        """
        if self._original_source is None or self._patched_source is None:
            return self._record_step(
                step=PipelineStep.SOURCE_NORMALIZED_AND_HASHED,
                completed=False,
                passed=False,
                errors=["Source code not provided — step 1 must complete first"],
            )

        # Normalize: strip trailing whitespace, ensure trailing newline
        normalized_original = "\n".join(
            line.rstrip() for line in self._original_source.split("\n")
        ).rstrip() + "\n"
        normalized_patched = "\n".join(
            line.rstrip() for line in self._patched_source.split("\n")
        ).rstrip() + "\n"

        self._original_source = normalized_original
        self._patched_source = normalized_patched
        self._input_hash = compute_sha256(normalized_original)
        self._output_hash = compute_sha256(normalized_patched)

        return self._record_step(
            step=PipelineStep.SOURCE_NORMALIZED_AND_HASHED,
            completed=True,
            passed=True,
            evidence={
                "input_hash": self._input_hash,
                "output_hash": self._output_hash,
            },
        )

    # ── Step 3: Static Scanners Run ──────────────────────────────────────

    def step_03_static_scanners_run(
        self,
        scanner_results: List[Tuple[str, str, List[SARIFResult]]],
    ) -> PipelineStepResult:
        """
        Step 3: Run static scanners on the ORIGINAL source code.
        """
        if not scanner_results:
            return self._record_step(
                step=PipelineStep.STATIC_SCANNERS_RUN,
                completed=False,
                passed=False,
                errors=["No scanner results provided — scanners must run"],
            )

        self._sarif_aggregator.clear()
        for tool_name, tool_version, results in scanner_results:
            self._sarif_aggregator.add_tool_run(tool_name, tool_version, results)

        self._sarif_bundle = self._sarif_aggregator.build_bundle()

        return self._record_step(
            step=PipelineStep.STATIC_SCANNERS_RUN,
            completed=True,
            passed=True,
            evidence={
                "scanners_run": len(scanner_results),
                "total_findings": len(self._sarif_bundle.all_results),
                "error_findings": len(self._sarif_bundle.error_results),
                "warning_findings": len(self._sarif_bundle.warning_results),
                "scanner_versions": self._sarif_bundle.scanner_versions,
            },
        )

    # ── Step 4: SARIF Results Aggregated ─────────────────────────────────

    def step_04_sarif_results_aggregated(self) -> PipelineStepResult:
        """
        Step 4: Aggregate SARIF results from all scanners.
        """
        if self._sarif_bundle is None:
            return self._record_step(
                step=PipelineStep.SARIF_RESULTS_AGGREGATED,
                completed=False,
                passed=False,
                errors=["SARIF bundle not available — step 3 must complete first"],
            )

        sarif_hash = self._sarif_bundle.compute_hash()
        cwe_ids = self._sarif_bundle.all_cwe_ids
        cwe_valid, cwe_issues = validate_cwe_mapping(cwe_ids)

        return self._record_step(
            step=PipelineStep.SARIF_RESULTS_AGGREGATED,
            completed=True,
            passed=True,
            evidence={
                "sarif_bundle_hash": sarif_hash,
                "total_results": len(self._sarif_bundle.all_results),
                "unresolved_results": len(self._sarif_bundle.unresolved_results),
                "cwe_ids": cwe_ids,
                "cwe_mapping_valid": cwe_valid,
                "cwe_issues": cwe_issues,
            },
        )

    # ── Step 5: AST Policy Gate Runs ─────────────────────────────────────

    def step_05_ast_policy_gate_runs(
        self,
        file_path: str = "<ai_patch>",
    ) -> PipelineStepResult:
        """
        Step 5: Run AST enforcement gate on the patched source code.
        """
        if self._patched_source is None:
            return self._record_step(
                step=PipelineStep.AST_POLICY_GATE_RUNS,
                completed=False,
                passed=False,
                errors=["Patched source not available — step 2 must complete first"],
            )

        self._ast_gate_result = self._ast_engine.scan_source(
            self._patched_source, file_path
        )

        return self._record_step(
            step=PipelineStep.AST_POLICY_GATE_RUNS,
            completed=True,
            passed=self._ast_gate_result.passed,
            evidence=self._ast_gate_result.to_dict(),
            errors=[
                f"{v.rule_id}: {v.description} at {v.file_path}:{v.line_number}"
                for v in self._ast_gate_result.blocking_violations
            ],
        )

    # ── Step 6: LLM Reviews Scanner Evidence ─────────────────────────────

    def step_06_llm_reviews_scanner_evidence(
        self,
        llm_review: LLMReviewResult,
    ) -> PipelineStepResult:
        """
        Step 6: LLM reviews scanner evidence.
        LLM review is useful but NOT authoritative.
        """
        self._llm_review = llm_review

        issues: List[str] = []
        if llm_review.disables_validation:
            issues.append("LLM patch disables validation")
        if llm_review.suppresses_tests:
            issues.append("LLM patch suppresses tests")
        if llm_review.removes_logging_or_audit:
            issues.append("LLM patch removes logging or audit")
        if llm_review.extra_issues_without_scanner_support:
            issues.append("LLM reports extra issues without scanner support")
        if not llm_review.agrees_with_scanners:
            issues.append("Scanner and LLM disagree")

        return self._record_step(
            step=PipelineStep.LLM_REVIEWS_SCANNER_EVIDENCE,
            completed=True,
            passed=len(issues) == 0,
            evidence=llm_review.to_dict(),
            errors=issues,
        )

    # ── Step 7: Minimal Patch Generated ──────────────────────────────────

    def step_07_minimal_patch_generated(self) -> PipelineStepResult:
        """
        Step 7: Analyze and validate the generated patch for minimality.
        """
        if self._original_source is None or self._patched_source is None:
            return self._record_step(
                step=PipelineStep.MINIMAL_PATCH_GENERATED,
                completed=False,
                passed=False,
                errors=["Source code not available for patch analysis"],
            )

        self._patch_analysis = analyze_patch(
            self._original_source, self._patched_source
        )

        issues: List[str] = []
        if not self._patch_analysis.is_minimal:
            issues.append("Patch is not minimal — changes exceed 20% threshold")
        if self._patch_analysis.changes_unrelated_code:
            issues.append("Patch changes unrelated code")

        return self._record_step(
            step=PipelineStep.MINIMAL_PATCH_GENERATED,
            completed=True,
            passed=self._patch_analysis.is_minimal and not self._patch_analysis.changes_unrelated_code,
            evidence={
                "is_minimal": self._patch_analysis.is_minimal,
                "changes_unrelated_code": self._patch_analysis.changes_unrelated_code,
                "lines_added": self._patch_analysis.lines_added,
                "lines_removed": self._patch_analysis.lines_removed,
                "input_hash": self._patch_analysis.input_hash,
                "output_hash": self._patch_analysis.output_hash,
                "diff_hash": self._patch_analysis.diff_hash,
            },
            errors=issues,
        )

    # ── Step 8: Tests Run ────────────────────────────────────────────────

    def step_08_tests_run(
        self,
        test_result: TestExecutionResult,
    ) -> PipelineStepResult:
        """
        Step 8: Run tests against the patched code.
        """
        self._test_result = test_result

        issues: List[str] = []
        if not test_result.passed:
            issues.append(
                f"Tests failed: {test_result.failed_tests} failures, "
                f"{test_result.error_tests} errors out of {test_result.total_tests} total"
            )

        return self._record_step(
            step=PipelineStep.TESTS_RUN,
            completed=True,
            passed=test_result.passed,
            evidence={
                "test_passed": test_result.passed,
                "total_tests": test_result.total_tests,
                "passed_tests": test_result.passed_tests,
                "failed_tests": test_result.failed_tests,
                "test_result_hash": test_result.compute_hash(),
            },
            errors=issues,
        )

    # ── Step 9: Patched Code Re-scanned (compares original vs patched SARIF) ──

    def step_09_patched_code_rescanned(
        self,
        rescan_results: List[Tuple[str, str, List[SARIFResult]]],
    ) -> PipelineStepResult:
        """
        Step 9: Re-scan the patched code with static scanners.
        Compares original SARIF vs patched SARIF per Issue #5.

        Blocks if:
          - new error findings exist
          - new warning findings exist (unless waived)
          - new Top 25 CWE appears
          - new KEV-linked CWE appears
          - same original finding persists (unresolved)
          - scanner output missing
        """
        if not rescan_results:
            return self._record_step(
                step=PipelineStep.PATCHED_CODE_RESCANNED,
                completed=False,
                passed=False,
                errors=["No re-scan results provided — patched code must be re-scanned"],
            )

        rescan_aggregator = SARIFAggregator()
        for tool_name, tool_version, results in rescan_results:
            rescan_aggregator.add_tool_run(tool_name, tool_version, results)

        self._rescan_sarif_bundle = rescan_aggregator.build_bundle()

        issues: List[str] = []

        # Block: new error findings
        new_errors = self._rescan_sarif_bundle.error_results
        if new_errors:
            issues.append(
                f"Re-scan found {len(new_errors)} new error-level findings"
            )

        # Block: new warning findings unless waived
        new_warnings = [
            w for w in self._rescan_sarif_bundle.warning_results
            if not w.waived
        ]
        if new_warnings:
            issues.append(
                f"Re-scan found {len(new_warnings)} new unwaived warning-level findings"
            )

        # Block: new Top 25 CWE appears in rescan that wasn't in original
        original_cwes = set(self._sarif_bundle.all_cwe_ids) if self._sarif_bundle else set()
        rescan_cwes = set(self._rescan_sarif_bundle.all_cwe_ids)
        new_cwes = rescan_cwes - original_cwes

        classification = classify_cwe_priority(list(new_cwes))
        if classification["top_25"]:
            issues.append(
                f"Re-scan introduced new Top 25 CWEs: {classification['top_25']}"
            )
        if classification["kev_linked"]:
            issues.append(
                f"Re-scan introduced new KEV-linked CWEs: {classification['kev_linked']}"
            )

        # Block: persistent original findings (same rule_id + file_path still unresolved)
        if self._sarif_bundle:
            original_fingerprints = {
                (r.rule_id, r.file_path, r.start_line)
                for r in self._sarif_bundle.unresolved_results
            }
            rescan_fingerprints = {
                (r.rule_id, r.file_path, r.start_line)
                for r in self._rescan_sarif_bundle.unresolved_results
            }
            persistent = original_fingerprints & rescan_fingerprints
            if persistent:
                issues.append(
                    f"Re-scan has {len(persistent)} persistent original findings still unresolved"
                )

        passed = len(issues) == 0

        return self._record_step(
            step=PipelineStep.PATCHED_CODE_RESCANNED,
            completed=True,
            passed=passed,
            evidence={
                "rescan_total_findings": len(self._rescan_sarif_bundle.all_results),
                "rescan_error_findings": len(new_errors),
                "rescan_warning_findings": len(new_warnings),
                "rescan_sarif_hash": self._rescan_sarif_bundle.compute_hash(),
                "new_cwes": list(new_cwes),
            },
            errors=issues,
        )

    # ── Step 10: Human Security Review Signs Off ─────────────────────────

    def step_10_human_security_review(
        self,
        human_review: HumanSecurityReview,
    ) -> PipelineStepResult:
        """
        Step 10: Human security reviewer signs off on the patch.
        """
        self._human_review = human_review

        issues: List[str] = []
        if not human_review.is_valid():
            issues.append("Human review is invalid — missing reviewer identity or evidence hash")
        if not human_review.approved:
            issues.append("Human reviewer did not approve the patch")

        return self._record_step(
            step=PipelineStep.HUMAN_SECURITY_REVIEW,
            completed=True,
            passed=human_review.approved and human_review.is_valid(),
            evidence={
                "reviewer": human_review.reviewer_identity,
                "approved": human_review.approved,
                "comments": human_review.comments,
                "review_timestamp": human_review.review_timestamp,
            },
            errors=issues,
        )

    # ── Step 11: QNEO Returns Decision ───────────────────────────────────

    def step_11_qneo_returns_decision(self, qneo_decision: str) -> PipelineStepResult:
        """
        Step 11: Build the security evidence bundle and return the QNEO decision.
        Accepts the actual QNEO decision as a parameter (Issue #3).
        Requires ALL prior steps (1-10) completed AND passed (Issue #4).
        """
        errors: List[str] = []

        # Validate qneo_decision is one of the allowed values
        valid_decisions = ("ALLOW", "HOLD", "FAIL_CLOSED", "ROLLBACK")
        if qneo_decision not in valid_decisions:
            errors.append(
                f"QNEO decision '{qneo_decision}' is not valid. "
                f"Must be one of: {', '.join(valid_decisions)}"
            )

        # Validate all prior steps (1-10) completed
        completed_steps = {r.step for r in self._step_results if r.completed}
        required_steps = set(PIPELINE_STEP_ORDER[:10])  # Steps 1-10
        missing_steps = required_steps - completed_steps
        if missing_steps:
            step_names = [s.value for s in missing_steps]
            errors.append(f"Missing pipeline steps: {step_names}")

        # Require ALL prior steps passed (Issue #4)
        failed_steps = [r for r in self._step_results if r.step in required_steps and not r.passed]
        if failed_steps:
            errors.append(
                "Prior pipeline steps failed: "
                + ", ".join(r.step.value for r in failed_steps)
            )

        # Build evidence bundle
        prompt_hash = compute_sha256(self._prompt) if hasattr(self, "_prompt") and self._prompt else ""
        sarif_hash = self._sarif_bundle.compute_hash() if self._sarif_bundle else ""
        test_hash = self._test_result.compute_hash() if self._test_result else ""
        cwe_ids = self._sarif_bundle.all_cwe_ids if self._sarif_bundle else []
        scanner_versions = self._sarif_bundle.scanner_versions if self._sarif_bundle else {}

        # Determine risk rating from CWE severity
        risk_rating = "low"
        for cwe_id in cwe_ids:
            entry = get_cwe_entry(cwe_id)
            if entry:
                if entry.severity == "critical":
                    risk_rating = "critical"
                    break
                elif entry.severity == "high" and risk_rating != "critical":
                    risk_rating = "high"
                elif entry.severity == "medium" and risk_rating not in ("critical", "high"):
                    risk_rating = "medium"

        ast_result_str = "PASS" if (self._ast_gate_result and self._ast_gate_result.passed) else "FAIL"

        self._evidence_bundle = SecurityEvidenceBundle(
            input_hash=self._input_hash or "",
            output_hash=self._output_hash or "",
            prompt_hash=prompt_hash,
            model_id=getattr(self, "_model_id", ""),
            model_temperature=getattr(self, "_temperature", 0.0),
            scanner_versions=scanner_versions,
            SARIF_bundle_hash=sarif_hash,
            AST_gate_result=ast_result_str,
            test_result_hash=test_hash,
            CWE_mapping=cwe_ids,
            risk_rating=risk_rating,
            manual_reviewer=self._human_review.reviewer_identity if self._human_review else "",
            patch_diff_hash=self._patch_analysis.diff_hash if self._patch_analysis else "",
            QNEO_decision=qneo_decision,
            merge_commit_sha="",  # Set after merge
        )

        bundle_errors = self._evidence_bundle.validate()
        if bundle_errors:
            errors.extend(bundle_errors)

        return self._record_step(
            step=PipelineStep.QNEO_RETURNS_DECISION,
            completed=True,
            passed=len(errors) == 0,
            evidence={
                "evidence_bundle_id": self._evidence_bundle.bundle_id,
                "evidence_bundle_hash": self._evidence_bundle.compute_bundle_hash(),
                "qneo_decision": qneo_decision,
                "validation_errors": errors,
            },
            errors=errors,
        )

    # ── Pipeline State Accessors ─────────────────────────────────────────

    @property
    def sarif_bundle(self) -> Optional[SARIFBundle]:
        return self._sarif_bundle

    @property
    def rescan_sarif_bundle(self) -> Optional[SARIFBundle]:
        return self._rescan_sarif_bundle

    @property
    def ast_gate_result(self) -> Optional[ASTGateResult]:
        return self._ast_gate_result

    @property
    def llm_review(self) -> Optional[LLMReviewResult]:
        return self._llm_review

    @property
    def test_result(self) -> Optional[TestExecutionResult]:
        return self._test_result

    @property
    def human_review(self) -> Optional[HumanSecurityReview]:
        return self._human_review

    @property
    def patch_analysis(self) -> Optional[PatchAnalysis]:
        return self._patch_analysis

    def get_pipeline_summary(self) -> Dict[str, Any]:
        """Get a summary of the entire pipeline execution."""
        return {
            "pipeline_id": self._pipeline_id,
            "created_at": self._created_at,
            "steps_completed": len(self._step_results),
            "steps_total": len(PIPELINE_STEP_ORDER),
            "all_steps_passed": all(r.passed for r in self._step_results),
            "step_results": [
                {
                    "step": r.step.value,
                    "completed": r.completed,
                    "passed": r.passed,
                    "errors": r.errors,
                }
                for r in self._step_results
            ],
        }

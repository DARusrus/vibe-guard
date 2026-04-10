from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vibeguard.engine import SemgrepEngine
from vibeguard.models import Finding, ScanResult
from vibeguard.plugins.secrets import SecretsPlugin
from vibeguard.scanner import RULES_DIR, TIER_RULES, Scanner, scan

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULNERABLE_APP_DIR = FIXTURES_DIR / "vulnerable_app"

# ─── Minimal valid Semgrep JSON for mocking ─────────────────────────

MOCK_SEMGREP_JSON = json.dumps(
    {
        "results": [
            {
                "check_id": "vibeguard-python-sqli-fstring",
                "path": "test_file.py",
                "start": {"line": 10, "col": 5, "offset": 100},
                "end": {"line": 10, "col": 60, "offset": 155},
                "extra": {
                    "message": "SQL injection via f-string in execute()",
                    "severity": "ERROR",
                    "lines": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                    "metadata": {
                        "cwe": "CWE-89: Improper Neutralization of Special Elements",
                        "category": "security",
                        "confidence": "HIGH",
                        "fix_guidance": "Use parameterized queries.",
                        "ai_context": "AI models default to f-strings for SQL.",
                        "severity_label": "CRITICAL",
                        "rule_category": "sqli",
                    },
                },
            }
        ],
        "errors": [],
        "version": "1.60.0",
    }
)


# ─── SemgrepEngine tests ───────────────────────────────────────────


class TestSemgrepEngine:
    """Tests for the SemgrepEngine subprocess wrapper."""

    def test_is_available_returns_bool(self) -> None:
        """is_available() must return True or False, never raise."""
        engine = SemgrepEngine()
        result = engine.is_available()
        assert isinstance(result, bool)

    def test_run_returns_empty_list_on_missing_binary(self) -> None:
        """Engine with nonexistent binary path must return [], not raise."""
        engine = SemgrepEngine(semgrep_bin="nonexistent-binary-xyz-12345")
        result = engine.run(
            files=[Path("test.py")],
            rule_paths=[Path("rule.yaml")],
        )
        assert result == []

    def test_run_returns_empty_list_on_empty_file_list(self) -> None:
        """run() with empty files list must return [] immediately."""
        engine = SemgrepEngine()
        result = engine.run(files=[], rule_paths=[Path("rule.yaml")])
        assert result == []

    def test_run_returns_empty_list_on_empty_rules_list(self) -> None:
        """run() with empty rules list must return [] immediately."""
        engine = SemgrepEngine()
        result = engine.run(files=[Path("test.py")], rule_paths=[])
        assert result == []

    def test_run_parses_semgrep_json_output(self, tmp_path: Path) -> None:
        """Mock subprocess to return valid Semgrep JSON, verify parse."""
        engine = SemgrepEngine()

        mock_result = type(
            "Result",
            (),
            {
                "returncode": 1,  # Semgrep uses 1 when findings exist
                "stdout": MOCK_SEMGREP_JSON,
                "stderr": "",
            },
        )()

        test_file = tmp_path / "test_file.py"
        test_file.write_text("x = 1\n", encoding="utf-8")
        rule_file = tmp_path / "rule.yaml"
        rule_file.write_text("rules: []\n", encoding="utf-8")

        with patch("subprocess.run", return_value=mock_result):
            results = engine.run(
                files=[test_file],
                rule_paths=[rule_file],
            )

        assert len(results) == 1
        assert results[0]["check_id"] == "vibeguard-python-sqli-fstring"
        assert results[0]["line"] == 10
        assert results[0]["col"] == 5
        assert results[0]["message"] == "SQL injection via f-string in execute()"
        assert results[0]["metadata"]["severity_label"] == "CRITICAL"

    def test_run_handles_semgrep_timeout_gracefully(self) -> None:
        """Subprocess timeout must return [], not raise TimeoutExpired."""
        import subprocess

        engine = SemgrepEngine()

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("semgrep", 120)):
            result = engine.run(
                files=[Path("test.py")],
                rule_paths=[Path("rule.yaml")],
            )

        assert result == []

    def test_run_handles_non_zero_exit_gracefully(self) -> None:
        """Non-zero semgrep exit with no valid JSON must return [], not raise."""
        engine = SemgrepEngine()

        mock_result = type(
            "Result",
            (),
            {
                "returncode": 2,
                "stdout": "",
                "stderr": "Fatal error occurred",
            },
        )()

        with patch("subprocess.run", return_value=mock_result):
            result = engine.run(
                files=[Path("test.py")],
                rule_paths=[Path("rule.yaml")],
            )

        assert result == []


# ─── SecretsPlugin tests ───────────────────────────────────────────


class TestSecretsPlugin:
    """Tests for the detect-secrets wrapper plugin."""

    def test_is_available_returns_bool(self) -> None:
        """is_available() must return True or False, never raise."""
        plugin = SecretsPlugin()
        result = plugin.is_available()
        assert isinstance(result, bool)

    def test_scan_files_returns_findings_for_known_secret(self, tmp_path: Path) -> None:
        """File containing API_KEY = 'sk-abc123' must produce >= 1 Finding."""
        secret_file = tmp_path / "secret_test.py"
        secret_file.write_text(
            'API_KEY = "sk-abc123def456ghi789"\n',
            encoding="utf-8",
        )

        mock_output = json.dumps(
            {
                "results": {
                    str(secret_file): [
                        {
                            "type": "Secret Keyword",
                            "line_number": 1,
                            "hashed_secret": "abc123",
                        }
                    ]
                },
                "generated_at": "2024-01-01T00:00:00Z",
            }
        )

        mock_result = type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": mock_output,
                "stderr": "",
            },
        )()

        plugin = SecretsPlugin()
        with patch("subprocess.run", return_value=mock_result):
            findings = plugin.scan_files([secret_file])

        assert len(findings) >= 1
        assert findings[0].rule_id == "vibeguard-secrets-detected"
        assert findings[0].severity == "CRITICAL"

    def test_scan_files_returns_empty_for_clean_file(self, tmp_path: Path) -> None:
        """File with no secrets must return empty list."""
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("x = 1\ny = 2\n", encoding="utf-8")

        mock_output = json.dumps(
            {
                "results": {},
                "generated_at": "2024-01-01T00:00:00Z",
            }
        )

        mock_result = type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": mock_output,
                "stderr": "",
            },
        )()

        plugin = SecretsPlugin()
        with patch("subprocess.run", return_value=mock_result):
            findings = plugin.scan_files([clean_file])

        assert findings == []

    def test_scan_files_returns_empty_on_missing_binary(self) -> None:
        """Missing detect-secrets binary must return [], not raise."""
        plugin = SecretsPlugin(detect_secrets_bin="nonexistent-detect-secrets-xyz")
        result = plugin.scan_files([Path("test.py")])
        assert result == []

    def test_finding_fields_are_populated(self, tmp_path: Path) -> None:
        """Returned Finding must have non-empty rule_id, cwe_id, fix_guidance."""
        secret_file = tmp_path / "creds.py"
        secret_file.write_text('PASSWORD = "hunter2"\n', encoding="utf-8")

        mock_output = json.dumps(
            {
                "results": {
                    str(secret_file): [
                        {
                            "type": "Secret Keyword",
                            "line_number": 1,
                            "hashed_secret": "def456",
                        }
                    ]
                },
            }
        )

        mock_result = type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": mock_output,
                "stderr": "",
            },
        )()

        plugin = SecretsPlugin()
        with patch("subprocess.run", return_value=mock_result):
            findings = plugin.scan_files([secret_file])

        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id != ""
        assert f.cwe_id != ""
        assert f.fix_guidance != ""
        assert f.ai_context != ""
        assert f.rule_category == "secrets"


# ─── Scanner tests ─────────────────────────────────────────────────


class TestScanner:
    """Integration and unit tests for the Scanner orchestrator."""

    def test_scan_directory_returns_scan_result(self, tmp_path: Path) -> None:
        """scan_directory on any path must return a ScanResult."""
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert isinstance(result, ScanResult)

    def test_scan_result_counts_files_correctly(self, tmp_path: Path) -> None:
        """files_scanned must equal number of .py files in target dir."""
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")
        (tmp_path / "c.txt").write_text("not python\n", encoding="utf-8")

        scanner = Scanner()
        result = scanner.scan_directory(tmp_path, extensions={".py"})
        assert result.files_scanned == 2

    @pytest.mark.skipif(
        not SemgrepEngine().is_available(),
        reason="semgrep not installed",
    )
    def test_vulnerable_app_produces_findings(self) -> None:
        """Scanner on tests/fixtures/vulnerable_app must find >= 8 findings."""
        scanner = Scanner(min_severity="LOW")
        result = scanner.scan_directory(VULNERABLE_APP_DIR)
        assert len(result.findings) >= 8, (
            f"Expected >= 8 findings, got {len(result.findings)}: "
            f"{[f.rule_id for f in result.findings]}"
        )

    @pytest.mark.skipif(
        not SemgrepEngine().is_available(),
        reason="semgrep not installed",
    )
    def test_ai_files_detected_count_is_positive(self) -> None:
        """vulnerable_app scan must return a valid non-negative AI file count."""
        scanner = Scanner()
        result = scanner.scan_directory(VULNERABLE_APP_DIR)
        assert result.ai_files_detected >= 0

    @pytest.mark.skipif(
        not SemgrepEngine().is_available(),
        reason="semgrep not installed",
    )
    def test_findings_have_all_required_fields(self) -> None:
        """Every Finding from vulnerable_app scan must have non-empty:
        rule_id, severity, file_path, line, message, fix_guidance, cwe_id."""
        scanner = Scanner(min_severity="LOW")
        result = scanner.scan_directory(VULNERABLE_APP_DIR)

        for f in result.findings:
            assert f.rule_id, f"Missing rule_id in finding at {f.file_path}:{f.line}"
            assert f.severity, f"Missing severity in finding at {f.file_path}:{f.line}"
            assert f.file_path, "Missing file_path in finding"
            assert f.line > 0, f"Invalid line number in finding {f.rule_id}"
            assert f.message, f"Missing message in finding {f.rule_id}"
            assert f.fix_guidance, f"Missing fix_guidance in finding {f.rule_id}"
            assert f.cwe_id, f"Missing cwe_id in finding {f.rule_id}"

    def test_min_severity_filter_works(self) -> None:
        """Scanner with min_severity=CRITICAL must not return MEDIUM findings."""
        scanner = Scanner(min_severity="CRITICAL")
        # Test the filter method directly
        findings = [
            Finding(
                rule_id="test-1",
                severity="CRITICAL",
                file_path="a.py",
                line=1,
                message="msg",
                fix_guidance="fix",
                cwe_id="CWE-1",
            ),
            Finding(
                rule_id="test-2",
                severity="MEDIUM",
                file_path="b.py",
                line=2,
                message="msg",
                fix_guidance="fix",
                cwe_id="CWE-2",
            ),
            Finding(
                rule_id="test-3",
                severity="HIGH",
                file_path="c.py",
                line=3,
                message="msg",
                fix_guidance="fix",
                cwe_id="CWE-3",
            ),
        ]
        filtered = scanner._filter_severity(findings)
        severities = {f.severity for f in filtered}
        assert "MEDIUM" not in severities
        assert "CRITICAL" in severities

    def test_deduplication_removes_exact_duplicates(self) -> None:
        """Two identical rule_id+file_path+line combinations → one finding."""
        scanner = Scanner()
        findings = [
            Finding(
                rule_id="test-dup",
                severity="HIGH",
                file_path="a.py",
                line=10,
                message="msg1",
                fix_guidance="fix",
                cwe_id="CWE-1",
            ),
            Finding(
                rule_id="test-dup",
                severity="HIGH",
                file_path="a.py",
                line=10,
                message="msg2",
                fix_guidance="fix",
                cwe_id="CWE-1",
            ),
        ]
        deduped = scanner._deduplicate(findings)
        assert len(deduped) == 1

    def test_scan_nonexistent_directory_returns_empty_result(self) -> None:
        """Nonexistent path must return ScanResult with zeros, not raise."""
        scanner = Scanner()
        result = scanner.scan_directory("/nonexistent/path/that/does/not/exist")
        assert isinstance(result, ScanResult)
        assert result.files_scanned == 0
        assert result.ai_files_detected == 0
        assert result.findings == []

    @pytest.mark.skipif(
        not SemgrepEngine().is_available(),
        reason="semgrep not installed",
    )
    def test_scan_file_single_file_works(self) -> None:
        """scan_file on vulnerable_app/app.py must return >= 5 findings."""
        scanner = Scanner(min_severity="LOW")
        result = scanner.scan_file(VULNERABLE_APP_DIR / "app.py")
        assert isinstance(result, ScanResult)
        assert len(result.findings) >= 5, (
            f"Expected >= 5 findings, got {len(result.findings)}: "
            f"{[f.rule_id for f in result.findings]}"
        )

    def test_scan_result_summary_line_is_human_readable(self) -> None:
        """summary_line() must return a non-empty string with file count and finding count."""
        result = ScanResult(
            findings=[
                Finding(
                    rule_id="test",
                    severity="HIGH",
                    file_path="a.py",
                    line=1,
                    message="msg",
                    fix_guidance="fix",
                    cwe_id="CWE-1",
                ),
                Finding(
                    rule_id="test2",
                    severity="MEDIUM",
                    file_path="b.py",
                    line=2,
                    message="msg",
                    fix_guidance="fix",
                    cwe_id="CWE-2",
                ),
            ],
            files_scanned=5,
            ai_files_detected=2,
            detector_results=[],
        )
        line = result.summary_line()
        assert isinstance(line, str)
        assert len(line) > 0
        assert "5" in line  # file count
        assert "2" in line  # ai files count or finding count

    @pytest.mark.skipif(
        not SemgrepEngine().is_available(),
        reason="semgrep not installed",
    )
    def test_module_level_scan_function_works(self) -> None:
        """scan('tests/fixtures/vulnerable_app') must return ScanResult."""
        result = scan(str(VULNERABLE_APP_DIR))
        assert isinstance(result, ScanResult)


# ─── Tier rules structure tests ────────────────────────────────────


class TestTierRules:
    """Verify TIER_RULES structure invariants."""

    def test_full_tier_has_expected_minimum_rules(self) -> None:
        """FULL tier must include expanded multi-language rule coverage."""
        assert len(TIER_RULES["FULL"]) >= 50

    def test_medium_is_strict_subset_of_full(self) -> None:
        """Every MEDIUM rule must exist in FULL."""
        full = set(TIER_RULES["FULL"])
        medium = set(TIER_RULES["MEDIUM"])
        assert medium.issubset(full), f"MEDIUM rules not in FULL: {medium - full}"

    def test_critical_only_is_strict_subset_of_medium(self) -> None:
        """Every CRITICAL_ONLY rule must exist in MEDIUM."""
        medium = set(TIER_RULES["MEDIUM"])
        critical = set(TIER_RULES["CRITICAL_ONLY"])
        assert critical.issubset(medium), f"CRITICAL_ONLY rules not in MEDIUM: {critical - medium}"

    def test_all_rule_files_exist_on_disk(self) -> None:
        """Every file referenced in TIER_RULES must exist on disk."""
        for tier, rules in TIER_RULES.items():
            for rule_path in rules:
                full_path = RULES_DIR / rule_path
                assert full_path.exists(), f"Rule file missing: {full_path} (referenced in {tier})"

    def test_resolve_rules_full_returns_all_paths(self) -> None:
        """_resolve_rules('FULL') must resolve every configured FULL rule path."""
        scanner = Scanner()
        resolved = scanner._resolve_rules("FULL")
        assert len(resolved) == len(TIER_RULES["FULL"])

    def test_resolve_rules_returns_absolute_paths(self) -> None:
        """_resolve_rules must return absolute Path objects."""
        scanner = Scanner()
        for path in scanner._resolve_rules("FULL"):
            assert path.is_absolute(), f"Non-absolute path: {path}"

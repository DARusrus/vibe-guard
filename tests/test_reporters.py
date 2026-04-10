from __future__ import annotations

import json

import pytest

from vibeguard.models import DetectorResult, Finding, ScanResult
from vibeguard.reporters import get_reporter


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        rule_id="vibeguard-python-sqli-fstring",
        severity="CRITICAL",
        file_path="app.py",
        line=42,
        col=8,
        message="SQL injection via f-string in execute() call.",
        fix_guidance="Use parameterized queries.",
        cwe_id="CWE-89",
        ai_context="AI models use f-strings for SQL by default.",
        file_confidence=0.82,
        rule_category="sqli",
        snippet='    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        semgrep_rule_id="vibeguard-python-sqli-fstring",
    )


@pytest.fixture
def sample_result(sample_finding: Finding) -> ScanResult:
    dr = DetectorResult(
        file_path="app.py",
        confidence=0.82,
        scan_tier="FULL",
        signals={"comments": 0.7, "structure": 0.8, "tokens": 0.9},
    )
    return ScanResult(
        findings=[sample_finding],
        files_scanned=3,
        ai_files_detected=1,
        detector_results=[dr],
        scan_duration_seconds=1.23,
        rules_applied=10,
    )


class TestTerminalReporter:
    def test_render_returns_string(self, sample_result: ScanResult) -> None:
        reporter = get_reporter("terminal")
        out = reporter.render(sample_result)
        assert isinstance(out, str)
        assert len(out) > 0

    def test_render_contains_rule_id(self, sample_result: ScanResult) -> None:
        out = get_reporter("terminal").render(sample_result)
        assert "vibeguard-python-sqli-fstring" in out

    def test_render_contains_severity(self, sample_result: ScanResult) -> None:
        out = get_reporter("terminal").render(sample_result)
        assert "CRITICAL" in out

    def test_render_empty_result_shows_no_findings_message(self) -> None:
        empty = ScanResult(
            findings=[],
            files_scanned=2,
            ai_files_detected=0,
            detector_results=[],
            scan_duration_seconds=0.1,
            rules_applied=5,
        )
        out = get_reporter("terminal").render(empty)
        assert "No findings" in out or "clean" in out.lower()


class TestSarifReporter:
    def test_render_is_valid_json(self, sample_result: ScanResult) -> None:
        out = get_reporter("sarif").render(sample_result)
        data = json.loads(out)
        assert data is not None

    def test_sarif_version_is_correct(self, sample_result: ScanResult) -> None:
        data = json.loads(get_reporter("sarif").render(sample_result))
        assert data["version"] == "2.1.0"

    def test_sarif_contains_runs(self, sample_result: ScanResult) -> None:
        data = json.loads(get_reporter("sarif").render(sample_result))
        assert len(data["runs"]) == 1

    def test_sarif_tool_name_is_vibe_guard(self, sample_result: ScanResult) -> None:
        data = json.loads(get_reporter("sarif").render(sample_result))
        assert data["runs"][0]["tool"]["driver"]["name"] == "vibe-guard"

    def test_sarif_results_count_matches_findings(self, sample_result: ScanResult) -> None:
        data = json.loads(get_reporter("sarif").render(sample_result))
        assert len(data["runs"][0]["results"]) == 1

    def test_sarif_level_for_critical_is_error(self, sample_result: ScanResult) -> None:
        data = json.loads(get_reporter("sarif").render(sample_result))
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_empty_result_has_no_results(self) -> None:
        empty = ScanResult(
            findings=[],
            files_scanned=0,
            ai_files_detected=0,
            detector_results=[],
            scan_duration_seconds=0.0,
            rules_applied=0,
        )
        data = json.loads(get_reporter("sarif").render(empty))
        assert data["runs"][0]["results"] == []


class TestJsonReporter:
    def test_render_is_valid_json(self, sample_result: ScanResult) -> None:
        out = get_reporter("json").render(sample_result)
        data = json.loads(out)
        assert data is not None

    def test_json_has_required_top_level_keys(self, sample_result: ScanResult) -> None:
        data = json.loads(get_reporter("json").render(sample_result))
        for key in ("vibe_guard_version", "scan_timestamp", "summary", "findings", "detector_results"):
            assert key in data

    def test_json_summary_counts_are_correct(self, sample_result: ScanResult) -> None:
        data = json.loads(get_reporter("json").render(sample_result))
        assert data["summary"]["files_scanned"] == 3
        assert data["summary"]["total_findings"] == 1
        assert data["summary"]["ai_files_detected"] == 1

    def test_json_finding_has_all_fields(self, sample_result: ScanResult) -> None:
        data = json.loads(get_reporter("json").render(sample_result))
        finding = data["findings"][0]
        for field in (
            "rule_id",
            "severity",
            "file_path",
            "line",
            "col",
            "message",
            "fix_guidance",
            "cwe_id",
            "ai_context",
            "file_confidence",
            "rule_category",
        ):
            assert field in finding

    def test_get_reporter_raises_on_unknown_format(self) -> None:
        with pytest.raises(ValueError, match="Unknown format"):
            get_reporter("xml")

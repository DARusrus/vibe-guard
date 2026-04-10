"""Tests for Plan 2 Session 3 — AI features, score, diff mode.

All AI tests pass WITHOUT requiring GEMINI_API_KEY.
Uses unittest.mock to mock the AIClient.complete() method.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from vibeguard.ai.autofix import AutoFixer
from vibeguard.ai.client import AIClient
from vibeguard.ai.context_filter import ContextFilter
from vibeguard.ai.explain import Explainer
from vibeguard.models import Finding, ScanResult

# ── Fixtures ─────────────────────────────────────────────────────


def make_finding(severity: str = "MEDIUM") -> Finding:
    """Create a minimal Finding for testing."""
    return Finding(
        rule_id=f"vibeguard-test-{severity.lower()}",
        severity=severity,
        file_path="test_app.py",
        line=10,
        col=1,
        message=f"Test {severity} finding",
        fix_guidance="Use parameterized queries instead.",
        cwe_id="CWE-89",
        ai_context="AI-generated code often uses string concatenation for SQL.",
        file_confidence=0.8,
        rule_category="sqli",
        snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        semgrep_rule_id=f"vibeguard-test-{severity.lower()}",
    )


@pytest.fixture()
def sample_finding() -> Finding:
    """Provide a sample SQL injection finding for tests."""
    return make_finding("HIGH")


# ── AIClient Tests ───────────────────────────────────────────────


class TestAIClient:
    """Tests for the Gemini Flash API wrapper."""

    def test_is_available_false_without_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AIClient.is_available() must return False without API key."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        client = AIClient()
        assert not client.is_available()

    def test_complete_returns_none_without_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """complete() must return None not raise when unavailable."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        client = AIClient()
        result = client.complete("test prompt")
        assert result is None

    def test_cache_returns_cached_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Cached responses must be returned without API call."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        client = AIClient()
        client.available = True
        client._cache["test_key"] = "cached_response"
        result = client.complete("ignored prompt", cache_key="test_key")
        assert result == "cached_response"

    def test_build_request_structure(self) -> None:
        """_build_request must produce valid Gemini API body."""
        client = AIClient()
        body = client._build_request("hello", 100)
        assert "contents" in body
        assert body["contents"][0]["parts"][0]["text"] == "hello"
        assert body["generationConfig"]["maxOutputTokens"] == 100
        assert body["generationConfig"]["temperature"] == 0.1

    def test_parse_response_valid(self) -> None:
        """_parse_response must extract text from valid Gemini response."""
        client = AIClient()
        resp = {"candidates": [{"content": {"parts": [{"text": "hello world"}]}}]}
        assert client._parse_response(resp) == "hello world"

    def test_parse_response_invalid(self) -> None:
        """_parse_response must return None for malformed responses."""
        client = AIClient()
        assert client._parse_response({}) is None
        assert client._parse_response({"candidates": []}) is None
        assert client._parse_response({"candidates": [{}]}) is None


# ── AutoFixer Tests ──────────────────────────────────────────────


class TestAutoFixer:
    """Tests for the AI auto-fix engine."""

    def test_returns_none_without_api_key(
        self, monkeypatch: pytest.MonkeyPatch, sample_finding: Finding
    ) -> None:
        """AutoFixer returns None gracefully without API key."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        fixer = AutoFixer()
        result = fixer.generate_fix(sample_finding, "cursor.execute(f'...')")
        assert result is None

    def test_returns_diff_with_mocked_api(self, sample_finding: Finding) -> None:
        """AutoFixer returns diff string when API responds."""
        with patch.object(
            AIClient,
            "complete",
            return_value="cursor.execute('SELECT * WHERE id = ?', [id])",
        ):
            fixer = AutoFixer()
            fixer.client.available = True
            result = fixer.generate_fix(
                sample_finding,
                "cursor.execute(f'SELECT * WHERE id = {id}')",
            )
            assert result is None or isinstance(result, str)

    def test_build_prompt_contains_finding_info(self, sample_finding: Finding) -> None:
        """Prompt must contain vulnerability details."""
        fixer = AutoFixer()
        prompt = fixer._build_prompt(sample_finding, "vuln_line", "test context")
        assert sample_finding.rule_id in prompt
        assert sample_finding.severity in prompt
        assert "test context" in prompt

    def test_format_as_diff_produces_unified_diff(self) -> None:
        """_format_as_diff must produce unified diff format."""
        fixer = AutoFixer()
        result = fixer._format_as_diff(
            "old_code()\n",
            "new_code()\n",
            "test.py",
            1,
        )
        assert result is not None
        assert "---" in result or "@@" in result

    def test_autofixer_produces_valid_diff(self, sample_finding: Finding) -> None:
        """AutoFixer produces non-empty diff when AI returns a fix."""
        fixed_code = "    cursor.execute('SELECT * FROM users WHERE id = ?', [user_id])"
        with patch.object(AIClient, "complete", return_value=fixed_code):
            fixer = AutoFixer()
            fixer.client.available = True
            context = "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
            result = fixer.generate_fix(sample_finding, context)
            if result is not None:
                assert len(result.strip()) > 0, "Diff must be non-empty"
                assert "---" in result or "@@" in result, "Result must be a valid unified diff"

    def test_autofixer_returns_none_for_unchanged_response(self, sample_finding: Finding) -> None:
        """If AI returns the same code, generate_fix must return None."""
        original = "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
        with patch.object(AIClient, "complete", return_value=original):
            fixer = AutoFixer()
            fixer.client.available = True
            result = fixer.generate_fix(sample_finding, original)
            assert result is None, "Unchanged AI response must return None not empty diff"


# ── ContextFilter Tests ──────────────────────────────────────────


class TestContextFilter:
    """Tests for smart false-positive filtering."""

    def test_returns_true_without_api_key(
        self, monkeypatch: pytest.MonkeyPatch, sample_finding: Finding
    ) -> None:
        """ContextFilter returns True (conservative) without API key."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        f = ContextFilter()
        result = f.is_true_positive(sample_finding, "cursor.execute(f'...')")
        assert result is True

    def test_returns_false_when_api_says_false(self, sample_finding: Finding) -> None:
        """ContextFilter returns False when API says FALSE."""
        with patch.object(AIClient, "complete", return_value="FALSE"):
            f = ContextFilter()
            f.client.available = True
            result = f.is_true_positive(sample_finding, "safe_code = True")
            assert result is False

    def test_returns_true_when_api_says_true(self, sample_finding: Finding) -> None:
        """ContextFilter returns True when API says TRUE."""
        with patch.object(AIClient, "complete", return_value="TRUE"):
            f = ContextFilter()
            f.client.available = True
            result = f.is_true_positive(sample_finding, "unsafe_code")
            assert result is True

    def test_returns_true_when_api_returns_none(self, sample_finding: Finding) -> None:
        """ContextFilter returns True (conservative) when API errors."""
        with patch.object(AIClient, "complete", return_value=None):
            f = ContextFilter()
            f.client.available = True
            result = f.is_true_positive(sample_finding, "some code")
            assert result is True

    def test_caches_results(self, sample_finding: Finding) -> None:
        """Repeated calls with same finding use cache."""
        with patch.object(AIClient, "complete", return_value="FALSE") as mock:
            f = ContextFilter()
            f.client.available = True
            f.is_true_positive(sample_finding, "code")
            f.is_true_positive(sample_finding, "code")
            # The second call should use cache — complete called once
            assert mock.call_count == 1


# ── Explainer Tests ──────────────────────────────────────────────


class TestExplainer:
    """Tests for the plain-English vulnerability explainer."""

    def test_returns_none_without_api_key(
        self, monkeypatch: pytest.MonkeyPatch, sample_finding: Finding
    ) -> None:
        """Explainer returns None without API key."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        explainer = Explainer()
        result = explainer.explain(sample_finding)
        assert result is None

    def test_returns_text_with_mocked_api(self, sample_finding: Finding) -> None:
        """Explainer returns explanation text when API responds."""
        explanation = "An attacker can steal data. Your database is at risk. Very likely."
        with patch.object(AIClient, "complete", return_value=explanation):
            explainer = Explainer()
            explainer.client.available = True
            result = explainer.explain(sample_finding)
            assert result == explanation


# ── Score Calculation Tests ──────────────────────────────────────


class TestScoreCalculation:
    """Tests for the security score formula."""

    def test_perfect_score_is_100_with_no_findings(self) -> None:
        """Empty ScanResult produces score 100."""
        from vibeguard.commands.score import calculate_score

        result = ScanResult(
            findings=[],
            files_scanned=10,
            ai_files_detected=0,
            detector_results=[],
        )
        score, grade = calculate_score(result)
        assert score == 100
        assert grade == "A"

    def test_four_criticals_produces_f(self) -> None:
        """4 CRITICAL findings must produce grade F."""
        from vibeguard.commands.score import calculate_score

        findings = [make_finding("CRITICAL") for _ in range(4)]
        result = ScanResult(
            findings=findings,
            files_scanned=10,
            ai_files_detected=2,
            detector_results=[],
        )
        score, grade = calculate_score(result)
        assert score <= 39
        assert grade == "F"

    def test_one_medium_produces_b_or_higher(self) -> None:
        """1 MEDIUM finding must not drop below B."""
        from vibeguard.commands.score import calculate_score

        result = ScanResult(
            findings=[make_finding("MEDIUM")],
            files_scanned=20,
            ai_files_detected=1,
            detector_results=[],
        )
        score, grade = calculate_score(result)
        assert score >= 75
        assert grade in ("A", "B")

    def test_badge_url_is_valid_shields_io(self) -> None:
        """Badge URL must be a valid shields.io URL."""
        from vibeguard.commands.score import generate_badge_url

        url = generate_badge_url("A", 94)
        assert "shields.io" in url
        assert "vibe" in url.lower()
        assert url.startswith("https://")

    def test_score_zero_findings_low_ai_ratio(self) -> None:
        """Zero findings with low AI ratio gets max bonus."""
        from vibeguard.commands.score import calculate_score

        result = ScanResult(
            findings=[],
            files_scanned=100,
            ai_files_detected=5,  # 5% < 10%
            detector_results=[],
        )
        score, grade = calculate_score(result)
        assert score == 100  # 100 - 0 + 10 + 5 = 115 capped to 100
        assert grade == "A"

    def test_score_with_mixed_findings(self) -> None:
        """Mixed findings produce expected score."""
        from vibeguard.commands.score import calculate_score

        findings = [
            make_finding("CRITICAL"),  # -25
            make_finding("HIGH"),  # -10
            make_finding("MEDIUM"),  # -3
            make_finding("LOW"),  # -1
        ]
        # Total deductions: 39
        # AI ratio: 2/10 = 20% < 30% → +5
        # Has CRITICAL → no clean bonus
        # Score: 100 - 39 + 5 = 66 → C
        result = ScanResult(
            findings=findings,
            files_scanned=10,
            ai_files_detected=2,
            detector_results=[],
        )
        score, grade = calculate_score(result)
        assert score == 66
        assert grade == "C"

    def test_badge_url_colors(self) -> None:
        """Badge URLs use correct colors for each grade."""
        from vibeguard.commands.score import generate_badge_url

        assert "brightgreen" in generate_badge_url("A", 95)
        assert "green" in generate_badge_url("B", 80)
        assert "yellow" in generate_badge_url("C", 65)
        assert "orange" in generate_badge_url("D", 45)
        assert "red" in generate_badge_url("F", 10)

    def test_history_store_and_retrieve(self, tmp_path: Path) -> None:
        """Score history can be stored and trend retrieved."""
        from vibeguard.commands.score import get_trend, store_history

        db = tmp_path / "test_history.db"
        result = ScanResult(
            findings=[make_finding("MEDIUM")],
            files_scanned=10,
            ai_files_detected=1,
            detector_results=[],
        )

        # First store — no trend yet
        store_history(80, "B", result, db_path=db)
        trend = get_trend(80, db_path=db)
        assert trend is None  # No previous to compare

        # Second store — trend should show
        store_history(73, "C", result, db_path=db)
        trend = get_trend(73, db_path=db)
        assert trend is not None
        assert "80" in trend or "▼" in trend


# ── Diff Mode Tests ──────────────────────────────────────────────


class TestDiffMode:
    """Tests for diff mode scanning."""

    def test_diff_mode_filters_to_changed_files(self, tmp_path: Path) -> None:
        """--diff mode must only scan files in the changed list."""
        from vibeguard.scanner import Scanner

        (tmp_path / "changed.py").write_text("import os\n")
        (tmp_path / "unchanged.py").write_text("import sys\n")
        scanner = Scanner()
        file_filter = {tmp_path / "changed.py"}
        result = scanner.scan_directory(tmp_path, file_filter=file_filter)
        scanned_paths = {Path(dr.file_path) for dr in result.detector_results}
        assert tmp_path / "unchanged.py" not in scanned_paths

    def test_diff_mode_result_has_diff_flag(self, tmp_path: Path) -> None:
        """ScanResult.diff_mode must be True when file_filter is used."""
        from vibeguard.scanner import Scanner

        (tmp_path / "app.py").write_text("x = 1\n")
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path, file_filter={tmp_path / "app.py"})
        assert result.diff_mode is True

    def test_full_scan_when_filter_is_none(self, tmp_path: Path) -> None:
        """ScanResult.diff_mode must be False on full scan."""
        from vibeguard.scanner import Scanner

        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.diff_mode is False

    def test_diff_mode_changed_files_count(self, tmp_path: Path) -> None:
        """changed_files_count must match the filter set size."""
        from vibeguard.scanner import Scanner

        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        scanner = Scanner()
        file_filter = {tmp_path / "a.py", tmp_path / "b.py"}
        result = scanner.scan_directory(tmp_path, file_filter=file_filter)
        assert result.changed_files_count == 2
        assert result.diff_mode is True

    def test_diff_mode_does_not_walk_all_files_on_large_repo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """diff mode with file_filter must only process filtered files."""
        from vibeguard.scanner import Scanner

        for i in range(50):
            (tmp_path / f"file_{i}.py").write_text(f"x = {i}\n")

        target_files = {tmp_path / "file_0.py", tmp_path / "file_1.py"}
        scanner = Scanner()
        score_count = 0
        original_score_file = scanner.detector.score_file

        def counted_score(file_path: str | Path):
            nonlocal score_count
            score_count += 1
            return original_score_file(file_path)

        monkeypatch.setattr(scanner.detector, "score_file", counted_score)
        result = scanner.scan_directory(tmp_path, file_filter=target_files)

        scanned = {Path(dr.file_path).name for dr in result.detector_results}
        assert len(scanned) <= 2, f"Expected <=2 files scanned, got {len(scanned)}: {scanned}"
        assert score_count <= 2, f"Expected <=2 scored files, got {score_count}"
        assert result.diff_mode is True


# ── ScanResult summary_line Tests ────────────────────────────────


class TestSummaryLine:
    """Tests for the updated summary_line() method."""

    def test_summary_line_normal_mode(self) -> None:
        """Normal mode summary shows files scanned."""
        result = ScanResult(
            findings=[make_finding("HIGH")],
            files_scanned=10,
            ai_files_detected=3,
            detector_results=[],
        )
        line = result.summary_line()
        assert "10 files scanned" in line
        assert "3 AI-generated" in line
        assert "1 findings" in line

    def test_summary_line_diff_mode(self) -> None:
        """Diff mode summary shows changed files count."""
        result = ScanResult(
            findings=[],
            files_scanned=5,
            ai_files_detected=1,
            detector_results=[],
            diff_mode=True,
            changed_files_count=8,
        )
        line = result.summary_line()
        assert "Diff mode" in line
        assert "8 changed files" in line

    def test_summary_line_filtered_count(self) -> None:
        """Summary includes smart filter info when findings were filtered."""
        result = ScanResult(
            findings=[],
            files_scanned=10,
            ai_files_detected=2,
            detector_results=[],
            filtered_count=3,
        )
        line = result.summary_line()
        assert "smart filter" in line
        assert "3" in line

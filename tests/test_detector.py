from __future__ import annotations

from pathlib import Path

from vibeguard.detector import Detector, score
from vibeguard.signals.comments import CommentsSignal
from vibeguard.signals.structure import StructureSignal
from vibeguard.signals.tokens import TokenSignal

FIXTURES_DIR = Path(__file__).parent / "fixtures"
AI_FIXTURE = FIXTURES_DIR / "ai_sample.py"
HUMAN_FIXTURE = FIXTURES_DIR / "human_sample.py"


class TestCommentsSignal:
    def test_google_docstring_raises_score(self) -> None:
        """Score on source with Args:/Returns: sections must be >= 0.20."""
        source = """
def fn(a):
    \"\"\"
    Args:
        a: value
    Returns:
        int
    \"\"\"
    return a
"""
        assert CommentsSignal().score(source) >= 0.20

    def test_numpy_docstring_raises_score(self) -> None:
        """Score on source with Parameters\n---- pattern must be >= 0.15."""
        source = """
def fn(a):
    \"\"\"
    Parameters
    ----------
    a : int
    \"\"\"
    return a
"""
        assert CommentsSignal().score(source) >= 0.15

    def test_todo_feature_comment_raises_score(self) -> None:
        """Source with '# TODO: implement X' must score >= 0.15."""
        source = "# TODO: implement plugin registry support\nvalue = 1\n"
        assert CommentsSignal().score(source) >= 0.15

    def test_empty_source_returns_zero(self) -> None:
        """Empty string must return 0.0."""
        assert CommentsSignal().score("") == 0.0

    def test_plain_code_scores_below_threshold(self) -> None:
        """human_sample.py must score <= 0.20 on CommentsSignal."""
        source = HUMAN_FIXTURE.read_text(encoding="utf-8")
        assert CommentsSignal().score(source) <= 0.20


class TestStructureSignal:
    def test_uniform_functions_score_high(self) -> None:
        """ai_sample.py must score >= 0.40 on StructureSignal."""
        source = AI_FIXTURE.read_text(encoding="utf-8")
        assert StructureSignal().score(source) >= 0.40

    def test_irregular_functions_score_low(self) -> None:
        """human_sample.py must score <= 0.25 on StructureSignal."""
        source = HUMAN_FIXTURE.read_text(encoding="utf-8")
        assert StructureSignal().score(source) <= 0.25

    def test_textbook_names_detected(self) -> None:
        """Source with user_id, is_valid, response_data must score >= 0.20."""
        source = """
user_id = \"x\"
is_valid = True
response_data = {}
result = None
message = \"ok\"
"""
        assert StructureSignal().score(source) >= 0.20

    def test_syntax_error_returns_zero(self) -> None:
        """Unparseable source must return 0.0, not raise."""
        assert StructureSignal().score("def broken(:\n") == 0.0

    def test_no_functions_returns_zero(self) -> None:
        """Source with only module-level code must not crash."""
        source = "a = 1\nb = 2\nprint(a + b)\n"
        value = StructureSignal().score(source)
        assert 0.0 <= value <= 1.0


class TestTokenSignal:
    def test_bare_exception_swallow_detected(self) -> None:
        """except Exception as e: pass pattern must score >= 0.20."""
        source = """
try:
    run()
except Exception as e:
    pass
"""
        assert TokenSignal().score(source) >= 0.20

    def test_create_then_return_detected(self) -> None:
        """result = x; return result pattern must score >= 0.15."""
        source = """
def fn(x):
    value = x + 1
    result = value
    return result
"""
        assert TokenSignal().score(source) >= 0.15

    def test_isinstance_guards_detected(self) -> None:
        """Function with isinstance on 2+ params must score >= 0.15."""
        source = """
def fn(a, b, c):
    if not isinstance(a, str):
        return None
    if not isinstance(b, int):
        return None
    return c
"""
        assert TokenSignal().score(source) >= 0.15

    def test_clean_code_scores_low(self) -> None:
        """human_sample.py must score <= 0.20 on TokenSignal."""
        source = HUMAN_FIXTURE.read_text(encoding="utf-8")
        assert TokenSignal().score(source) <= 0.20

    def test_syntax_error_returns_zero(self) -> None:
        """Unparseable source must return 0.0, not raise."""
        assert TokenSignal().score("def bad(:\n") == 0.0


class TestDetector:
    def test_ai_fixture_scores_above_point_five(self) -> None:
        """ai_sample.py must produce DetectorResult.confidence >= 0.55."""
        result = Detector().score_file(AI_FIXTURE)
        assert result.confidence >= 0.55

    def test_human_fixture_scores_below_point_four(self) -> None:
        """human_sample.py must produce DetectorResult.confidence <= 0.40."""
        result = Detector().score_file(HUMAN_FIXTURE)
        assert result.confidence <= 0.40

    def test_ai_fixture_tier_is_full_or_medium(self) -> None:
        """ai_sample.py scan_tier must be FULL or MEDIUM."""
        result = Detector().score_file(AI_FIXTURE)
        assert result.scan_tier in {"FULL", "MEDIUM"}

    def test_human_fixture_tier_is_critical_only(self) -> None:
        """human_sample.py scan_tier must be CRITICAL_ONLY."""
        result = Detector().score_file(HUMAN_FIXTURE)
        assert result.scan_tier == "CRITICAL_ONLY"

    def test_signals_dict_has_all_keys(self) -> None:
        """DetectorResult.signals must contain 'comments','structure','tokens'."""
        result = Detector().score_file(AI_FIXTURE)
        assert set(result.signals) == {"comments", "structure", "tokens"}

    def test_score_directory_skips_node_modules(self, tmp_path: Path) -> None:
        """Files under node_modules/ must not appear in results."""
        detector = Detector()
        node_mod = tmp_path / "node_modules"
        src_dir = tmp_path / "src"
        node_mod.mkdir()
        src_dir.mkdir()
        (node_mod / "ignore.py").write_text("x = 1\n", encoding="utf-8")
        (src_dir / "keep.py").write_text("x = 1\n", encoding="utf-8")

        results = detector.score_directory(tmp_path, extensions={".py"})
        paths = {Path(item.file_path).name for item in results}
        assert "ignore.py" not in paths
        assert "keep.py" in paths

    def test_score_directory_returns_sorted_descending(self, tmp_path: Path) -> None:
        """Results must be sorted by confidence, highest first."""
        detector = Detector()
        high = tmp_path / "high.py"
        low = tmp_path / "low.py"
        high.write_text("# TODO: implement add support\n", encoding="utf-8")
        low.write_text("x = 1\n", encoding="utf-8")

        results = detector.score_directory(tmp_path, extensions={".py"})
        confidences = [item.confidence for item in results]
        assert confidences == sorted(confidences, reverse=True)

    def test_unreadable_file_returns_zero_not_crash(self, tmp_path: Path) -> None:
        """Non-UTF-8 or permission-denied file must return confidence=0.0."""
        detector = Detector()
        unreadable = tmp_path / "blocked.py"
        unreadable.mkdir()
        result = detector.score_file(unreadable)
        assert result.confidence == 0.0

    def test_nonexistent_file_returns_zero_not_crash(self) -> None:
        """score('/does/not/exist.py') must return confidence=0.0."""
        result = score("/does/not/exist.py")
        assert result.confidence == 0.0

    def test_confidence_always_clamped_to_unit_interval(self, tmp_path: Path) -> None:
        """Confidence must always be in [0.0, 1.0]."""
        detector = Detector()
        sample = tmp_path / "sample.py"
        sample.write_text("x = 1\n", encoding="utf-8")
        result = detector.score_file(sample)
        assert 0.0 <= result.confidence <= 1.0

    def test_aggregate_score_formula_is_weighted_sum(self) -> None:
        """Verify aggregate = comments*0.30 + structure*0.35 + tokens*0.35."""
        from vibeguard.detector import SIGNAL_WEIGHTS

        # Use a controlled source that produces predictable signal scores
        # by scoring it through each signal independently, then computing
        # the expected aggregate manually and comparing to Detector output.
        fixtures = Path(__file__).parent / "fixtures"
        source = (fixtures / "ai_sample.py").read_text(encoding="utf-8")

        c_score = CommentsSignal().score(source)
        s_score = StructureSignal().score(source)
        t_score = TokenSignal().score(source)

        expected = round(
            c_score * SIGNAL_WEIGHTS["comments"]
            + s_score * SIGNAL_WEIGHTS["structure"]
            + t_score * SIGNAL_WEIGHTS["tokens"],
            4,
        )
        expected = round(min(1.0, max(0.0, expected)), 4)

        detector = Detector()
        result = detector.score_file(fixtures / "ai_sample.py")

        assert result.confidence == expected, (
            f"Aggregate mismatch. "
            f"Expected {expected} (c={c_score:.4f}*0.30 + "
            f"s={s_score:.4f}*0.35 + t={t_score:.4f}*0.35), "
            f"got {result.confidence}"
        )
        assert result.signals["comments"] == c_score
        assert result.signals["structure"] == s_score
        assert result.signals["tokens"] == t_score

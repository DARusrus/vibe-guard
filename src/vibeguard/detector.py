from __future__ import annotations

from pathlib import Path

from vibeguard.models import DetectorResult
from vibeguard.signals import CommentsSignal, StructureSignal, TokenSignal

SIGNAL_WEIGHTS = {
    "comments": 0.30,
    "structure": 0.35,
    "tokens": 0.35,
}

SKIP_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    "venv",
    ".venv",
    "dist",
    "build",
    ".eggs",
    "*.egg-info",
    ".tox",
    ".mypy_cache",
}

DEFAULT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".sh",
    ".bash",
    ".sql",
    ".yml",
    ".yaml",
}


class Detector:
    """Compute AI-likelihood confidence for files and directories."""

    def __init__(self, ai_threshold: float = 0.6) -> None:
        """Initialize the detector with threshold used for scan tier mapping."""
        self.threshold = ai_threshold
        self._comments = CommentsSignal()
        self._structure = StructureSignal()
        self._tokens = TokenSignal()

    def score_file(self, file_path: str | Path) -> DetectorResult:
        """Score a single file and never raise on read/parse/runtime signal errors."""
        path = Path(file_path)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return self._zero_result(str(file_path))

        try:
            scores = {
                "comments": self._comments.score(source),
                "structure": self._structure.score(source),
                "tokens": self._tokens.score(source),
            }
            confidence = sum(scores[key] * SIGNAL_WEIGHTS[key] for key in scores)
            confidence = round(min(1.0, max(0.0, confidence)), 4)
            tier = self._assign_tier(confidence)
            return DetectorResult(
                file_path=str(path),
                confidence=confidence,
                scan_tier=tier,
                signals=scores,
            )
        except Exception:
            return self._zero_result(str(path))

    def score_directory(
        self,
        path: str | Path,
        extensions: set[str] | None = None,
    ) -> list[DetectorResult]:
        """Walk directory, score matching files, return sorted by confidence desc."""
        exts = extensions or DEFAULT_EXTENSIONS
        root = Path(path)
        if not root.exists():
            return []

        results: list[DetectorResult] = []
        for candidate in root.rglob("*"):
            if self._should_skip(candidate):
                continue
            if not candidate.is_file():
                continue
            if candidate.suffix in exts or candidate.name == "Dockerfile":
                results.append(self.score_file(candidate))

        return sorted(results, key=lambda result: result.confidence, reverse=True)

    def _assign_tier(self, confidence: float) -> str:
        if confidence >= self.threshold:
            return "FULL"
        if confidence >= 0.3:
            return "MEDIUM"
        return "CRITICAL_ONLY"

    def _zero_result(self, file_path: str) -> DetectorResult:
        return DetectorResult(
            file_path=file_path,
            confidence=0.0,
            scan_tier="CRITICAL_ONLY",
            signals={"comments": 0.0, "structure": 0.0, "tokens": 0.0},
        )

    def _should_skip(self, path: Path) -> bool:
        parts = set(path.parts)
        if parts & (SKIP_DIRS - {"*.egg-info"}):
            return True
        return any(part.endswith(".egg-info") for part in path.parts)


def score(file_path: str | Path) -> DetectorResult:
    """Module-level convenience wrapper. Used by Session 2's scanner."""
    return Detector().score_file(file_path)

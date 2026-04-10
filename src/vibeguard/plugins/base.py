from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from vibeguard.models import Finding


class BasePlugin(ABC):
    """Base class for all vibe-guard scanner plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin identifier. Used in logging and --disable-plugin flag."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the plugin can run (deps available, etc.)."""

    @abstractmethod
    def scan(
        self,
        files: list[Path],
        project_root: Path,
    ) -> list[Finding]:
        """Run the plugin against a list of files.

        Must never raise. Return empty list on any error.
        Must never produce duplicate findings (deduplicate internally).
        """

    def _make_finding(self, **kwargs: object) -> Finding:
        """Convenience method — sets plugin-invariant defaults."""
        defaults: dict[str, object] = {
            "col": 1,
            "snippet": "",
            "semgrep_rule_id": "",
            "file_confidence": 0.0,
        }
        defaults.update(kwargs)
        return Finding(**defaults)  # type: ignore[arg-type]

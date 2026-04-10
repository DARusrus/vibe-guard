from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from vibeguard.models import ScanResult


class BaseReporter(ABC):
    """All reporters implement this interface."""

    @abstractmethod
    def render(self, result: ScanResult) -> str:
        """Return the full report as a string."""

    def write(self, result: ScanResult, output_path: Path | None = None) -> None:
        """Write rendered report to file or stdout."""
        content = self.render(result)
        if output_path:
            output_path.write_text(content, encoding="utf-8")
        else:
            print(content)


def get_reporter(format: str) -> BaseReporter:
    """Factory. Raises ValueError for unknown format strings."""
    from vibeguard.reporters.json_out import JsonReporter
    from vibeguard.reporters.sarif import SarifReporter
    from vibeguard.reporters.terminal import TerminalReporter

    reporters = {
        "terminal": TerminalReporter,
        "sarif": SarifReporter,
        "json": JsonReporter,
    }
    if format not in reporters:
        raise ValueError(f"Unknown format '{format}'. Choose from: {list(reporters)}")
    return reporters[format]()


__all__ = ["BaseReporter", "get_reporter"]

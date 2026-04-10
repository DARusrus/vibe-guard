from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DetectorResult:
    file_path: str
    confidence: float
    scan_tier: str
    signals: dict[str, float]

    def is_ai_generated(self, threshold: float = 0.6) -> bool:
        """Return True when confidence is at or above threshold."""
        return self.confidence >= threshold


@dataclass
class Finding:
    """A single security finding produced by the scanner engine."""

    rule_id: str = ""
    severity: str = ""  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    file_path: str = ""
    line: int = 0
    col: int = 0
    message: str = ""
    fix_guidance: str = ""
    cwe_id: str = ""
    ai_context: str = ""  # why AI code specifically produces this
    file_confidence: float = 0.0  # detector score of the source file
    rule_category: str = ""  # e.g. "sqli", "cmdi", "secrets"
    snippet: str = ""  # the offending code line(s), max 3 lines
    semgrep_rule_id: str = ""  # raw Semgrep rule id for deduplication

    def is_critical_or_high(self) -> bool:
        """Return True if severity is CRITICAL or HIGH."""
        return self.severity in {"CRITICAL", "HIGH"}


@dataclass
class ScanResult:
    """Aggregated results from a full scan pipeline run."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    ai_files_detected: int = 0
    detector_results: list[DetectorResult] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    rules_applied: int = 0
    diff_mode: bool = False
    changed_files_count: int = 0
    filtered_count: int = 0

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity level, ordered CRITICAL→LOW."""
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        grouped: dict[str, list[Finding]] = {s: [] for s in order}
        for finding in self.findings:
            if finding.severity in grouped:
                grouped[finding.severity].append(finding)
            else:
                grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    def highest_severity(self) -> str | None:
        """Return the highest severity present, or None if no findings."""
        if not self.findings:
            return None
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return min(
            (f.severity for f in self.findings),
            key=lambda s: order.get(s, 99),
        )

    def summary_line(self) -> str:
        """Return a one-line human-readable summary for terminal output.

        Example: '12 files scanned (4 AI-generated), 7 findings [2 HIGH, 5 MEDIUM]'
        Diff mode: 'Diff mode: 8 changed files scanned, 3 AI-generated, 2 findings'
        """
        parts = []
        by_sev = self.findings_by_severity()
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = len(by_sev.get(sev, []))
            if count:
                parts.append(f"{count} {sev}")
        severity_str = f" [{', '.join(parts)}]" if parts else ""

        if self.diff_mode:
            prefix = f"Diff mode: {self.changed_files_count} changed files scanned"
        else:
            prefix = f"{self.files_scanned} files scanned"

        line = (
            f"{prefix} "
            f"({self.ai_files_detected} AI-generated), "
            f"{len(self.findings)} findings{severity_str}"
        )

        if self.filtered_count > 0:
            line += f" (smart filter: removed {self.filtered_count} likely false positives)"

        return line

from __future__ import annotations

import json
from datetime import datetime, timezone

from vibeguard import __version__
from vibeguard.models import ScanResult
from vibeguard.reporters import BaseReporter

try:
    from datetime import UTC
except ImportError:
    UTC = timezone.utc  # type: ignore[assignment]


class JsonReporter(BaseReporter):
    """Render machine-readable JSON output for CI integrations."""

    def render(self, result: ScanResult) -> str:
        """Return ScanResult encoded as formatted JSON."""
        by_severity = result.findings_by_severity()

        payload = {
            "vibe_guard_version": __version__,
            "scan_timestamp": datetime.now(UTC).isoformat(),
            "summary": {
                "files_scanned": result.files_scanned,
                "ai_files_detected": result.ai_files_detected,
                "total_findings": len(result.findings),
                "findings_by_severity": {
                    "CRITICAL": len(by_severity.get("CRITICAL", [])),
                    "HIGH": len(by_severity.get("HIGH", [])),
                    "MEDIUM": len(by_severity.get("MEDIUM", [])),
                    "LOW": len(by_severity.get("LOW", [])),
                },
                "scan_duration_seconds": _round4(result.scan_duration_seconds),
                "rules_applied": result.rules_applied,
            },
            "detector_results": [
                {
                    "file_path": dr.file_path,
                    "confidence": _round4(dr.confidence),
                    "scan_tier": dr.scan_tier,
                    "signals": {
                        "comments": _round4(dr.signals.get("comments", 0.0)),
                        "structure": _round4(dr.signals.get("structure", 0.0)),
                        "tokens": _round4(dr.signals.get("tokens", 0.0)),
                    },
                }
                for dr in result.detector_results
            ],
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "file_path": finding.file_path,
                    "line": finding.line,
                    "col": finding.col,
                    "message": finding.message,
                    "fix_guidance": finding.fix_guidance,
                    "cwe_id": finding.cwe_id,
                    "ai_context": finding.ai_context,
                    "file_confidence": _round4(finding.file_confidence),
                    "rule_category": finding.rule_category,
                    "snippet": finding.snippet,
                }
                for finding in result.findings
            ],
        }

        return json.dumps(payload, indent=2, sort_keys=False)


def _round4(value: float) -> float:
    """Round floating-point values to 4 decimal places."""
    return round(float(value), 4)

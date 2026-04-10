from __future__ import annotations

import json
from pathlib import Path

from vibeguard import __version__
from vibeguard.models import Finding, ScanResult
from vibeguard.reporters import BaseReporter

_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


class SarifReporter(BaseReporter):
    """Render scan results as SARIF 2.1.0 JSON."""

    def render(self, result: ScanResult) -> str:
        """Return a SARIF 2.1.0 JSON report."""
        rules = self._build_rules(result.findings)
        rule_index = {rule["id"]: idx for idx, rule in enumerate(rules)}

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "vibe-guard",
                            "version": __version__,
                            "informationUri": "https://github.com/ahmbt/vibe-guard",
                            "rules": rules,
                        }
                    },
                    "results": [
                        self._build_result_item(finding, rule_index)
                        for finding in result.findings
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _build_rules(self, findings: list[Finding]) -> list[dict]:
        """Deduplicate and build SARIF driver rules from findings."""
        by_rule: dict[str, dict] = {}

        for finding in findings:
            if finding.rule_id in by_rule:
                continue

            by_rule[finding.rule_id] = {
                "id": finding.rule_id,
                "name": _to_pascal_case(finding.rule_id),
                "shortDescription": {"text": finding.message},
                "fullDescription": {
                    "text": f"{finding.message}. {finding.fix_guidance}".strip()
                },
                "helpUri": "https://github.com/ahmbt/vibe-guard/blob/main/rules/",
                "properties": {
                    "tags": [finding.rule_category, "security", "ai-generated"],
                    "severity": finding.severity,
                    "cwe": finding.cwe_id,
                },
            }

        return list(by_rule.values())

    def _build_result_item(self, finding: Finding, rule_index: dict[str, int]) -> dict:
        """Build one SARIF result object from a finding."""
        return {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index.get(finding.rule_id, 0),
            "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
            "message": {
                "text": f"{finding.message}. AI context: {finding.ai_context}".strip()
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _to_relative_uri(finding.file_path),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line,
                            "startColumn": finding.col,
                        },
                    }
                }
            ],
            "properties": {
                "fix_guidance": finding.fix_guidance,
                "ai_context": finding.ai_context,
                "file_confidence": finding.file_confidence,
                "vibe_guard_severity": finding.severity,
            },
        }


def _to_pascal_case(rule_id: str) -> str:
    """Convert rule id strings into a PascalCase display name."""
    return "".join(part.capitalize() for part in rule_id.replace("_", "-").split("-") if part)


def _to_relative_uri(file_path: str) -> str:
    """Return a SARIF-friendly relative URI path."""
    path = Path(file_path)
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(Path.cwd().resolve())
        except Exception:
            path = Path(path.name)

    return path.as_posix()

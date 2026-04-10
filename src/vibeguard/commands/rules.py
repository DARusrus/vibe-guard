from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.table import Table

_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "dim",
}


def list_rules(
    language: str | None = None,
    severity: str | None = None,
    category: str | None = None,
) -> None:
    """Print a Rich table of all built-in rules."""
    console = Console()
    rows = _load_rules()

    language_filter = language.lower() if language else None
    severity_filter = severity.upper() if severity else None
    category_filter = category.lower() if category else None

    filtered = [
        row
        for row in rows
        if (not language_filter or row["source_language"] == language_filter)
        and (not severity_filter or row["severity"] == severity_filter)
        and (not category_filter or row["category"].lower() == category_filter)
    ]

    table = Table(title="Built-in vibe-guard rules")
    table.add_column("ID", overflow="fold")
    table.add_column("Language")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("CWE")
    table.add_column("Description", overflow="fold")

    for row in filtered:
        table.add_row(
            row["id"],
            row["language_display"],
            f"[{_SEVERITY_STYLE.get(row['severity'], 'white')}]{row['severity']}[/]",
            row["category"],
            row["cwe"],
            row["description"],
        )

    console.print(table)

    py_count = sum(1 for row in filtered if row["source_language"] == "python")
    js_count = sum(1 for row in filtered if row["source_language"] == "javascript")
    ts_count = sum(1 for row in filtered if row["source_language"] == "typescript")
    console.print(
        f"Total: {len(filtered)} rules ({py_count} Python, {js_count} JavaScript, {ts_count} TypeScript)"
    )


def _load_rules() -> list[dict[str, str]]:
    """Read rule YAML files under rules/ and return one normalized row per file."""
    rules_root = Path(__file__).resolve().parent.parent / "rules"
    results: list[dict[str, str]] = []

    for yaml_path in sorted(rules_root.rglob("*.yaml")):
        source_language = yaml_path.parent.name.lower()
        file_data = _safe_yaml_load(yaml_path)

        rules_data = file_data.get("rules", [])
        if not isinstance(rules_data, list):
            continue

        first_rule = next(
            (rule for rule in rules_data if isinstance(rule, dict)),
            None,
        )
        if first_rule is None:
            continue

        metadata = (
            first_rule.get("metadata", {}) if isinstance(first_rule.get("metadata"), dict) else {}
        )
        cwe = str(metadata.get("cwe", ""))
        cwe_short = cwe.split(":", 1)[0]
        message = str(first_rule.get("message", "")).strip().replace("\n", " ")
        description = _truncate(message, 60)

        languages = first_rule.get("languages", [])
        language_display = ",".join(str(item) for item in languages if isinstance(item, str))

        results.append(
            {
                "id": str(first_rule.get("id", "")),
                "source_language": source_language,
                "language_display": language_display,
                "severity": str(metadata.get("severity_label", "")).upper(),
                "category": str(metadata.get("rule_category", "")),
                "cwe": cwe_short,
                "description": description,
            }
        )

    return results


def _safe_yaml_load(path: Path) -> dict[str, Any]:
    """Load YAML safely and return a mapping or empty mapping."""
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max_len while preserving readability."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."

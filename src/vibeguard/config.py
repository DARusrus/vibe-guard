from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_VALID_FORMATS = {"terminal", "sarif", "json"}


@dataclass
class Config:
    """Runtime configuration for scanner and CLI behavior."""

    ai_threshold: float = 0.6
    min_severity: str = "MEDIUM"
    extensions: list[str] = field(default_factory=lambda: [".py", ".js", ".ts", ".jsx", ".tsx"])

    default_format: str = "terminal"
    output_path: str | None = None

    ignore_rules: list[str] = field(default_factory=list)
    extra_rules_dirs: list[str] = field(default_factory=list)

    exclude_paths: list[str] = field(
        default_factory=lambda: [
            "node_modules",
            ".git",
            "__pycache__",
            "venv",
            ".venv",
            "dist",
            "build",
        ]
    )

    fail_on_findings: bool = True
    no_fail: bool = False


def load_config(start_path: str | Path = ".") -> Config:
    """Load .vibeguard.toml by searching start_path and parent directories.

    Returns default Config when no config file is found, parser support is
    unavailable, or config content is malformed.
    """
    config = Config()
    start = Path(start_path)

    config_file: Path | None
    if start.is_file() and start.name == ".vibeguard.toml":
        config_file = start
    else:
        search_root = start if start.is_dir() else start.parent
        config_file = _find_config_file(search_root)

    if config_file is None:
        return config

    if tomllib is None:
        logger.warning("tomllib/tomli unavailable; using default configuration")
        return config

    try:
        with config_file.open("rb") as handle:
            data = tomllib.load(handle)
    except Exception as exc:
        logger.warning("Failed to parse config %s: %s", config_file, exc)
        return config

    if not isinstance(data, dict):
        return config

    return _merge_toml(config, data)


def _find_config_file(start: Path) -> Path | None:
    """Search start and all parent directories for .vibeguard.toml."""
    current = start.resolve() if start.exists() else start.absolute()
    for candidate in [current, *current.parents]:
        config_file = candidate / ".vibeguard.toml"
        if config_file.exists() and config_file.is_file():
            return config_file
    return None


def _merge_toml(config: Config, data: dict[str, Any]) -> Config:
    """Merge TOML data over defaults while ignoring unknown keys."""
    merged = Config(**config.__dict__)

    sources: list[dict[str, Any]] = [data]
    for section in ("vibeguard", "vibe-guard", "vibe_guard"):
        section_data = data.get(section)
        if isinstance(section_data, dict):
            sources.append(section_data)

    tool_section = data.get("tool")
    if isinstance(tool_section, dict):
        for section in ("vibeguard", "vibe-guard", "vibe_guard"):
            section_data = tool_section.get(section)
            if isinstance(section_data, dict):
                sources.append(section_data)

    for source in sources:
        _apply_known_keys(merged, source)

    return merged


def _apply_known_keys(config: Config, values: dict[str, Any]) -> None:
    """Apply supported keys from values onto config in-place."""
    ai_threshold = values.get("ai_threshold")
    if isinstance(ai_threshold, (int, float)):
        config.ai_threshold = float(ai_threshold)

    min_severity = values.get("min_severity")
    if isinstance(min_severity, str):
        candidate = min_severity.upper()
        if candidate in _VALID_SEVERITIES:
            config.min_severity = candidate

    extensions = values.get("extensions")
    if isinstance(extensions, list):
        normalized_ext: list[str] = []
        for ext in extensions:
            if not isinstance(ext, str) or not ext.strip():
                continue
            clean = ext.strip()
            if not clean.startswith("."):
                clean = f".{clean}"
            normalized_ext.append(clean)
        if normalized_ext:
            config.extensions = normalized_ext

    default_format = values.get("default_format")
    if isinstance(default_format, str):
        candidate = default_format.lower()
        if candidate in _VALID_FORMATS:
            config.default_format = candidate

    output_path = values.get("output_path")
    if output_path is None or isinstance(output_path, str):
        config.output_path = output_path

    ignore_rules = values.get("ignore_rules")
    if isinstance(ignore_rules, list):
        config.ignore_rules = [v for v in ignore_rules if isinstance(v, str)]

    extra_rules_dirs = values.get("extra_rules_dirs")
    if isinstance(extra_rules_dirs, list):
        config.extra_rules_dirs = [v for v in extra_rules_dirs if isinstance(v, str)]

    exclude_paths = values.get("exclude_paths")
    if isinstance(exclude_paths, list):
        config.exclude_paths = [v for v in exclude_paths if isinstance(v, str)]

    fail_on_findings = values.get("fail_on_findings")
    if isinstance(fail_on_findings, bool):
        config.fail_on_findings = fail_on_findings

    no_fail = values.get("no_fail")
    if isinstance(no_fail, bool):
        config.no_fail = no_fail

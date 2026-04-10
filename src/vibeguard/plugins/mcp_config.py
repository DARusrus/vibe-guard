from __future__ import annotations

import json
import logging
import math
import re
from pathlib import Path

from vibeguard.models import Finding
from vibeguard.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

_SECRET_NAMES = re.compile(
    r"(?i)(password|passwd|pwd|secret|api_key|apikey|token|"
    r"auth_token|access_token|private_key|client_secret|"
    r"credentials|stripe|sendgrid|twilio|aws|jwt|database_url|"
    r"mongo|redis|smtp|mailgun|slack|discord|webhook)",
)

_MCP_CONFIG_PATHS = [
    ".claude/settings.json",
    ".cursor/mcp.json",
    "mcp.config.json",
    ".mcp/config.json",
    ".mcp.json",
    "claude_desktop_config.json",
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character.

    Args:
        s: Input string.

    Returns:
        Entropy value in bits per character.
    """
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length) for count in freq.values()
    )


class MCPConfigPlugin(BasePlugin):
    """Scans MCP configuration files for exposed secrets.

    AI agents store credentials in MCP configuration files.
    This is a 2026-specific attack surface that GitGuardian
    identifies as critical.
    """

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "mcp_config"

    def is_available(self) -> bool:
        """Always available — no external deps required."""
        return True

    def scan(self, files: list[Path], project_root: Path) -> list[Finding]:
        """Scan MCP config files for secrets and .gitignore issues.

        Args:
            files: List of source files (unused — MCP walks project_root).
            project_root: Root directory of the project to scan.

        Returns:
            List of findings. Never raises.
        """
        try:
            return self._scan_impl(project_root)
        except Exception:
            logger.exception("MCPConfigPlugin.scan failed")
            return []

    def _scan_impl(self, project_root: Path) -> list[Finding]:
        """Core scan logic."""
        findings: list[Finding] = []
        seen_keys: set[tuple[str, str, int]] = set()

        # Step A — Find MCP config files
        mcp_files = self._find_mcp_files(project_root)
        if not mcp_files:
            return []

        # Load .gitignore patterns
        gitignore_patterns = self._load_gitignore(project_root)

        for mcp_file in mcp_files:
            # Step B — Parse and scan for secrets
            secret_findings = self._scan_mcp_secrets(mcp_file)
            for f in secret_findings:
                key = (f.rule_id, f.file_path, f.line)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(f)

            # Step C — Check .gitignore
            rel_path = str(mcp_file.relative_to(project_root))
            if not self._is_in_gitignore(rel_path, mcp_file.name, gitignore_patterns):
                f = self._make_finding(
                    rule_id="vibeguard-mcp-config-not-in-gitignore",
                    severity="CRITICAL",
                    file_path=str(mcp_file),
                    line=1,
                    message=(
                        f"MCP config file {mcp_file.name} is not in .gitignore. "
                        f"AI agent credentials may be committed to version control."
                    ),
                    fix_guidance=(
                        f"Add '{rel_path}' to .gitignore immediately."
                    ),
                    cwe_id="CWE-538: Insertion of Sensitive Information into Externally-Accessible File",
                    ai_context=(
                        "AI coding agents store API keys and service credentials "
                        "in MCP configuration files. These files are frequently "
                        "committed to version control, exposing all connected "
                        "service credentials."
                    ),
                    rule_category="mcp_config",
                )
                key = (f.rule_id, f.file_path, f.line)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(f)

        return findings

    def _find_mcp_files(self, project_root: Path) -> list[Path]:
        """Find MCP configuration files in the project.

        Args:
            project_root: Project root directory.

        Returns:
            List of MCP config file paths.
        """
        found: list[Path] = []

        # Check known paths
        for rel_path in _MCP_CONFIG_PATHS:
            candidate = project_root / rel_path
            if candidate.exists() and candidate.is_file():
                found.append(candidate)

        # Walk for mcp*.json and *mcp.json files
        try:
            for item in project_root.rglob("*.json"):
                name_lower = item.name.lower()
                if name_lower.startswith("mcp") or name_lower.endswith("mcp.json"):
                    if item not in found:
                        found.append(item)
        except OSError:
            pass

        return found

    def _load_gitignore(self, project_root: Path) -> list[str]:
        """Load .gitignore patterns.

        Args:
            project_root: Project root directory.

        Returns:
            List of gitignore pattern strings.
        """
        gitignore = project_root / ".gitignore"
        if not gitignore.exists():
            return []
        try:
            return [
                line.strip()
                for line in gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        except OSError:
            return []

    def _is_in_gitignore(
        self, rel_path: str, filename: str, patterns: list[str],
    ) -> bool:
        """Check if a path matches any .gitignore pattern.

        Args:
            rel_path: Relative path from project root.
            filename: Just the filename.
            patterns: List of gitignore patterns.

        Returns:
            True if covered by a gitignore pattern.
        """
        # Normalize path separators
        rel_path_normalized = rel_path.replace("\\", "/")
        for pattern in patterns:
            p = pattern.rstrip("/")
            if p == rel_path_normalized or p == filename:
                return True
            # Check parent directory patterns
            if p.endswith("/*") and rel_path_normalized.startswith(p[:-2] + "/"):
                return True
            # Check directory pattern
            if rel_path_normalized.startswith(p + "/"):
                return True
            if p.startswith("*") and rel_path_normalized.endswith(p[1:]):
                return True
        return False

    def _scan_mcp_secrets(self, mcp_file: Path) -> list[Finding]:
        """Scan an MCP config file for embedded secrets.

        Args:
            mcp_file: Path to the MCP config file.

        Returns:
            List of CRITICAL findings for detected secrets.
        """
        try:
            text = mcp_file.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
        except (json.JSONDecodeError, OSError):
            return []

        findings: list[Finding] = []
        self._walk_json(data, mcp_file, findings, depth=0)
        return findings

    def _walk_json(
        self,
        obj: object,
        mcp_file: Path,
        findings: list[Finding],
        depth: int,
        parent_key: str = "",
    ) -> None:
        """Recursively walk JSON structure looking for secrets.

        Args:
            obj: Current JSON node.
            mcp_file: Path to the source file.
            findings: Accumulator list for findings.
            depth: Current recursion depth.
            parent_key: Key name of the current node's parent.
        """
        if depth > 20:
            return

        if isinstance(obj, dict):
            for key, value in obj.items():
                self._walk_json(value, mcp_file, findings, depth + 1, parent_key=str(key))
        elif isinstance(obj, list):
            for item in obj:
                self._walk_json(item, mcp_file, findings, depth + 1, parent_key=parent_key)
        elif isinstance(obj, str):
            self._check_string_value(obj, parent_key, mcp_file, findings)

    def _check_string_value(
        self,
        value: str,
        key: str,
        mcp_file: Path,
        findings: list[Finding],
    ) -> None:
        """Check if a string value looks like a secret.

        Args:
            value: The string value to check.
            key: The key/field name for this value.
            mcp_file: Path to the source file.
            findings: Accumulator list for findings.
        """
        if not value or len(value) < 8:
            return

        # Skip URLs
        if value.startswith("http://") or value.startswith("https://"):
            return

        is_secret = False

        # Check if key name matches secret patterns
        if _SECRET_NAMES.search(key):
            is_secret = True

        # Check entropy regardless of key name
        if not is_secret and len(value) > 15:
            entropy = _shannon_entropy(value)
            if entropy > 3.5:
                is_secret = True

        if is_secret:
            # Mask the value
            masked = value[:6] + "..." if len(value) > 6 else "***"
            findings.append(self._make_finding(
                rule_id="vibeguard-mcp-config-secret",
                severity="CRITICAL",
                file_path=str(mcp_file),
                line=1,
                message=(
                    f"Secret detected in MCP config file for key '{key}': "
                    f"'{masked}'. AI agent credentials must not be committed."
                ),
                fix_guidance=(
                    "Move this credential to an environment variable. "
                    "Use runtime injection instead of hardcoding in config."
                ),
                cwe_id="CWE-798: Use of Hard-coded Credentials",
                ai_context=(
                    "AI coding agents store API keys and service credentials "
                    "in MCP configuration files. These files are frequently "
                    "committed to version control, exposing all connected "
                    "service credentials."
                ),
                rule_category="mcp_config",
            ))

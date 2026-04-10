from __future__ import annotations

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

_PLACEHOLDER_RE = re.compile(
    r"(?i)(YOUR_|<|>|XXXX|example|placeholder|changeme|todo|fixme|replace)",
)

_ENV_TARGET_NAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        ".env.staging",
        ".env.development",
    }
)

_ENV_SKIP_NAMES = frozenset(
    {
        ".env.example",
        ".env.template",
        ".env.sample",
    }
)

_KV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)")

_MAX_LINES = 200


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
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class DotenvPlugin(BasePlugin):
    """Scans .env files for high-entropy secrets and .gitignore exclusion.

    Detects:
    - .env files not listed in .gitignore (credential exposure risk)
    - High-entropy secret values for sensitive key names
    """

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "dotenv"

    def is_available(self) -> bool:
        """Always available — no external deps required."""
        return True

    def scan(self, files: list[Path], project_root: Path) -> list[Finding]:
        """Scan for .env file issues.

        Args:
            files: List of source files (unused — dotenv walks project_root).
            project_root: Root directory of the project to scan.

        Returns:
            List of findings. Never raises.
        """
        try:
            return self._scan_impl(project_root)
        except Exception:
            logger.exception("DotenvPlugin.scan failed")
            return []

    def _scan_impl(self, project_root: Path) -> list[Finding]:
        """Core scan logic."""
        findings: list[Finding] = []
        seen_keys: set[tuple[str, str, int]] = set()

        # Step A — Find .env files
        env_files = self._find_env_files(project_root)
        if not env_files:
            return []

        # Load .gitignore patterns
        gitignore_patterns = self._load_gitignore(project_root)

        for env_file in env_files:
            rel_path = env_file.name

            # Step B — Check .gitignore exclusion
            if not self._is_in_gitignore(rel_path, gitignore_patterns):
                f = self._make_finding(
                    rule_id="vibeguard-dotenv-not-in-gitignore",
                    severity="CRITICAL",
                    file_path=str(env_file),
                    line=1,
                    message=(
                        ".env file exists but is not in .gitignore. "
                        "This file may be committed to version control, "
                        "exposing all credentials it contains."
                    ),
                    fix_guidance="Add '.env' to .gitignore immediately. Run: echo '.env' >> .gitignore",
                    cwe_id="CWE-538: Insertion of Sensitive Information into Externally-Accessible File",
                    ai_context=(
                        "AI code generators frequently create .env files with real "
                        "credentials but forget to add .gitignore entries."
                    ),
                    rule_category="dotenv",
                )
                key = (f.rule_id, f.file_path, f.line)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(f)

            # Step C — Scan for high-value secrets
            secret_findings = self._scan_env_secrets(env_file)
            for f in secret_findings:
                key = (f.rule_id, f.file_path, f.line)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(f)

        return findings

    def _find_env_files(self, project_root: Path) -> list[Path]:
        """Find .env files in the project root (non-recursive).

        Args:
            project_root: Project root directory.

        Returns:
            List of .env file paths.
        """
        result: list[Path] = []
        try:
            for item in project_root.iterdir():
                if item.is_file() and item.name in _ENV_TARGET_NAMES:
                    result.append(item)
        except OSError:
            pass
        return result

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

    def _is_in_gitignore(self, filename: str, patterns: list[str]) -> bool:
        """Check if a filename matches any .gitignore pattern.

        Args:
            filename: The filename to check (e.g., '.env').
            patterns: List of gitignore patterns.

        Returns:
            True if the filename is covered by a gitignore pattern.
        """
        for pattern in patterns:
            p = pattern.rstrip("/")
            # Exact match
            if p == filename:
                return True
            # Glob patterns
            if p == ".env*" or p == "*.env":
                return True
            # Pattern matches the base name
            if p == ".env" and filename.startswith(".env"):
                # .env pattern covers .env but not .env.local
                if filename == ".env":
                    return True
        return False

    def _scan_env_secrets(self, env_file: Path) -> list[Finding]:
        """Scan a .env file for high-entropy secrets.

        Args:
            env_file: Path to the .env file.

        Returns:
            List of CRITICAL findings for detected secrets.
        """
        findings: list[Finding] = []
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        for line_num, raw_line in enumerate(text.splitlines()[:_MAX_LINES], 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            m = _KV_RE.match(line)
            if not m:
                continue

            key = m.group(1)
            value = m.group(2).strip().strip("'\"")

            if not value:
                continue

            # Check if key is a secret name
            if not _SECRET_NAMES.search(key):
                continue

            # Check for placeholder values
            if _PLACEHOLDER_RE.search(value):
                continue

            # Entropy check
            entropy = _shannon_entropy(value)
            is_secret = False

            if entropy > 3.5:
                is_secret = True
            elif len(value) > 20 and not _PLACEHOLDER_RE.search(value):
                is_secret = True

            if is_secret:
                findings.append(
                    self._make_finding(
                        rule_id="vibeguard-dotenv-exposed-secret",
                        severity="CRITICAL",
                        file_path=str(env_file),
                        line=line_num,
                        message=(
                            f"High-entropy secret detected in .env file for key '{key}'. "
                            f"If this file is committed, the credential is exposed."
                        ),
                        fix_guidance=(
                            "Never commit .env files. Add '.env' to .gitignore "
                            "and rotate this credential immediately."
                        ),
                        cwe_id="CWE-798: Use of Hard-coded Credentials",
                        ai_context=(
                            "AI code generators frequently create .env files "
                            "with example credentials that look realistic and have "
                            "high entropy, making them indistinguishable from real secrets."
                        ),
                        rule_category="dotenv",
                    )
                )

        return findings

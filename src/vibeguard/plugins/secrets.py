from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from vibeguard.models import Finding

logger = logging.getLogger(__name__)

_AI_CONTEXT = (
    "AI models frequently embed credentials in code when generating "
    "working examples, often using realistic-looking but hardcoded values."
)

_FIX_GUIDANCE = (
    "Move this value to an environment variable. "
    "Use os.environ.get('KEY_NAME') and document "
    "the required variable in .env.example."
)


class SecretsPlugin:
    """Wraps detect-secrets CLI for high-confidence secret detection."""

    def __init__(self, detect_secrets_bin: str = "detect-secrets") -> None:
        """Initialize with path or name of detect-secrets binary.

        Args:
            detect_secrets_bin: Path to detect-secrets. Defaults to
                                'detect-secrets' which assumes it is on PATH.
        """
        self.detect_secrets_bin = detect_secrets_bin

    def is_available(self) -> bool:
        """Return True if detect-secrets is on PATH."""
        try:
            result = subprocess.run(
                [self.detect_secrets_bin, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def scan_files(
        self,
        files: list[Path],
        existing_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Run detect-secrets scan on the given files.

        Args:
            files: List of file paths to scan for secrets.
            existing_findings: Optional list of existing findings from
                               Semgrep secrets rules, used for deduplication.

        Returns:
            List of Finding objects for detected secrets. Returns empty
            list (never raises) if detect-secrets is not installed or
            returns a non-zero exit code.
        """
        if not files:
            return []

        try:
            return self._execute(files, existing_findings or [])
        except Exception:
            logger.exception("Unexpected error in SecretsPlugin.scan_files")
            return []

    def _execute(
        self,
        files: list[Path],
        existing_findings: list[Finding],
    ) -> list[Finding]:
        """Internal execution method."""
        cmd = [self.detect_secrets_bin, "scan", "--list-all-plugins"]
        for f in files:
            cmd.append(str(f))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            logger.warning("detect-secrets binary not found: %s", self.detect_secrets_bin)
            return []
        except subprocess.TimeoutExpired:
            logger.warning("detect-secrets timed out")
            return []

        if result.returncode != 0:
            logger.warning(
                "detect-secrets exited with code %d: %s",
                result.returncode,
                result.stderr[:500] if result.stderr else "(no stderr)",
            )
            return []

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("Failed to parse detect-secrets JSON output")
            return []

        # Build dedup set from existing findings
        existing_keys: set[tuple[str, int]] = set()
        for f in existing_findings:
            existing_keys.add((f.file_path, f.line))

        findings: list[Finding] = []
        results_dict = data.get("results", {})

        for file_path, secret_list in results_dict.items():
            if not isinstance(secret_list, list):
                continue
            for secret in secret_list:
                line_num = secret.get("line_number", 0)

                # Deduplicate against existing Semgrep secrets findings
                if (file_path, line_num) in existing_keys:
                    continue

                secret_type = secret.get("type", "Unknown")
                findings.append(
                    Finding(
                        rule_id="vibeguard-secrets-detected",
                        severity="CRITICAL",
                        file_path=file_path,
                        line=line_num,
                        col=0,
                        message=f"Hardcoded secret detected ({secret_type})",
                        fix_guidance=_FIX_GUIDANCE,
                        cwe_id="CWE-798",
                        ai_context=_AI_CONTEXT,
                        file_confidence=0.0,  # Set later by scanner
                        rule_category="secrets",
                        snippet="",
                        semgrep_rule_id="",
                    )
                )

        return findings

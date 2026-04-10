from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Rule packs now include Python, JavaScript, TypeScript, Bash, Dockerfile,
# YAML (GitHub Actions/Kubernetes), and generic-mode SQL patterns.
SUPPORTED_RULE_LANGUAGES = (
    "python",
    "javascript",
    "typescript",
    "bash",
    "dockerfile",
    "yaml",
    "generic",
)


class SemgrepEngine:
    """Calls Semgrep CE via subprocess and parses its JSON output."""

    def __init__(self, semgrep_bin: str = "semgrep") -> None:
        """Initialize with the path or name of the semgrep binary.

        Args:
            semgrep_bin: Path to the semgrep executable. Defaults to 'semgrep'
                         which assumes it is on PATH.
        """
        self.semgrep_bin = semgrep_bin

    def is_available(self) -> bool:
        """Return True if semgrep is on PATH and responds to --version."""
        try:
            result = subprocess.run(
                [self.semgrep_bin, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def run(
        self,
        files: list[Path],
        rule_paths: list[Path],
        timeout_seconds: int = 120,
    ) -> list[dict]:
        """Run semgrep on the given files with the given rules.

        Returns raw Semgrep result dicts (one per finding).
        Returns empty list (never raises) on:
          - Semgrep not installed
          - Semgrep timeout
          - Semgrep non-zero exit with unparseable output
          - Empty file list or empty rule list

        Args:
            files: List of file paths to scan.
            rule_paths: List of paths to Semgrep rule YAML files.
            timeout_seconds: Maximum seconds before killing the subprocess.

        Returns:
            List of normalized finding dicts. Empty list on any error.
        """
        if not files or not rule_paths:
            return []

        try:
            return self._execute(files, rule_paths, timeout_seconds)
        except Exception:
            logger.exception("Unexpected error in SemgrepEngine.run")
            return []

    def _execute(
        self,
        files: list[Path],
        rule_paths: list[Path],
        timeout_seconds: int,
    ) -> list[dict]:
        """Internal execution method. Raises on errors for run() to catch."""
        # Write file list to a temporary file to avoid ARG_MAX limits
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            for f in files:
                tmp.write(f"{f}\n")
            target_list_path = tmp.name

        try:
            base_cmd = [
                self.semgrep_bin,
                "--json",
                "--quiet",
                "--no-git-ignore",
            ]

            for rule_path in rule_paths:
                base_cmd.extend(["--config", str(rule_path)])

            cmd = [*base_cmd, "--target-list", target_list_path]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            # Newer Semgrep builds may not support --target-list.
            if (
                result.returncode > 1
                and "unknown option '--target-list'" in result.stderr
            ):
                fallback_cmd = [*base_cmd, *[str(file) for file in files]]
                result = subprocess.run(
                    fallback_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                )

            # Semgrep exits with 1 when findings are present — this is normal
            # Exit codes > 1 indicate actual errors
            if result.returncode > 1:
                logger.warning(
                    "Semgrep exited with code %d: %s",
                    result.returncode,
                    result.stderr[:500] if result.stderr else "(no stderr)",
                )

            if not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            raw_results = data.get("results", [])

            return [self._parse_finding(r) for r in raw_results]

        except FileNotFoundError:
            logger.warning("Semgrep binary not found: %s", self.semgrep_bin)
            return []
        except subprocess.TimeoutExpired:
            logger.warning(
                "Semgrep timed out after %d seconds", timeout_seconds
            )
            return []
        except json.JSONDecodeError:
            logger.warning("Failed to parse Semgrep JSON output")
            return []
        finally:
            # Clean up the temporary target list file
            try:
                Path(target_list_path).unlink(missing_ok=True)
            except Exception:
                pass

    def _parse_finding(self, raw: dict) -> dict:
        """Normalize a single Semgrep finding dict into a flat dict.

        Maps nested Semgrep JSON structure to flat keys that correspond
        directly to Finding dataclass fields.

        Args:
            raw: A single result dict from Semgrep's JSON output.

        Returns:
            Flat dict with keys: check_id, path, line, col, message,
            severity, metadata, snippet.
        """
        extra = raw.get("extra", {})
        start = raw.get("start", {})
        end = raw.get("end", {})
        metadata = extra.get("metadata", {})

        # Build snippet from the matched lines
        lines = extra.get("lines", "")
        if isinstance(lines, str):
            snippet_lines = lines.strip().splitlines()[:3]
            snippet = "\n".join(snippet_lines)
        else:
            snippet = ""

        return {
            "check_id": raw.get("check_id", ""),
            "path": raw.get("path", ""),
            "line": start.get("line", 0),
            "col": start.get("col", 0),
            "end_line": end.get("line", 0),
            "end_col": end.get("col", 0),
            "message": extra.get("message", ""),
            "severity": extra.get("severity", ""),
            "metadata": metadata,
            "snippet": snippet,
        }

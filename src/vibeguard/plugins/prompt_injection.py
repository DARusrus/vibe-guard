from __future__ import annotations

import logging
import re
from pathlib import Path

from vibeguard.models import Finding
from vibeguard.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Direct instruction override
    re.compile(r"(?i)ignore\s+(previous|all|above|prior)\s+instructions?"),
    re.compile(r"(?i)forget\s+everything\s+(you\s+)?(know|learned)"),
    re.compile(r"(?i)disregard\s+(previous|all|prior)\s+(instructions?|context)"),
    re.compile(r"(?i)you\s+are\s+now\s+(a\s+)?different"),
    re.compile(r"(?i)new\s+system\s+prompt"),
    # Security bypass phrases specific to code review context
    re.compile(r"(?i)this\s+code\s+is\s+(legit|safe|secure|tested|approved)"),
    re.compile(r"(?i)(do\s+not|don't)\s+(flag|report|scan|analyze)\s+this"),
    re.compile(r"(?i)skip\s+(security|this)\s+(check|scan|analysis)"),
    re.compile(r"(?i)(sandbox|internal|verified)\s+environment"),
    re.compile(r"(?i)security\s+(approved|reviewed|cleared)"),
    # Prompt extraction attempts
    re.compile(r"(?i)print\s+(your\s+)?(system\s+)?prompt"),
    re.compile(r"(?i)reveal\s+(your\s+)?(instructions?|system)"),
    re.compile(r"(?i)what\s+(are|were)\s+your\s+instructions"),
]

_SCANNABLE_EXTENSIONS = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".json",
        ".yaml",
        ".yml",
    }
)

_STRING_DELIMITERS = re.compile(r"""(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')""")


class PromptInjectionPlugin(BasePlugin):
    """Detects adversarial LLM manipulation strings in source files.

    Scans for strings designed to manipulate LLM-based code reviewers
    into approving malicious code. This attack vector was confirmed
    in real npm packages in 2026.
    """

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "prompt_injection"

    def is_available(self) -> bool:
        """Always available — no external deps required."""
        return True

    def scan(self, files: list[Path], project_root: Path) -> list[Finding]:
        """Scan source files for prompt injection strings.

        Args:
            files: List of source files to scan.
            project_root: Root directory of the project.

        Returns:
            List of findings. Never raises.
        """
        try:
            return self._scan_impl(files, project_root)
        except Exception:
            logger.exception("PromptInjectionPlugin.scan failed")
            return []

    def _scan_impl(
        self,
        files: list[Path],
        project_root: Path,
    ) -> list[Finding]:
        """Core scan logic."""
        findings: list[Finding] = []
        seen_keys: set[tuple[str, str, int]] = set()

        # Collect scannable files from both provided list and project walk
        scan_files = self._collect_scannable_files(files, project_root)

        for file_path in scan_files:
            file_findings = self._scan_file(file_path)
            for f in file_findings:
                key = (f.rule_id, f.file_path, f.line)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(f)

        return findings

    def _collect_scannable_files(
        self,
        files: list[Path],
        project_root: Path,
    ) -> list[Path]:
        """Collect files to scan from both the provided list and project walk.

        Args:
            files: Explicitly provided file list.
            project_root: Project root for walking.

        Returns:
            Deduplicated list of scannable files.
        """
        result_set: set[Path] = set()

        # Add provided files that have scannable extensions
        for f in files:
            if f.suffix in _SCANNABLE_EXTENSIONS and f.is_file():
                result_set.add(f.resolve())

        # Walk project root for scannable files
        try:
            for ext in _SCANNABLE_EXTENSIONS:
                for f in project_root.rglob(f"*{ext}"):
                    if f.is_file():
                        result_set.add(f.resolve())
        except OSError:
            pass

        return list(result_set)

    def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file for prompt injection patterns.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of findings for this file.
        """
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        findings: list[Finding] = []

        for line_num, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if not line:
                continue

            # Extract string literals from the line
            strings = _STRING_DELIMITERS.findall(raw_line)
            if not strings:
                # For JSON/YAML files, the whole line may be the value
                if file_path.suffix in (".json", ".yaml", ".yml"):
                    strings = [raw_line]
                else:
                    continue

            for string_content in strings:
                # Remove surrounding quotes for matching
                inner = string_content
                if len(inner) >= 2 and inner[0] in ('"', "'") and inner[-1] == inner[0]:
                    inner = inner[1:-1]

                for pattern in INJECTION_PATTERNS:
                    if pattern.search(inner):
                        findings.append(
                            self._make_finding(
                                rule_id="vibeguard-prompt-injection-string",
                                severity="CRITICAL",
                                file_path=str(file_path),
                                line=line_num,
                                message=(
                                    "Adversarial LLM manipulation string detected in source. "
                                    "This pattern attempts to override AI code review tools."
                                ),
                                fix_guidance=(
                                    "Remove this string. If it appeared in a dependency, "
                                    "do not install that package — report it to the "
                                    "registry as malicious."
                                ),
                                cwe_id="CWE-116: Improper Encoding or Escaping of Output",
                                ai_context=(
                                    "Malicious packages embed prompt injection strings to "
                                    "manipulate LLM-based code reviewers into classifying "
                                    "them as safe. This was confirmed in a real npm package "
                                    "(eslint-plugin-unicorn-ts-2) in 2026."
                                ),
                                rule_category="prompt_injection",
                            )
                        )
                        break  # One finding per string, avoid duplicates

        return findings

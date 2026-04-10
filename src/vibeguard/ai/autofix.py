"""AI-powered auto-fix engine for security findings.

Generates contextually correct secure code replacements using
Gemini Flash. Falls back to manual fix_guidance when no API key
is configured.
"""

from __future__ import annotations

import difflib

from vibeguard.ai.client import AIClient
from vibeguard.models import Finding


class AutoFixer:
    """Generates contextually correct secure code replacements."""

    def __init__(self) -> None:
        self.client = AIClient()

    def generate_fix(
        self,
        finding: Finding,
        source_context: str,
    ) -> str | None:
        """Generate a secure replacement for the vulnerable code.

        Returns a unified diff string or None if unavailable.

        Args:
            finding: The security finding to fix.
            source_context: 5 lines before the finding, the finding line,
                            and 5 lines after.

        Returns:
            Unified diff string, or None if AI is unavailable.
        """
        if not self.client.is_available():
            return None

        context_lines = source_context.splitlines()
        context_start = max(0, finding.line - 6)
        snippet_line_idx = finding.line - 1 - context_start
        if 0 <= snippet_line_idx < len(context_lines):
            actual_snippet = context_lines[snippet_line_idx]
        else:
            actual_snippet = finding.snippet or ""

        cache_key = f"{finding.rule_id}:{actual_snippet[:50]}"
        prompt = self._build_prompt(finding, actual_snippet, source_context)
        response = self.client.complete(
            prompt,
            max_tokens=400,
            cache_key=cache_key,
        )
        if response is None:
            return None
        return self._format_as_diff(
            actual_snippet,
            response.strip(),
            finding.file_path,
            finding.line,
        )

    def _build_prompt(
        self,
        finding: Finding,
        vulnerable_code: str,
        context: str,
    ) -> str:
        """Build the prompt for the Gemini API."""
        return (
            "You are a secure code expert. Generate a secure replacement\n"
            "for this vulnerable code snippet.\n\n"
            f"VULNERABILITY: {finding.rule_id}\n"
            f"SEVERITY: {finding.severity}\n"
            f"ISSUE: {finding.message}\n"
            f"FIX GUIDANCE: {finding.fix_guidance}\n\n"
            f"VULNERABLE CODE (line {finding.line}):\n"
            f"{vulnerable_code}\n\n"
            "NEARBY CONTEXT (read-only):\n"
            f"{context}\n\n"
            "Generate ONLY the corrected version of the vulnerable lines.\n"
            "Return ONLY the replacement lines.\n"
            "Do not repeat the surrounding context.\n"
            "Do not include the lines before or after the vulnerable section.\n"
            "No explanation. No markdown. Just the corrected code.\n"
            "Preserve indentation exactly."
        )

    def _format_as_diff(
        self,
        original: str,
        fixed: str,
        file_path: str,
        line: int,
    ) -> str | None:
        """Format as a minimal unified diff."""
        orig_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)
        # Ensure trailing newlines for clean diff output
        if orig_lines and not orig_lines[-1].endswith("\n"):
            orig_lines[-1] += "\n"
        if fixed_lines and not fixed_lines[-1].endswith("\n"):
            fixed_lines[-1] += "\n"
        diff = difflib.unified_diff(
            orig_lines,
            fixed_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            n=3,
        )
        diff_text = "".join(diff)
        if not diff_text.strip():
            return None
        return diff_text

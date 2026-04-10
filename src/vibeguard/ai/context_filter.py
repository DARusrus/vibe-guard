"""Smart false-positive filter using LLM context analysis.

Uses Gemini Flash to distinguish real vulnerabilities from false
positives by analyzing surrounding code context. Conservative by
default — assumes real if AI is unavailable.
"""

from __future__ import annotations

from vibeguard.ai.client import AIClient
from vibeguard.models import Finding


class ContextFilter:
    """Uses LLM to reduce false positives for HIGH/CRITICAL findings."""

    def __init__(self) -> None:
        self.client = AIClient()
        self._cache: dict[str, bool] = {}

    def is_true_positive(
        self,
        finding: Finding,
        file_content: str,
    ) -> bool:
        """Return True if the finding is a real vulnerability.

        Returns True (assume real) if AI is unavailable.
        Never raises.

        Args:
            finding: The security finding to evaluate.
            file_content: Full content of the source file.

        Returns:
            True if likely a real vulnerability, False if likely FP.
        """
        if not self.client.is_available():
            return True  # Conservative: assume real if no AI

        cache_key = f"{finding.rule_id}:{finding.file_path}:{finding.line}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Extract context around finding
        lines = file_content.splitlines()
        start = max(0, finding.line - 6)
        end = min(len(lines), finding.line + 5)
        context = "\n".join(lines[start:end])

        prompt = (
            "Is this a real security vulnerability or a false positive?\n\n"
            f"RULE: {finding.rule_id}\n"
            f"SEVERITY: {finding.severity}\n"
            f"MESSAGE: {finding.message}\n\n"
            f"CODE CONTEXT (lines {start + 1}-{end}):\n"
            f"{context}\n\n"
            "Answer with exactly one word: TRUE (real vulnerability) "
            "or FALSE (false positive).\n"
            "Consider: Is user-controlled data actually reaching the "
            "vulnerable sink?\n"
            "Is there sanitization or validation in the context shown?"
        )

        response = self.client.complete(prompt, max_tokens=10, cache_key=cache_key)
        result = response is None or "TRUE" in response.upper()
        self._cache[cache_key] = result
        return result

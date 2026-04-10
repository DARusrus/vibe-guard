"""Plain-English attack scenario explainer.

Uses Gemini Flash to generate 3-sentence vulnerability explanations
aimed at developers without security backgrounds.
"""

from __future__ import annotations

from vibeguard.ai.client import AIClient
from vibeguard.models import Finding


class Explainer:
    """Generates plain-English attack scenario explanations."""

    def __init__(self) -> None:
        self.client = AIClient()

    def explain(self, finding: Finding, language: str = "python") -> str | None:
        """Return plain-English explanation of the attack.

        Returns None if AI is unavailable. Never raises.

        Args:
            finding: The security finding to explain.
            language: The programming language of the vulnerable code.

        Returns:
            Plain-English explanation string, or None.
        """
        prompt = (
            "Explain this security vulnerability to a developer who\n"
            "may not have a security background. They used an AI coding tool "
            "and this\nvulnerability appeared in their code.\n\n"
            f"VULNERABILITY: {finding.severity} — {finding.rule_id}\n"
            f"WHAT WAS FOUND: {finding.message}\n"
            f"VULNERABLE CODE: {finding.snippet}\n"
            f"LANGUAGE: {language}\n\n"
            "Write 3 short sentences:\n"
            "1. What an attacker can do with this vulnerability "
            "(be specific and concrete)\n"
            "2. What data or systems are at risk\n"
            "3. How likely this is to be exploited in the real world\n\n"
            "Use plain English. No jargon. Write like you are explaining "
            "to a smart\nnon-security person. Do not repeat the rule name."
        )

        return self.client.complete(prompt, max_tokens=200)

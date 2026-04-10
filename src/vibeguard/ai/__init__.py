"""AI-powered features for vibe-guard.

Provides autofix, explain, and smart false-positive filtering
via the Gemini Flash API. All features degrade gracefully when
GEMINI_API_KEY is not set.
"""

from __future__ import annotations

__all__ = ["AIClient", "AutoFixer", "ContextFilter", "Explainer"]


def __getattr__(name: str) -> object:
    """Lazy imports to avoid unnecessary API client instantiation."""
    if name == "AIClient":
        from vibeguard.ai.client import AIClient

        return AIClient
    if name == "AutoFixer":
        from vibeguard.ai.autofix import AutoFixer

        return AutoFixer
    if name == "ContextFilter":
        from vibeguard.ai.context_filter import ContextFilter

        return ContextFilter
    if name == "Explainer":
        from vibeguard.ai.explain import Explainer

        return Explainer
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)

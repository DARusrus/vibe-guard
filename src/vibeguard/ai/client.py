"""Thin wrapper for the Gemini Flash API.

All AI features (autofix, explain, smart-filter) go through this client.
Falls back gracefully when GEMINI_API_KEY is not set — never raises,
never prompts the user.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

API_KEY_ENV = "GEMINI_API_KEY"
GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/"
    "models/gemini-2.0-flash:generateContent"
)

_TIMEOUT_SECONDS = 15
_MAX_RETRIES = 1


class AIClient:
    """Thin wrapper for Gemini Flash API. All AI features use this."""

    def __init__(self) -> None:
        self.api_key: str | None = os.environ.get(API_KEY_ENV)
        self.available: bool = self.api_key is not None
        self._cache: dict[str, str] = {}

    def complete(
        self,
        prompt: str,
        max_tokens: int = 512,
        cache_key: str | None = None,
    ) -> str | None:
        """Call Gemini Flash. Returns None on error or if unavailable.

        Never raises. Caches responses by cache_key if provided.
        Timeout: 15 seconds. Retries: 1.
        """
        if not self.available:
            return None

        if cache_key and cache_key in self._cache:
            return self._cache[cache_key]

        body = self._build_request(prompt, max_tokens)
        result = self._call_api(body)

        if result is not None and cache_key:
            self._cache[cache_key] = result

        return result

    def is_available(self) -> bool:
        """True if GEMINI_API_KEY is set."""
        return self.available

    def _build_request(self, prompt: str, max_tokens: int) -> dict:
        """Build the Gemini API request body."""
        return {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": 0.1,
            },
        }

    def _parse_response(self, response_json: dict) -> str | None:
        """Extract text from Gemini response. Return None on any error."""
        try:
            return response_json["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError):
            return None

    def _call_api(self, body: dict) -> str | None:
        """Execute the HTTP call with retry logic. Never raises."""
        url = f"{GEMINI_API_URL}?key={self.api_key}"
        data = json.dumps(body).encode("utf-8")

        for attempt in range(_MAX_RETRIES + 1):
            try:
                req = urllib.request.Request(
                    url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
                    response_json = json.loads(resp.read().decode("utf-8"))
                    return self._parse_response(response_json)
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                logger.debug(
                    "Gemini API call attempt %d failed: %s", attempt + 1, exc
                )
                if attempt >= _MAX_RETRIES:
                    return None
            except Exception:
                logger.debug("Unexpected error calling Gemini API", exc_info=True)
                return None
        return None

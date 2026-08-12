"""Ingress sanitization for user prompts (see docs/ARCHITECTURE.md §3.1 step 2).

This is a defense-in-depth layer, NOT the primary security control — it only
mitigates the crudest injection/resource-exhaustion patterns. It must never
be presented as a complete defense on its own.
"""

from __future__ import annotations

import re
import unicodedata


def sanitize(prompt: str, max_length: int, deny_patterns: list[str]) -> tuple[bool, str | None]:
    """Normalize, length-cap and pattern-check a raw user prompt.

    Returns (ok, cleaned_prompt). If ok is False, the caller must reject the
    request with ErrorCode.POLICY_VIOLATION without calling the LLM.
    """
    normalized = unicodedata.normalize("NFKC", prompt)

    if len(normalized) > max_length:
        return False, None

    for pattern in deny_patterns:
        if re.search(pattern, normalized, re.IGNORECASE):
            return False, None

    return True, normalized

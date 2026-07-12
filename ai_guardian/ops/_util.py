"""Shared helpers for AI Guardian ops modules.

Normalises Ollama model/runtime records and sanitises all model-supplied text
(names, licenses, templates) before it reaches the agent — a local model's
metadata is still untrusted input per the prompt-injection defense.
"""

from __future__ import annotations

from typing import Any

from ai_guardian.governance import sanitize


def as_list(data: Any, key: str = "models") -> list[dict]:
    """Ollama list endpoints wrap results in ``{"models": [...]}``."""
    if isinstance(data, dict):
        items = data.get(key, [])
    else:
        items = data
    return [i for i in (items or []) if isinstance(i, dict)]


def as_obj(data: Any) -> dict:
    return data if isinstance(data, dict) else {}


def s(value: Any, limit: int = 256) -> str:
    """Sanitize an arbitrary value to a bounded, injection-safe string."""
    return sanitize(str(value if value is not None else ""), limit)


def base_model(name: str) -> str:
    """Normalise a model ref to its base name (strip ``:tag``, lowercase)."""
    return s(name, 128).split(":")[0].strip().lower()

"""Shared helpers for AI Guardian ops modules.

Normalises Ollama model/runtime records and sanitises all model-supplied text
(names, licenses, templates) before it reaches the agent — a local model's
metadata is still untrusted input per the output-hygiene rule.
"""

from __future__ import annotations

from typing import Any

from ai_guardian.governance import opt_str, sanitize


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


def opt_s(value: Any, limit: int = 256) -> str | None:
    """Sanitize a value that may legitimately be absent, preserving that absence.

    Companion to :func:`s`, which folds ``None`` into ``""``. That conflation
    matters more here than almost anywhere: this tool's whole job is reporting
    honestly on local models, and several runtimes genuinely expose no digest, no
    version, and no license. ``""`` reads as "the runtime reported this and it
    was blank"; the truth is "this runtime cannot tell you". A smaller local
    model reading its own governance report will not recover that difference.

    Absence stays ``null`` — which ``model_provenance`` already reads as
    ``unverifiable`` rather than as drift. Use :func:`s` for values that are
    always present, and for anything fed to ``fnmatch`` or ``.split()``.
    """
    return opt_str(value, limit)


def base_model(name: str) -> str:
    """Normalise a model ref to its base name (strip ``:tag``, lowercase)."""
    return s(name, 128).split(":")[0].strip().lower()

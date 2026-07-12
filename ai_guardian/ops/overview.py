"""One-shot AI Guardian posture (read-only).

Folds model inventory + policy verdicts + observed-usage stats into one summary.
Resilient — a failing sub-call degrades to a partial summary with ``errors``.
"""

from __future__ import annotations

from typing import Any

from ai_guardian.config import AppConfig


def posture_overview(conn: Any, config: AppConfig, store: Any) -> dict:
    """[READ] Models installed/running, shadow count, and observed-usage stats."""
    from ai_guardian.ops.models import list_models, running_models

    errors: list[str] = []

    def _safe(fn: Any, label: str, default: Any) -> Any:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 — collect, keep going
            errors.append(f"{label}: {str(exc)[:120]}")
            return default

    installed = _safe(lambda: list_models(conn, config), "models", [])
    running = _safe(lambda: running_models(conn, config), "running", [])
    stats = store.stats()

    return {
        "installedModels": len(installed),
        "runningModels": len(running),
        "shadowModels": sum(1 for m in installed if not m.get("allowed")),
        "observedPrompts": stats["total"],
        "highRiskObserved": stats["byRisk"].get("high", 0) + stats["byRisk"].get("critical", 0),
        "blockedObserved": stats["disallowed"],
        "errors": errors,
    }

"""Model inventory, runtime state, and lifecycle across local-LLM runtimes.

Reads annotate each installed/running model with the allow/deny policy verdict so
shadow (unsanctioned) models are visible at a glance — for Ollama and for the
OpenAI-compatible runtimes (llama.cpp / LM Studio / vLLM) alike, dispatched on the
target's runtime. Writes (pull / remove / unload) are Ollama-native; the
OpenAI-compatible servers load a model at startup and expose no lifecycle
endpoint, so those writes are refused for them with a clear message.
``remove_model`` captures the model's manifest before deleting so the harness can
record an undo (re-pull) descriptor.
"""

from __future__ import annotations

from typing import Any

from ai_guardian.config import AppConfig
from ai_guardian.ops._util import as_list, as_obj, opt_s, s
from ai_guardian.runtimes import runtime_for_conn

_TAGS = "/api/tags"
_PS = "/api/ps"
_SHOW = "/api/show"
_PULL = "/api/pull"
_DELETE = "/api/delete"
_GENERATE = "/api/generate"
_VERSION = "/api/version"


def _norm_model(raw: dict, config: AppConfig) -> dict:
    details = raw.get("details") or {}
    name = s(raw.get("name") or raw.get("model"))
    return {
        "name": name,
        "digest": opt_s(raw.get("digest"), 80),
        "sizeBytes": raw.get("size"),
        "family": opt_s(details.get("family")),
        "parameterSize": opt_s(details.get("parameter_size"), 32),
        "quantization": opt_s(details.get("quantization_level"), 32),
        "modifiedAt": opt_s(raw.get("modified_at"), 40),
        "allowed": config.model_allowed(name),
    }


def list_models(conn: Any, config: AppConfig) -> list[dict]:
    """[READ] Installed models, each annotated with the allow/deny verdict."""
    spec = runtime_for_conn(conn)
    if spec.is_openai_compat:
        from ai_guardian.ops import openai_compat as oc

        return oc.list_models(conn, config, spec)
    return [_norm_model(r, config) for r in as_list(conn.get(_TAGS))]


def running_models(conn: Any, config: AppConfig) -> list[dict]:
    """[READ] Currently loaded models: VRAM footprint + residency expiry."""
    spec = runtime_for_conn(conn)
    if spec.is_openai_compat:
        from ai_guardian.ops import openai_compat as oc

        return oc.running_models(conn, config, spec)
    rows = []
    for r in as_list(conn.get(_PS)):
        name = s(r.get("name") or r.get("model"))
        rows.append({
            "name": name,
            "digest": opt_s(r.get("digest"), 80),
            "sizeVramBytes": r.get("size_vram"),
            "expiresAt": opt_s(r.get("expires_at"), 40),
            "allowed": config.model_allowed(name),
        })
    return rows


def model_details(conn: Any, model: str) -> dict:
    """[READ] License / parameters / capabilities for one model (/api/show)."""
    spec = runtime_for_conn(conn)
    if spec.is_openai_compat:
        from ai_guardian.ops import openai_compat as oc

        return oc.model_details(conn, model, spec)
    raw = as_obj(conn.post(_SHOW, json={"model": model}))
    details = raw.get("details") or {}
    return {
        "model": s(model),
        "license": opt_s(raw.get("license"), 400),
        "family": opt_s(details.get("family")),
        "parameterSize": opt_s(details.get("parameter_size"), 32),
        "quantization": opt_s(details.get("quantization_level"), 32),
        "capabilities": [s(c, 32) for c in (raw.get("capabilities") or [])],
    }


def server_status(conn: Any) -> dict:
    """[READ] Runtime reachability + version (version blank for non-Ollama)."""
    spec = runtime_for_conn(conn)
    if spec.is_openai_compat:
        from ai_guardian.ops import openai_compat as oc

        return oc.server_status(conn, spec)
    try:
        info = as_obj(conn.get(_VERSION))
        return {"reachable": True, "version": opt_s(info.get("version"), 32)}
    except Exception as exc:  # noqa: BLE001 — status, not a crash
        return {"reachable": False, "error": s(exc, 200)}


def vram_usage(conn: Any, budget_bytes: int | None = None) -> dict:
    """[READ] Total VRAM used by loaded models; flag over-budget.

    OpenAI-compatible runtimes expose no per-model VRAM figure, so the total is
    reported as ``None`` (unknown) rather than guessed."""
    spec = runtime_for_conn(conn)
    if spec.is_openai_compat:
        from ai_guardian.ops import openai_compat as oc

        loaded = oc.running_models(conn, AppConfig(), spec)
        return {"loadedModels": len(loaded), "totalVramBytes": None,
                "budgetBytes": budget_bytes, "overBudget": False,
                "models": [{"name": m["name"], "sizeVramBytes": None} for m in loaded]}
    loaded = as_list(conn.get(_PS))
    total = sum(m.get("size_vram") or 0 for m in loaded)
    return {
        "loadedModels": len(loaded),
        "totalVramBytes": total,
        "budgetBytes": budget_bytes,
        "overBudget": bool(budget_bytes and total > budget_bytes),
        "models": [{"name": s(m.get("name")), "sizeVramBytes": m.get("size_vram")}
                   for m in loaded],
    }


# ── writes ───────────────────────────────────────────────────────────────


def _require_lifecycle(conn: Any, action: str) -> None:
    """Guard model-lifecycle writes to Ollama-only runtimes."""
    spec = runtime_for_conn(conn)
    if not spec.supports_lifecycle:
        raise ValueError(
            f"{spec.display_name} does not support '{action}' via its API — it loads "
            f"a model at server start. Manage the model in the runtime itself "
            f"({spec.start_hint})."
        )


def pull_model(conn: Any, config: AppConfig, model: str) -> dict:
    """[WRITE] Pull a model — refused if the model is on the denylist."""
    _require_lifecycle(conn, "pull_model")
    if not config.model_allowed(model):
        raise ValueError(
            f"Model '{model}' is not permitted by policy (denylist or not on the "
            f"allowlist). Update the allowlist first if this is sanctioned."
        )
    conn.post(_PULL, json={"model": model, "stream": False})
    return {"action": "pull_model", "model": s(model)}


def remove_model(conn: Any, model: str) -> dict:
    """[WRITE][high] Delete a local model — captures its manifest for undo (re-pull)."""
    _require_lifecycle(conn, "remove_model")
    prior = {}
    try:
        prior = model_details(conn, model)
    except Exception:  # noqa: BLE001 — best-effort manifest capture
        prior = {"model": s(model)}
    conn.delete(_DELETE, json={"model": model})
    return {"action": "remove_model", "model": s(model),
            "priorState": {"model": s(model), "license": prior.get("license"),
                           "family": prior.get("family")}}


def unload_model(conn: Any, model: str) -> dict:
    """[WRITE] Evict a model from VRAM (keep_alive:0)."""
    _require_lifecycle(conn, "unload_model")
    conn.post(_GENERATE, json={"model": model, "prompt": "", "keep_alive": 0})
    return {"action": "unload_model", "model": s(model)}

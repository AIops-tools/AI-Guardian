"""Model allow/deny policy + provenance pinning (view + governed writes).

Policy lives in ``~/.ai-guardian/config.yaml`` (non-secret): ``allowed_models`` /
``denied_models`` (shell-glob patterns) and ``pinned_digests`` (model → expected
digest). ``model_provenance`` compares each installed model's current digest
against its pin and flags **drift** (re-pulled / tampered / renamed weights) — a
supply-chain signal for local models.
"""

from __future__ import annotations

from typing import Any

import yaml

from ai_guardian.config import CONFIG_DIR, CONFIG_FILE, AppConfig
from ai_guardian.ops._util import s


def policy_view(config: AppConfig) -> dict:
    """[READ] The current model allow/deny policy + provenance pins."""
    return {
        "allowedModels": list(config.allowed_models),
        "deniedModels": list(config.denied_models),
        "pinnedDigests": config.pins,
        "note": "Empty allowlist = allow-all. Deny patterns always win.",
    }


def _load_raw() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    return yaml.safe_load(CONFIG_FILE.read_text("utf-8")) or {}


def _write_raw(doc: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.chmod(0o700)
    except OSError:
        pass
    CONFIG_FILE.write_text(yaml.safe_dump(doc, sort_keys=False), "utf-8")


def set_allowlist(models: list[str]) -> dict:
    """[WRITE] Replace the model allowlist (immutable replace, not append)."""
    doc = _load_raw()
    prior = list(doc.get("allowed_models", []) or [])
    doc["allowed_models"] = [s(m, 128) for m in models]
    _write_raw(doc)
    return {"action": "set_model_allowlist", "allowedModels": doc["allowed_models"],
            "priorState": {"allowedModels": prior}}


def set_denylist(models: list[str]) -> dict:
    """[WRITE] Replace the model denylist."""
    doc = _load_raw()
    prior = list(doc.get("denied_models", []) or [])
    doc["denied_models"] = [s(m, 128) for m in models]
    _write_raw(doc)
    return {"action": "set_model_denylist", "deniedModels": doc["denied_models"],
            "priorState": {"deniedModels": prior}}


def pin_model_digest(model: str, digest: str) -> dict:
    """[WRITE] Pin a model's expected provenance digest."""
    doc = _load_raw()
    pins = dict(doc.get("pinned_digests", {}) or {})
    prior = pins.get(model)
    pins[model] = s(digest, 80)
    doc["pinned_digests"] = pins
    _write_raw(doc)
    return {"action": "pin_model_digest", "model": s(model), "digest": s(digest, 80),
            "priorState": {"digest": prior}}


def model_provenance(conn: Any, config: AppConfig) -> dict:
    """[READ] Compare each installed model's digest against its pin; flag drift.

    Provenance strength varies by runtime: Ollama and llama.cpp expose a digest
    (content hash / derived ``/props`` identity), so a mismatch is real **DRIFT**.
    LM Studio / vLLM expose only a model id — no weight identity — so a pinned
    model with no digest is reported ``unverifiable`` (honestly weaker), never a
    false DRIFT."""
    from ai_guardian.ops.models import list_models

    pins = config.pins
    installed = list_models(conn, config)
    rows = []
    drift = 0
    for m in installed:
        pinned = pins.get(m["name"])
        current = m["digest"]
        if not pinned:
            status = "unpinned"
        elif not current:
            status = "unverifiable"  # runtime exposes no digest to compare
        elif pinned == current:
            status = "ok"
        else:
            status = "DRIFT"
            drift += 1
        rows.append({"model": m["name"], "currentDigest": current,
                     "pinnedDigest": pinned, "status": status})
    return {"driftCount": drift, "pinnedCount": len(pins), "models": rows}

"""Route-through content governance + usage/anomaly reporting.

Local runtimes keep no prompt history, so *content* is observed by routing a
prompt THROUGH the guardian: ``guarded_generate`` / ``observe_chat`` scan the
prompt (secrets / PII / code / jailbreak), check the model against policy, decide
block-or-pass by risk band, record the interaction to ai-guardian's own usage
log, and only then (if allowed) call the runtime — Ollama's native API or an
OpenAI-compatible ``/v1/chat/completions`` (llama.cpp / LM Studio / vLLM),
dispatched on the target's runtime. The raw prompt is never stored — only its
length and the redacted findings.
"""

from __future__ import annotations

from typing import Any

from ai_guardian import scanner
from ai_guardian.config import AppConfig
from ai_guardian.ops._util import s
from ai_guardian.runtimes import runtime_for_conn

_GENERATE = "/api/generate"
_CHAT = "/api/chat"

# band ordering for threshold comparisons
_BANDS = ("none", "low", "medium", "high", "critical")


def _band_ge(band: str, threshold: str) -> bool:
    try:
        return _BANDS.index(band) >= _BANDS.index(threshold)
    except ValueError:
        return False


def scan_prompt(text: str) -> dict:
    """[READ] Pure content scan of a supplied text — no Ollama call."""
    return scanner.summarize(scanner.scan_text(text))


def _observe(conn: Any, config: AppConfig, store: Any, *, model: str, text: str,
             agent: str, user: str, block_threshold: str, call: Any) -> dict:
    """Shared scan → policy → record → (maybe) call flow."""
    summary = scanner.summarize(scanner.scan_text(text))
    band = summary["riskBand"]
    model_allowed = config.model_allowed(model)
    blocked = (not model_allowed) or _band_ge(band, block_threshold)

    store.record(target=s(conn.target.name), model=s(model), agent=s(agent, 32),
                 user=s(user, 64), prompt_chars=len(text or ""), risk_level=band,
                 findings=summary["findings"], allowed=not blocked)

    result = {"model": s(model), "riskBand": band, "findings": summary["findings"],
              "modelAllowed": model_allowed, "blocked": blocked}
    if blocked:
        reason = ("model not permitted by policy" if not model_allowed
                  else f"prompt risk band '{band}' >= block threshold '{block_threshold}'")
        result["reason"] = reason
        return result
    result["response"] = call()
    return result


def guarded_generate(conn: Any, config: AppConfig, store: Any, model: str, prompt: str,
                     agent: str = "unknown", user: str = "",
                     block_threshold: str = "high") -> dict:
    """[WRITE] Scan + policy-gate a generate prompt, record it, then run if allowed."""
    def _call() -> str:
        spec = runtime_for_conn(conn)
        if spec.is_openai_compat:
            from ai_guardian.ops import openai_compat as oc

            return oc.generate_completion(conn, model, prompt)
        resp = conn.post(_GENERATE, json={"model": model, "prompt": prompt, "stream": False})
        return s((resp or {}).get("response"), 4000) if isinstance(resp, dict) else ""

    return _observe(conn, config, store, model=model, text=prompt, agent=agent,
                    user=user, block_threshold=block_threshold, call=_call)


def observe_chat(conn: Any, config: AppConfig, store: Any, model: str, messages: list[dict],
                 agent: str = "unknown", user: str = "",
                 block_threshold: str = "high") -> dict:
    """[WRITE] Scan + policy-gate a /api/chat exchange, record it, then run if allowed."""
    text = "\n".join(s(m.get("content"), 4000) for m in (messages or [])
                     if isinstance(m, dict))

    def _call() -> str:
        spec = runtime_for_conn(conn)
        if spec.is_openai_compat:
            from ai_guardian.ops import openai_compat as oc

            return oc.chat_completion(conn, model, messages)
        resp = conn.post(_CHAT, json={"model": model, "messages": messages, "stream": False})
        msg = (resp or {}).get("message") if isinstance(resp, dict) else None
        return s((msg or {}).get("content"), 4000) if isinstance(msg, dict) else ""

    return _observe(conn, config, store, model=model, text=text, agent=agent,
                    user=user, block_threshold=block_threshold, call=_call)


def usage_events(store: Any, model: str | None = None, risk_level: str | None = None,
                 allowed: bool | None = None, since: str | None = None,
                 limit: int = 100) -> dict:
    """[READ] Query ai-guardian's observed-usage log."""
    rows = store.query(model=model, risk_level=risk_level, allowed=allowed,
                       since=since, limit=limit)
    return {"count": len(rows), "events": rows}


def anomaly_report(conn: Any, config: AppConfig, store: Any) -> dict:
    """[READ] Rollup: shadow models, digest drift, high-risk usage, blocked count."""
    from ai_guardian.ops.models import list_models
    from ai_guardian.ops.policy import model_provenance

    try:
        installed = list_models(conn, config)
        shadow = [m["name"] for m in installed if not m["allowed"]]
    except Exception as exc:  # noqa: BLE001 — degrade to partial
        return {"error": s(exc, 200)}
    try:
        prov = model_provenance(conn, config)
        drift = [r["model"] for r in prov["models"] if r["status"] == "DRIFT"]
    except Exception:  # noqa: BLE001
        drift = []

    stats = store.stats()
    high_risk = stats["byRisk"].get("high", 0) + stats["byRisk"].get("critical", 0)
    return {
        "shadowModels": shadow,
        "digestDrift": drift,
        "highRiskPrompts": high_risk,
        "blockedPrompts": stats["disallowed"],
        "totalObserved": stats["total"],
    }

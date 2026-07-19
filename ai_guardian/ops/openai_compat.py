"""Shared OpenAI-compatible transport for local LLM runtimes.

ONE implementation of the ``/v1/models`` + ``/v1/chat/completions`` shape backs
every OpenAI-compatible runtime — **llama.cpp** (``llama-server``), **LM Studio**,
and **local single-node vLLM** — so there is no per-runtime copy. Per-runtime
differences (default port, health probe, provenance richness) are carried by the
:class:`~ai_guardian.runtimes.RuntimeSpec` passed in, not branched here.

Provenance honesty:
- **llama.cpp** exposes ``/props`` (served model path + size) → a stable, pinnable
  identity digest is derived from it.
- **LM Studio / vLLM** expose only a model **id** → no weight identity; the digest
  is left empty and drift is reported as ``unverifiable`` (see ops/policy.py).

Model lifecycle (pull / remove / unload) is intentionally NOT implemented: these
servers load a model at startup and expose no OpenAI endpoint to change it — the
ops layer refuses those writes for OpenAI-compatible runtimes.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ai_guardian.config import AppConfig
from ai_guardian.ops._util import opt_s, s
from ai_guardian.runtimes import PROV_PROPS, RuntimeSpec

_MODELS = "/v1/models"
_CHAT = "/v1/chat/completions"


def _data_list(payload: Any) -> list[dict]:
    """OpenAI list endpoints wrap results in ``{"object":"list","data":[...]}``."""
    items = payload.get("data") if isinstance(payload, dict) else payload
    return [i for i in (items or []) if isinstance(i, dict)]


def _props_identity(props: dict) -> tuple[str, int | None]:
    """Derive a stable (digest, sizeBytes) identity from a llama.cpp ``/props``.

    ``/props`` reports the served model's path and (when available) size. The
    digest is a short hash of ``path|size`` — weaker than a content hash but
    stable enough to pin and detect a swapped weights file. Returns ``("", None)``
    when the runtime exposes no path (nothing to pin honestly)."""
    gen = props.get("default_generation_settings")
    gen = gen if isinstance(gen, dict) else {}
    model_path = props.get("model_path") or gen.get("model") or props.get("model")
    size = props.get("model_size") or gen.get("model_size")
    size_int = size if isinstance(size, int) else None
    if not model_path:
        return "", size_int
    material = f"{model_path}|{size_int}".encode()
    digest = "gguf:" + hashlib.sha256(material).hexdigest()[:16]  # nosec B324 — identity, not auth
    return digest, size_int


def _fetch_props(conn: Any, spec: RuntimeSpec) -> dict:
    if not (spec.props_path and spec.provenance == PROV_PROPS):
        return {}
    try:
        raw = conn.get(spec.props_path)
        return raw if isinstance(raw, dict) else {}
    except Exception:  # noqa: BLE001 — provenance enrichment is best-effort
        return {}


def _norm_model(raw: dict, config: AppConfig, digest: str, size: int | None) -> dict:
    name = s(raw.get("id") or raw.get("model") or raw.get("name"))
    return {
        "name": name,
        "digest": opt_s(digest, 80) or None,
        "sizeBytes": raw.get("size") or size,
        "family": opt_s(raw.get("owned_by")),
        # This API carries no parameter/quantization block at all — null says
        # "the runtime cannot tell you", which "" does not.
        "parameterSize": None,
        "quantization": None,
        "modifiedAt": opt_s(raw.get("created"), 40),
        "allowed": config.model_allowed(name),
    }


def list_models(conn: Any, config: AppConfig, spec: RuntimeSpec) -> list[dict]:
    """[READ] Served models (``GET /v1/models``), each with the allow/deny verdict.

    For llama.cpp the single served model is enriched with a ``/props``-derived
    provenance digest + size; id-only runtimes leave the digest empty."""
    props = _fetch_props(conn, spec)
    digest, size = _props_identity(props) if props else ("", None)
    return [_norm_model(r, config, digest, size) for r in _data_list(conn.get(_MODELS))]


def running_models(conn: Any, config: AppConfig, spec: RuntimeSpec) -> list[dict]:
    """[READ] Served models treated as loaded (these servers load at startup).

    No per-model VRAM figure is exposed over the OpenAI API, so ``sizeVramBytes``
    is ``None`` — reported honestly rather than guessed."""
    return [
        {
            "name": m["name"],
            "digest": m["digest"],
            "sizeVramBytes": None,
            "expiresAt": None,  # these servers hold a model for the process lifetime
            "allowed": m["allowed"],
        }
        for m in list_models(conn, config, spec)
    ]


def model_details(conn: Any, model: str, spec: RuntimeSpec) -> dict:
    """[READ] Best-effort metadata for one served model.

    The OpenAI API carries no license/capability block; llama.cpp adds the served
    model path/size via ``/props``. Fields absent for a runtime are returned
    empty (documented weaker provenance), never fabricated."""
    props = _fetch_props(conn, spec)
    digest, size = _props_identity(props) if props else ("", None)
    return {
        "model": s(model),
        # Absent from the OpenAI API, not empty in the model: null, never "".
        "license": None,
        "family": None,
        "parameterSize": None,
        "quantization": None,
        "capabilities": [],
        "digest": opt_s(digest, 80) or None,
        "sizeBytes": size,
        "runtime": spec.name,
    }


def server_status(conn: Any, spec: RuntimeSpec) -> dict:
    """[READ] Reachability via the runtime's health probe.

    llama.cpp has a native ``/health``; LM Studio / vLLM reuse ``/v1/models`` as a
    liveness probe. No version string is exposed, so ``version`` is empty."""
    try:
        conn.get(spec.health_path)
        # No version string is exposed by this API — unknown, not blank.
        return {"reachable": True, "version": None}
    except Exception as exc:  # noqa: BLE001 — status, not a crash
        return {"reachable": False, "error": s(exc, 200)}


def chat_completion(conn: Any, model: str, messages: list[dict]) -> str | None:
    """POST ``/v1/chat/completions`` → the first choice's message content.

    ``None`` when the server returned no usable choice at all — distinct from a
    model that answered with an empty string.
    """
    resp = conn.post(_CHAT, json={"model": model, "messages": messages, "stream": False})
    if not isinstance(resp, dict):
        return None
    choices = resp.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        return None
    msg = choices[0].get("message")
    return opt_s((msg or {}).get("content"), 4000) if isinstance(msg, dict) else None


def generate_completion(conn: Any, model: str, prompt: str) -> str | None:
    """A single-turn generate mapped onto the universal chat endpoint."""
    return chat_completion(conn, model, [{"role": "user", "content": prompt}])

"""OpenAI-compatible transport edge cases: /props enrichment, model_details,
running_models, and defensive parsing of malformed chat payloads.
"""

from __future__ import annotations

from typing import Any

import pytest

from ai_guardian.config import AppConfig
from ai_guardian.ops import openai_compat as oc
from ai_guardian.runtimes import get_runtime

pytestmark = pytest.mark.unit

_LLAMACPP = get_runtime("llamacpp")
_VLLM = get_runtime("vllm")


class _Conn:
    """Path-substring routed fake; can raise on /props to test best-effort enrich."""

    def __init__(self, routes: dict, *, raise_on: str | None = None):
        self.routes = routes
        self.raise_on = raise_on

    def get(self, path: str, **k: Any) -> Any:
        if self.raise_on and self.raise_on in path:
            raise RuntimeError("props unavailable")
        for key, val in self.routes.items():
            if key in path:
                return val
        return {}

    def post(self, path: str, *, json: Any = None, **k: Any) -> Any:
        for key, val in self.routes.items():
            if key in path:
                return val
        return {}


_MODELS = {"data": [{"id": "llama-3.2-3b", "owned_by": "local"}]}
_PROPS = {"model_path": "/models/llama-3.2-3b.Q4.gguf", "model_size": 2_100_000_000}


def test_model_details_llamacpp_enriches_from_props():
    conn = _Conn({"/props": _PROPS})
    out = oc.model_details(conn, "llama-3.2-3b", _LLAMACPP)
    assert out["digest"].startswith("gguf:")
    assert out["sizeBytes"] == 2_100_000_000
    assert out["runtime"] == "llamacpp"
    assert out["license"] == ""  # not fabricated


def test_model_details_id_only_leaves_digest_empty():
    conn = _Conn({})
    out = oc.model_details(conn, "mixtral", _VLLM)
    assert out["digest"] == "" and out["sizeBytes"] is None


def test_props_identity_uses_nested_generation_settings():
    props = {"default_generation_settings": {"model": "/m/x.gguf", "model_size": 42}}
    digest, size = oc._props_identity(props)
    assert digest.startswith("gguf:") and size == 42


def test_props_identity_empty_when_no_path():
    digest, size = oc._props_identity({"model_size": 10})
    assert digest == "" and size == 10


def test_fetch_props_swallows_errors():
    conn = _Conn({"/props": _PROPS}, raise_on="/props")
    # best-effort: a failing /props degrades to empty, not a crash
    assert oc._fetch_props(conn, _LLAMACPP) == {}


def test_fetch_props_skipped_for_id_only_runtime():
    conn = _Conn({"/props": _PROPS})
    assert oc._fetch_props(conn, _VLLM) == {}


def test_running_models_reports_none_vram():
    conn = _Conn({"/v1/models": _MODELS, "/props": _PROPS})
    rows = oc.running_models(conn, AppConfig(), _LLAMACPP)
    assert rows[0]["sizeVramBytes"] is None
    assert rows[0]["digest"].startswith("gguf:")


def test_chat_completion_parses_first_choice():
    conn = _Conn({"/v1/chat/completions": {"choices": [{"message": {"content": "hi"}}]}})
    assert oc.chat_completion(conn, "m", [{"role": "user", "content": "q"}]) == "hi"


def test_chat_completion_defensive_on_empty_choices():
    conn = _Conn({"/v1/chat/completions": {"choices": []}})
    assert oc.chat_completion(conn, "m", []) == ""


def test_chat_completion_defensive_on_non_dict_response():
    conn = _Conn({"/v1/chat/completions": "not-a-dict"})
    assert oc.chat_completion(conn, "m", []) == ""


def test_generate_completion_maps_prompt_to_chat():
    conn = _Conn({"/v1/chat/completions": {"choices": [{"message": {"content": "ok"}}]}})
    assert oc.generate_completion(conn, "m", "one-shot prompt") == "ok"

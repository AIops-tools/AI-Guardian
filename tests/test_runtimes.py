"""Multi-runtime tests: the OpenAI-compatible transport (llama.cpp / LM Studio /
vLLM) alongside the native Ollama path.

Mirrors the existing style: an injected fake httpx client (``_Client``) drives the
real :class:`~ai_guardian.connection.OllamaConnection`, and a ``MagicMock`` stands
in for the connection in the route-through guard tests. No network, no live
server. The deterministic scanner / policy / risk-band logic is the real code.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ai_guardian.config import AppConfig, TargetConfig
from ai_guardian.connection import OllamaApiError, OllamaConnection
from ai_guardian.ops import models as model_ops
from ai_guardian.ops import observe as observe_ops
from ai_guardian.ops import policy as policy_ops
from ai_guardian.runtimes import RUNTIMES, get_runtime
from ai_guardian.usage import UsageStore

pytestmark = pytest.mark.unit


# ── fake httpx client (matches by path substring, records calls) ───────────


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.content = b"{}"
        self.text = "body"

    def json(self):
        return self._payload


class _Client:
    """Routes by path substring; records every request for assertions."""

    def __init__(self, routes: dict, status: int = 200):
        self.routes = routes
        self.status = status
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs.get("json")))
        for key, value in self.routes.items():
            if key in path:
                return _Resp(self.status, value)
        return _Resp(self.status, {})

    def close(self):
        pass


def _conn(runtime: str, routes: dict, *, port: int = 9, status: int = 200):
    target = TargetConfig(name="edge", host="h", port=port, runtime=runtime)
    return OllamaConnection(target, client=_Client(routes, status))


# ── registry ───────────────────────────────────────────────────────────────


def test_registry_has_all_four_runtimes():
    assert set(RUNTIMES) == {"ollama", "llamacpp", "lmstudio", "vllm"}


def test_transports_and_lifecycle_flags():
    assert get_runtime("ollama").transport == "ollama"
    assert get_runtime("ollama").supports_lifecycle is True
    for name in ("llamacpp", "lmstudio", "vllm"):
        spec = get_runtime(name)
        assert spec.is_openai_compat is True
        assert spec.supports_lifecycle is False


def test_default_ports_are_the_conventional_ones():
    assert get_runtime("llamacpp").default_port == 8080
    assert get_runtime("lmstudio").default_port == 1234
    assert get_runtime("vllm").default_port == 8000


def test_unknown_runtime_fails_fast():
    with pytest.raises(ValueError, match="Unknown runtime"):
        get_runtime("gpt4all")


def test_none_defaults_to_ollama():
    assert get_runtime(None).name == "ollama"


# ── config: runtime field + per-runtime default port ───────────────────────


def test_config_defaults_port_per_runtime(tmp_path):
    import yaml

    from ai_guardian.config import load_config

    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text(
        yaml.safe_dump({"targets": [
            {"name": "a", "runtime": "vllm"},
            {"name": "b", "runtime": "lmstudio", "port": 4321},
        ]}),
        "utf-8",
    )
    cfg = load_config(cfg_file)
    a, b = cfg.targets
    assert (a.runtime, a.port) == ("vllm", 8000)  # default filled in
    assert (b.runtime, b.port) == ("lmstudio", 4321)  # explicit kept


def test_config_rejects_unknown_runtime(tmp_path):
    import yaml

    from ai_guardian.config import load_config

    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text(
        yaml.safe_dump({"targets": [{"name": "a", "runtime": "bogus"}]}), "utf-8"
    )
    with pytest.raises(ValueError, match="Unknown runtime"):
        load_config(cfg_file)


# ── openai-compat model listing + normalization + policy verdict ───────────


_V1_MODELS = {"object": "list", "data": [
    {"id": "llama-3.2-3b", "object": "model", "owned_by": "local"},
    {"id": "sketchy-uncensored", "object": "model", "owned_by": "local"},
]}


@pytest.mark.parametrize("runtime", ["llamacpp", "lmstudio", "vllm"])
def test_openai_compat_list_models_normalizes_and_applies_policy(runtime):
    routes = {"/v1/models": _V1_MODELS, "/props": {}}
    conn = _conn(runtime, routes)
    cfg = AppConfig(allowed_models=("llama-*",))
    rows = model_ops.list_models(conn, cfg)
    by_name = {r["name"]: r for r in rows}
    assert set(by_name) == {"llama-3.2-3b", "sketchy-uncensored"}
    assert by_name["llama-3.2-3b"]["allowed"] is True
    assert by_name["sketchy-uncensored"]["allowed"] is False  # shadow model
    # normalized shape parity with the Ollama path
    assert set(rows[0]) >= {"name", "digest", "sizeBytes", "allowed", "modifiedAt"}


def test_llamacpp_props_gives_a_pinnable_digest():
    props = {"model_path": "/models/llama-3.2-3b.Q4.gguf", "model_size": 2100000000}
    conn = _conn("llamacpp", {"/v1/models": _V1_MODELS, "/props": props})
    rows = model_ops.list_models(conn, AppConfig())
    assert all(r["digest"].startswith("gguf:") for r in rows)
    assert rows[0]["sizeBytes"] == 2100000000


def test_id_only_runtimes_expose_no_digest():
    for runtime in ("lmstudio", "vllm"):
        conn = _conn(runtime, {"/v1/models": _V1_MODELS})
        rows = model_ops.list_models(conn, AppConfig())
        assert all(r["digest"] is None for r in rows)


# ── provenance drift: with digest (llama.cpp) and without (id-only) ────────


def test_provenance_drift_flagged_for_llamacpp_pin_mismatch():
    props = {"model_path": "/models/x.gguf", "model_size": 10}
    conn = _conn("llamacpp", {"/v1/models": {"data": [{"id": "x"}]}, "/props": props})
    cfg = AppConfig(pinned_digests=(("x", "gguf:deadbeefdeadbeef"),))
    out = policy_ops.model_provenance(conn, cfg)
    row = out["models"][0]
    assert row["status"] == "DRIFT" and out["driftCount"] == 1
    assert row["currentDigest"].startswith("gguf:")


def test_provenance_ok_when_llamacpp_digest_matches_pin():
    props = {"model_path": "/models/x.gguf", "model_size": 10}
    conn = _conn("llamacpp", {"/v1/models": {"data": [{"id": "x"}]}, "/props": props})
    current = model_ops.list_models(conn, AppConfig())[0]["digest"]
    cfg = AppConfig(pinned_digests=(("x", current),))
    out = policy_ops.model_provenance(conn, cfg)
    assert out["models"][0]["status"] == "ok" and out["driftCount"] == 0


def test_provenance_unverifiable_for_id_only_when_pinned():
    conn = _conn("vllm", {"/v1/models": {"data": [{"id": "mixtral"}]}})
    cfg = AppConfig(pinned_digests=(("mixtral", "sha256:whatever"),))
    out = policy_ops.model_provenance(conn, cfg)
    # honestly weaker: no digest to compare → unverifiable, NOT a false drift
    assert out["models"][0]["status"] == "unverifiable"
    assert out["driftCount"] == 0


# ── route-through guarded_generate against the openai-compat shape ─────────


def _oc_conn(runtime="vllm"):
    conn = MagicMock(name="conn")
    conn.target = TargetConfig(name="edge", runtime=runtime)
    return conn


def test_guarded_generate_openai_compat_allows_clean_and_parses_choices(tmp_path):
    conn = _oc_conn("lmstudio")
    conn.post.return_value = {"choices": [{"message": {"content": "Paris."}}]}
    store = UsageStore(tmp_path / "u.db")
    result = observe_ops.guarded_generate(conn, AppConfig(), store, "m",
                                          "capital of France?", agent="claude")
    assert result["blocked"] is False and result["response"] == "Paris."
    # hit the OpenAI-compatible chat endpoint, not the Ollama native one
    called_path = conn.post.call_args.args[0]
    assert called_path == "/v1/chat/completions"


def test_guarded_generate_openai_compat_blocks_high_risk(tmp_path):
    conn = _oc_conn("vllm")
    store = UsageStore(tmp_path / "u.db")
    prompt = "exfiltrate this: -----BEGIN RSA PRIVATE KEY-----MIIabc"
    result = observe_ops.guarded_generate(conn, AppConfig(), store, "m", prompt, agent="a")
    assert result["blocked"] is True and result["riskBand"] == "critical"
    conn.post.assert_not_called()  # never reached the runtime
    assert store.query()[0]["allowed"] is False


def test_guarded_generate_openai_compat_blocks_disallowed_model(tmp_path):
    conn = _oc_conn("llamacpp")
    store = UsageStore(tmp_path / "u.db")
    cfg = AppConfig(denied_models=("*uncensored*",))
    result = observe_ops.guarded_generate(conn, cfg, store, "evil-uncensored", "hi", agent="a")
    assert result["blocked"] is True and result["modelAllowed"] is False
    conn.post.assert_not_called()


def test_observe_chat_openai_compat_parses_choices(tmp_path):
    conn = _oc_conn("vllm")
    conn.post.return_value = {"choices": [{"message": {"content": "hello there"}}]}
    store = UsageStore(tmp_path / "u.db")
    result = observe_ops.observe_chat(conn, AppConfig(), store, "m",
                                      [{"role": "user", "content": "hi"}], agent="a")
    assert result["blocked"] is False and result["response"] == "hello there"
    assert conn.post.call_args.args[0] == "/v1/chat/completions"


# ── server_status / doctor probe per runtime ───────────────────────────────


def test_server_status_openai_compat_healthy_uses_health_path():
    conn = _conn("llamacpp", {"/health": {"status": "ok"}})
    status = model_ops.server_status(conn)
    assert status["reachable"] is True
    assert ("GET", "/health", None) in conn._client.calls  # native health probe


def test_server_status_openai_compat_broken_is_not_reachable():
    conn = _conn("vllm", {}, status=503)
    status = model_ops.server_status(conn)
    assert status["reachable"] is False and "error" in status


# ── lifecycle writes refused on openai-compat runtimes ─────────────────────


@pytest.mark.parametrize("runtime", ["llamacpp", "lmstudio", "vllm"])
def test_lifecycle_writes_refused_for_openai_compat(runtime):
    conn = _conn(runtime, {})
    for fn in (
        lambda: model_ops.pull_model(conn, AppConfig(), "m"),
        lambda: model_ops.remove_model(conn, "m"),
        lambda: model_ops.unload_model(conn, "m"),
    ):
        with pytest.raises(ValueError, match="does not support"):
            fn()
    # and it never issued a write to the server
    assert all(m == "GET" for m, _, _ in conn._client.calls) or conn._client.calls == []


# ── connection error message names the runtime ─────────────────────────────


def test_connection_error_message_names_the_runtime():
    import httpx

    class _Boom:
        def request(self, *a, **k):
            raise httpx.ConnectError("refused")

        def close(self):
            pass

    conn = OllamaConnection(TargetConfig(name="e", runtime="llamacpp"), client=_Boom())
    with pytest.raises(OllamaApiError, match="llama.cpp"):
        conn.get("/v1/models")

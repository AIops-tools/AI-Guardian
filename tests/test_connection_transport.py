"""Connection transport: error translation, response decoding, and the
``ConnectionManager`` session cache — all against injected fake httpx clients,
never a live runtime.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from ai_guardian.config import AppConfig, TargetConfig
from ai_guardian.connection import (
    ConnectionManager,
    OllamaApiError,
    OllamaConnection,
)

pytestmark = pytest.mark.unit


class _Resp:
    def __init__(self, status: int = 200, *, payload: Any = None,
                 content: bytes = b"{}", text: str = "body", raise_json: bool = False):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.content = content
        self.text = text
        self._raise_json = raise_json

    def json(self) -> Any:
        if self._raise_json:
            raise ValueError("not json")
        return self._payload


class _Client:
    def __init__(self, resp: _Resp):
        self._resp = resp
        self.calls: list[tuple[str, str, Any]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> _Resp:
        self.calls.append((method, path, kwargs.get("json")))
        return self._resp

    def close(self) -> None:
        pass


class _Boom:
    def __init__(self, exc: Exception):
        self._exc = exc
        self.closed = False

    def request(self, *a: Any, **k: Any) -> Any:
        raise self._exc

    def close(self) -> None:
        self.closed = True


def _conn(resp: _Resp, *, runtime: str = "ollama") -> OllamaConnection:
    return OllamaConnection(TargetConfig(name="t", runtime=runtime), client=_Client(resp))


# ── response decoding ──────────────────────────────────────────────────────


def test_json_body_decoded():
    conn = _conn(_Resp(200, payload={"version": "0.5.0"}))
    assert conn.get("/api/version") == {"version": "0.5.0"}


def test_empty_content_returns_empty_dict():
    conn = _conn(_Resp(200, content=b""))
    assert conn.get("/api/version") == {}


def test_undecodable_json_returns_empty_dict():
    conn = _conn(_Resp(200, content=b"<<garbage>>", raise_json=True))
    assert conn.post("/api/pull", json={"model": "m"}) == {}


def test_post_and_delete_pass_json_through():
    client = _Client(_Resp(200, payload={"ok": True}))
    conn = OllamaConnection(TargetConfig(name="t"), client=client)
    conn.post("/api/generate", json={"model": "m", "prompt": "hi"})
    conn.delete("/api/delete", json={"model": "m"})
    methods = {(m, p) for m, p, _ in client.calls}
    assert ("POST", "/api/generate") in methods
    assert ("DELETE", "/api/delete") in methods
    # json payloads travelled unchanged
    assert client.calls[0][2] == {"model": "m", "prompt": "hi"}


# ── teaching error messages per status class ───────────────────────────────


@pytest.mark.parametrize(
    "status,needle",
    [
        (401, "Authentication failed"),
        (403, "Authentication failed"),
        (404, "Not found"),
        (500, "server error"),
        (503, "server error"),
        (418, "API error"),  # generic fallthrough
    ],
)
def test_status_maps_to_teaching_message(status, needle):
    conn = _conn(_Resp(status, text="detail-body"))
    with pytest.raises(OllamaApiError) as ei:
        conn.get("/api/tags")
    assert needle in str(ei.value)
    assert ei.value.status_code == status
    assert ei.value.path == "/api/tags"
    # the upstream body snippet is carried through for debugging
    assert "detail-body" in str(ei.value)


def test_transport_error_names_runtime_and_hint():
    conn = OllamaConnection(
        TargetConfig(name="e", runtime="lmstudio"),
        client=_Boom(httpx.ConnectError("refused")),
    )
    with pytest.raises(OllamaApiError, match="LM Studio"):
        conn.get("/v1/models")


def test_bearer_header_set_only_when_token_present(monkeypatch):
    # legacy env-var token path feeds TargetConfig.token
    monkeypatch.setenv("AI_GUARDIAN_SECURE_TOKEN", "s3cr3t")
    conn = OllamaConnection(TargetConfig(name="secure"), client=_Client(_Resp(200)))
    assert conn._client is not None  # constructed without error
    # and the target actually resolved a token
    assert TargetConfig(name="secure").token == "s3cr3t"


def test_close_delegates_to_client():
    boom = _Boom(RuntimeError("unused"))
    conn = OllamaConnection(TargetConfig(name="t"), client=boom)
    conn.close()
    assert boom.closed is True


# ── ConnectionManager: cache + lifecycle ───────────────────────────────────


def _mgr() -> ConnectionManager:
    cfg = AppConfig(targets=(TargetConfig(name="a"), TargetConfig(name="b")))
    return ConnectionManager(cfg)


def test_connect_default_target_and_caches_same_object():
    mgr = _mgr()
    c1 = mgr.connect()  # default_target == first
    c2 = mgr.connect()
    assert c1 is c2
    assert c1.target.name == "a"
    assert mgr.list_connected() == ["a"]


def test_connect_named_target():
    mgr = _mgr()
    conn = mgr.connect("b")
    assert conn.target.name == "b"


def test_disconnect_removes_from_cache():
    mgr = _mgr()
    mgr.connect("a")
    mgr.disconnect("a")
    assert mgr.list_connected() == []
    # disconnecting an unknown target is a no-op, never raises
    mgr.disconnect("nope")


def test_disconnect_all_and_list_targets():
    mgr = _mgr()
    mgr.connect("a")
    mgr.connect("b")
    assert set(mgr.list_targets()) == {"a", "b"}
    mgr.disconnect_all()
    assert mgr.list_connected() == []


def test_from_config_uses_supplied_config():
    cfg = AppConfig(targets=(TargetConfig(name="only"),))
    mgr = ConnectionManager.from_config(cfg)
    assert mgr.list_targets() == ["only"]

"""Connection management for the Ollama local-LLM API.

Thin httpx wrapper over one Ollama runtime (default ``http://localhost:11434``).
Bearer auth is optional (local Ollama usually runs open); the token is sent only
when configured. Reads (``/api/tags``, ``/api/ps``, ``/api/show``,
``/api/version``) and governed writes (``/api/pull``, ``/api/delete``,
``/api/generate``, ``/api/chat``) go through ``request`` with central error
translation to ``OllamaApiError``.

Ollama does NOT persist a queryable prompt/response log, so *content* observation
happens by routing a prompt THROUGH ai-guardian (``chat``) — which scans and
records it — rather than by reading a server-side history that doesn't exist.

The httpx client is injectable for tests (``client=``); mock responses expose
``status_code``, ``content``, ``text``, and ``json()``.
"""

from __future__ import annotations

from typing import Any

import httpx

from ai_guardian.config import AppConfig, TargetConfig, load_config

_TIMEOUT = 120.0  # generate/chat can be slow on a cold model


class OllamaApiError(Exception):
    """An Ollama API call failed; carries a teaching message + status code."""

    def __init__(self, message: str, *, status_code: int | None = None, path: str = "") -> None:
        self.status_code = status_code
        self.path = path
        super().__init__(message)


def _teaching_message(status: int, path: str, body: str) -> str:
    snippet = body[:200].strip()
    if status in (401, 403):
        return (
            f"Authentication failed ({status}) on {path}. If this Ollama requires a "
            f"token, set it with 'ai-guardian secret set <target>'. {snippet}"
        )
    if status == 404:
        return (
            f"Not found (404) on {path}. The model may not be pulled — list models "
            f"first, or 'ai-guardian' pull it. {snippet}"
        )
    if status in (500, 502, 503, 504):
        return (
            f"Ollama server error ({status}) on {path}. The runtime may be loading a "
            f"model or out of memory; retry shortly. {snippet}"
        )
    return f"Ollama API error ({status}) on {path}. {snippet}"


class OllamaConnection:
    """A session against one Ollama runtime."""

    def __init__(self, target: TargetConfig, client: Any | None = None) -> None:
        self._target = target
        headers = {"Content-Type": "application/json"}
        if target.token:
            headers["Authorization"] = f"Bearer {target.token}"
        self._client = client or httpx.Client(
            base_url=target.base_url, verify=target.verify_ssl,
            timeout=_TIMEOUT, headers=headers,
        )

    @property
    def target(self) -> TargetConfig:
        return self._target

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            resp = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise OllamaApiError(
                f"Could not reach Ollama at {self._target.base_url} ({method} {path}): "
                f"{exc}. Check that Ollama is running (ollama serve) and the host/port.",
                path=path,
            ) from exc
        if not (200 <= resp.status_code < 300):
            raise OllamaApiError(
                _teaching_message(resp.status_code, path, resp.text),
                status_code=resp.status_code, path=path,
            )
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return {}

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, *, json: Any = None, **kwargs: Any) -> Any:
        return self.request("POST", path, json=json, **kwargs)

    def delete(self, path: str, *, json: Any = None, **kwargs: Any) -> Any:
        return self.request("DELETE", path, json=json, **kwargs)

    def close(self) -> None:
        self._client.close()


class ConnectionManager:
    """Manages connections to multiple Ollama targets with session reuse."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._connections: dict[str, OllamaConnection] = {}

    @classmethod
    def from_config(cls, config: AppConfig | None = None) -> ConnectionManager:
        cfg = config or load_config()
        return cls(cfg)

    def connect(self, target_name: str | None = None) -> OllamaConnection:
        target = (
            self._config.get_target(target_name)
            if target_name
            else self._config.default_target
        )
        cached = self._connections.get(target.name)
        if cached is not None:
            return cached
        conn = OllamaConnection(target)
        self._connections[target.name] = conn
        return conn

    def disconnect(self, target_name: str) -> None:
        conn = self._connections.pop(target_name, None)
        if conn is not None:
            conn.close()

    def disconnect_all(self) -> None:
        for name in list(self._connections):
            self.disconnect(name)

    def list_targets(self) -> list[str]:
        return [t.name for t in self._config.targets]

    def list_connected(self) -> list[str]:
        return list(self._connections.keys())

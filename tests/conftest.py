"""Shared test doubles for the ops layer (no live Ollama).

``FakeOllama`` mimics :class:`ai_guardian.connection.OllamaConnection`'s surface
(``get``/``post``/``delete``). Responses are matched by substring of the API
path, so a single fake can serve the several calls an operation issues, and
every call is recorded for assertions.
"""

from __future__ import annotations

from typing import Any

import pytest


@pytest.fixture(autouse=True)
def _default_approver(monkeypatch):
    """Record a synthetic approver on every audit row so the trail looks
    realistic. The approver is an optional annotation now — it gates nothing —
    but the governance-persistence tests clear it to prove a high-risk write
    still runs without one."""
    monkeypatch.setenv("AI_GUARDIAN_AUDIT_APPROVED_BY", "pytest")


class FakeOllama:
    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, str, Any]] = []

    def _respond(self, method: str, path: str, payload: Any) -> Any:
        self.calls.append((method, path, payload))
        for key, value in self.responses.items():
            if key in path:
                return value
        return {}

    def get(self, path: str, **kwargs: Any) -> Any:
        return self._respond("GET", path, None)

    def post(self, path: str, *, json: Any = None, **kwargs: Any) -> Any:
        return self._respond("POST", path, json)

    def delete(self, path: str, *, json: Any = None, **kwargs: Any) -> Any:
        return self._respond("DELETE", path, json)

    def close(self) -> None:
        pass


@pytest.fixture
def fake_ollama():
    return FakeOllama

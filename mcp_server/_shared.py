"""Shared MCP server primitives: the FastMCP instance, connection helper,
error sanitisation, and the ``@tool_errors`` decorator.

Tool modules under ``mcp_server/tools/`` import ``mcp`` from here and register
their ``@mcp.tool()`` functions onto it. ``mcp_server/server.py`` then imports
those modules and runs the server.

Keep ``Optional[X]`` (never PEP 604 ``X | None``) in any FastMCP-reflected
tool signature — on older mcp/pydantic the union eval'd to ``types.UnionType``
crashes FastMCP's ``issubclass`` check.
"""

import functools
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, Optional

import httpx
from mcp.server.fastmcp import FastMCP

from ai_guardian.config import AppConfig, load_config
from ai_guardian.connection import ConnectionManager, OllamaApiError
from ai_guardian.governance import mark_unknown, sanitize
from ai_guardian.usage import UsageStore

logger = logging.getLogger(__name__)

_DOCTOR_HINT = "Run 'ai-guardian doctor' to check the Ollama endpoint."


# Failures that leave the request's fate genuinely undetermined: the bytes
# went out and either the response or the rest of the connection was lost. A
# write that hits one of these MAY have taken effect on the server.
#
# Deliberately narrow. Connect errors and pool timeouts mean the request never
# left this process, and an API error carrying a status means the server
# answered — all are ordinary failures where nothing, or a known something,
# happened. Marking them 'unknown' would cry wolf on every unreachable host.
_UNDETERMINED_ERRORS = (
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.ReadError,
    httpx.WriteError,
    httpx.RemoteProtocolError,
)


# Long enough to carry the remediation sentence. These messages teach the
# caller what to do instead, and that clause comes last — a 300-char cap cut
# it off silently on every refusal long enough to need one.
_ERROR_MAX = 800


def _safe_error(exc: Exception, tool: str) -> str:
    """Return an agent-safe error string; log full detail server-side only."""
    logger.error("Tool %s failed", tool, exc_info=True)
    _passthrough = (
        ValueError,
        FileNotFoundError,
        KeyError,
        PermissionError,
        TimeoutError,
        ConnectionError,
        OllamaApiError,
    )
    if isinstance(exc, _passthrough):
        return sanitize(str(exc), _ERROR_MAX)
    return f"{type(exc).__name__}: operation failed."


def tool_errors(shape: str = "dict") -> Callable:
    """Wrap a tool body in the canonical try/except → ``_safe_error`` pattern.

    Place this *between* ``@governed_tool`` and the function so the audit
    decorator and FastMCP still see the original signature.
    """

    def decorator(func: Callable) -> Callable:
        name = func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:  # noqa: BLE001 — sanitised below
                msg = _safe_error(e, name)
                if shape == "list":
                    return [{"error": msg, "hint": _DOCTOR_HINT}]
                if shape == "str":
                    return f"Error: {msg} {_DOCTOR_HINT}"
                payload = {"error": msg, "hint": _DOCTOR_HINT}
                # Flatten the exception into a dict and its type is gone
                # for good — so classify here, while it is still known,
                # whether the operation may nonetheless have taken effect.
                if isinstance(e, _UNDETERMINED_ERRORS):
                    return mark_unknown(payload)
                return payload

        return wrapper

    return decorator


mcp = FastMCP(
    "ai-guardian",
    instructions=(
        "On-endpoint local-LLM (Ollama) observability + governance — the "
        "complement to IGEL AI Armor: Armor governs WHETHER a model runs; this "
        "records WHAT it did. Inventory + runtime state (list_models, "
        "running_models, model_details, vram_usage) annotated with the allow/deny "
        "policy; provenance/digest-drift detection; a deterministic prompt scanner "
        "(secrets / PII / source-code / jailbreak) via 'scan_prompt'; and the "
        "route-through guards 'guarded_generate' / 'observe_chat' that scan + "
        "policy-gate a prompt, record it to the usage log, and only then call the "
        "model. Governed writes: pull / remove (high, dry-run) / unload models and "
        "set the allow/deny policy. Every tool runs through the ai-guardian "
        "governance harness (audit / budget / risk-tier / undo)."
    ),
)

_conn_mgr: Optional[ConnectionManager] = None
_config: Optional[AppConfig] = None
_store: Optional[UsageStore] = None


def _load() -> AppConfig:
    config_path_str = os.environ.get("AI_GUARDIAN_AIOPS_CONFIG")
    config_path = Path(config_path_str) if config_path_str else None
    return load_config(config_path)


def _get_config() -> AppConfig:
    """Return the app config (endpoints + model policy), lazily loaded."""
    global _config  # noqa: PLW0603
    if _config is None:
        _config = _load()
    return _config


def _get_connection(target: Optional[str] = None) -> Any:
    """Return an Ollama connection, lazily initialising the manager."""
    global _conn_mgr  # noqa: PLW0603
    if _conn_mgr is None:
        _conn_mgr = ConnectionManager(_get_config())
    return _conn_mgr.connect(target)


def _get_store() -> UsageStore:
    """Return the observed-usage store (ai-guardian's own log)."""
    global _store  # noqa: PLW0603
    if _store is None:
        _store = UsageStore()
    return _store

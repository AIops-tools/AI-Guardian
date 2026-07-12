"""Model policy + provenance MCP tools (read + governed writes)."""

from typing import Any, Optional

from ai_guardian.governance import governed_tool
from ai_guardian.ops import policy as ops
from mcp_server._shared import _get_config, _get_connection, mcp, tool_errors


def _allowlist_undo(params: dict[str, Any], result: Any) -> Optional[dict]:
    if not isinstance(result, dict):
        return None
    prior = (result.get("priorState") or {}).get("allowedModels")
    if prior is None:
        return None
    return {"tool": "set_model_allowlist", "params": {"models": prior},
            "note": "Restore the prior model allowlist."}


def _denylist_undo(params: dict[str, Any], result: Any) -> Optional[dict]:
    if not isinstance(result, dict):
        return None
    prior = (result.get("priorState") or {}).get("deniedModels")
    if prior is None:
        return None
    return {"tool": "set_model_denylist", "params": {"models": prior},
            "note": "Restore the prior model denylist."}


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def policy_view() -> dict:
    """[READ] The current model allow/deny policy + provenance digest pins."""
    return ops.policy_view(_get_config())


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def model_provenance(target: Optional[str] = None) -> dict:
    """[READ] Compare each installed model's digest against its pin; flag drift.

    Args:
        target: Ollama target name from config; omit for the default.
    """
    return ops.model_provenance(_get_connection(target), _get_config())


@mcp.tool()
@governed_tool(risk_level="medium", undo=_allowlist_undo)
@tool_errors("dict")
def set_model_allowlist(models: list[str]) -> dict:
    """[WRITE][risk=medium] Replace the model allowlist (glob patterns; empty = allow-all).

    Args:
        models: Shell-glob patterns of permitted model names (e.g. ["llama3.*", "qwen*"]).
    """
    return ops.set_allowlist(models)


@mcp.tool()
@governed_tool(risk_level="medium", undo=_denylist_undo)
@tool_errors("dict")
def set_model_denylist(models: list[str]) -> dict:
    """[WRITE][risk=medium] Replace the model denylist (deny patterns always win).

    Args:
        models: Shell-glob patterns of forbidden model names.
    """
    return ops.set_denylist(models)


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def pin_model_digest(model: str, digest: str) -> dict:
    """[WRITE][risk=medium] Pin a model's expected provenance digest (drift detection).

    Args:
        model: Model name.
        digest: The expected digest to pin (from list_models / model_details).
    """
    return ops.pin_model_digest(model, digest)

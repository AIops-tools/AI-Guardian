"""Model inventory + lifecycle MCP tools (read + guarded writes)."""

from typing import Any, Optional

from ai_guardian.governance import governed_tool
from ai_guardian.ops import models as ops
from mcp_server._shared import _get_config, _get_connection, mcp, tool_errors


def _remove_undo(params: dict[str, Any], result: Any) -> Optional[dict]:
    """Inverse of remove_model: re-pull the deleted model — when policy permits.

    pull_model refuses any model the allow/deny policy rejects, so for a denied
    model this descriptor would be recorded, look valid in undo_list, and then
    fail at undo_apply. remove_model reports that verdict as ``reversible``;
    honour it and record nothing rather than promise a replay that cannot run.
    """
    if not isinstance(result, dict):
        return None
    if result.get("reversible") is False:
        return None  # policy-denied model — a re-pull would be refused
    model = (result.get("priorState") or {}).get("model") or params.get("model")
    if not model:
        return None
    return {"tool": "pull_model", "params": {"model": model},
            "note": "Re-pull the model that was removed."}


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def list_models(target: Optional[str] = None) -> list:
    """[READ] Installed models, each annotated with the allow/deny policy verdict.

    Shadow (unsanctioned) models show ``allowed: false``.

    Args:
        target: Ollama target name from config; omit for the default (local).
    """
    return ops.list_models(_get_connection(target), _get_config())


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def running_models(target: Optional[str] = None) -> list:
    """[READ] Currently loaded models: VRAM footprint + residency expiry.

    Args:
        target: Ollama target name from config; omit for the default.
    """
    return ops.running_models(_get_connection(target), _get_config())


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def model_details(model: str, target: Optional[str] = None) -> dict:
    """[READ] License / parameters / capabilities for one model.

    Args:
        model: Model name (e.g. "llama3.2:3b").
        target: Ollama target name from config; omit for the default.
    """
    return ops.model_details(_get_connection(target), model)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def server_status(target: Optional[str] = None) -> dict:
    """[READ] Ollama reachability + version.

    Args:
        target: Ollama target name from config; omit for the default.
    """
    return ops.server_status(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def vram_usage(budget_bytes: Optional[int] = None, target: Optional[str] = None) -> dict:
    """[READ] Total VRAM used by loaded models; flag over-budget.

    Args:
        budget_bytes: Optional VRAM budget; models over it are flagged.
        target: Ollama target name from config; omit for the default.
    """
    return ops.vram_usage(_get_connection(target), budget_bytes)


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def pull_model(model: str, target: Optional[str] = None) -> dict:
    """[WRITE][risk=medium] Pull a model — refused if it violates the deny/allow policy.

    Args:
        model: Model name to pull.
        target: Ollama target name from config; omit for the default.
    """
    return ops.pull_model(_get_connection(target), _get_config(), model)


@mcp.tool()
@governed_tool(risk_level="high", undo=_remove_undo)
@tool_errors("dict")
def remove_model(model: str, dry_run: bool = False, target: Optional[str] = None) -> dict:
    """[WRITE][risk=high] Delete a local model. Destructive — pass dry_run=True to preview.

    Captures the model's manifest so the harness records an undo (re-pull).

    An undo is recorded only when the allow/deny policy would permit re-pulling
    the model. For a denied one the result says reversible=false and explains
    why, rather than recording a re-pull that undo_apply is bound to refuse.
    The dry-run preview carries the same verdict, so the caller learns it before
    the deletion rather than after.

    Args:
        model: Model name to delete.
        dry_run: If True, return what WOULD be deleted without deleting.
        target: Ollama target name from config; omit for the default.
    """
    conn = _get_connection(target)
    config = _get_config()
    if dry_run:
        return {"dryRun": True,
                "wouldRemove": {"model": model},
                "reversible": bool(config.model_allowed(model))}
    return ops.remove_model(conn, config, model)


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def unload_model(model: str, target: Optional[str] = None) -> dict:
    """[WRITE][risk=medium] Evict a model from VRAM (keep_alive:0).

    Args:
        model: Model name to unload.
        target: Ollama target name from config; omit for the default.
    """
    return ops.unload_model(_get_connection(target), model)

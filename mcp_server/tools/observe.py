"""Route-through content governance + usage/anomaly MCP tools."""

from typing import Optional

from ai_guardian.governance import governed_tool
from ai_guardian.ops import observe as ops
from mcp_server._shared import _get_config, _get_connection, _get_store, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def scan_prompt(text: str) -> dict:
    """[READ] Pure content scan of a text for secrets / PII / code / jailbreak.

    No Ollama call — a deterministic scan returning findings + a weighted risk band.
    Use it to pre-check anything before sending it to a local model.

    Args:
        text: The text to scan.
    """
    return ops.scan_prompt(text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def usage_events(
    model: Optional[str] = None, risk_level: Optional[str] = None,
    allowed: Optional[bool] = None, since: Optional[str] = None, limit: int = 100,
) -> dict:
    """[READ] Query the observed-usage log (route-through prompts + their findings).

    Args:
        model: Filter by model name.
        risk_level: Filter by risk band (none/low/medium/high/critical).
        allowed: True = only allowed calls; False = only blocked.
        since: ISO start timestamp.
        limit: Max rows.
    """
    return ops.usage_events(_get_store(), model=model, risk_level=risk_level,
                            allowed=allowed, since=since, limit=limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def anomaly_report(target: Optional[str] = None) -> dict:
    """[READ] Rollup: shadow models, digest drift, high-risk prompts, blocked count.

    Args:
        target: Ollama target name from config; omit for the default.
    """
    return ops.anomaly_report(_get_connection(target), _get_config(), _get_store())


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def guarded_generate(
    model: str, prompt: str, agent: str = "unknown", user: str = "",
    block_threshold: str = "high", target: Optional[str] = None,
) -> dict:
    """[WRITE][risk=medium] Scan + policy-gate a prompt, record it, then run if allowed.

    The route-through guard: scans the prompt (secrets/PII/code/jailbreak), checks
    the model against policy, blocks if the risk band >= block_threshold or the
    model is disallowed, records the interaction to the usage log, and only calls
    Ollama if allowed. The raw prompt is never stored.

    Args:
        model: Model to run.
        prompt: The prompt text (scanned before any model call).
        agent / user: Actor attribution recorded in the usage log.
        block_threshold: Block when risk band >= this (none/low/medium/high/critical).
        target: Ollama target name from config; omit for the default.
    """
    return ops.guarded_generate(_get_connection(target), _get_config(), _get_store(),
                                model, prompt, agent=agent, user=user,
                                block_threshold=block_threshold)


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def observe_chat(
    model: str, messages: list[dict], agent: str = "unknown", user: str = "",
    block_threshold: str = "high", target: Optional[str] = None,
) -> dict:
    """[WRITE][risk=medium] Scan + policy-gate a chat exchange, record it, then run if allowed.

    Args:
        model: Model to run.
        messages: OpenAI-style [{"role","content"}] messages (contents are scanned).
        agent / user: Actor attribution recorded in the usage log.
        block_threshold: Block when risk band >= this.
        target: Ollama target name from config; omit for the default.
    """
    return ops.observe_chat(_get_connection(target), _get_config(), _get_store(),
                            model, messages, agent=agent, user=user,
                            block_threshold=block_threshold)

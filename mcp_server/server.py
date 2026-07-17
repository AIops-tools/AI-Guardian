"""MCP server wrapping ai-guardian operations (stdio transport).

Thin adapter layer: each ``@mcp.tool()`` function (in ``mcp_server/tools/``)
delegates to the ``ai_guardian`` ops package and is wrapped with the
ai-guardian ``@governed_tool`` harness (audit / budget / undo / risk-tier).

Standalone, self-governed on-endpoint local-LLM (Ollama) observability +
governance (preview) — the complement to IGEL AI Armor.

Source: https://github.com/AIops-tools/AI-Guardian
License: MIT
"""

import logging

from mcp_server._shared import _safe_error, mcp, tool_errors

# Importing the tool modules registers every @mcp.tool() onto the shared
# `mcp` instance. Order does not matter; each module is self-contained.
from mcp_server.tools import (  # noqa: F401 — side effects
    models,
    observe,
    policy,
    undo,
)

__all__ = ["mcp", "main", "_safe_error", "tool_errors"]


def main() -> None:
    """Run the MCP server over stdio."""
    logging.basicConfig(level=logging.INFO)
    mcp.run(transport="stdio")

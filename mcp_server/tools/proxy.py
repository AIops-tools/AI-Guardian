"""The capture proxy's read-only surface.

The proxy itself is a CLI command: it blocks for as long as it is listening, so an
MCP tool that started it would hang the calling agent for the lifetime of the
process. This tool composes the command and states the enforcement caveat — the
same shape the sibling compliance tool uses for its cron hint. Traffic the proxy
captures is recorded to the ordinary usage log, so `observed_usage` and
`anomaly_report` already surface it.
"""

from typing import Optional

from ai_guardian.governance import governed_tool
from ai_guardian.ops import proxy as ops
from mcp_server._shared import _get_config, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def proxy_guidance(listen_host: str = "127.0.0.1", listen_port: int = 11435,
                   target: Optional[str] = None) -> dict:
    """[READ] How to run the transparent capture proxy, and what it does NOT guarantee.

    WRITES NOTHING and starts no listener — it composes the `ai-guardian proxy
    serve` command plus the client-side change, and returns the caveat that
    matters: the proxy is a CHOKEPOINT, not an enforcement boundary. Any client
    that can still reach the runtime's real port bypasses it entirely, and this
    tool cannot detect that. Captured traffic is a sample, not the population,
    until the runtime is unreachable except through the proxy.

    Requests are scanned before forwarding; responses stream through uninspected,
    because buffering them would turn every streaming client into a blocking one.
    A governed request whose body cannot be parsed is refused, not forwarded.

    Args:
        listen_host: Address the proxy would bind.
        listen_port: Port the proxy would bind (default 11435).
        target: Runtime target from config; omit for the default.
    """
    return ops.proxy_guidance(_get_config(), listen_host=listen_host,
                              listen_port=listen_port, target=target)

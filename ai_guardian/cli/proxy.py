"""``ai-guardian proxy`` — run the transparent capture proxy, or print its guidance.

``serve`` is deliberately CLI-only. It blocks for as long as it is proxying, so
exposing it as an MCP tool would hang the calling agent for the lifetime of the
listener; the sibling compliance tool draws the same line with its cron hint.
Everything the proxy captures lands in the usual usage log, so the existing read
tools (``guard usage``, ``guard anomalies``) surface it with no new surface.
"""

from __future__ import annotations

import json
from typing import Annotated

import typer

from ai_guardian.cli._common import (
    TargetOption,
    cli_errors,
    console,
    get_connection,
)

proxy_app = typer.Typer(
    name="proxy",
    help="Transparent capture proxy: scan/gate/record traffic from clients that "
    "did not opt in.",
    no_args_is_help=True,
)


@proxy_app.command("hint")
@cli_errors
def proxy_hint(
    listen_host: Annotated[str, typer.Option("--host", help="Listen address")] = "127.0.0.1",
    listen_port: Annotated[int, typer.Option("--port", help="Listen port")] = 11435,
    target: TargetOption = None,
) -> None:
    """Print the serve command, the client change, and what the proxy does NOT guarantee."""
    from ai_guardian.config import load_config
    from ai_guardian.ops import proxy as ops

    console.print_json(json.dumps(
        ops.proxy_guidance(load_config(), listen_host=listen_host,
                           listen_port=listen_port, target=target)))


@proxy_app.command("serve")
@cli_errors
def proxy_serve(
    listen: Annotated[
        str, typer.Option("--listen", help="host:port to listen on")
    ] = "127.0.0.1:11435",
    block_threshold: Annotated[
        str, typer.Option("--block-threshold",
                          help="Block at this risk band or above (none/low/medium/high/critical)")
    ] = "high",
    target: TargetOption = None,
) -> None:
    """Run the capture proxy in the foreground (Ctrl-C to stop).

    Scans each governed request, applies the model allow/deny policy, records the
    verdict to the usage log, and forwards only what passes — streaming responses
    through untouched.
    """
    from ai_guardian.ops import proxy as ops
    from ai_guardian.proxy import GuardianProxy
    from ai_guardian.usage import UsageStore

    host, _, port_text = listen.rpartition(":")
    if not host or not port_text.isdigit():
        console.print(
            f"[red]Error:[/] --listen must be host:port (got {listen!r}), "
            f"e.g. 127.0.0.1:11435."
        )
        raise typer.Exit(1)

    # get_connection returns (conn, AppConfig) — the resolved TARGET comes from the
    # config, not from that tuple. Reaching for `.name` on the second element is
    # how this first ran into 'AppConfig has no attribute name'.
    conn, config = get_connection(target)
    resolved = config.get_target(target) if target else config.default_target
    guidance = ops.proxy_guidance(config, listen_host=host, listen_port=int(port_text),
                                  target=target)
    store = UsageStore()
    recorder = ops.make_recorder(config, store, resolved.name)

    server = GuardianProxy(
        (host, int(port_text)),
        resolved.base_url,
        model_allowed=config.model_allowed,
        block_threshold=block_threshold,
        on_event=recorder,
    )
    console.print(f"[bold]ai-guardian proxy[/] {listen} → {resolved.base_url}")
    console.print(f"  governed paths : {', '.join(guidance['governedPaths'])}")
    console.print(f"  block at       : {block_threshold} and above")
    console.print(f"  client change  : {guidance['clientChange']}")
    # Printed every start, not tucked into docs: an operator who believes this is
    # enforcing will not firewall the runtime, and then it enforces nothing.
    console.print(f"[bold yellow]NOT ENFORCEMENT:[/] {guidance['notEnforcement']}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\nstopping…")
    finally:
        server.shutdown()
        server.server_close()

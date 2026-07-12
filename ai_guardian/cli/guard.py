"""``ai-guardian guard`` — policy, prompt scanning, usage + anomaly reports."""

from __future__ import annotations

import json
from typing import Annotated

import typer

from ai_guardian.cli._common import TargetOption, cli_errors, console, get_connection

guard_app = typer.Typer(
    name="guard",
    help="Policy, prompt scanning, usage log, and anomaly reports.",
    no_args_is_help=True,
)


@guard_app.command("policy")
@cli_errors
def guard_policy() -> None:
    """Show the current model allow/deny policy + digest pins."""
    from ai_guardian.config import load_config
    from ai_guardian.ops import policy as ops

    console.print_json(json.dumps(ops.policy_view(load_config())))


@guard_app.command("provenance")
@cli_errors
def guard_provenance(target: TargetOption = None) -> None:
    """Check installed model digests against their pins (drift detection)."""
    from ai_guardian.ops import policy as ops

    conn, cfg = get_connection(target)
    console.print_json(json.dumps(ops.model_provenance(conn, cfg)))


@guard_app.command("scan")
@cli_errors
def guard_scan(
    text: Annotated[str, typer.Argument(help="Text to scan for secrets/PII/jailbreak")],
) -> None:
    """Scan a piece of text (deterministic; no model call)."""
    from ai_guardian.ops import observe as ops

    console.print_json(json.dumps(ops.scan_prompt(text)))


@guard_app.command("usage")
@cli_errors
def guard_usage(
    limit: Annotated[int, typer.Option("--limit", help="Max rows")] = 50,
) -> None:
    """Query the observed-usage log."""
    from ai_guardian.ops import observe as ops
    from ai_guardian.usage import UsageStore

    console.print_json(json.dumps(ops.usage_events(UsageStore(), limit=limit)))


@guard_app.command("anomalies")
@cli_errors
def guard_anomalies(target: TargetOption = None) -> None:
    """Rollup: shadow models, digest drift, high-risk + blocked prompts."""
    from ai_guardian.ops import observe as ops
    from ai_guardian.usage import UsageStore

    conn, cfg = get_connection(target)
    console.print_json(json.dumps(ops.anomaly_report(conn, cfg, UsageStore())))

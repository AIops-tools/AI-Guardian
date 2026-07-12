"""``ai-guardian overview`` — one-shot local-LLM posture."""

from __future__ import annotations

import json

from ai_guardian.cli._common import TargetOption, cli_errors, console, get_connection


@cli_errors
def overview_cmd(target: TargetOption = None) -> None:
    """One-shot posture: models installed/running, shadow count, observed-usage stats."""
    from ai_guardian.ops import overview as ops
    from ai_guardian.usage import UsageStore

    conn, cfg = get_connection(target)
    console.print_json(json.dumps(ops.posture_overview(conn, cfg, UsageStore())))

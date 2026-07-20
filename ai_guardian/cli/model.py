"""``ai-guardian model`` — Ollama model inventory + guarded lifecycle."""

from __future__ import annotations

import json
from typing import Annotated

import typer

from ai_guardian.cli._common import (
    DryRunOption,
    TargetOption,
    cli_errors,
    console,
    double_confirm,
    dry_run_preview,
    get_connection,
)

model_app = typer.Typer(
    name="model",
    help="Local models: list, details, running, pull, remove, unload.",
    no_args_is_help=True,
)

NameArg = Annotated[str, typer.Argument(help="Model name (e.g. llama3.2:3b)")]


@model_app.command("list")
@cli_errors
def model_list(target: TargetOption = None) -> None:
    """List installed models with the allow/deny verdict."""
    from ai_guardian.ops import models as ops

    conn, cfg = get_connection(target)
    console.print_json(json.dumps(ops.list_models(conn, cfg)))


@model_app.command("running")
@cli_errors
def model_running(target: TargetOption = None) -> None:
    """Show loaded models (VRAM + expiry)."""
    from ai_guardian.ops import models as ops

    conn, cfg = get_connection(target)
    console.print_json(json.dumps(ops.running_models(conn, cfg)))


@model_app.command("details")
@cli_errors
def model_details(model: NameArg, target: TargetOption = None) -> None:
    """Show a model's license / parameters / capabilities."""
    from ai_guardian.ops import models as ops

    conn, _ = get_connection(target)
    console.print_json(json.dumps(ops.model_details(conn, model)))


@model_app.command("pull")
@cli_errors
def model_pull(model: NameArg, target: TargetOption = None) -> None:
    """Pull a model (refused if it violates policy)."""
    from mcp_server.tools import models as gov

    console.print_json(json.dumps(gov.pull_model(model=model, target=target)))


@model_app.command("remove")
@cli_errors
def model_remove(model: NameArg, target: TargetOption = None,
                 dry_run: DryRunOption = False) -> None:
    """Delete a local model (dry-run + double confirm)."""
    from mcp_server.tools import models as gov

    if dry_run:
        # Through the governed call: the preview carries the reversible verdict,
        # so the operator learns there will be no undo BEFORE deleting.
        dry_run_preview(
            gov.remove_model(model=model, dry_run=True, target=target),
            operation="remove_model", api_call="DELETE /api/delete",
            parameters={"model": model})
        return
    double_confirm("remove model", model)
    console.print_json(json.dumps(gov.remove_model(model=model, target=target)))


@model_app.command("unload")
@cli_errors
def model_unload(model: NameArg, target: TargetOption = None) -> None:
    """Evict a model from VRAM (keep_alive:0)."""
    from mcp_server.tools import models as gov

    console.print_json(json.dumps(gov.unload_model(model=model, target=target)))

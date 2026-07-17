"""Top-level Typer app: assembles sub-apps and top-level commands."""

from __future__ import annotations

import typer

from ai_guardian.cli._common import cli_errors
from ai_guardian.cli.doctor import doctor_cmd
from ai_guardian.cli.guard import guard_app
from ai_guardian.cli.init import init_cmd
from ai_guardian.cli.model import model_app
from ai_guardian.cli.overview import overview_cmd
from ai_guardian.cli.secret import secret_app
from ai_guardian.cli.undo import undo_app

app = typer.Typer(
    name="ai-guardian",
    help="Governed observability + governance for on-endpoint local LLMs (Ollama) "
    "— the complement to IGEL AI Armor.",
    no_args_is_help=True,
)

app.add_typer(model_app, name="model")
app.add_typer(guard_app, name="guard")
app.add_typer(secret_app, name="secret")
app.add_typer(undo_app, name="undo")
app.command("init")(init_cmd)
app.command("overview")(overview_cmd)
app.command("doctor")(doctor_cmd)


@app.command("mcp")
@cli_errors
def mcp_cmd() -> None:
    """Start the MCP server (stdio transport).

    Single-command entry point for MCP clients (does not go through uvx/PyPI
    resolution at launch):
        ai-guardian mcp
    """
    import sys

    if sys.version_info < (3, 11):
        typer.echo(
            f"ERROR: ai-guardian requires Python >= 3.11 "
            f"(got {sys.version_info.major}.{sys.version_info.minor}).\n"
            f"Fix: uv python install 3.12 && "
            f"uv tool install --python 3.12 --force ai-guardian",
            err=True,
        )
        raise typer.Exit(2)

    from mcp_server.server import main as _mcp_main

    _mcp_main()


if __name__ == "__main__":
    app()

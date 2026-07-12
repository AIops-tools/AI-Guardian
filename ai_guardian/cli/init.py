"""``ai-guardian init`` — a friendly, interactive onboarding wizard.

Sets up the Ollama endpoint(s) and an optional model allowlist in
``~/.ai-guardian/config.yaml``. Most setups just need the local Ollama, so it
defaults to ``localhost:11434`` and no token. A bearer token (rare for local
Ollama) is stored *encrypted* if supplied.
"""

from __future__ import annotations

import getpass

import typer
import yaml

from ai_guardian.cli._common import cli_errors, console
from ai_guardian.config import CONFIG_DIR, CONFIG_FILE, DEFAULT_HOST, DEFAULT_PORT


def _write_config(doc: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.chmod(0o700)
    except OSError:
        pass
    CONFIG_FILE.write_text(yaml.safe_dump(doc, sort_keys=False), "utf-8")


@cli_errors
def init_cmd() -> None:
    """Interactively set up the Ollama endpoint + model allowlist."""
    console.print("[bold cyan]AI Guardian — setup wizard[/]")
    console.print(
        "This records the Ollama endpoint(s) and an optional model allowlist to "
        "config.yaml. Local Ollama usually needs no token.\n"
    )

    name = typer.prompt("Target name", default="local").strip()
    host = typer.prompt("Ollama host", default=DEFAULT_HOST).strip()
    port = typer.prompt("Ollama port", default=DEFAULT_PORT, type=int)
    scheme = "https" if typer.confirm("Use HTTPS?", default=False) else "http"

    entry = {"name": name, "host": host, "port": port, "scheme": scheme}
    doc: dict = {"targets": [entry]}

    if typer.confirm("Does this Ollama require a bearer token?", default=False):
        from ai_guardian.secretstore import SecretStore, resolve_master_password

        password = resolve_master_password(confirm_if_new=True)
        store = SecretStore.unlock(password)
        token = getpass.getpass(f"Token for '{name}' (hidden): ")
        store.set(name, token)
        console.print("[green]✓ Token stored encrypted.[/]")

    console.print("\n[bold]Model policy (optional)[/]")
    console.print(
        "[dim]Allowlist patterns (shell globs, comma-separated) restrict which "
        "models are sanctioned; anything else shows as a 'shadow' model. Leave "
        "blank to allow all.[/]"
    )
    allow = typer.prompt("Allowed model patterns", default="").strip()
    if allow:
        doc["allowed_models"] = [p.strip() for p in allow.split(",") if p.strip()]
    deny = typer.prompt("Denied model patterns", default="").strip()
    if deny:
        doc["denied_models"] = [p.strip() for p in deny.split(",") if p.strip()]

    _write_config(doc)
    console.print(f"\n[green]✓ Setup complete.[/] Config: {CONFIG_FILE}")
    if typer.confirm("Run a reachability check now (ai-guardian doctor)?", default=True):
        from ai_guardian.doctor import run_doctor

        raise typer.Exit(run_doctor())

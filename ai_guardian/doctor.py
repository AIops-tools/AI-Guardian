"""Environment + local-LLM endpoint diagnostics for AI Guardian.

Probes every configured runtime target — Ollama and the OpenAI-compatible
runtimes (llama.cpp / LM Studio / vLLM) — reporting each with its runtime name.
"""

from __future__ import annotations

from rich.console import Console

from ai_guardian.config import load_config
from ai_guardian.secretstore import SECRETS_FILE, check_permissions, has_store

_console = Console()


def run_doctor(skip_auth: bool = False) -> int:
    """Check config, model policy, and Ollama reachability.

    Returns 0 healthy, 1 if problems. Never raises — a doctor must survive the
    thing it diagnoses being unhealthy. Works with zero config (defaults to the
    local Ollama).
    """
    problems = 0

    try:
        config = load_config()
    except Exception as exc:  # noqa: BLE001 — report, do not crash
        _console.print(f"[red]✗ Config load failed: {exc}[/]")
        return 1

    _console.print(f"[green]✓ {len(config.targets)} runtime target(s) configured[/]")
    _console.print(
        f"[dim]  policy: {len(config.allowed_models)} allow / "
        f"{len(config.denied_models)} deny pattern(s), {len(config.pins)} digest pin(s)[/]"
    )

    if has_store():
        _console.print(f"[green]✓ Encrypted secret store present: {SECRETS_FILE}[/]")
        perm_warning = check_permissions()
        if perm_warning:
            _console.print(f"[yellow]! {perm_warning}[/]")
    else:
        _console.print("[dim]! No secret store — local Ollama usually needs no token.[/]")

    if skip_auth:
        _console.print("[dim]Skipping reachability check (--skip-auth).[/]")
        return 1 if problems else 0

    from ai_guardian.connection import ConnectionManager
    from ai_guardian.ops.models import server_status

    mgr = ConnectionManager(config)
    for target in config.targets:
        conn = mgr.connect(target.name)
        status = server_status(conn)
        if status.get("reachable"):
            version = status.get("version") or "reachable"
            _console.print(
                f"[green]✓ '{target.name}' ({target.base_url}) — "
                f"{target.spec.display_name} {version}[/]"
            )
        else:
            _console.print(
                f"[red]✗ '{target.name}' ({target.base_url}) unreachable: "
                f"{status.get('error', '')}[/]"
            )
            problems += 1

    return 1 if problems else 0

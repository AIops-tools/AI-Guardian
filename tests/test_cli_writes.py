"""CLI confirmed-write path — past dry-run, through governance, onto disk.

The CLI write commands delegate real execution to the ``@governed_tool``
functions in ``mcp_server.tools``. These tests drive a write command PAST the
dry-run branch and the double-confirm prompts and assert the call really went
through the governed path (audit row on disk) — the regression test for the
"CLI writes were unaudited" line-wide fix.
"""

from __future__ import annotations

import sqlite3

import pytest
from typer.testing import CliRunner

import ai_guardian.governance.audit as audit_mod
import ai_guardian.governance.policy as policy_mod
import ai_guardian.governance.undo as undo_mod


@pytest.fixture
def gov_home(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_GUARDIAN_AIOPS_HOME", str(tmp_path))
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()
    yield tmp_path
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()


def _audit_tools(db_path) -> list[str]:
    conn = sqlite3.connect(db_path)
    try:
        return [r[0] for r in conn.execute("SELECT tool FROM audit_log ORDER BY id")]
    finally:
        conn.close()


@pytest.mark.unit
def test_cli_model_remove_dry_run_makes_no_call_and_no_audit(gov_home, monkeypatch, fake_ollama):
    from ai_guardian.cli import app

    fake = fake_ollama()
    import mcp_server.tools.models as gov_models

    monkeypatch.setattr(gov_models, "_get_connection", lambda target=None: fake)
    result = CliRunner().invoke(app, ["model", "remove", "llama3.2:3b", "--dry-run"])
    assert result.exit_code == 0
    assert "DRY-RUN" in result.output
    assert fake.calls == [], "a dry-run must never touch the runtime"
    # The preview now routes through the governed twin so it can report whether
    # an undo will be recorded, which also lands an audit row. Not new behaviour
    # but the removal of an inconsistency: MCP dry-runs have always audited, the
    # CLI was the outlier. The invariant that matters is above — no API call.
    assert _audit_tools(gov_home / "audit.db") == ["remove_model"]


@pytest.mark.unit
def test_cli_model_remove_confirmed_goes_through_governance(gov_home, monkeypatch, fake_ollama):
    """Confirmed CLI write must execute via the governed twin: the API call runs
    AND an audit row lands in audit.db (this is what the reroute fix bought)."""
    from ai_guardian.cli import app

    manifest = {"license": "MIT License", "details": {"family": "llama"}}
    fake = fake_ollama(responses={"/api/show": manifest})
    import mcp_server.tools.models as gov_models

    monkeypatch.setattr(gov_models, "_get_connection", lambda target=None: fake)
    result = CliRunner().invoke(app, ["model", "remove", "llama3.2:3b"], input="y\ny\n")
    assert result.exit_code == 0, result.output
    assert ("DELETE", "/api/delete", {"model": "llama3.2:3b"}) in fake.calls
    assert _audit_tools(gov_home / "audit.db") == ["remove_model"]


@pytest.mark.unit
def test_cli_model_remove_aborts_without_double_confirm(gov_home, monkeypatch, fake_ollama):
    from ai_guardian.cli import app

    fake = fake_ollama()
    import mcp_server.tools.models as gov_models

    monkeypatch.setattr(gov_models, "_get_connection", lambda target=None: fake)
    result = CliRunner().invoke(app, ["model", "remove", "llama3.2:3b"], input="y\nn\n")
    assert result.exit_code != 0
    assert fake.calls == []
    assert not (gov_home / "audit.db").exists()

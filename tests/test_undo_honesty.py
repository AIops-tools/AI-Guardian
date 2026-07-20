"""Never record an undo this tool's own policy engine will refuse to replay.

``remove_model`` recorded ``{"tool": "pull_model", ...}`` as its inverse
unconditionally. But ``pull_model`` refuses any model ``config.model_allowed``
rejects, and denylist patterns always win. So the natural containment sequence —
denylist ``llama3*``, then remove ``llama3`` — recorded an undo that:

  * was written to the undo store,
  * appeared perfectly valid in ``undo_list``,
  * and failed at ``undo_apply``.

That is the worst variant of an irreversible write: an audit trail asserting a
reversibility that does not exist, discovered during an incident rather than
before one. The fix is local and deterministic — evaluate the same policy at
remove time and record nothing when the re-pull would be refused, saying so in
the result.

The check must be EXACT: removing an allowed model still records its re-pull.
"""

from __future__ import annotations

import pytest

from ai_guardian.config import AppConfig
from ai_guardian.ops import models as model_ops
from mcp_server.tools.models import _remove_undo

pytestmark = pytest.mark.unit

_SHOW = {"license": "MIT License", "details": {"family": "llama"}}


@pytest.fixture
def gov_home(tmp_path, monkeypatch):
    """Point the governance harness at a throwaway home (audit/undo/policy)."""
    import ai_guardian.governance.audit as audit_mod
    import ai_guardian.governance.policy as policy_mod
    import ai_guardian.governance.undo as undo_mod

    monkeypatch.setenv("AI_GUARDIAN_AIOPS_HOME", str(tmp_path))
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()
    yield tmp_path
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()


_DENIED = AppConfig(denied_models=("llama3*",))
_ALLOWED = AppConfig()


# ── the ops layer reports the verdict ───────────────────────────────────────


def test_removing_a_denied_model_reports_itself_irreversible(fake_ollama):
    conn = fake_ollama(responses={"/api/show": _SHOW})
    out = model_ops.remove_model(conn, _DENIED, "llama3")
    assert out["reversible"] is False
    assert ("DELETE", "/api/delete", {"model": "llama3"}) in conn.calls, (
        "the removal itself must still happen — this is honesty, not a veto"
    )


def test_the_note_explains_why_and_what_to_do_instead(fake_ollama):
    conn = fake_ollama(responses={"/api/show": _SHOW})
    out = model_ops.remove_model(conn, _DENIED, "llama3")
    note = out["note"]
    assert "pull_model" in note, "must name the inverse that would be refused"
    assert "no undo was recorded" in note, "must be explicit that there is no undo"
    assert "ollama pull" in note, "must offer the route that does work"


def test_removing_an_allowed_model_is_still_reversible(fake_ollama):
    conn = fake_ollama(responses={"/api/show": _SHOW})
    out = model_ops.remove_model(conn, _ALLOWED, "llama3.2:3b")
    assert out["reversible"] is True
    assert "note" not in out, "no caveat belongs on a genuinely reversible write"


def test_an_allowlist_miss_counts_as_denied_too(fake_ollama):
    """model_allowed is false for anything off a non-empty allowlist."""
    conn = fake_ollama(responses={"/api/show": _SHOW})
    config = AppConfig(allowed_models=("mistral*",))
    out = model_ops.remove_model(conn, config, "llama3")
    assert out["reversible"] is False


def test_the_prior_manifest_is_still_captured_for_a_denied_model(fake_ollama):
    """Losing the undo must not also lose the audit trail's before-state."""
    conn = fake_ollama(responses={"/api/show": _SHOW})
    out = model_ops.remove_model(conn, _DENIED, "llama3")
    assert out["priorState"]["license"] == "MIT License"
    assert out["priorState"]["family"] == "llama"


# ── the undo callback honours it ────────────────────────────────────────────


def test_no_undo_descriptor_is_built_for_an_irreversible_removal():
    result = {"action": "remove_model", "model": "llama3", "reversible": False,
              "priorState": {"model": "llama3"}}
    assert _remove_undo({"model": "llama3"}, result) is None


def test_an_undo_descriptor_is_built_for_a_reversible_removal():
    result = {"action": "remove_model", "model": "llama3.2:3b", "reversible": True,
              "priorState": {"model": "llama3.2:3b"}}
    descriptor = _remove_undo({"model": "llama3.2:3b"}, result)
    assert descriptor["tool"] == "pull_model"
    assert descriptor["params"] == {"model": "llama3.2:3b"}


def test_a_result_without_the_verdict_still_gets_its_undo():
    """Only an explicit False suppresses it — absence is not a denial."""
    result = {"action": "remove_model", "priorState": {"model": "m"}}
    assert _remove_undo({"model": "m"}, result) is not None


# ── end to end: the sequence that produced the bug ──────────────────────────


def test_the_containment_sequence_records_no_undo(gov_home, monkeypatch, fake_ollama):
    """denylist llama3* then remove llama3 — the exact reported reproduction."""
    import mcp_server.tools.models as gov

    conn = fake_ollama(responses={"/api/show": _SHOW})
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)
    monkeypatch.setattr(gov, "_get_config", lambda: _DENIED)

    recorded: list = []

    class _Store:
        def record(self, *, skill, tool, undo_descriptor, orig_params, effect_verified=True):
            recorded.append(undo_descriptor)
            return "undo-1"

    import ai_guardian.governance.undo as undo_mod

    monkeypatch.setattr(undo_mod, "get_undo_store", lambda: _Store())

    out = gov.remove_model(model="llama3")
    assert out["reversible"] is False
    assert recorded == [], (
        "a descriptor pull_model will refuse must never reach the undo store"
    )


def test_an_allowed_removal_still_records_its_re_pull(gov_home, monkeypatch, fake_ollama):
    """Exactness: the honest path must not cost the reversible case its undo."""
    import ai_guardian.governance.undo as undo_mod
    import mcp_server.tools.models as gov

    conn = fake_ollama(responses={"/api/show": _SHOW})
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)
    monkeypatch.setattr(gov, "_get_config", lambda: _ALLOWED)

    recorded: list = []

    class _Store:
        def record(self, *, skill, tool, undo_descriptor, orig_params, effect_verified=True):
            recorded.append(undo_descriptor)
            return "undo-2"

    monkeypatch.setattr(undo_mod, "get_undo_store", lambda: _Store())

    out = gov.remove_model(model="llama3.2:3b")
    assert out["reversible"] is True
    assert recorded and recorded[0]["tool"] == "pull_model"


# ── the preview says it before the deletion, not after ──────────────────────


def test_the_dry_run_preview_carries_the_verdict(gov_home, monkeypatch, fake_ollama):
    import mcp_server.tools.models as gov

    conn = fake_ollama(responses={"/api/show": _SHOW})
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)
    monkeypatch.setattr(gov, "_get_config", lambda: _DENIED)

    preview = gov.remove_model(model="llama3", dry_run=True)
    assert preview["dryRun"] is True and preview["reversible"] is False
    assert conn.calls == [], "a dry-run must never touch the runtime"


def test_the_dry_run_preview_is_positive_for_an_allowed_model(gov_home, monkeypatch,
                                                              fake_ollama):
    import mcp_server.tools.models as gov

    conn = fake_ollama(responses={"/api/show": _SHOW})
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)
    monkeypatch.setattr(gov, "_get_config", lambda: _ALLOWED)

    preview = gov.remove_model(model="llama3.2:3b", dry_run=True)
    assert preview["reversible"] is True
    assert conn.calls == []


def test_the_cli_preview_warns_before_deleting(gov_home, monkeypatch, fake_ollama):
    """The operator must learn there is no undo BEFORE confirming the removal."""
    from typer.testing import CliRunner

    import mcp_server.tools.models as gov
    from ai_guardian.cli import app

    conn = fake_ollama(responses={"/api/show": _SHOW})
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)
    monkeypatch.setattr(gov, "_get_config", lambda: _DENIED)

    result = CliRunner().invoke(app, ["model", "remove", "llama3", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "DRY-RUN" in result.output
    assert "NOT reversible" in result.output
    assert conn.calls == []

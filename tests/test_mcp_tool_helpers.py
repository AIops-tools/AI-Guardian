"""MCP tool layer: pure undo-descriptor builders + a few read/write tools driven
through the real governance harness (temp home, reset singletons, connection
monkeypatched to a FakeOllama). No live runtime.
"""

from __future__ import annotations

import pytest

import ai_guardian.governance.audit as audit_mod
import ai_guardian.governance.policy as policy_mod
import ai_guardian.governance.undo as undo_mod
from mcp_server.tools import models as model_tools
from mcp_server.tools import observe as observe_tools
from mcp_server.tools import policy as policy_tools

pytestmark = pytest.mark.unit


def _reset() -> None:
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()


@pytest.fixture
def harness_home(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_GUARDIAN_AIOPS_HOME", str(tmp_path))
    monkeypatch.setenv("AI_GUARDIAN_AUDIT_APPROVED_BY", "pytest")
    _reset()
    yield tmp_path
    _reset()


# ── pure undo-descriptor builders ──────────────────────────────────────────


def test_remove_undo_builds_repull_descriptor():
    d = model_tools._remove_undo({"model": "m"}, {"priorState": {"model": "llama3"}})
    assert d == {"tool": "pull_model", "params": {"model": "llama3"},
                 "note": "Re-pull the model that was removed."}


def test_remove_undo_falls_back_to_params_model():
    d = model_tools._remove_undo({"model": "fromparams"}, {"priorState": {}})
    assert d["params"]["model"] == "fromparams"


def test_remove_undo_none_when_no_model_and_bad_result():
    assert model_tools._remove_undo({}, "not-a-dict") is None
    assert model_tools._remove_undo({}, {"priorState": {}}) is None


def test_allowlist_undo_restores_prior():
    d = policy_tools._allowlist_undo({}, {"priorState": {"allowedModels": ["old*"]}})
    assert d == {"tool": "set_model_allowlist", "params": {"models": ["old*"]},
                 "note": "Restore the prior model allowlist."}


def test_allowlist_undo_none_when_prior_absent():
    assert policy_tools._allowlist_undo({}, {"priorState": {}}) is None
    assert policy_tools._allowlist_undo({}, "nope") is None


def test_denylist_undo_restores_prior():
    d = policy_tools._denylist_undo({}, {"priorState": {"deniedModels": ["*bad*"]}})
    assert d["tool"] == "set_model_denylist"
    assert d["params"] == {"models": ["*bad*"]}


def test_denylist_undo_none_when_prior_absent():
    assert policy_tools._denylist_undo({}, {"priorState": {}}) is None


# ── tools driven through the governance harness ────────────────────────────


_TAGS = {"models": [
    {"name": "llama3.2:3b", "digest": "sha256:aaa", "size": 1},
    {"name": "shadow-uncensored", "digest": "sha256:bbb", "size": 1},
]}


def test_list_models_tool_returns_annotated_rows(harness_home, monkeypatch, fake_ollama):
    fake = fake_ollama(responses={"/api/tags": _TAGS})
    monkeypatch.setattr(model_tools, "_get_connection", lambda target=None: fake)
    # allow-all config → nothing shadowed
    rows = model_tools.list_models()
    assert {r["name"] for r in rows} == {"llama3.2:3b", "shadow-uncensored"}


def test_remove_model_dry_run_does_not_delete(harness_home, monkeypatch, fake_ollama):
    fake = fake_ollama(responses={"/api/show": {"license": "MIT"}})
    monkeypatch.setattr(model_tools, "_get_connection", lambda target=None: fake)
    out = model_tools.remove_model(model="llama3.2:3b", dry_run=True)
    assert out["dryRun"] is True
    assert out["wouldRemove"] == {"model": "llama3.2:3b"}
    assert fake.calls == []  # nothing sent to the runtime


def test_scan_prompt_tool_flags_secret(harness_home):
    out = observe_tools.scan_prompt(text="key AKIAIOSFODNN7EXAMPLE")
    assert out["riskBand"] == "critical"
    assert any(f["kind"] == "aws_access_key" for f in out["findings"])


def test_policy_view_tool_reports_rules(harness_home, monkeypatch):
    from ai_guardian.config import AppConfig
    monkeypatch.setattr(policy_tools, "_get_config",
                        lambda: AppConfig(denied_models=("*bad*",)))
    out = policy_tools.policy_view()
    assert out["deniedModels"] == ["*bad*"]

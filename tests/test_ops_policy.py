"""Model allow/deny policy + provenance writes.

The write helpers persist to ``config.yaml``; the module-level ``CONFIG_FILE`` /
``CONFIG_DIR`` are redirected to a temp dir so nothing touches the real
``~/.ai-guardian``. Reads (``policy_view`` / ``model_provenance``) use the
in-memory ``AppConfig`` + the ``FakeOllama`` double.
"""

from __future__ import annotations

import pytest
import yaml

from ai_guardian.config import AppConfig
from ai_guardian.ops import policy as policy_ops

pytestmark = pytest.mark.unit


@pytest.fixture
def cfg_file(tmp_path, monkeypatch):
    f = tmp_path / "config.yaml"
    monkeypatch.setattr(policy_ops, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(policy_ops, "CONFIG_FILE", f)
    return f


def test_policy_view_reports_current_rules():
    cfg = AppConfig(allowed_models=("llama*",), denied_models=("*bad*",),
                    pinned_digests=(("m", "sha256:x"),))
    out = policy_ops.policy_view(cfg)
    assert out["allowedModels"] == ["llama*"]
    assert out["deniedModels"] == ["*bad*"]
    assert out["pinnedDigests"] == {"m": "sha256:x"}


def test_set_allowlist_replaces_and_returns_prior(cfg_file):
    cfg_file.write_text(yaml.safe_dump({"allowed_models": ["old*"]}), "utf-8")
    out = policy_ops.set_allowlist(["llama*", "qwen*"])
    assert out["allowedModels"] == ["llama*", "qwen*"]
    assert out["priorState"]["allowedModels"] == ["old*"]
    # persisted to disk
    doc = yaml.safe_load(cfg_file.read_text("utf-8"))
    assert doc["allowed_models"] == ["llama*", "qwen*"]


def test_set_denylist_replaces_and_returns_prior_empty(cfg_file):
    out = policy_ops.set_denylist(["*uncensored*"])
    assert out["deniedModels"] == ["*uncensored*"]
    assert out["priorState"]["deniedModels"] == []  # no prior file → empty


def test_pin_model_digest_records_prior(cfg_file):
    first = policy_ops.pin_model_digest("llama3", "sha256:aaa")
    assert first["priorState"]["digest"] is None
    second = policy_ops.pin_model_digest("llama3", "sha256:bbb")
    assert second["priorState"]["digest"] == "sha256:aaa"
    doc = yaml.safe_load(cfg_file.read_text("utf-8"))
    assert doc["pinned_digests"]["llama3"] == "sha256:bbb"


def test_writes_preserve_unrelated_keys(cfg_file):
    cfg_file.write_text(yaml.safe_dump({"targets": [{"name": "local"}]}), "utf-8")
    policy_ops.set_allowlist(["llama*"])
    doc = yaml.safe_load(cfg_file.read_text("utf-8"))
    assert doc["targets"] == [{"name": "local"}]  # untouched
    assert doc["allowed_models"] == ["llama*"]


# ── provenance drift on the native transport ───────────────────────────────


_ONE = {"models": [{"name": "llama3", "digest": "sha256:live", "size": 1}]}


def test_provenance_flags_drift_when_digest_differs(fake_ollama):
    conn = fake_ollama(responses={"/api/tags": _ONE})
    cfg = AppConfig(pinned_digests=(("llama3", "sha256:pinned"),))
    out = policy_ops.model_provenance(conn, cfg)
    row = out["models"][0]
    assert row["status"] == "DRIFT" and out["driftCount"] == 1
    assert row["currentDigest"].startswith("sha256:live")


def test_provenance_ok_when_digest_matches(fake_ollama):
    conn = fake_ollama(responses={"/api/tags": _ONE})
    cfg = AppConfig(pinned_digests=(("llama3", "sha256:live"),))
    out = policy_ops.model_provenance(conn, cfg)
    assert out["models"][0]["status"] == "ok" and out["driftCount"] == 0


def test_provenance_unpinned_when_no_pin(fake_ollama):
    conn = fake_ollama(responses={"/api/tags": _ONE})
    out = policy_ops.model_provenance(conn, AppConfig())
    assert out["models"][0]["status"] == "unpinned"
    assert out["pinnedCount"] == 0

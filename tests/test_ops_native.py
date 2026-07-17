"""Ops layer against the native Ollama transport (the openai-compat path is
covered in test_runtimes). Uses the ``FakeOllama`` double from conftest —
matched-by-path-substring, records every call — so reads/writes are asserted
without a live server.
"""

from __future__ import annotations

import pytest

from ai_guardian.config import AppConfig, TargetConfig
from ai_guardian.ops import models as model_ops
from ai_guardian.ops import observe as observe_ops
from ai_guardian.ops import overview as overview_ops
from ai_guardian.usage import UsageStore

pytestmark = pytest.mark.unit


_TAGS = {"models": [
    {"name": "llama3.2:3b", "digest": "sha256:aaa", "size": 2_000_000_000,
     "modified_at": "2026-01-01", "details": {"family": "llama",
                                               "parameter_size": "3B",
                                               "quantization_level": "Q4"}},
    {"name": "sketchy-uncensored:latest", "digest": "sha256:bbb", "size": 5},
]}
_PS = {"models": [
    {"name": "llama3.2:3b", "digest": "sha256:aaa", "size_vram": 1_500_000_000,
     "expires_at": "2026-01-01T01:00:00Z"},
]}
_SHOW = {"license": "MIT License", "details": {"family": "llama",
                                               "parameter_size": "3B",
                                               "quantization_level": "Q4"},
         "capabilities": ["completion", "tools"]}


# ── reads ──────────────────────────────────────────────────────────────────


def test_list_models_normalizes_and_flags_shadow(fake_ollama):
    conn = fake_ollama(responses={"/api/tags": _TAGS})
    cfg = AppConfig(allowed_models=("llama*",))
    rows = model_ops.list_models(conn, cfg)
    by = {r["name"]: r for r in rows}
    assert by["llama3.2:3b"]["allowed"] is True
    assert by["llama3.2:3b"]["family"] == "llama"
    assert by["llama3.2:3b"]["sizeBytes"] == 2_000_000_000
    assert by["sketchy-uncensored:latest"]["allowed"] is False  # shadow


def test_running_models_reports_vram_and_expiry(fake_ollama):
    conn = fake_ollama(responses={"/api/ps": _PS})
    rows = model_ops.running_models(conn, AppConfig())
    assert rows[0]["sizeVramBytes"] == 1_500_000_000
    assert rows[0]["expiresAt"].startswith("2026")


def test_model_details_extracts_license_and_capabilities(fake_ollama):
    conn = fake_ollama(responses={"/api/show": _SHOW})
    out = model_ops.model_details(conn, "llama3.2:3b")
    assert out["license"] == "MIT License"
    assert out["family"] == "llama"
    assert set(out["capabilities"]) == {"completion", "tools"}


def test_server_status_reachable_reports_version(fake_ollama):
    conn = fake_ollama(responses={"/api/version": {"version": "0.5.7"}})
    status = model_ops.server_status(conn)
    assert status == {"reachable": True, "version": "0.5.7"}


def test_server_status_unreachable_is_caught():
    class _Broken:
        target = None

        def get(self, path, **k):
            raise RuntimeError("connection refused")

    # give it a target with a runtime for runtime_for_conn
    broken = _Broken()
    broken.target = TargetConfig(name="t", runtime="ollama")
    status = model_ops.server_status(broken)
    assert status["reachable"] is False and "connection refused" in status["error"]


def test_vram_usage_flags_over_budget(fake_ollama):
    conn = fake_ollama(responses={"/api/ps": _PS})
    out = model_ops.vram_usage(conn, budget_bytes=1_000_000_000)
    assert out["loadedModels"] == 1
    assert out["totalVramBytes"] == 1_500_000_000
    assert out["overBudget"] is True


def test_vram_usage_under_budget_not_flagged(fake_ollama):
    conn = fake_ollama(responses={"/api/ps": _PS})
    out = model_ops.vram_usage(conn, budget_bytes=9_000_000_000)
    assert out["overBudget"] is False


# ── writes ─────────────────────────────────────────────────────────────────


def test_pull_model_denied_by_policy_never_calls_runtime(fake_ollama):
    conn = fake_ollama()
    cfg = AppConfig(denied_models=("*uncensored*",))
    with pytest.raises(ValueError, match="not permitted by policy"):
        model_ops.pull_model(conn, cfg, "evil-uncensored")
    assert conn.calls == []  # refused before any write


def test_pull_model_allowed_posts_pull(fake_ollama):
    conn = fake_ollama()
    out = model_ops.pull_model(conn, AppConfig(), "llama3.2:3b")
    assert out == {"action": "pull_model", "model": "llama3.2:3b"}
    assert ("POST", "/api/pull", {"model": "llama3.2:3b", "stream": False}) in conn.calls


def test_remove_model_captures_prior_manifest_for_undo(fake_ollama):
    conn = fake_ollama(responses={"/api/show": _SHOW})
    out = model_ops.remove_model(conn, "llama3.2:3b")
    assert out["action"] == "remove_model"
    assert out["priorState"]["license"] == "MIT License"
    assert out["priorState"]["family"] == "llama"
    # the manifest was captured BEFORE the delete
    kinds = [(m, p) for m, p, _ in conn.calls]
    assert kinds.index(("POST", "/api/show")) < kinds.index(("DELETE", "/api/delete"))


def test_remove_model_survives_missing_manifest(fake_ollama):
    class _NoShow:
        target = TargetConfig(name="t", runtime="ollama")
        calls: list = []

        def post(self, path, *, json=None, **k):
            raise RuntimeError("show failed")

        def delete(self, path, *, json=None, **k):
            self.calls.append(("DELETE", path, json))
            return {}

    conn = _NoShow()
    out = model_ops.remove_model(conn, "gone:latest")
    assert out["priorState"]["model"] == "gone:latest"
    assert out["priorState"]["license"] is None


def test_unload_model_sends_keep_alive_zero(fake_ollama):
    conn = fake_ollama()
    out = model_ops.unload_model(conn, "llama3.2:3b")
    assert out["action"] == "unload_model"
    payload = conn.calls[0][2]
    assert payload["keep_alive"] == 0 and payload["prompt"] == ""


# ── route-through guard on the native transport ────────────────────────────


def _with_target(fake):
    fake.target = TargetConfig(name="local", runtime="ollama")
    return fake


def test_guarded_generate_native_allows_and_parses_response(fake_ollama, tmp_path):
    conn = _with_target(
        fake_ollama(responses={"/api/generate": {"response": "The capital is Paris."}}))
    store = UsageStore(tmp_path / "u.db")
    out = observe_ops.guarded_generate(conn, AppConfig(), store, "llama3", "capital?",
                                       agent="claude")
    assert out["blocked"] is False
    assert out["response"] == "The capital is Paris."
    assert out["riskBand"] == "none"
    # recorded to usage log
    assert store.query()[0]["allowed"] is True


def test_guarded_generate_native_blocks_secret_prompt(fake_ollama, tmp_path):
    conn = _with_target(fake_ollama(responses={"/api/generate": {"response": "should not run"}}))
    store = UsageStore(tmp_path / "u.db")
    prompt = "here is my key AKIAIOSFODNN7EXAMPLE please use it"
    out = observe_ops.guarded_generate(conn, AppConfig(), store, "llama3", prompt, agent="a")
    assert out["blocked"] is True and out["riskBand"] == "critical"
    assert "response" not in out
    assert conn.calls == []  # never reached the runtime
    assert store.query()[0]["allowed"] is False


def test_guarded_generate_blocks_disallowed_model(fake_ollama, tmp_path):
    conn = _with_target(fake_ollama())
    store = UsageStore(tmp_path / "u.db")
    cfg = AppConfig(denied_models=("*uncensored*",))
    out = observe_ops.guarded_generate(conn, cfg, store, "bad-uncensored", "hi", agent="a")
    assert out["blocked"] is True and out["modelAllowed"] is False
    assert "model not permitted" in out["reason"]
    assert conn.calls == []


def test_observe_chat_native_joins_messages_and_parses(fake_ollama, tmp_path):
    conn = _with_target(fake_ollama(responses={"/api/chat": {"message": {"content": "hello!"}}}))
    store = UsageStore(tmp_path / "u.db")
    out = observe_ops.observe_chat(conn, AppConfig(), store, "llama3",
                                   [{"role": "user", "content": "hi"}], agent="a")
    assert out["blocked"] is False and out["response"] == "hello!"


def test_scan_prompt_is_pure_and_calls_no_runtime():
    out = observe_ops.scan_prompt("email me at admin@corp.com")
    assert out["riskBand"] in {"low", "medium"}
    assert any(f["kind"] == "email" for f in out["findings"])


# ── usage_events + anomaly + overview rollups ──────────────────────────────


def test_usage_events_wraps_store_query(tmp_path):
    store = UsageStore(tmp_path / "u.db")
    store.record(target="t", model="m", agent="a", user="", prompt_chars=1,
                 risk_level="high", findings=[], allowed=False)
    out = observe_ops.usage_events(store)
    assert out["count"] == 1 and out["events"][0]["model"] == "m"


def test_anomaly_report_rolls_up_shadow_drift_and_stats(fake_ollama, tmp_path):
    conn = fake_ollama(responses={"/api/tags": _TAGS})
    cfg = AppConfig(allowed_models=("llama*",),
                    pinned_digests=(("llama3.2:3b", "sha256:DIFFERENT"),))
    store = UsageStore(tmp_path / "u.db")
    store.record(target="t", model="llama3.2:3b", agent="a", user="", prompt_chars=1,
                 risk_level="critical", findings=[], allowed=False)
    out = observe_ops.anomaly_report(conn, cfg, store)
    assert "sketchy-uncensored:latest" in out["shadowModels"]
    assert "llama3.2:3b" in out["digestDrift"]  # pin mismatch
    assert out["highRiskPrompts"] == 1
    assert out["blockedPrompts"] == 1
    assert out["totalObserved"] == 1


def test_anomaly_report_degrades_on_list_failure(tmp_path):
    class _Broken:
        target = TargetConfig(name="t", runtime="ollama")

        def get(self, path, **k):
            raise RuntimeError("boom")

    store = UsageStore(tmp_path / "u.db")
    out = observe_ops.anomaly_report(_Broken(), AppConfig(), store)
    assert "error" in out


def test_posture_overview_happy_path(fake_ollama, tmp_path):
    conn = fake_ollama(responses={"/api/tags": _TAGS, "/api/ps": _PS})
    cfg = AppConfig(allowed_models=("llama*",))
    store = UsageStore(tmp_path / "u.db")
    store.record(target="t", model="llama3.2:3b", agent="a", user="", prompt_chars=1,
                 risk_level="high", findings=[], allowed=False)
    out = overview_ops.posture_overview(conn, cfg, store)
    assert out["installedModels"] == 2
    assert out["runningModels"] == 1
    assert out["shadowModels"] == 1
    assert out["highRiskObserved"] == 1
    assert out["blockedObserved"] == 1
    assert out["errors"] == []


def test_posture_overview_collects_partial_errors(tmp_path):
    class _Broken:
        target = TargetConfig(name="t", runtime="ollama")

        def get(self, path, **k):
            raise RuntimeError("unreachable")

    store = UsageStore(tmp_path / "u.db")
    out = overview_ops.posture_overview(_Broken(), AppConfig(), store)
    # both list_models and running_models failed → two collected errors, safe defaults
    assert out["installedModels"] == 0 and out["runningModels"] == 0
    assert len(out["errors"]) == 2

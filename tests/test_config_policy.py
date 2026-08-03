"""AppConfig/TargetConfig: token resolution (encrypted store + legacy env),
allow/deny glob logic, target lookup, and per-runtime port defaults on load.
"""

from __future__ import annotations

import pytest
import yaml

from ai_guardian import config as cfg_mod
from ai_guardian.config import AppConfig, TargetConfig, load_config

pytestmark = pytest.mark.unit


# ── model_allowed glob semantics ───────────────────────────────────────────


def test_empty_allowlist_is_allow_all():
    assert AppConfig().model_allowed("anything:latest") is True


def test_deny_always_wins_over_allow():
    c = AppConfig(allowed_models=("llama*",), denied_models=("*uncensored*",))
    assert c.model_allowed("llama-uncensored") is False
    assert c.model_allowed("llama3.2:3b") is True


def test_allowlist_excludes_unlisted():
    c = AppConfig(allowed_models=("llama*",))
    assert c.model_allowed("mistral") is False


# ── target lookup ──────────────────────────────────────────────────────────


def test_get_target_found_and_missing():
    c = AppConfig(targets=(TargetConfig(name="a"), TargetConfig(name="b")))
    assert c.get_target("b").name == "b"
    with pytest.raises(KeyError, match="Available: a, b"):
        c.get_target("z")


def test_default_target_first_or_raises():
    assert AppConfig(targets=(TargetConfig(name="only"),)).default_target.name == "only"
    with pytest.raises(ValueError, match="No targets configured"):
        _ = AppConfig().default_target


def test_base_url_and_spec():
    t = TargetConfig(name="t", host="h", port=9000, runtime="vllm")
    assert t.base_url == "http://h:9000"
    assert t.spec.name == "vllm"


# ── token resolution ───────────────────────────────────────────────────────


def test_token_from_encrypted_store(monkeypatch):
    monkeypatch.setattr(cfg_mod, "has_store", lambda: True)
    monkeypatch.setattr(cfg_mod, "get_secret", lambda name: "enc-token")
    assert TargetConfig(name="edge").token == "enc-token"


def test_token_falls_back_to_legacy_env(monkeypatch):
    monkeypatch.setattr(cfg_mod, "has_store", lambda: False)
    monkeypatch.setenv("AI_GUARDIAN_EDGE_TOKEN", "legacy-token")
    assert TargetConfig(name="edge").token == "legacy-token"


def test_token_store_error_falls_through_to_no_token(monkeypatch):
    def _boom(name):
        raise cfg_mod.SecretStoreError("locked")

    monkeypatch.setattr(cfg_mod, "has_store", lambda: True)
    monkeypatch.setattr(cfg_mod, "get_secret", _boom)
    monkeypatch.delenv("AI_GUARDIAN_EDGE_TOKEN", raising=False)
    assert TargetConfig(name="edge").token == ""


def test_secret_env_key_normalizes_dashes():
    assert cfg_mod._secret_env_key("edge-gpu") == "AI_GUARDIAN_EDGE_GPU_TOKEN"


# ── load_config ────────────────────────────────────────────────────────────


def test_load_config_missing_file_gives_local_default(tmp_path):
    cfg = load_config(tmp_path / "absent.yaml")
    assert cfg.targets[0].name == "local"
    assert cfg.targets[0].runtime == "ollama"


def test_load_config_reads_policy_and_pins(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(yaml.safe_dump({
        "targets": [{"name": "gpu", "runtime": "vllm"}],
        "allowed_models": ["llama*"],
        "denied_models": ["*bad*"],
        "pinned_digests": {"llama3": "sha256:x"},
    }), "utf-8")
    cfg = load_config(f)
    assert cfg.targets[0].port == 8000  # vllm default filled in
    assert cfg.allowed_models == ("llama*",)
    assert cfg.denied_models == ("*bad*",)
    assert cfg.pins == {"llama3": "sha256:x"}


@pytest.mark.unit
def test_a_non_string_pin_stays_a_pin_instead_of_silently_unpinning(tmp_path):
    """An unusable pin must not turn the provenance guard off for that model.

    An unquoted all-digit digest parses as an int, which then read as falsy: the
    model came back ``unpinned`` with ``driftCount: 0`` — a tamper check
    reporting "nothing to check" rather than "this does not match". Seen while
    exercising drift detection against a real Ollama 0.32.5.
    """
    f = tmp_path / "c.yaml"
    f.write_text(
        "targets:\n  - name: local\n"
        "pinned_digests:\n  m1: 0000000000\n  m2: ''\n  m3: abc123\n",
        "utf-8",
    )
    pins = load_config(f).pins
    # YAML has already turned the unquoted digits into an int by this point, so
    # the original text is gone either way. What matters is that a pin remains
    # PRESENT and truthy, so the guard stays armed and reports DRIFT, instead of
    # vanishing into "unpinned".
    assert "m1" in pins
    assert isinstance(pins["m1"], str) and pins["m1"]
    assert pins["m3"] == "abc123"
    assert "m2" not in pins  # a blank value really is "no pin"

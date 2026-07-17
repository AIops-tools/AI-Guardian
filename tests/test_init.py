"""Tests for the ``ai-guardian init`` onboarding wizard.

Driven end-to-end through Typer's CliRunner against an isolated
``AI_GUARDIAN_AIOPS_HOME`` — nothing touches the real ``~/.ai-guardian`` and no
network call is ever attempted (the closing doctor prompt is declined or the
doctor function is patched out).

The wizard differs from sibling AIops tools: it targets a local runtime, so the
bearer token is OPTIONAL (declined by default) and it additionally collects a
model allow/deny policy.

Prompt order: runtime (choice), name, host, port, HTTPS? (confirm), bearer
token? (confirm, optional getpass), allowed patterns, denied patterns, run
doctor? (confirm).
"""

from __future__ import annotations

import pytest
import yaml
from typer.testing import CliRunner

import ai_guardian.cli.init as init_mod
import ai_guardian.config as config_mod
import ai_guardian.secretstore as ss
from ai_guardian.cli._root import app

pytestmark = pytest.mark.unit

MASTER_PW = "wizard-master-pw"
runner = CliRunner()


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Point every path constant the wizard touches at a throwaway home."""
    config_file = tmp_path / "config.yaml"
    monkeypatch.setenv("AI_GUARDIAN_AIOPS_HOME", str(tmp_path))
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, MASTER_PW)

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(config_mod, "ENV_FILE", tmp_path / ".env")
    # init imported the names directly; patch its namespace too.
    monkeypatch.setattr(init_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(init_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", tmp_path / "secrets.enc")
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(ss, "_cached", None)
    return tmp_path


def _run_init(answers: list[str]):
    return runner.invoke(app, ["init"], input="".join(a + "\n" for a in answers))


# runtime, name, host, port (blank = accept default), HTTPS?, token?, allow, deny, doctor?
HAPPY_ANSWERS = ["", "", "", "", "n", "n", "", "", "n"]


def test_defaults_write_local_target(isolated_home):
    result = _run_init(HAPPY_ANSWERS)
    assert result.exit_code == 0, result.output

    raw = yaml.safe_load((isolated_home / "config.yaml").read_text("utf-8"))
    assert raw["targets"] == [
        {"name": "local", "runtime": "ollama", "host": "localhost",
         "port": 11434, "scheme": "http"}
    ]
    # No policy entered and no token — neither may appear in the config.
    assert "allowed_models" not in raw
    assert "denied_models" not in raw
    assert not (isolated_home / "secrets.enc").exists()


def test_custom_endpoint_and_https(isolated_home):
    answers = ["", "edge-1", "10.0.0.5", "8443", "y", "n", "", "", "n"]
    result = _run_init(answers)
    assert result.exit_code == 0, result.output

    raw = yaml.safe_load((isolated_home / "config.yaml").read_text("utf-8"))
    assert raw["targets"] == [
        {"name": "edge-1", "runtime": "ollama", "host": "10.0.0.5",
         "port": 8443, "scheme": "https"}
    ]


def test_llamacpp_runtime_defaults_to_its_port(isolated_home):
    # Pick the llama.cpp runtime; accepting the port default must yield 8080.
    answers = ["llamacpp", "edge-gguf", "", "", "n", "n", "", "", "n"]
    result = _run_init(answers)
    assert result.exit_code == 0, result.output

    raw = yaml.safe_load((isolated_home / "config.yaml").read_text("utf-8"))
    assert raw["targets"] == [
        {"name": "edge-gguf", "runtime": "llamacpp", "host": "localhost",
         "port": 8080, "scheme": "http"}
    ]


def test_lmstudio_and_vllm_default_ports(isolated_home):
    for runtime, port in (("lmstudio", 1234), ("vllm", 8000)):
        answers = [runtime, "t", "", "", "n", "n", "", "", "n"]
        result = _run_init(answers)
        assert result.exit_code == 0, result.output
        raw = yaml.safe_load((isolated_home / "config.yaml").read_text("utf-8"))
        assert raw["targets"][0]["runtime"] == runtime
        assert raw["targets"][0]["port"] == port


def test_model_policy_recorded_from_comma_lists(isolated_home):
    answers = ["", "", "", "", "n", "n", "llama3*, mistral*", "evil*", "n"]
    result = _run_init(answers)
    assert result.exit_code == 0, result.output

    raw = yaml.safe_load((isolated_home / "config.yaml").read_text("utf-8"))
    assert raw["allowed_models"] == ["llama3*", "mistral*"]
    assert raw["denied_models"] == ["evil*"]


def test_optional_token_lands_encrypted_not_in_config(isolated_home, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "bearer-token-xyz")
    answers = ["", "", "", "", "n", "y", "", "", "n"]  # opt IN to the bearer token
    result = _run_init(answers)
    assert result.exit_code == 0, result.output
    assert "Token stored encrypted" in result.output

    config_text = (isolated_home / "config.yaml").read_text("utf-8")
    assert "bearer-token-xyz" not in config_text
    secrets_blob = (isolated_home / "secrets.enc").read_text("utf-8")
    assert "bearer-token-xyz" not in secrets_blob
    assert ss.SecretStore.unlock(MASTER_PW).get("local") == "bearer-token-xyz"


def test_rules_yaml_seeded_with_approver_tier(isolated_home):
    result = _run_init(HAPPY_ANSWERS)
    assert result.exit_code == 0, result.output

    rules = (isolated_home / "rules.yaml").read_text("utf-8")
    assert "high-risk-requires-approver" in rules
    assert "risk_tiers" in rules


def test_rerun_does_not_clobber_existing_rules(isolated_home):
    (isolated_home / "rules.yaml").write_text("# operator-authored\n", "utf-8")
    result = _run_init(HAPPY_ANSWERS)
    assert result.exit_code == 0, result.output
    assert (isolated_home / "rules.yaml").read_text("utf-8") == "# operator-authored\n"


def test_declining_doctor_prompt_skips_reachability(isolated_home, monkeypatch):
    def _boom(*a, **k):  # pragma: no cover — must not be reached
        raise AssertionError("run_doctor must not run when declined")

    monkeypatch.setattr("ai_guardian.doctor.run_doctor", _boom)
    result = _run_init(HAPPY_ANSWERS)
    assert result.exit_code == 0, result.output


def test_accepting_doctor_prompt_runs_it_and_propagates_exit(isolated_home, monkeypatch):
    calls: list[bool] = []

    def _fake_doctor(*a, **k) -> int:
        calls.append(True)
        return 1  # unhealthy — init must exit with the doctor's code

    monkeypatch.setattr("ai_guardian.doctor.run_doctor", _fake_doctor)
    answers = ["", "", "", "", "n", "n", "", "", "y"]
    result = _run_init(answers)
    assert calls == [True]
    assert result.exit_code == 1

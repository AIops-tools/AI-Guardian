"""Tests for ``ai_guardian.doctor.run_doctor``.

All filesystem paths are redirected to a tmp dir and the Ollama layer is mocked
at the ConnectionManager boundary — no test ever performs real HTTP against an
Ollama runtime or touches the real ``~/.ai-guardian``.

Unlike sibling AIops tools, ai-guardian is zero-config friendly: a missing
config.yaml is NOT a failure (it defaults to the local Ollama), and a missing
secret store is only an informational note (local Ollama usually needs no token).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import yaml

import ai_guardian.config as config_mod
import ai_guardian.doctor as doctor_mod
import ai_guardian.secretstore as ss
from ai_guardian.doctor import run_doctor

pytestmark = pytest.mark.unit

MASTER_PW = "test-master-pw"


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Redirect every config/secret path constant at a throwaway directory."""
    config_file = tmp_path / "config.yaml"
    env_file = tmp_path / ".env"
    secrets_file = tmp_path / "secrets.enc"

    monkeypatch.setenv("AI_GUARDIAN_AIOPS_HOME", str(tmp_path))
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, MASTER_PW)

    # config module reads its globals at call time.
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(config_mod, "ENV_FILE", env_file)
    # doctor imported SECRETS_FILE directly (for the message); patch its namespace.
    monkeypatch.setattr(doctor_mod, "SECRETS_FILE", secrets_file)
    # secret store paths + cache (its CONFIG_DIR ignores the env var).
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", secrets_file)
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", env_file)
    monkeypatch.setattr(ss, "_cached", None)
    return tmp_path


def _write_config(home, doc: dict) -> None:
    (home / "config.yaml").write_text(yaml.safe_dump(doc), "utf-8")


def _target(name: str = "local", port: int = 11434) -> dict:
    return {"name": name, "host": "localhost", "port": port}


def _store_secret(name: str = "local", value: str = "bearer-token") -> None:
    ss.SecretStore.unlock(MASTER_PW).set(name, value)


def _reachable_conn(version: str = "0.9.9") -> MagicMock:
    """A connection whose GET /api/version answers happily."""
    conn = MagicMock(name="OllamaConnection")
    conn.get.return_value = {"version": version}
    return conn


@pytest.fixture
def ok_connection(monkeypatch):
    """A ConnectionManager whose connect() yields a reachable Ollama."""
    mgr = MagicMock(name="ConnectionManager")
    mgr.return_value.connect.return_value = _reachable_conn()
    monkeypatch.setattr("ai_guardian.connection.ConnectionManager", mgr)
    return mgr


def _out(capsys) -> str:
    # Rich wraps long lines (tmp paths); normalize whitespace before matching.
    return " ".join(capsys.readouterr().out.split())


def test_zero_config_defaults_to_local_target(isolated_home, ok_connection, capsys):
    # No config.yaml at all — doctor must still work against the local default.
    assert run_doctor() == 0
    out = _out(capsys)
    assert "1 runtime target(s) configured" in out
    assert "No secret store" in out  # informational, not a failure
    assert "'local' (http://localhost:11434) — Ollama 0.9.9" in out
    ok_connection.return_value.connect.assert_called_once_with("local")


def test_config_load_failure_reported_not_raised(isolated_home, capsys):
    # A target without the required 'name' key makes load_config raise; doctor
    # must report the failure as a check, never a traceback.
    _write_config(isolated_home, {"targets": [{"host": "localhost"}]})
    assert run_doctor() == 1
    assert "Config load failed" in _out(capsys)


def test_all_healthy_exits_zero(isolated_home, ok_connection, capsys):
    _write_config(isolated_home, {"targets": [_target()]})
    _store_secret()
    assert run_doctor() == 0
    out = _out(capsys)
    assert "1 runtime target(s) configured" in out
    assert "Encrypted secret store present" in out
    assert "'local' (http://localhost:11434) — Ollama 0.9.9" in out
    ok_connection.return_value.connect.assert_called_once_with("local")


def test_policy_counts_reported(isolated_home, capsys):
    _write_config(
        isolated_home,
        {
            "targets": [_target()],
            "allowed_models": ["llama3*", "mistral*"],
            "denied_models": ["evil*"],
            "pinned_digests": {"llama3:8b": "sha256:abc"},
        },
    )
    assert run_doctor(skip_auth=True) == 0
    assert "2 allow / 1 deny pattern(s), 1 digest pin(s)" in _out(capsys)


def test_unreachable_endpoint_is_a_problem(isolated_home, monkeypatch, capsys):
    _write_config(isolated_home, {"targets": [_target()]})
    mgr = MagicMock(name="ConnectionManager")
    conn = MagicMock(name="OllamaConnection")
    conn.get.side_effect = ConnectionError("connection refused")
    mgr.return_value.connect.return_value = conn
    monkeypatch.setattr("ai_guardian.connection.ConnectionManager", mgr)

    assert run_doctor() == 1
    out = _out(capsys)
    assert "'local' (http://localhost:11434) unreachable" in out
    assert "connection refused" in out


def test_mixed_targets_reported_per_target(isolated_home, monkeypatch, capsys):
    _write_config(isolated_home, {"targets": [_target("edge-a"), _target("edge-b", 11435)]})

    def _connect(name):
        if name == "edge-b":
            conn = MagicMock(name="OllamaConnection")
            conn.get.side_effect = ConnectionError("connection refused")
            return conn
        return _reachable_conn("0.5.1")

    mgr = MagicMock(name="ConnectionManager")
    mgr.return_value.connect.side_effect = _connect
    monkeypatch.setattr("ai_guardian.connection.ConnectionManager", mgr)

    assert run_doctor() == 1
    out = _out(capsys)
    assert "'edge-a' (http://localhost:11434) — Ollama 0.5.1" in out
    assert "'edge-b' (http://localhost:11435) unreachable" in out


def test_skip_auth_never_touches_connection_layer(isolated_home, monkeypatch, capsys):
    _write_config(isolated_home, {"targets": [_target()]})

    def _boom(*a, **k):  # pragma: no cover — must not be reached
        raise AssertionError("ConnectionManager must not be constructed with --skip-auth")

    monkeypatch.setattr("ai_guardian.connection.ConnectionManager", _boom)
    assert run_doctor(skip_auth=True) == 0
    assert "Skipping reachability check" in _out(capsys)


def test_no_secret_store_is_informational_not_fatal(isolated_home, capsys):
    # Local Ollama usually runs open — no store must NOT fail the doctor.
    _write_config(isolated_home, {"targets": [_target()]})
    assert run_doctor(skip_auth=True) == 0
    assert "local Ollama usually needs no token" in _out(capsys)


def test_permission_warning_surfaced(isolated_home, capsys):
    _write_config(isolated_home, {"targets": [_target()]})
    _store_secret()
    (isolated_home / "secrets.enc").chmod(0o644)
    assert run_doctor(skip_auth=True) == 0
    assert "should be 600" in _out(capsys)

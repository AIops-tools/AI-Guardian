"""Absent fields come back as null, not as an empty string.

This tool's whole job is reporting honestly on local models, and the runtimes it
supports genuinely differ in what they can report: Ollama exposes a digest and a
version, LM Studio and vLLM expose neither. ``""`` reads as "the runtime told us
and it was blank"; the truth is "this runtime cannot tell you". These tests pin
that distinction, the provenance verdict that depends on it, and the truncation
envelope on the usage log.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ai_guardian.config import AppConfig
from ai_guardian.governance import opt_str
from ai_guardian.ops import models as model_ops
from ai_guardian.ops import observe as observe_ops
from ai_guardian.ops import policy as policy_ops
from ai_guardian.ops._util import opt_s, s

pytestmark = pytest.mark.unit


@pytest.mark.unit
def test_opt_str_distinguishes_absent_from_empty():
    assert opt_str(None) is None, "absent must stay absent"
    assert opt_str("") == "", "a genuinely empty value is not the same as absent"
    assert opt_str("llama3:8b", 64) == "llama3:8b"


@pytest.mark.unit
def test_opt_str_still_sanitizes_and_truncates():
    assert opt_str("a\x00b") == "ab"  # control character stripped
    assert opt_str("abcdef", 3) == "abc"


@pytest.mark.unit
def test_opt_str_accepts_non_string_values():
    assert opt_str(42) == "42"


@pytest.mark.unit
def test_opt_s_and_s_differ_only_on_absence():
    assert s(None) == "" and opt_s(None) is None
    assert s("llama3") == opt_s("llama3") == "llama3"


# ── model inventory ──────────────────────────────────────────────────────


@pytest.mark.unit
def test_model_rows_report_absent_metadata_as_none():
    conn = MagicMock()
    conn.get.return_value = {"models": [{"name": "llama3:8b"}]}
    row = model_ops.list_models(conn, AppConfig())[0]
    assert row["name"] == "llama3:8b"
    assert row["digest"] is None
    assert row["family"] is None and row["quantization"] is None


@pytest.mark.unit
def test_model_rows_keep_empty_string_when_the_runtime_sent_one():
    conn = MagicMock()
    conn.get.return_value = {"models": [{"name": "llama3:8b", "digest": ""}]}
    assert model_ops.list_models(conn, AppConfig())[0]["digest"] == ""


@pytest.mark.unit
def test_ops_never_drop_the_key_itself():
    """Keys are always present; only their value may be null."""
    conn = MagicMock()
    conn.get.return_value = {"models": [{"name": "m"}]}
    row = model_ops.list_models(conn, AppConfig())[0]
    for key in ("name", "digest", "sizeBytes", "family", "parameterSize",
                "quantization", "modifiedAt", "allowed"):
        assert key in row, f"{key} must be present even when the source omitted it"


@pytest.mark.unit
def test_model_name_stays_a_string_for_policy_matching():
    """``name`` feeds fnmatch in model_allowed — it must never become None."""
    conn = MagicMock()
    conn.get.return_value = {"models": [{}]}
    row = model_ops.list_models(conn, AppConfig())[0]
    assert isinstance(row["name"], str)
    assert isinstance(row["allowed"], bool)


@pytest.mark.unit
def test_server_version_is_none_when_the_runtime_reports_none():
    conn = MagicMock()
    conn.get.return_value = {}
    assert model_ops.server_status(conn)["version"] is None


# ── the consumer the null shape feeds ────────────────────────────────────


@pytest.mark.unit
def test_absent_digest_is_unverifiable_not_drift():
    """A runtime that cannot identify weights must not be reported as tampered.

    This is the consumer that makes the absent/empty distinction load-bearing:
    ``model_provenance`` reads a missing digest as `unverifiable`, and only a
    digest that is present AND different is DRIFT.
    """
    conn = MagicMock()
    conn.get.return_value = {"models": [{"name": "llama3:8b"}]}  # no digest
    config = AppConfig(pinned_digests=(("llama3:8b", "sha256:expected"),))

    out = policy_ops.model_provenance(conn, config)
    assert out["driftCount"] == 0
    assert out["models"][0]["status"] == "unverifiable"
    assert out["models"][0]["currentDigest"] is None


@pytest.mark.unit
def test_a_changed_digest_is_still_drift():
    conn = MagicMock()
    conn.get.return_value = {"models": [{"name": "llama3:8b", "digest": "sha256:other"}]}
    config = AppConfig(pinned_digests=(("llama3:8b", "sha256:expected"),))

    out = policy_ops.model_provenance(conn, config)
    assert out["driftCount"] == 1 and out["models"][0]["status"] == "DRIFT"


# ── truncation announces itself ──────────────────────────────────────────


class _Store:
    """A usage store that honours ``limit`` the way the real one does."""

    def __init__(self, n: int) -> None:
        self.rows = [{"id": i, "model": "llama3", "risk_level": "low"} for i in range(n)]
        self.last_limit: int | None = None

    def query(self, *, limit: int = 100, **kw):
        self.last_limit = limit
        return self.rows[:limit]


@pytest.mark.unit
def test_usage_events_returns_a_truncation_envelope():
    store = _Store(5)
    out = observe_ops.usage_events(store, limit=2)
    assert out["returned"] == 2 and out["limit"] == 2 and out["truncated"] is True
    assert len(out["events"]) == 2


@pytest.mark.unit
def test_usage_events_count_describes_what_you_were_given():
    store = _Store(5)
    out = observe_ops.usage_events(store, limit=2)
    assert out["count"] == out["returned"] == len(out["events"]) == 2


@pytest.mark.unit
def test_usage_events_is_not_truncated_at_exactly_the_limit():
    """The boundary case a length-comparison heuristic gets wrong.

    An under-reported usage log looks like an absence of risky prompts, so this
    is the flag that keeps "I saw everything" honest.
    """
    store = _Store(2)
    out = observe_ops.usage_events(store, limit=2)
    assert out["returned"] == 2 and out["truncated"] is False


@pytest.mark.unit
def test_usage_events_fetches_one_extra_row_to_measure():
    store = _Store(5)
    observe_ops.usage_events(store, limit=2)
    assert store.last_limit == 3, "the probe row is what makes truncated measured"


@pytest.mark.unit
def test_undo_list_envelope_measures_truncation(monkeypatch):
    from mcp_server.tools import undo as undo_tools

    rows = [
        {
            "undo_id": f"u{i}",
            "ts": "2026-07-18T00:00:00Z",
            "tool": "some_tool",
            "undo_tool": "some_inverse_tool",
            "note": "",
        }
        for i in range(4)
    ]
    captured = {}

    class _Store:
        def list(self, *, status=None, limit=50):
            captured["limit"] = limit
            return rows[:limit]

    monkeypatch.setattr(undo_tools, "get_undo_store", lambda: _Store())
    result = undo_tools.undo_list(limit=3)
    assert captured["limit"] == 4, "one extra row is fetched to measure truncation"
    assert result["returned"] == 3
    assert result["limit"] == 3
    assert result["truncated"] is True
    assert len(result["undos"]) == 3

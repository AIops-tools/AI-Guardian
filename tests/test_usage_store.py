"""UsageStore: record + query filters + stats against a throwaway sqlite file.

The raw prompt is never persisted — only its length and the (redacted) findings —
so these tests assert the row shape as well as the aggregation math.
"""

from __future__ import annotations

import pytest

from ai_guardian.usage import UsageStore

pytestmark = pytest.mark.unit


def _store(tmp_path):
    return UsageStore(tmp_path / "usage.db")


def _seed(store):
    store.record(target="local", model="llama3", agent="claude", user="alice",
                 prompt_chars=10, risk_level="none", findings=[], allowed=True)
    store.record(target="local", model="llama3", agent="claude", user="bob",
                 prompt_chars=20, risk_level="high",
                 findings=[{"category": "secret", "kind": "aws"}], allowed=False)
    store.record(target="local", model="mistral", agent="agent-x", user="",
                 prompt_chars=5, risk_level="critical", findings=[], allowed=False)


def test_query_empty_before_any_write(tmp_path):
    assert _store(tmp_path).query() == []


def test_record_then_query_roundtrip_decodes_findings(tmp_path):
    store = _store(tmp_path)
    _seed(store)
    rows = store.query()
    assert len(rows) == 3
    # newest first (id DESC)
    assert rows[0]["model"] == "mistral"
    high = next(r for r in rows if r["risk_level"] == "high")
    assert high["allowed"] is False
    assert high["findings"] == [{"category": "secret", "kind": "aws"}]
    assert high["finding_count"] == 1
    assert high["prompt_chars"] == 20


def test_query_filters_by_model_and_risk_and_allowed(tmp_path):
    store = _store(tmp_path)
    _seed(store)
    assert {r["model"] for r in store.query(model="llama3")} == {"llama3"}
    assert all(r["risk_level"] == "critical" for r in store.query(risk_level="critical"))
    blocked = store.query(allowed=False)
    assert len(blocked) == 2 and all(r["allowed"] is False for r in blocked)
    allowed = store.query(allowed=True)
    assert len(allowed) == 1 and allowed[0]["allowed"] is True


def test_query_since_and_limit(tmp_path):
    store = _store(tmp_path)
    _seed(store)
    assert len(store.query(limit=1)) == 1
    # a future timestamp filters everything out
    assert store.query(since="2999-01-01T00:00:00+00:00") == []


def test_stats_aggregates_by_risk_model_and_disallowed(tmp_path):
    store = _store(tmp_path)
    _seed(store)
    stats = store.stats()
    assert stats["total"] == 3
    assert stats["byRisk"] == {"none": 1, "high": 1, "critical": 1}
    assert stats["byModel"] == {"llama3": 2, "mistral": 1}
    assert stats["disallowed"] == 2


def test_stats_zeroed_before_any_write(tmp_path):
    stats = _store(tmp_path).stats()
    assert stats == {"total": 0, "byRisk": {}, "byModel": {}, "disallowed": 0}


def test_record_is_a_noop_when_store_failed_to_init(tmp_path):
    store = _store(tmp_path)
    store._ok = False  # simulate a failed DB init
    # must not raise even though the store is disabled
    store.record(target="t", model="m", agent="a", user="u", prompt_chars=1,
                 risk_level="none", findings=[], allowed=True)
    # nothing was written
    assert store.query() == []

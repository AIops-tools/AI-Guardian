"""Observed local-LLM usage log — ai-guardian's own store.

Separate from the governance ``audit.db`` (which records the guardian's own tool
calls): this ``usage.db`` records *what the local models were asked to do* — one
row per prompt routed through ``guarded_generate``: the model, the actor, the
prompt size, and the scanner's risk findings (redacted). The raw prompt text is
**not** stored — only its length + the (already-masked) findings — so the guard
log never becomes a second copy of the secrets it caught.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from ai_guardian.config import USAGE_DB

_log = logging.getLogger("ai-guardian.usage")

_CREATE = """\
CREATE TABLE IF NOT EXISTS usage_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT    NOT NULL,
    target       TEXT    NOT NULL DEFAULT '',
    model        TEXT    NOT NULL DEFAULT '',
    agent        TEXT    NOT NULL DEFAULT 'unknown',
    user         TEXT    NOT NULL DEFAULT '',
    prompt_chars INTEGER NOT NULL DEFAULT 0,
    risk_level   TEXT    NOT NULL DEFAULT 'none',
    finding_count INTEGER NOT NULL DEFAULT 0,
    findings     TEXT    NOT NULL DEFAULT '[]',
    allowed      INTEGER NOT NULL DEFAULT 1
)
"""


class UsageStore:
    """Append + query the observed-usage log."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._path = Path(db_path).expanduser() if db_path else USAGE_DB
        self._ok = False
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            conn = self._connect()
            conn.execute(_CREATE)
            conn.commit()
            conn.close()
            self._ok = True
        except sqlite3.Error:
            _log.warning("Cannot init usage DB at %s", self._path, exc_info=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def record(self, *, target: str, model: str, agent: str, user: str,
               prompt_chars: int, risk_level: str, findings: list[dict],
               allowed: bool) -> None:
        """Append one observed-usage row (best-effort; never raises)."""
        if not self._ok:
            return
        try:
            conn = self._connect()
            conn.execute(
                "INSERT INTO usage_log (ts,target,model,agent,user,prompt_chars,"
                "risk_level,finding_count,findings,allowed) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (datetime.now(tz=UTC).isoformat(), target, model, agent, user,
                 prompt_chars, risk_level, len(findings),
                 json.dumps(findings, ensure_ascii=False), int(allowed)),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error:
            _log.warning("Failed to record usage", exc_info=True)

    def query(self, *, model: str | None = None, risk_level: str | None = None,
              allowed: bool | None = None, since: str | None = None,
              limit: int = 200) -> list[dict]:
        """Query usage rows (newest first)."""
        if not self._path.exists():
            return []
        clauses, values = [], []
        for col, val in (("model", model), ("risk_level", risk_level)):
            if val is not None:
                clauses.append(f"{col} = ?")
                values.append(val)
        if allowed is not None:
            clauses.append("allowed = ?")
            values.append(int(allowed))
        if since is not None:
            clauses.append("ts >= ?")
            values.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM usage_log {where} ORDER BY id DESC LIMIT ?"  # nosec B608
        try:
            conn = self._connect()
            rows = conn.execute(sql, [*values, limit]).fetchall()
            conn.close()
        except sqlite3.Error:
            return []
        out = []
        for r in rows:
            row = dict(r)
            row["allowed"] = bool(row["allowed"])
            try:
                row["findings"] = json.loads(row["findings"])
            except (ValueError, TypeError):
                row["findings"] = []
            out.append(row)
        return out

    def stats(self) -> dict:
        """Aggregate: totals by risk level, by model, and disallowed count."""
        if not self._path.exists():
            return {"total": 0, "byRisk": {}, "byModel": {}, "disallowed": 0}
        try:
            conn = self._connect()
            total = conn.execute("SELECT COUNT(*) c FROM usage_log").fetchone()["c"]
            by_risk = {r["risk_level"]: r["c"] for r in conn.execute(
                "SELECT risk_level, COUNT(*) c FROM usage_log GROUP BY risk_level")}
            by_model = {r["model"]: r["c"] for r in conn.execute(
                "SELECT model, COUNT(*) c FROM usage_log GROUP BY model")}
            disallowed = conn.execute(
                "SELECT COUNT(*) c FROM usage_log WHERE allowed = 0").fetchone()["c"]
            conn.close()
        except sqlite3.Error:
            return {"total": 0, "byRisk": {}, "byModel": {}, "disallowed": 0}
        return {"total": total, "byRisk": by_risk, "byModel": by_model,
                "disallowed": disallowed}

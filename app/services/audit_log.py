"""Append-only audit log over SQLite.

The MVP printed a cosmetic audit string and never persisted anything. This is
the real thing: every approval, action, and analyst feedback event is written
as an immutable row. There is no UPDATE or DELETE path in this module - a
correction is a new row, which is what an auditor actually wants.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "audit.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    message_id    TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    verdict       TEXT,
    risk_score    INTEGER,
    policy_band   TEXT,
    action        TEXT,
    approved      INTEGER,
    analyst       TEXT,
    llm_mode      TEXT,
    evidence_json TEXT,
    notes         TEXT
);
CREATE TABLE IF NOT EXISTS analyst_feedback (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    message_id   TEXT NOT NULL,
    predicted    TEXT,
    feedback     TEXT NOT NULL,
    corrected    TEXT,
    analyst      TEXT,
    notes        TEXT
);
CREATE TABLE IF NOT EXISTS message_state (
    message_id    TEXT PRIMARY KEY,
    action_status TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with closing(_connect()) as connection:
        connection.executescript(SCHEMA)
        connection.commit()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def record_event(
    message_id: str,
    event_type: str,
    verdict: str = "",
    risk_score: int = 0,
    policy_band: str = "",
    action: str = "",
    approved: bool = False,
    analyst: str = "analyst@company.example",
    llm_mode: str = "",
    evidence: list | None = None,
    notes: str = "",
) -> int:
    init_db()
    with closing(_connect()) as connection:
        cursor = connection.execute(
            """INSERT INTO audit_log
               (timestamp, message_id, event_type, verdict, risk_score, policy_band,
                action, approved, analyst, llm_mode, evidence_json, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                _now(),
                message_id,
                event_type,
                verdict,
                int(risk_score),
                policy_band,
                action,
                1 if approved else 0,
                analyst,
                llm_mode,
                json.dumps(evidence or []),
                notes,
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def approve_action(
    message_id: str,
    action: str,
    verdict: str,
    risk_score: int,
    policy_band: str,
    new_status: str = "quarantined",
    analyst: str = "analyst@company.example",
    llm_mode: str = "",
) -> None:
    """Record an approved containment action and flip the message state."""
    record_event(
        message_id=message_id,
        event_type="action_approved",
        verdict=verdict,
        risk_score=risk_score,
        policy_band=policy_band,
        action=action,
        approved=True,
        analyst=analyst,
        llm_mode=llm_mode,
        notes="Simulated containment - no live mail tenant is connected.",
    )
    set_action_status(message_id, new_status)


def set_action_status(message_id: str, status: str) -> None:
    init_db()
    with closing(_connect()) as connection:
        connection.execute(
            """INSERT INTO message_state (message_id, action_status, updated_at)
               VALUES (?,?,?)
               ON CONFLICT(message_id) DO UPDATE SET action_status=excluded.action_status,
                                                     updated_at=excluded.updated_at""",
            (message_id, status, _now()),
        )
        connection.commit()


def get_action_status(message_id: str, default: str = "delivered") -> str:
    init_db()
    with closing(_connect()) as connection:
        row = connection.execute(
            "SELECT action_status FROM message_state WHERE message_id = ?", (message_id,)
        ).fetchone()
    return row["action_status"] if row else default


def all_action_statuses() -> dict[str, str]:
    init_db()
    with closing(_connect()) as connection:
        rows = connection.execute("SELECT message_id, action_status FROM message_state").fetchall()
    return {row["message_id"]: row["action_status"] for row in rows}


def record_feedback(
    message_id: str,
    predicted: str,
    feedback: str,
    corrected: str = "",
    analyst: str = "analyst@company.example",
    notes: str = "",
) -> None:
    init_db()
    with closing(_connect()) as connection:
        connection.execute(
            """INSERT INTO analyst_feedback
               (timestamp, message_id, predicted, feedback, corrected, analyst, notes)
               VALUES (?,?,?,?,?,?,?)""",
            (_now(), message_id, predicted, feedback, corrected, analyst, notes),
        )
        connection.commit()
    record_event(
        message_id=message_id,
        event_type="analyst_feedback",
        verdict=predicted,
        action=feedback,
        analyst=analyst,
        notes=f"corrected={corrected or 'n/a'}; {notes}".strip(),
    )


def read_log(limit: int = 200) -> list[dict]:
    init_db()
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def read_feedback(limit: int = 200) -> list[dict]:
    init_db()
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT * FROM analyst_feedback ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]

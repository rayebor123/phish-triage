"""
SQLite persistence for triage history.

Every completed verdict is written here alongside its indicators, so the
dashboard reflects results across app restarts rather than just the current
session. Plain sqlite3 -- no ORM -- to match the rest of this codebase.
"""

import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "triage_history.db")

STATUSES = ["Pending", "Reviewed", "Escalated", "False Positive"]


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _connect()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            filename TEXT,
            subject TEXT,
            from_addr TEXT,
            verdict TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            summary TEXT,
            recommended_action TEXT,
            status TEXT NOT NULL DEFAULT 'Pending'
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id INTEGER NOT NULL REFERENCES emails(id),
            indicator TEXT NOT NULL,
            severity TEXT NOT NULL,
            evidence TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def save_result(filename: str, parsed: dict, result: dict) -> int:
    """Persist a completed verdict and its indicators. Returns the new row id."""
    conn = _connect()
    cur = conn.execute(
        """
        INSERT INTO emails
            (timestamp, filename, subject, from_addr, verdict, confidence, summary, recommended_action)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            filename,
            parsed.get("subject") or "",
            parsed.get("from_addr") or "",
            result["verdict"],
            result["confidence"],
            result["summary"],
            result["recommended_action"],
        ),
    )
    email_id = cur.lastrowid
    conn.executemany(
        "INSERT INTO indicators (email_id, indicator, severity, evidence) VALUES (?, ?, ?, ?)",
        [
            (email_id, ind["indicator"], ind["severity"], ind.get("evidence", ""))
            for ind in result.get("indicators", [])
        ],
    )
    conn.commit()
    conn.close()
    return email_id


def get_all_emails() -> list[dict]:
    conn = _connect()
    rows = conn.execute("SELECT * FROM emails ORDER BY timestamp DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_status(email_id: int, status: str) -> None:
    conn = _connect()
    conn.execute("UPDATE emails SET status = ? WHERE id = ?", (status, email_id))
    conn.commit()
    conn.close()


def indicator_counts(limit: int = 10) -> list[tuple]:
    """Most frequently cited indicator strings across all saved verdicts."""
    conn = _connect()
    rows = conn.execute(
        "SELECT indicator, COUNT(*) AS n FROM indicators GROUP BY indicator ORDER BY n DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [(r["indicator"], r["n"]) for r in rows]

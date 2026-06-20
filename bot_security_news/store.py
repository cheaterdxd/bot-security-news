from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import SecurityItem


SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    stable_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    kind TEXT NOT NULL,
    published_at TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    sent_at TEXT,
    reasons TEXT
);

CREATE TABLE IF NOT EXISTS reports (
    report_date TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    sent_at TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def upsert_items(self, items: list[SecurityItem]) -> None:
        now = _utc_now()
        with self.connection:
            for item in items:
                self.connection.execute(
                    """
                    INSERT INTO items (
                        stable_id, source, title, url, kind, published_at,
                        first_seen_at, reasons
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(stable_id) DO UPDATE SET
                        title = excluded.title,
                        url = excluded.url,
                        reasons = excluded.reasons
                    """,
                    (
                        item.stable_id,
                        item.source,
                        item.title,
                        item.url,
                        item.kind.value,
                        item.published_iso,
                        now,
                        ", ".join(item.reasons),
                    ),
                )

    def filter_unsent(self, items: list[SecurityItem]) -> list[SecurityItem]:
        if not items:
            return []
        placeholders = ",".join("?" for _ in items)
        rows = self.connection.execute(
            f"SELECT stable_id FROM items WHERE sent_at IS NOT NULL AND stable_id IN ({placeholders})",
            [item.stable_id for item in items],
        ).fetchall()
        sent_ids = {row[0] for row in rows}
        return [item for item in items if item.stable_id not in sent_ids]

    def mark_sent(self, items: list[SecurityItem]) -> None:
        now = _utc_now()
        with self.connection:
            for item in items:
                self.connection.execute(
                    "UPDATE items SET sent_at = ? WHERE stable_id = ?",
                    (now, item.stable_id),
                )

    def should_send_report_summary(self, report_date: str, content_hash: str) -> bool:
        row = self.connection.execute(
            "SELECT content_hash FROM reports WHERE report_date = ?",
            (report_date,),
        ).fetchone()
        return row is None or row[0] != content_hash

    def mark_report_summary_sent(self, report_date: str, content_hash: str) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO reports (report_date, content_hash, sent_at)
                VALUES (?, ?, ?)
                ON CONFLICT(report_date) DO UPDATE SET
                    content_hash = excluded.content_hash,
                    sent_at = excluded.sent_at
                """,
                (report_date, content_hash, _utc_now()),
            )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

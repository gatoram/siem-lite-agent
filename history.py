"""Історія по IP (компонент 5): усі події зберігаються в SQLite (history.db).

Агент отримує не лише інцидент, а й зведення по IP за весь час, що є в базі:
скільки подій, скільки вдалих і невдалих входів, чи був успішний вхід після
серії невдалих (ознака успішного brute-force), перша й остання поява.

Повторне завантаження тих самих логів не дублює події: унікальність за
(source_ip, timestamp, raw).
"""

import json
import sqlite3
from pathlib import Path

DEFAULT_DB = Path(__file__).parent / "history.db"

# Скільки невдалих входів поспіль (без успішних між ними) вважається "серією"
FAILS_BEFORE_SUCCESS_MIN = 5

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    timestamp   TEXT NOT NULL,          -- ISO 8601, сортується як рядок
    source_ip   TEXT NOT NULL,
    log_source  TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    raw         TEXT NOT NULL,
    meta        TEXT NOT NULL,          -- JSON
    UNIQUE (source_ip, timestamp, raw)
);
CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events (source_ip, timestamp);
"""


class History:
    def __init__(self, path: str | Path = DEFAULT_DB):
        self.conn = sqlite3.connect(str(path))
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "History":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def store_events(self, events: list[dict]) -> int:
        """Зберігає події; повертає кількість нових (дублікати пропускаються)."""
        before = self.conn.total_changes
        self.conn.executemany(
            "INSERT OR IGNORE INTO events (timestamp, source_ip, log_source, event_type, raw, meta) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(e["timestamp"], e["source_ip"], e["log_source"], e["event_type"], e["raw"],
              json.dumps(e.get("meta", {}), ensure_ascii=False)) for e in events],
        )
        self.conn.commit()
        return self.conn.total_changes - before

    def ip_summary(self, ip: str) -> dict:
        """Зведення по IP. Для IP, якого немає в базі, total_events = 0, а дати — None."""
        total, first_seen, last_seen = self.conn.execute(
            "SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM events WHERE source_ip = ?", (ip,)
        ).fetchone()
        # Подія "message repeated N times" рахується як N спроб
        by_type = dict(self.conn.execute(
            "SELECT event_type, SUM(COALESCE(json_extract(meta, '$.repeated'), 1)) "
            "FROM events WHERE source_ip = ? GROUP BY event_type", (ip,)))
        by_source = dict(self.conn.execute(
            "SELECT log_source, COUNT(*) FROM events WHERE source_ip = ? GROUP BY log_source", (ip,)))
        compromise = self._success_after_failures(ip)

        return {
            "ip": ip,
            "total_events": total,
            "events_by_source": by_source,
            "login_fail": by_type.get("login_fail", 0),
            "login_success": by_type.get("login_success", 0),
            "http_requests": by_type.get("http_request", 0),
            "firewall_blocks": by_type.get("firewall_block", 0),
            "success_after_failures": compromise is not None,
            "success_after_failures_detail": compromise,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

    def _success_after_failures(self, ip: str) -> dict | None:
        """Перший успішний вхід, якому передувало FAILS_BEFORE_SUCCESS_MIN+ невдалих поспіль."""
        rows = self.conn.execute(
            "SELECT timestamp, event_type, meta FROM events "
            "WHERE source_ip = ? AND event_type IN ('login_fail', 'login_success') ORDER BY timestamp, id",
            (ip,))
        fails_in_row, series_start = 0, None
        for timestamp, event_type, meta in rows:
            if event_type == "login_fail":
                if fails_in_row == 0:
                    series_start = timestamp
                fails_in_row += json.loads(meta).get("repeated", 1)
                continue
            if fails_in_row >= FAILS_BEFORE_SUCCESS_MIN:
                return {
                    "success_time": timestamp,
                    "user": json.loads(meta).get("user"),
                    "failures_before": fails_in_row,
                    "failures_since": series_start,
                }
            fails_in_row = 0
        return None

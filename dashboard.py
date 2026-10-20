"""Веб-дашборд SIEM-lite: SOC-консоль поверх history.db.

Дашборд нічого не аналізує, а лише читає те, що записали main.py batch і live:
події (таблиця events) та інциденти з висновками AI-агента (incidents).
Сторінка (dashboard.html) сама опитує JSON-ендпоінти кожні 3 секунди.

Запуск: py -3 dashboard.py        → http://127.0.0.1:8000
        py -3 dashboard.py --db інша.db

Безпека: рядки логів пише атакуючий, а текст пояснень пише модель, тому
сторінка виводить їх лише через textContent. Додатково Content-Security-Policy
дозволяє тільки скрипт і стилі з nonce цієї відповіді: навіть якщо колись
з'явиться вставка HTML, інлайн-обробники (onerror=) і чужі <script> не
виконаються. Сервер слухає лише 127.0.0.1.
"""

import argparse
import json
import logging
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, Response, abort, g, jsonify, request

import history

HOST, PORT = "127.0.0.1", 8000
PAGE = Path(__file__).parent / "dashboard.html"

# Графік: події за часом надходження в базу, кошики по 10 с за останні 15 хв.
# Час із самих логів не підходить: SSH пише місцевий, а web-парсер — UTC.
TIMELINE_SPAN = timedelta(minutes=15)
TIMELINE_BUCKET_SECONDS = 10
INCIDENTS_LIMIT = 500
TOP_IPS = 5

SEVERITY_ORDER = "CASE severity WHEN 'Critical' THEN 3 WHEN 'High' THEN 2 WHEN 'Medium' THEN 1 ELSE 0 END"

LIST_COLUMNS = ("id", "rule", "source_ip", "log_source", "severity", "detector_severity", "agent_severity",
                "threat_type", "first_seen", "last_seen", "event_count", "detected_at", "updated_at")
DETAIL_COLUMNS = LIST_COLUMNS + ("severity_note", "explanation", "recommendation", "tool_calls", "model",
                                 "details", "examples")
JSON_COLUMNS = ("tool_calls", "details", "examples")


def create_app(db_path: str | Path = history.DEFAULT_DB) -> Flask:
    db_path = Path(db_path).resolve()
    # Схема (і сам файл, якщо live ще не запускали) — щоб читання не падало на порожній базі
    history.History(db_path).close()
    page = PAGE.read_text(encoding="utf-8")

    app = Flask(__name__)
    app.json.ensure_ascii = False
    app.json.sort_keys = False

    def db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=5)
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc) -> None:
        if (conn := g.pop("db", None)) is not None:
            conn.close()

    @app.after_request
    def security_headers(resp: Response) -> Response:
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/")
    def index() -> Response:
        nonce = secrets.token_urlsafe(16)
        resp = Response(page.replace("__CSP_NONCE__", nonce), mimetype="text/html")
        resp.headers["Content-Security-Policy"] = (
            f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
            "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'")
        return resp

    @app.get("/api/summary")
    def summary():
        conn = db()
        events, last_ingested = conn.execute("SELECT COUNT(*), MAX(ingested_at) FROM events").fetchone()
        by_severity = dict(conn.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity").fetchall())
        return jsonify({
            "events": events,
            "incidents": sum(by_severity.values()),
            "by_severity": {sev: by_severity.get(sev, 0) for sev in reversed(history.SEVERITIES)},
            "rules": [r[0] for r in conn.execute("SELECT DISTINCT rule FROM incidents ORDER BY rule")],
            "sources": [r[0] for r in conn.execute("SELECT DISTINCT log_source FROM incidents ORDER BY log_source")],
            "last_ingested": last_ingested,
            "server_time": history.now(),
        })

    @app.get("/api/incidents")
    def incidents():
        where, params = [], []
        for column, arg in (("severity", "severity"), ("rule", "rule"), ("log_source", "source")):
            if value := request.args.get(arg):
                where.append(f"{column} = ?")
                params.append(value)
        sql = (f"SELECT {', '.join(LIST_COLUMNS)} FROM incidents"
               + (f" WHERE {' AND '.join(where)}" if where else "")
               + " ORDER BY detected_at DESC, first_seen DESC, id DESC LIMIT ?")
        rows = db().execute(sql, [*params, INCIDENTS_LIMIT]).fetchall()
        return jsonify([dict(row) for row in rows])

    @app.get("/api/incidents/<int:incident_id>")
    def incident(incident_id: int):
        row = db().execute(f"SELECT {', '.join(DETAIL_COLUMNS)} FROM incidents WHERE id = ?",
                           (incident_id,)).fetchone()
        if row is None:
            abort(404)
        data = dict(row)
        for column in JSON_COLUMNS:
            data[column] = json.loads(data[column]) if data[column] else None
        return jsonify(data)

    @app.get("/api/timeline")
    def timeline():
        conn = db()
        end = datetime.now()
        last = conn.execute("SELECT MAX(ingested_at) FROM events").fetchone()[0]
        # Свіжих подій немає (лише старий batch) — показуємо останні 15 хв, коли дані були
        if last and datetime.fromisoformat(last) < end - TIMELINE_SPAN:
            end = datetime.fromisoformat(last)
        step = TIMELINE_BUCKET_SECONDS
        end = end.replace(microsecond=0, second=end.second // step * step)
        start = end - TIMELINE_SPAN
        # "YYYY-MM-DDTHH:MM:S" — перші 18 символів, тобто кошик у 10 секунд
        counts = dict(conn.execute(
            "SELECT substr(ingested_at, 1, 18), COUNT(*) FROM events "
            "WHERE ingested_at >= ? GROUP BY 1", (start.isoformat(),)).fetchall())
        points, t = [], start
        while t <= end:
            iso = t.isoformat()
            points.append({"t": iso, "count": counts.get(iso[:18], 0)})
            t += timedelta(seconds=step)
        return jsonify({"bucket_seconds": step, "points": points})

    @app.get("/api/top_ips")
    def top_ips():
        rows = db().execute(
            f"SELECT source_ip, COUNT(*) AS incidents, SUM(event_count) AS events, MAX({SEVERITY_ORDER}) AS rank "
            "FROM incidents GROUP BY source_ip ORDER BY incidents DESC, rank DESC, events DESC LIMIT ?",
            (TOP_IPS,)).fetchall()
        return jsonify([{"source_ip": r["source_ip"], "incidents": r["incidents"], "events": r["events"],
                         "max_severity": history.SEVERITIES[r["rank"]]} for r in rows])

    return app


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="SIEM-lite: веб-дашборд (лише читає history.db)")
    parser.add_argument("--db", type=Path, default=history.DEFAULT_DB, help="SQLite-база (за замовчуванням history.db)")
    args = parser.parse_args()
    # Сторінка опитує 4 ендпоінти кожні 3 с — журнал кожного запиту лише засмічує консоль
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    print(f"SIEM-lite dashboard: http://{HOST}:{PORT}  (база {args.db}, Ctrl+C — зупинка)")
    create_app(args.db).run(host=HOST, port=PORT, debug=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Тест веб-дашборду (dashboard.py): XSS з логу і з відповіді моделі виводиться як текст.

Запуск: py -3 test_dashboard.py

Сценарій: атакуючий пише в access.log запит з <script>alert(1)</script> в URL
і <img src=x onerror=alert(2)> в User-Agent; детектор знаходить xss, висновок
"агента" теж містить HTML. Перевіряється:
  1. history.store_incident: повторний запис без AI не стирає висновок, severity не знижується;
  2. ендпоінти віддають payload дослівно, як JSON-рядок (application/json);
  3. сторінка не має жодного способу вставити HTML (innerHTML тощо), а CSP
     забороняє інлайн-скрипти без nonce;
  4. у справжньому браузері (headless Edge/Chrome, --dump-dom) деталі інциденту
     містять payload як текст (&lt;script&gt;), а не як елемент <script>/<img>.
     Якщо браузера немає — крок пропускається з повідомленням.

База створюється у тимчасовій теці, history.db не зачіпається.
"""

import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from werkzeug.serving import make_server

import dashboard
import detector
import history
from parsers import web_parser

SCRIPT_PAYLOAD = "<script>alert(1)</script>"
IMG_PAYLOAD = "<img src=x onerror=alert(2)>"
MODEL_PAYLOAD = '<img src=x onerror="document.title=\'pwned\'">'

ACCESS_LOG = [
    '198.51.100.7 - - [30/Sep/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
    f'203.0.113.66 - - [30/Sep/2026:10:00:05 +0000] "GET /search?q={SCRIPT_PAYLOAD} HTTP/1.1" 200 734 '
    f'"-" "{IMG_PAYLOAD}"',
]

BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "msedge", "chrome", "chromium", "google-chrome",
]


def fake_analysis(severity: str) -> dict:
    return {
        "threat_type": f"XSS {MODEL_PAYLOAD}",
        "severity": severity,
        "severity_note": None,
        "explanation": f"У параметрі q передано {SCRIPT_PAYLOAD}",
        "recommendation": "Екранувати вивід. <b>bold</b>",
        "tool_calls": [{"name": "check_ip_reputation", "args": {"ip": "203.0.113.66"},
                        "result": {"abuseConfidenceScore": 87, "isp": MODEL_PAYLOAD}}],
        "provider": "test", "model": "fake",
    }


def check_store(db: history.History) -> int:
    events = [e for line in ACCESS_LOG if (e := web_parser.parse_line(line)) is not None]
    assert len(events) == 2, "обидва рядки access.log мають розпізнаватись"
    assert SCRIPT_PAYLOAD in events[1]["raw"]
    db.store_events(events)

    incidents = detector.detect(events)
    assert [i["rule"] for i in incidents] == ["xss"], incidents
    incident = incidents[0]
    inc_id = db.store_incident(incident, fake_analysis("High"))

    # Повторний запис без AI (live оновлює лічильники) — висновок агента залишається
    assert db.store_incident({**incident, "event_count": 1}) == inc_id
    row = db.conn.execute("SELECT severity, agent_severity, explanation, event_count FROM incidents "
                          "WHERE id = ?", (inc_id,)).fetchone()
    assert row == ("High", "High", fake_analysis("High")["explanation"], 1), row
    print("OK  store_incident: upsert без AI не стирає висновок агента")
    return inc_id


def check_api(app, inc_id: int) -> None:
    client = app.test_client()

    resp = client.get("/api/incidents")
    assert resp.status_code == 200 and resp.mimetype == "application/json"
    listed = resp.get_json()
    assert [r["id"] for r in listed] == [inc_id] and listed[0]["threat_type"] == f"XSS {MODEL_PAYLOAD}"

    resp = client.get(f"/api/incidents/{inc_id}")
    assert resp.mimetype == "application/json", resp.mimetype
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    detail = resp.get_json()
    assert any(SCRIPT_PAYLOAD in line for line in detail["examples"]), detail["examples"]
    assert any(IMG_PAYLOAD in line for line in detail["examples"])
    assert detail["tool_calls"][0]["result"]["isp"] == MODEL_PAYLOAD
    print("OK  /api/incidents/<id>: payload віддається дослівно як JSON-рядок")

    summary = client.get("/api/summary").get_json()
    assert summary["events"] == 2 and summary["incidents"] == 1 and summary["by_severity"]["High"] == 1
    assert client.get("/api/top_ips").get_json()[0]["source_ip"] == "203.0.113.66"
    assert sum(p["count"] for p in client.get("/api/timeline").get_json()["points"]) == 2
    assert client.get("/api/incidents?severity=Critical").get_json() == []
    assert client.get("/api/incidents/999").status_code == 404

    resp = client.get("/")
    csp = resp.headers["Content-Security-Policy"]
    page = resp.get_data(as_text=True)
    assert "unsafe-inline" not in csp and "script-src 'nonce-" in csp, csp
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'<script nonce="{nonce}">' in page and "__CSP_NONCE__" not in page
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in page, f"у сторінці є {sink}"
    print("OK  сторінка: CSP з nonce, жодного innerHTML/outerHTML/insertAdjacentHTML/document.write")


def find_browser() -> str | None:
    for candidate in BROWSERS:
        if os.path.isfile(candidate) or shutil.which(candidate):
            return candidate
    return None


def check_browser(app, inc_id: int) -> None:
    browser = find_browser()
    if browser is None:
        print("SKIP браузерна перевірка: не знайдено Edge/Chrome")
        return

    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/#incident={inc_id}"
    try:
        with tempfile.TemporaryDirectory() as profile:
            dom = subprocess.run(
                [browser, "--headless", "--disable-gpu", "--no-first-run", f"--user-data-dir={profile}",
                 "--virtual-time-budget=8000", "--dump-dom", url],
                capture_output=True, text=True, encoding="utf-8", timeout=90).stdout
    finally:
        server.shutdown()

    assert "Висновок AI-агента" in dom, "деталі інциденту не відрендерились:\n" + dom[-2000:]
    # Серіалізатор DOM екранує текст: якщо payload лежить як текст, він буде &lt;script&gt;
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in dom
    assert "&lt;img src=x onerror=alert(2)&gt;" in dom
    # Сирий "<" у серіалізованому DOM буває лише в тегах, тож це були б справжні елементи
    assert "<script>alert" not in dom, "payload став елементом <script>"
    assert "<img" not in dom.lower(), "payload став елементом <img>"
    assert "<title>SIEM-lite SOC</title>" in dom, "document.title змінено — скрипт моделі виконався"
    print(f"OK  браузер ({Path(browser).stem} headless): payload з логу і від моделі показано як текст")


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        with history.History(db_path) as db:
            inc_id = check_store(db)
        app = dashboard.create_app(db_path)
        check_api(app, inc_id)
        check_browser(app, inc_id)
    print("\nУсі перевірки дашборду пройдено.")


if __name__ == "__main__":
    main()

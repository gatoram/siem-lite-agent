"""Тест rule-based детектора на sample_logs.

Запуск: py -3 test_detector.py
(спочатку згенеруй логи: py -3 generate_logs.py)

Проганяє обидва лог-файли через парсери і детектор, виводить інциденти
і перевіряє, що знайдено рівно чотири вкраплені атаки без хибних спрацювань,
а два brute-force (без успіху і з успішним входом) розрізняються.
"""

import sys
from pathlib import Path

import detector
from parsers import ssh_parser, web_parser

LOGS_DIR = Path(__file__).parent / "sample_logs"
LOG_YEAR = 2026

BRUTE_FORCE_IP = "203.0.113.45"   # лише невдалі спроби
COMPROMISE_IP = "203.0.113.77"    # невдалі спроби, потім успішний вхід

EXPECTED = {
    ("brute_force", BRUTE_FORCE_IP),
    ("brute_force", COMPROMISE_IP),
    ("path_scanning", "198.51.100.200"),
    ("sqli", "192.0.2.66"),
}


def print_incident(incident: dict) -> None:
    print(f"[{incident['severity']}] {incident['rule']} з {incident['source_ip']}")
    print(f"  {incident['first_seen']} → {incident['last_seen']}, подій: {incident['event_count']}")
    print(f"  деталі: {incident['details']}")
    for event in incident["examples"]:
        print(f"    {event['raw']}")
    print()


def make_web_event(ip: str, url: str) -> dict:
    """Синтетична web-подія для перевірки правил, яких немає в sample_logs."""
    path, _, query = url.partition("?")
    return {
        "timestamp": "2026-09-30T12:00:00", "source_ip": ip, "log_source": "web",
        "event_type": "http_request", "raw": url,
        "meta": {"path": path, "query": query, "url": url, "status_code": 200},
    }


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")

    events = (ssh_parser.parse_file(LOGS_DIR / "auth.log", year=LOG_YEAR)
              + web_parser.parse_file(LOGS_DIR / "access.log"))
    incidents = detector.detect(events)

    print(f"Подій: {len(events)}, інцидентів: {len(incidents)}\n")
    for incident in incidents:
        print_incident(incident)

    # --- Рівно чотири очікувані інциденти ---
    found = {(i["rule"], i["source_ip"]) for i in incidents}
    assert len(incidents) == 4, f"очікувалось 4 інциденти, знайдено {len(incidents)}"
    assert found == EXPECTED, f"неочікувані інциденти: {found ^ EXPECTED}"

    by_rule = {i["rule"]: i for i in incidents if i["source_ip"] != COMPROMISE_IP}
    by_ip = {i["source_ip"]: i for i in incidents}

    # --- Два brute-force розрізняються ---
    plain, compromise = by_ip[BRUTE_FORCE_IP], by_ip[COMPROMISE_IP]
    assert plain["event_count"] == 30 and plain["severity"] == "High"
    assert plain["details"]["login_success_after"] is False
    assert compromise["severity"] == "Critical"
    assert compromise["details"]["login_success_after"] is True
    assert compromise["details"]["failed_attempts"] == 25
    assert compromise["details"]["compromised_user"] == "admin"
    assert compromise["examples"][-1]["event_type"] == "login_success"
    assert compromise["last_seen"] == compromise["details"]["success_time"]

    # Успішний вхід через годину після серії — вже не "одразу після" → High
    late = dict(compromise["examples"][-1], timestamp="2026-09-30T22:30:00")
    burst = [e for e in events if e["source_ip"] == COMPROMISE_IP and e["event_type"] == "login_fail"]
    assert detector.brute_force(burst + [late])[0]["severity"] == "High"
    assert by_rule["path_scanning"]["details"]["unique_paths"] == 25
    assert "or_tautology" in by_rule["sqli"]["details"]["matched_patterns"]

    # --- Звичайні невдалі входи не дають хибних спрацювань ---
    normal_fails = [e for e in events
                    if e["event_type"] == "login_fail" and e["source_ip"] not in (BRUTE_FORCE_IP, COMPROMISE_IP)]
    assert normal_fails, "у логах мають бути звичайні невдалі входи"
    assert detector.brute_force(normal_fails) == []

    # --- XSS (у sample_logs немає — перевіряємо на синтетичних подіях) ---
    xss_events = [
        make_web_event("192.0.2.99", "/search?q=<script>alert(1)</script>"),
        make_web_event("192.0.2.99", "/search?q=<img src=x onerror=alert(1)>"),
    ]
    xss_incidents = detector.xss(xss_events)
    assert len(xss_incidents) == 1 and xss_incidents[0]["event_count"] == 2

    # Безневинні URL не мають спрацьовувати як SQLi/XSS
    benign = [
        make_web_event("10.0.1.15", "/blog/my--first-post"),
        make_web_event("10.0.1.15", "/search?q=rock or roll"),
        make_web_event("10.0.1.15", "/products?sort=price&order=asc"),
    ]
    assert detector.sqli(benign) == [] and detector.xss(benign) == []

    print("Усі перевірки пройдено.")


if __name__ == "__main__":
    main()

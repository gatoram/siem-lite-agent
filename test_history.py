"""Тест історії по IP (history.py) на sample_logs.

Запуск: py -3 test_history.py
(спочатку згенеруй логи: py -3 generate_logs.py)

База створюється в пам'яті (":memory:"), history.db не зачіпається.
"""

import json
import sys
from pathlib import Path

import history
from parsers import ssh_parser, web_parser

LOGS_DIR = Path(__file__).parent / "sample_logs"


def ssh_event(ts: str, ip: str, event_type: str, user: str = "alice") -> dict:
    return {"timestamp": ts, "source_ip": ip, "log_source": "ssh", "event_type": event_type,
            "raw": f"{ts} {event_type} {user} {ip}", "meta": {"user": user}}


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")

    events = (ssh_parser.parse_file(LOGS_DIR / "auth.log", year=2026)
              + web_parser.parse_file(LOGS_DIR / "access.log"))
    db = history.History(":memory:")
    assert db.store_events(events) == len(events)
    assert db.store_events(events) == 0, "повторне завантаження не має дублювати події"

    # Brute-force без успіху
    plain = db.ip_summary("203.0.113.45")
    print(json.dumps(plain, ensure_ascii=False, indent=2))
    assert plain["total_events"] == 30 and plain["login_fail"] == 30 and plain["login_success"] == 0
    assert plain["success_after_failures"] is False and plain["success_after_failures_detail"] is None
    assert plain["first_seen"] < plain["last_seen"]

    # Brute-force з успішним входом
    compromise = db.ip_summary("203.0.113.77")
    print(json.dumps(compromise, ensure_ascii=False, indent=2))
    assert compromise["login_fail"] == 25 and compromise["login_success"] == 1
    assert compromise["success_after_failures"] is True
    detail = compromise["success_after_failures_detail"]
    assert detail["user"] == "admin" and detail["failures_before"] == 25
    assert detail["success_time"] == compromise["last_seen"]

    # Web-IP: лише HTTP-запити
    scanner = db.ip_summary("198.51.100.200")
    assert scanner["http_requests"] == 25 and scanner["events_by_source"] == {"web": 25}

    # Невідомий IP — "даних немає"
    unknown = db.ip_summary("192.0.2.250")
    assert unknown["total_events"] == 0 and unknown["first_seen"] is None
    assert unknown["success_after_failures"] is False

    # Кілька невдалих (менше порогу) і успішний вхід — звичайна помилка в паролі, не brute-force
    typo = [ssh_event(f"2026-10-01T09:00:0{i}", "10.9.9.9", "login_fail")
            for i in range(history.FAILS_BEFORE_SUCCESS_MIN - 1)]
    typo.append(ssh_event("2026-10-01T09:00:30", "10.9.9.9", "login_success"))
    db.store_events(typo)
    assert db.ip_summary("10.9.9.9")["success_after_failures"] is False

    db.close()
    print("Усі перевірки пройдено.")


if __name__ == "__main__":
    main()

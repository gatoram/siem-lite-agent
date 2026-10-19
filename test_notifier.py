"""Тест Telegram-сповіщень (notifier.py) без мережі.

Запуск: py -3 test_notifier.py

requests.post підміняється, тому в Telegram нічого не надсилається.
База — тимчасовий файл, history.db не зачіпається.
"""

from contextlib import closing
import logging
import sqlite3
import sys
import tempfile
from pathlib import Path

import requests

import notifier

INCIDENT = {
    "rule": "brute_force", "severity": "Critical", "source_ip": "203.0.113.77",
    "first_seen": "2026-09-30T21:10:02", "last_seen": "2026-09-30T21:11:29", "event_count": 26,
    "details": {"failed_attempts": 25, "targeted_users": ["admin", "root"], "login_success_after": True},
}
MEDIUM = {**INCIDENT, "rule": "path_scanning", "severity": "Medium", "source_ip": "198.51.100.23"}
ANALYSIS = {
    "threat_type": "SSH brute-force with successful login", "severity": "Critical",
    "explanation": "Після 25 невдалих спроб <admin> увійшов успішно.",
    "recommendation": "Ізолювати хост, змінити пароль admin.",
    "provider": "gemini", "model": "test-model",
}
TOKEN = "123456:SECRET-TOKEN"


class FakeResponse:
    def __init__(self, ok: bool = True, status_code: int = 200, description: str = ""):
        self.ok, self.status_code, self.text = ok, status_code, description

    def json(self) -> dict:
        return {"ok": self.ok, "description": self.text}


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    warnings: list[str] = []
    logging.getLogger("notifier").addHandler(type("H", (logging.Handler,), {
        "emit": lambda self, record: warnings.append(record.getMessage())})())

    # Поріг
    assert notifier.should_notify("Critical") and notifier.should_notify("High")
    assert not notifier.should_notify("Medium") and not notifier.should_notify("Low")

    # Текст: з AI-аналізом і без нього
    with_ai = notifier.format_message(INCIDENT, ANALYSIS)
    print(with_ai, end="\n\n")
    assert "🚨 <b>CRITICAL</b>" in with_ai and "203.0.113.77" in with_ai and "Подій: 26" in with_ai
    assert "&lt;admin&gt;" in with_ai, "текст моделі має екрануватися для HTML"
    assert "Ізолювати хост" in with_ai and "gemini/test-model" in with_ai

    detector_only = notifier.format_message(INCIDENT)
    print(detector_only, end="\n\n")
    assert "failed_attempts: 25" in detector_only and "Дані детектора" in detector_only
    assert "21:10:02 → 21:11:29" in detector_only

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        sent_texts: list[str] = []

        def fake_post(url, json, timeout):
            assert TOKEN in url and json["parse_mode"] == "HTML"
            sent_texts.append(json["text"])
            return FakeResponse()

        tg = notifier.TelegramNotifier(token=TOKEN, chat_id="42")
        pairs = [(INCIDENT, ANALYSIS), (MEDIUM, None)]

        # Dry-run друкує, але нічого не позначає як надіслане
        printed: list[str] = []
        with closing(sqlite3.connect(db_path)) as conn:
            stats = notifier.notify(pairs, notifier.SentLog(conn), dry_run=True, print_message=printed.append)
        assert stats["dry_run"] == 1 and stats["below_threshold"] == 1 and len(printed) == 1

        # Telegram недоступний: без винятку, попередження без токена, не позначено
        def down(url, json, timeout):
            raise requests.ConnectionError(f"Max retries exceeded with url: /bot{TOKEN}/sendMessage")

        requests.post = down
        with closing(sqlite3.connect(db_path)) as conn:
            stats = notifier.notify(pairs, notifier.SentLog(conn), notifier=tg)
        assert stats["failed"] == 1 and stats["sent"] == 0
        assert warnings and "Telegram недоступний" in warnings[-1] and TOKEN not in warnings[-1], warnings

        # Telegram відповів помилкою (напр. неправильний chat_id)
        requests.post = lambda url, json, timeout: FakeResponse(False, 400, "Bad Request: chat not found")
        with closing(sqlite3.connect(db_path)) as conn:
            stats = notifier.notify(pairs, notifier.SentLog(conn), notifier=tg)
        assert stats["failed"] == 1 and "chat not found" in warnings[-1]

        # Успішна відправка, потім "повторний запуск" — дубліката немає
        requests.post = fake_post
        with closing(sqlite3.connect(db_path)) as conn:
            stats = notifier.notify(pairs, notifier.SentLog(conn), notifier=tg)
        assert stats["sent"] == 1 and len(sent_texts) == 1
        with closing(sqlite3.connect(db_path)) as conn:
            stats = notifier.notify(pairs, notifier.SentLog(conn), notifier=tg)
        assert stats["sent"] == 0 and stats["duplicate"] == 1 and len(sent_texts) == 1

        # Той самий IP і правило, але інший час — це новий інцидент
        later = {**INCIDENT, "first_seen": "2026-10-01T08:00:00", "last_seen": "2026-10-01T08:01:00"}
        with closing(sqlite3.connect(db_path)) as conn:
            stats = notifier.notify([(later, None)], notifier.SentLog(conn), notifier=tg)
        assert stats["sent"] == 1 and len(sent_texts) == 2

        # Ескалація: той самий інцидент спершу High, потім Critical — друге сповіщення;
        # повтор Critical або знову High — дублікат
        early = {**INCIDENT, "first_seen": "2026-10-02T09:00:00", "severity": "High"}
        for incident, expected_sent in [(early, 1), ({**early, "severity": "Critical"}, 1),
                                        ({**early, "severity": "Critical"}, 0), (early, 0)]:
            with closing(sqlite3.connect(db_path)) as conn:
                stats = notifier.notify([(incident, None)], notifier.SentLog(conn), notifier=tg)
            assert stats["sent"] == expected_sent, (incident["severity"], stats)
        assert "CRITICAL" in sent_texts[-1] and len(sent_texts) == 4

    # Без токена — попередження, не падіння
    empty = notifier.TelegramNotifier(token="", chat_id="")
    empty.token = empty.chat_id = ""
    assert empty.send("test") is False and "не задано" in warnings[-1]

    print("OK: усі перевірки notifier пройдено")


if __name__ == "__main__":
    main()

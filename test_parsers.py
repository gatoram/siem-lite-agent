"""Простий тест парсерів на sample_logs.

Запуск: py -3 test_parsers.py
(спочатку згенеруй логи: py -3 generate_logs.py)

Виводить кількість подій кожного event_type і 3 приклади подій у JSON,
а потім перевіряє, що вкраплені атаки розпарсились коректно.
"""

import json
import sys
from collections import Counter
from pathlib import Path

from parsers import ssh_parser, web_parser

LOGS_DIR = Path(__file__).parent / "sample_logs"
# Реальний лог: вибірка OpenSSH_2k з Loghub (github.com/logpai/loghub)
REAL_SSH_LOG = Path(__file__).parent / "real_logs" / "OpenSSH_2k.log"
# sample_logs згенеровані за 30.09.2026 — рік задаємо явно, щоб тест не
# залежав від поточної дати
LOG_YEAR = 2026


def count_lines(path: Path) -> int:
    with open(path, encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")

    ssh_events = ssh_parser.parse_file(LOGS_DIR / "auth.log", year=LOG_YEAR)
    web_events = web_parser.parse_file(LOGS_DIR / "access.log")
    events = ssh_events + web_events

    print("Кількість подій за event_type:")
    counts = Counter((e["log_source"], e["event_type"]) for e in events)
    for (source, event_type), n in sorted(counts.items()):
        print(f"  {source:<4} {event_type:<14} {n}")
    print(f"  всього: {len(events)}")

    examples = [
        next(e for e in ssh_events if e["event_type"] == "login_success"),
        next(e for e in ssh_events if e["meta"]["invalid_user"]),
        next(e for e in web_events if "OR" in e["meta"]["query"]),
    ]
    print("\nПриклади подій:")
    for event in examples:
        print(json.dumps(event, ensure_ascii=False, indent=2))

    # --- Перевірки ---
    # Кожен рядок логу має розпізнатись
    assert len(ssh_events) == count_lines(LOGS_DIR / "auth.log")
    assert len(web_events) == count_lines(LOGS_DIR / "access.log")

    # Brute-force: 30 невдалих спроб з 203.0.113.45 в межах 2 хвилин
    brute = [e for e in ssh_events if e["source_ip"] == "203.0.113.45"]
    assert len(brute) == 30
    assert all(e["event_type"] == "login_fail" for e in brute)
    assert brute[0]["timestamp"].startswith("2026-09-30T03:22")

    # Сканування: 25 різних шляхів з 198.51.100.200
    scan = [e for e in web_events if e["source_ip"] == "198.51.100.200"]
    assert len({e["meta"]["path"] for e in scan}) == 25

    # SQLi: URL декодовано, оригінал збережено
    sqli = [e for e in web_events if e["source_ip"] == "192.0.2.66"]
    assert len(sqli) == 1
    assert sqli[0]["meta"]["query"] == "id=1' OR '1'='1' -- "
    assert "%27" in sqli[0]["meta"]["url_raw"]

    # Нерозпізнані рядки повертають None, а не падають
    assert ssh_parser.parse_line("garbage") is None
    assert web_parser.parse_line("garbage") is None

    check_real_ssh_log()

    print("\nУсі перевірки пройдено.")


def check_real_ssh_log() -> None:
    """Формати з реального sshd, яких немає в синтетичному auth.log."""
    # "message repeated N times" — одна подія з вагою N
    repeated = ssh_parser.parse_line(
        "Dec 10 07:13:56 LabSZ sshd[24227]: message repeated 5 times: "
        "[ Failed password for root from 5.36.59.76 port 42393 ssh2]", year=2026)
    assert repeated["event_type"] == "login_fail"
    assert repeated["source_ip"] == "5.36.59.76"
    assert repeated["meta"]["user"] == "root"
    assert repeated["meta"]["repeated"] == 5
    # Ім'я з пробілом на початку
    spaced = ssh_parser.parse_line(
        "Dec 10 08:30:12 LabSZ sshd[24361]: Failed password for invalid user  0101 "
        "from 5.188.10.180 port 36279 ssh2", year=2026)
    assert spaced["meta"]["invalid_user"] and spaced["meta"]["user"] == "0101"
    # Метод "none"
    none = ssh_parser.parse_line(
        "Dec 10 09:00:00 LabSZ sshd[1]: Failed none for invalid user admin "
        "from 192.0.2.1 port 1 ssh2", year=2026)
    assert none["meta"]["auth_method"] == "none"
    # Звичайні рядки не отримують meta["repeated"]
    assert "repeated" not in none["meta"]

    if not REAL_SSH_LOG.is_file():
        print(f"\n{REAL_SSH_LOG} немає, перевірку на реальному лозі пропущено")
        return
    events = ssh_parser.parse_file(REAL_SSH_LOG, year=2026)
    counts = Counter(e["event_type"] for e in events)
    print(f"\nРеальний лог {REAL_SSH_LOG.name}: {count_lines(REAL_SSH_LOG)} рядків, "
          f"подій {len(events)} {dict(counts)}")
    # Усі рядки Failed/Accepted (включно з "message repeated") розпізнані
    with open(REAL_SSH_LOG, encoding="utf-8") as f:
        auth_lines = sum(("Failed " in line or "Accepted " in line) for line in f)
    assert len(events) == auth_lines == 525
    assert counts == {"login_fail": 524, "login_success": 1}
    assert sum(e["meta"].get("repeated", 1) for e in events) == 533


if __name__ == "__main__":
    main()

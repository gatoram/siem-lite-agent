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

    print("\nУсі перевірки пройдено.")


if __name__ == "__main__":
    main()

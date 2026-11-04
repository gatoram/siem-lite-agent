"""Час на початку syslog-рядка — спільне для ssh_parser і firewall_parser.

Підтримуються два формати, визначаються автоматично по рядку:

  - класичний syslog (RFC 3164), старий rsyslog і Loghub:
      Sep 30 03:22:14 srv-web01 sshd[1234]: ...
    Року немає — його задає параметр `year` (або береться поточний рік, а
    якщо дата так опиняється в майбутньому, то попередній). Часового поясу
    теж немає: час лишається як записаний (місцевий час сервера).

  - ISO 8601 з часовим поясом (RFC 3339), rsyslog за замовчуванням в
    Ubuntu 24.04+ (RSYSLOG_FileFormat):
      2026-11-04T20:58:02.245641+00:00 UbuntuTestSiem sshd-session[9621]: ...
    Рік уже в рядку, тому `year` ігнорується. Час переводиться в UTC і
    зберігається без поясу — так само, як у web_parser. Мікросекунди
    зберігаються.

Результат в обох випадках — naive datetime, як і в решті подій.
"""

import re
from datetime import datetime, timedelta, timezone

# Група для вставки на початок регулярного виразу заголовка рядка.
# Задає або iso, або month/day/time.
TIMESTAMP_PATTERN = (
    r"(?:(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
    r"|(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}))"
)

# Допуск на розбіжність годинників, перш ніж вважати дату "майбутньою"
FUTURE_TOLERANCE = timedelta(days=1)


def _parse_iso(value: str) -> datetime:
    ts = datetime.fromisoformat(value)
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts


def _parse_rfc3164(month: str, day: str, time: str, year: int | None) -> datetime:
    explicit_year = year is not None
    if year is None:
        year = datetime.now().year
    ts = datetime.strptime(f"{year} {month} {day} {time}", "%Y %b %d %H:%M:%S")
    if not explicit_year and ts > datetime.now() + FUTURE_TOLERANCE:
        ts = ts.replace(year=year - 1)
    return ts


def parse_header_timestamp(match: re.Match, year: int | None) -> datetime:
    """Час з match-об'єкта виразу, що містить TIMESTAMP_PATTERN."""
    if match["iso"]:
        return _parse_iso(match["iso"])
    return _parse_rfc3164(match["month"], match["day"], match["time"], year)

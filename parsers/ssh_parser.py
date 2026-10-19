"""Парсер SSH auth.log (syslog-формат sshd) в уніфікований формат події.

Приклад рядка:
  Sep 30 03:22:14 srv-web01 sshd[1234]: Failed password for invalid user test from 203.0.113.45 port 51234 ssh2

Розпізнаються лише спроби входу (Accepted / Failed). Решта рядків sshd
(pam_unix, "Invalid user", disconnect, "POSSIBLE BREAK-IN ATTEMPT" тощо)
або дублює ту саму спробу, або не стосується автентифікації, тому
пропускається.

Особливості реальних логів (перевірено на вибірці OpenSSH з Loghub):
  - syslog стискає однакові рядки поспіль:
      message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]
    Це одна подія з meta["repeated"] = 5 (кількість спроб). Детектор і
    історія рахують таку подію з цією вагою.
  - ім'я користувача може починатися з пробілу ("invalid user  0101").
  - метод може бути "none" (Failed none for invalid user ...).

У syslog-форматі немає року. Парсер підставляє рік явно (параметр `year`),
а якщо його не задано — поточний рік. Якщо при цьому дата опиняється в
майбутньому (лог за грудень читається в січні), береться попередній рік.
"""

import re
from datetime import datetime, timedelta
from pathlib import Path

LOG_SOURCE = "ssh"

SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)
# "message repeated N times: [ <оригінальне повідомлення>]"
REPEATED_RE = re.compile(r"^message repeated (?P<count>\d+) times: \[\s*(?P<message>.*?)\s*\]$")
ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
FAILED_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user\s+)?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)

# Допуск на розбіжність годинників, перш ніж вважати дату "майбутньою"
FUTURE_TOLERANCE = timedelta(days=1)


def _parse_timestamp(month: str, day: str, time: str, year: int | None) -> datetime:
    explicit_year = year is not None
    if year is None:
        year = datetime.now().year
    ts = datetime.strptime(f"{year} {month} {day} {time}", "%Y %b %d %H:%M:%S")
    if not explicit_year and ts > datetime.now() + FUTURE_TOLERANCE:
        ts = ts.replace(year=year - 1)
    return ts


def parse_line(line: str, year: int | None = None) -> dict | None:
    line = line.rstrip("\r\n")
    header = SYSLOG_RE.match(line)
    if not header:
        return None

    message = header["message"]
    repeated = 1
    if r := REPEATED_RE.match(message):
        message, repeated = r["message"], int(r["count"])

    if m := ACCEPTED_RE.match(message):
        event_type = "login_success"
        invalid_user = False
    elif m := FAILED_RE.match(message):
        event_type = "login_fail"
        invalid_user = m["invalid"] is not None
    else:
        return None

    event = {
        "timestamp": _parse_timestamp(header["month"], header["day"], header["time"], year).isoformat(),
        "source_ip": m["ip"],
        "log_source": LOG_SOURCE,
        "event_type": event_type,
        "raw": line,
        "meta": {
            "user": m["user"],
            "invalid_user": invalid_user,
            "auth_method": m["method"],
            "port": int(m["port"]),
            "host": header["host"],
            "pid": int(header["pid"]),
        },
    }
    if repeated > 1:
        event["meta"]["repeated"] = repeated
    return event


def parse_file(path: str | Path, year: int | None = None) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [event for line in f if (event := parse_line(line, year)) is not None]

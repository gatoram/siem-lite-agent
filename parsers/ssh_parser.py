"""Парсер SSH auth.log (syslog-формат sshd) в уніфікований формат події.

Приклади рядків (формат визначається автоматично по кожному рядку):
  Sep 30 03:22:14 srv-web01 sshd[1234]: Failed password for invalid user test from 203.0.113.45 port 51234 ssh2
  2026-11-04T20:58:02.245641+00:00 UbuntuTestSiem sshd-session[9621]: Failed password for invalid user admin from 192.168.147.5 port 50940 ssh2

Другий — Ubuntu 24.04+: rsyslog пише час в ISO 8601 з часовим поясом, а
OpenSSH 9.8+ веде сесію в окремому процесі sshd-session. Приймаються обидва
імена процесу (sshd і sshd-session) з обома форматами часу. Розбір часу —
у parsers/syslog_time.py.

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

У старому syslog-форматі немає року. Парсер підставляє рік явно (параметр
`year`), а якщо його не задано — поточний рік. Якщо при цьому дата
опиняється в майбутньому (лог за грудень читається в січні), береться
попередній рік. Для ISO 8601 рік є в рядку, `year` не потрібен і
ігнорується; час переводиться в UTC.
"""

import re
from pathlib import Path

from parsers.syslog_time import TIMESTAMP_PATTERN, parse_header_timestamp

LOG_SOURCE = "ssh"

SYSLOG_RE = re.compile(
    rf"^{TIMESTAMP_PATTERN}\s+"
    r"(?P<host>\S+)\s+(?P<process>sshd(?:-session)?)\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
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
        "timestamp": parse_header_timestamp(header, year).isoformat(),
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
            "process": header["process"],
        },
    }
    if repeated > 1:
        event["meta"]["repeated"] = repeated
    return event


def parse_file(path: str | Path, year: int | None = None) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [event for line in f if (event := parse_line(line, year)) is not None]

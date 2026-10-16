"""Парсер nginx access.log (combined-формат) в уніфікований формат події.

Приклад рядка:
  192.0.2.66 - - [30/Sep/2026:19:47:33 +0000] "GET /products?id=1%27%20OR... HTTP/1.1" 500 1024 "-" "sqlmap/1.8.4"

URL у логах закодований (%27 замість ', %20 замість пробілу), тому шлях і
query-рядок декодуються — інакше детектор не побачить SQLi/XSS-патерни.
Оригінальний URL зберігається в meta["url_raw"].

Час переводиться в UTC і зберігається без часового поясу, як у SSH-подіях.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, unquote_plus

LOG_SOURCE = "web"

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<remote_user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


def _parse_timestamp(value: str) -> datetime:
    ts = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    return ts.astimezone(timezone.utc).replace(tzinfo=None)


def parse_line(line: str) -> dict | None:
    line = line.rstrip("\r\n")
    m = COMBINED_RE.match(line)
    if not m:
        return None

    url_raw = m["url"]
    path_raw, _, query_raw = url_raw.partition("?")
    path = unquote(path_raw)
    # У query-рядку "+" означає пробіл, тому unquote_plus
    query = unquote_plus(query_raw)

    return {
        "timestamp": _parse_timestamp(m["time"]).isoformat(),
        "source_ip": m["ip"],
        "log_source": LOG_SOURCE,
        "event_type": "http_request",
        "raw": line,
        "meta": {
            "method": m["method"],
            "path": path,
            "query": query,
            "url": f"{path}?{query}" if query else path,
            "url_raw": url_raw,
            "status_code": int(m["status"]),
            "size": 0 if m["size"] == "-" else int(m["size"]),
            "referer": None if m["referer"] == "-" else m["referer"],
            "user_agent": m["user_agent"],
            "protocol": m["protocol"],
        },
    }


def parse_file(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [event for line in f if (event := parse_line(line)) is not None]

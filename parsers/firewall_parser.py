"""Парсер firewall-логів (ufw / iptables LOG з syslog) в уніфікований формат події.

Приклади рядків:
  Sep 30 14:02:11 srv-web01 kernel: [86531.204117] [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=198.51.100.200 DST=203.0.113.10 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=51234 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0
  Sep 30 14:02:11 srv-web01 kernel: IPTABLES-DROP: IN=eth0 OUT= SRC=... DST=... PROTO=UDP SPT=5353 DPT=161 LEN=40

Обидва пише ядро (ціль LOG у netfilter): довільний префікс, а за ним пари
KEY=VALUE. Префікс визначає дію:
  - містить ALLOW / ACCEPT → event_type "firewall_allow";
  - містить AUDIT → рядок пропускається (ufw audit дублює той самий пакет);
  - інше (UFW BLOCK, DROP, REJECT, власний префікс або без префікса)
    → "firewall_block": правило LOG у iptables зазвичай стоїть перед DROP.

meta: proto, dpt (порт призначення), spt, interface (IN=), dst, action
(префікс без дужок), host. Для ICMP портів немає — dpt/spt = None.

Час — як у SSH auth.log (syslog без року, місцевий час), тому розбирається
тією ж функцією, що й у ssh_parser.
"""

import re
from pathlib import Path

from parsers.ssh_parser import _parse_timestamp

LOG_SOURCE = "firewall"

KERNEL_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+kernel:\s+(?:\[\s*\d+\.\d+\]\s+)?(?P<message>.*)$"
)
# Префікс — усе до першого "IN=" (його може й не бути)
NETFILTER_RE = re.compile(r"^(?P<prefix>.*?)\s*\bIN=")
FIELD_RE = re.compile(r"\b([A-Z]+)=(\S*)")


def _action(prefix: str) -> str | None:
    upper = prefix.upper()
    if "AUDIT" in upper:
        return None
    if "ALLOW" in upper or "ACCEPT" in upper:
        return "firewall_allow"
    return "firewall_block"


def _port(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() else None


def parse_line(line: str, year: int | None = None) -> dict | None:
    line = line.rstrip("\r\n")
    header = KERNEL_RE.match(line)
    if not header:
        return None
    message = header["message"]
    nf = NETFILTER_RE.match(message)
    if not nf:
        return None
    fields = dict(FIELD_RE.findall(message[nf.end("prefix"):]))
    if not fields.get("SRC"):
        return None
    event_type = _action(nf["prefix"])
    if event_type is None:
        return None

    return {
        "timestamp": _parse_timestamp(header["month"], header["day"], header["time"], year).isoformat(),
        "source_ip": fields["SRC"],
        "log_source": LOG_SOURCE,
        "event_type": event_type,
        "raw": line,
        "meta": {
            "action": nf["prefix"].strip("[] :") or None,
            "proto": fields.get("PROTO"),
            "dpt": _port(fields.get("DPT")),
            "spt": _port(fields.get("SPT")),
            "interface": fields.get("IN") or None,
            "dst": fields.get("DST"),
            "host": header["host"],
        },
    }


def parse_file(path: str | Path, year: int | None = None) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [event for line in f if (event := parse_line(line, year)) is not None]

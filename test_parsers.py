"""Простий тест парсерів на sample_logs.

Запуск: py -3 test_parsers.py
(спочатку згенеруй логи: py -3 generate_logs.py)

Виводить кількість подій кожного event_type і 3 приклади подій у JSON,
а потім перевіряє, що вкраплені атаки розпарсились коректно.
"""

import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

from parsers import firewall_parser, ssh_parser, web_parser

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
    fw_events = firewall_parser.parse_file(LOGS_DIR / "firewall.log", year=LOG_YEAR)
    events = ssh_events + web_events + fw_events

    print("Кількість подій за event_type:")
    counts = Counter((e["log_source"], e["event_type"]) for e in events)
    for (source, event_type), n in sorted(counts.items()):
        print(f"  {source:<8} {event_type:<14} {n}")
    print(f"  всього: {len(events)}")

    examples = [
        next(e for e in ssh_events if e["event_type"] == "login_success"),
        next(e for e in ssh_events if e["meta"]["invalid_user"]),
        next(e for e in web_events if "OR" in e["meta"]["query"]),
        fw_events[0],
    ]
    print("\nПриклади подій:")
    for event in examples:
        print(json.dumps(event, ensure_ascii=False, indent=2))

    # --- Перевірки ---
    # Кожен рядок логу має розпізнатись
    assert len(ssh_events) == count_lines(LOGS_DIR / "auth.log")
    assert len(web_events) == count_lines(LOGS_DIR / "access.log")
    assert len(fw_events) == count_lines(LOGS_DIR / "firewall.log")

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
    assert firewall_parser.parse_line("garbage") is None

    # Сканування портів: 25 різних портів з 198.51.100.200 (той самий IP, що й скан шляхів)
    port_scan = [e for e in fw_events if e["source_ip"] == "198.51.100.200"]
    assert len({e["meta"]["dpt"] for e in port_scan}) == 25
    assert all(e["event_type"] == "firewall_block" for e in fw_events)

    check_firewall_formats()
    check_real_ssh_log()
    check_ubuntu_2404_format()
    check_format_detection_with_noise()

    print("\nУсі перевірки пройдено.")


def check_firewall_formats() -> None:
    """ufw і iptables з різними префіксами та протоколами."""
    ufw = firewall_parser.parse_line(
        "Sep 30 14:02:11 srv-web01 kernel: [86531.204117] [UFW BLOCK] IN=eth0 OUT= "
        "MAC=52:54:00:12:34:56:52:54:00:65:43:21:08:00 SRC=1.2.3.4 DST=203.0.113.10 LEN=44 "
        "TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=51234 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0",
        year=2026)
    assert ufw["log_source"] == "firewall" and ufw["event_type"] == "firewall_block"
    assert ufw["source_ip"] == "1.2.3.4" and ufw["timestamp"] == "2026-09-30T14:02:11"
    assert ufw["meta"] == {"action": "UFW BLOCK", "proto": "TCP", "dpt": 22, "spt": 51234,
                           "interface": "eth0", "dst": "203.0.113.10", "host": "srv-web01"}
    # iptables з власним префіксом, без мітки uptime
    ipt = firewall_parser.parse_line(
        "Sep 30 14:02:12 gw kernel: IPTABLES-DROP: IN=ens3 OUT= SRC=5.6.7.8 DST=10.0.0.1 "
        "LEN=40 PROTO=UDP SPT=5353 DPT=161 LEN=20", year=2026)
    assert ipt["event_type"] == "firewall_block"
    meta = ipt["meta"]
    assert (meta["action"], meta["proto"], meta["dpt"], meta["interface"]) == ("IPTABLES-DROP", "UDP", 161, "ens3")
    # ICMP — без портів
    icmp = firewall_parser.parse_line(
        "Sep 30 14:02:13 gw kernel: [1.0] [UFW BLOCK] IN=eth0 OUT= SRC=5.6.7.8 DST=10.0.0.1 "
        "PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1", year=2026)
    assert icmp["meta"]["proto"] == "ICMP" and icmp["meta"]["dpt"] is None
    # ALLOW — окремий тип; AUDIT і не-netfilter рядки ядра пропускаються
    allow = firewall_parser.parse_line(
        "Sep 30 14:02:14 gw kernel: [1.0] [UFW ALLOW] IN=eth0 OUT= SRC=5.6.7.8 DST=10.0.0.1 "
        "PROTO=TCP SPT=1 DPT=443", year=2026)
    assert allow["event_type"] == "firewall_allow"
    assert firewall_parser.parse_line(
        "Sep 30 14:02:15 gw kernel: [1.0] [UFW AUDIT] IN=eth0 OUT= SRC=5.6.7.8 DST=10.0.0.1 "
        "PROTO=TCP SPT=1 DPT=443", year=2026) is None
    assert firewall_parser.parse_line("Sep 30 14:02:16 gw kernel: [1.0] eth0: link up", year=2026) is None
    # Рядки sshd firewall-парсер не бере, і навпаки, тож автовизначення формату не плутається
    ssh_line = "Sep 30 03:22:14 srv-web01 sshd[1234]: Failed password for root from 1.2.3.4 port 1 ssh2"
    assert firewall_parser.parse_line(ssh_line, year=2026) is None
    assert ssh_parser.parse_line(ufw["raw"], year=2026) is None


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


# Реальні рядки з Ubuntu 24.04 (rsyslog за замовчуванням: ISO 8601 з поясом,
# OpenSSH 9.8+: процес sshd-session)
UBUNTU_SSH_FAIL = ("2026-11-04T20:58:02.245641+00:00 UbuntuTestSiem sshd-session[9621]: "
                   "Failed password for invalid user admin from 192.168.147.5 port 50940 ssh2")
UBUNTU_UFW_BLOCK = ("2026-11-04T20:55:20.400557+00:00 UbuntuTestSiem kernel: [UFW BLOCK] IN=enp0s3 "
                    "OUT= MAC=... SRC=34.107.243.93 DST=10.0.2.15 LEN=64 PROTO=TCP SPT=443 "
                    "DPT=54516 WINDOW=65535")


def check_ubuntu_2404_format() -> None:
    """Новий формат rsyslog з Ubuntu 24.04 поряд зі старим, без прапорців."""
    # SSH: ISO-час, sshd-session; year не потрібен
    ssh = ssh_parser.parse_line(UBUNTU_SSH_FAIL)
    assert ssh is not None, "рядок Ubuntu 24.04 (sshd-session) не розпізнано"
    assert ssh["event_type"] == "login_fail"
    assert ssh["source_ip"] == "192.168.147.5"
    assert ssh["timestamp"] == "2026-11-04T20:58:02.245641"
    assert ssh["meta"]["user"] == "admin" and ssh["meta"]["invalid_user"]
    assert ssh["meta"]["port"] == 50940 and ssh["meta"]["pid"] == 9621
    assert ssh["meta"]["host"] == "UbuntuTestSiem"
    assert ssh["meta"]["process"] == "sshd-session"
    # Рік з рядка важливіший за параметр year
    assert ssh_parser.parse_line(UBUNTU_SSH_FAIL, year=2020)["timestamp"].startswith("2026-")
    # Успішний вхід у новому форматі
    ok = ssh_parser.parse_line(
        "2026-11-04T21:00:00.000001+00:00 UbuntuTestSiem sshd-session[9700]: "
        "Accepted password for siem from 192.168.147.5 port 50999 ssh2")
    assert ok["event_type"] == "login_success" and ok["meta"]["user"] == "siem"
    # Інший часовий пояс переводиться в UTC (як у web_parser)
    kyiv = ssh_parser.parse_line(UBUNTU_SSH_FAIL.replace("20:58:02.245641+00:00", "22:58:02.245641+02:00"))
    assert kyiv["timestamp"] == "2026-11-04T20:58:02.245641"
    # "message repeated" теж працює в новому форматі
    rep = ssh_parser.parse_line(
        "2026-11-04T20:58:10.000000+00:00 UbuntuTestSiem sshd-session[9621]: message repeated 3 times: "
        "[ Failed password for invalid user admin from 192.168.147.5 port 50940 ssh2]")
    assert rep["meta"]["repeated"] == 3
    # Старий формат з sshd-session і новий з sshd — комбінації теж приймаються
    assert ssh_parser.parse_line(
        "Nov  4 20:58:02 host sshd-session[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
        year=2026)["timestamp"] == "2026-11-04T20:58:02"
    assert ssh_parser.parse_line(
        "2026-11-04T20:58:02+00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"
    )["timestamp"] == "2026-11-04T20:58:02"
    # Інші процеси з префіксом sshd не підхоплюються
    assert ssh_parser.parse_line(
        "2026-11-04T20:58:02+00:00 host sshd-foo[1]: Failed password for root from 1.2.3.4 port 1 ssh2") is None

    # Firewall: ISO-час, без мітки uptime ядра
    fw = firewall_parser.parse_line(UBUNTU_UFW_BLOCK)
    assert fw is not None, "рядок Ubuntu 24.04 (ufw) не розпізнано"
    assert fw["event_type"] == "firewall_block"
    assert fw["source_ip"] == "34.107.243.93"
    assert fw["timestamp"] == "2026-11-04T20:55:20.400557"
    assert fw["meta"] == {"action": "UFW BLOCK", "proto": "TCP", "dpt": 54516, "spt": 443,
                          "interface": "enp0s3", "dst": "10.0.2.15", "host": "UbuntuTestSiem"}

    # Автовизначення формату файлу в main.py не плутає джерела і в новому форматі
    assert firewall_parser.parse_line(UBUNTU_SSH_FAIL) is None
    assert ssh_parser.parse_line(UBUNTU_UFW_BLOCK) is None
    assert web_parser.parse_line(UBUNTU_SSH_FAIL) is None

    print("\nUbuntu 24.04 (ISO 8601 + sshd-session):")
    for event in (ssh, fw):
        print(f"  {event['log_source']:<8} {event['event_type']:<14} {event['timestamp']}  "
              f"{event['source_ip']}")


# Системний шум реального /var/log/auth.log (Ubuntu 24.04), який жоден парсер не
# розпізнає — включно з рядками sshd-session, що не є спробою входу
AUTH_LOG_NOISE = [
    "2026-11-04T20:17:01.123456+00:00 UbuntuTestSiem CRON[{n}]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
    "2026-11-04T20:17:01.130000+00:00 UbuntuTestSiem CRON[{n}]: pam_unix(cron:session): session closed for user root",
    "2026-11-04T20:20:44.000001+00:00 UbuntuTestSiem sudo:     siem : TTY=pts/0 ; PWD=/home/siem ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/auth.log",
    "2026-11-04T20:20:44.000002+00:00 UbuntuTestSiem sudo: pam_unix(sudo:session): session opened for user root(uid=0) by siem(uid=1000)",
    "2026-11-04T20:21:00.000000+00:00 UbuntuTestSiem systemd-logind[{n}]: New session 7 of user siem.",
    "2026-11-04T20:58:00.100000+00:00 UbuntuTestSiem sshd-session[{n}]: Invalid user admin from 192.168.147.5 port 50940",
    "2026-11-04T20:58:00.200000+00:00 UbuntuTestSiem sshd-session[{n}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.147.5",
]


def check_format_detection_with_noise() -> None:
    """main.detect_format: шум на початку файлу не заважає визначити формат."""
    import main as siem

    parsers = siem.get_parsers(None)
    noise_count = siem.DETECT_SAMPLE_LINES * 3  # шуму більше, ніж перша вибірка
    noise = [AUTH_LOG_NOISE[i % len(AUTH_LOG_NOISE)].format(n=1000 + i) for i in range(noise_count)]
    ssh_lines = [UBUNTU_SSH_FAIL, UBUNTU_SSH_FAIL.replace("50940", "50941")]

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        def write(name: str, lines: list[str]) -> Path:
            path = tmp / name
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return path

        # Перші DETECT_SAMPLE_LINES — лише шум, SSH-рядки далі, вперемішку з шумом
        auth = write("auth.log", noise + ssh_lines[:1] + noise[:5] + ssh_lines[1:])
        assert all(parse(line) is None for line in noise for parse in parsers.values())
        assert siem.detect_format(auth, parsers) == "ssh"
        # batch бере з такого файлу саме SSH-події, а шум рахує нерозпізнаним
        events, stats = siem.load_events([auth], None)
        assert [e["source_ip"] for e in events] == ["192.168.147.5"] * 2
        assert stats[0]["format"] == "ssh" and stats[0]["lines"] == noise_count + 5 + 2

        # Те саме для ufw.log: блокування після шуму ядра
        fw = write("ufw.log", [f"2026-11-04T20:55:{i % 60:02d}+00:00 UbuntuTestSiem kernel: eth0: link up"
                               for i in range(noise_count)] + [UBUNTU_UFW_BLOCK])
        assert siem.detect_format(fw, parsers) == "firewall"

        # Лише шум у всьому файлі — формат не розпізнано
        assert siem.detect_format(write("noise.log", noise), parsers) is None
        events, stats = siem.load_events([tmp / "noise.log"], None)
        assert events == [] and stats[0]["format"] == "?"

        # Розпізнаний рядок за межею DETECT_MAX_LINES не шукається (скан обмежений)
        old_max = siem.DETECT_MAX_LINES
        siem.DETECT_MAX_LINES = noise_count
        try:
            assert siem.detect_format(auth, parsers) is None
        finally:
            siem.DETECT_MAX_LINES = old_max

        # Звичайний випадок не змінився: розпізнавані рядки на початку
        assert siem.detect_format(LOGS_DIR / "auth.log", parsers) == "ssh"
        assert siem.detect_format(LOGS_DIR / "access.log", parsers) == "web"
        assert siem.detect_format(LOGS_DIR / "firewall.log", parsers) == "firewall"

    print(f"\nАвтовизначення формату: {noise_count} рядків шуму на початку auth.log — формат ssh, "
          f"2 події; файл лише з шуму — не розпізнано")


if __name__ == "__main__":
    main()

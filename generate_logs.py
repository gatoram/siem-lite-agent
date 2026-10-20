"""Генератор синтетичних логів для розробки й демо SIEM-lite.

Створює:
  sample_logs/auth.log   — ~200 нормальних SSH-подій + дві brute-force атаки:
                           1) 30 невдалих спроб за 2 хвилини, усі невдалі;
                           2) з іншого IP: 25 невдалих спроб, після яких
                              вхід успішний (зламаний пароль admin)
  sample_logs/access.log — ~200 нормальних web-запитів (nginx combined)
                           + сканування шляхів + SQLi-спроба в параметрі
  sample_logs/firewall.log — ~200 звичайних блокувань ufw (інтернет-шум:
                           1-3 порти з IP) + сканування портів з IP веб-сканера
                           (розвідка перед сканом шляхів) + два "майже
                           сканування", що НЕ мають спрацьовувати: повільний
                           перебір портів (раз на годину) і багато спроб в
                           один порт

Атакуючі IP взяті з документаційних діапазонів (RFC 5737), щоб не зачіпати
реальні адреси. Генерація детермінована (фіксований seed) — однаковий
результат при кожному запуску, зручно для тестів детектора.
"""

import random
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

SEED = 42
OUTPUT_DIR = Path(__file__).parent / "sample_logs"
START_TIME = datetime(2026, 9, 30, 0, 0, 0)
DAY_SECONDS = 24 * 60 * 60

HOSTNAME = "srv-web01"

# Легітимні користувачі та їхні "звичні" IP (внутрішня мережа + пара зовнішніх)
SSH_USERS = {
    "alice": ["10.0.1.15", "10.0.1.16"],
    "bob": ["10.0.1.22"],
    "deploy": ["10.0.2.5"],
    "admin": ["10.0.1.10", "198.51.100.23"],
    "jenkins": ["10.0.2.8"],
}

BRUTE_FORCE_IP = "203.0.113.45"
BRUTE_FORCE_USERS = ["root", "admin", "test", "ubuntu", "oracle", "postgres", "user", "guest"]

# Другий сценарій: brute-force, що завершився успішним входом
COMPROMISE_IP = "203.0.113.77"
COMPROMISE_USERS = ["admin", "root", "admin", "administrator", "admin"]  # переважно admin
COMPROMISE_FAILS = 25
COMPROMISE_START = datetime(2026, 9, 30, 21, 10, 0)

WEB_CLIENT_IPS = [
    "10.0.1.15", "10.0.1.22", "198.51.100.7", "198.51.100.23", "198.51.100.88",
    "192.0.2.14", "192.0.2.77", "192.0.2.130",
]
WEB_PATHS = [
    ("/", 200), ("/index.html", 200), ("/about", 200), ("/contact", 200),
    ("/products", 200), ("/products?category=books", 200),
    ("/products?category=electronics&page=2", 200), ("/search?q=laptop", 200),
    ("/static/css/main.css", 200), ("/static/js/app.js", 200),
    ("/static/img/logo.png", 200), ("/favicon.ico", 200),
    ("/api/v1/items", 200), ("/api/v1/items/42", 200), ("/login", 200),
    ("/cart", 200), ("/old-page", 301), ("/missing-image.jpg", 404),
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]

SCANNER_IP = "198.51.100.200"
SCANNER_UA = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
SCAN_PATHS = [
    "/admin", "/admin.php", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma", "/.env", "/.git/config", "/.htaccess", "/config.php",
    "/backup.zip", "/backup.sql", "/db.sql", "/server-status", "/cgi-bin/test.cgi",
    "/shell.php", "/console", "/actuator/env", "/api/swagger.json", "/debug",
    "/test.php", "/info.php", "/xmlrpc.php", "/.DS_Store",
]

SQLI_IP = "192.0.2.66"
SQLI_UA = "sqlmap/1.8.4#stable (https://sqlmap.org)"
SQLI_PAYLOAD = "1' OR '1'='1' -- "


# Firewall: зовнішня адреса сервера, на яку йде трафік з інтернету
FIREWALL_IFACE = "eth0"
SERVER_EXT_IP = "203.0.113.10"
FIREWALL_START_UPTIME = 1_234_567.0  # [секунди від завантаження ядра] у рядку kernel
# Порти, які типово "мацають" боти (усі закриті, тож ufw їх блокує й логує)
NOISE_PORTS = [(23, "TCP"), (445, "TCP"), (3389, "TCP"), (1433, "TCP"), (5900, "TCP"),
               (8080, "TCP"), (2323, "TCP"), (6379, "TCP"), (123, "UDP"), (161, "UDP"),
               (53, "UDP"), (None, "ICMP")]
# Порт-скан з того ж IP, що й сканування шляхів (за 3 хвилини до нього)
PORT_SCAN_START = datetime(2026, 9, 30, 14, 2, 0)
PORT_SCAN_PORTS = [21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 993, 995, 1433, 1521,
                   1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
# Не мають спрацьовувати: 12 різних портів, але по одному на годину
SLOW_SCAN_IP = "203.0.113.180"
SLOW_SCAN_START = datetime(2026, 9, 30, 6, 30, 0)
# Не мають спрацьовувати: 40 спроб в один порт (RDP) за ~3 хвилини
SINGLE_PORT_IP = "192.0.2.201"
SINGLE_PORT_START = datetime(2026, 9, 30, 10, 15, 0)


def random_time(rng: random.Random) -> datetime:
    return START_TIME + timedelta(seconds=rng.randint(0, DAY_SECONDS - 1))


# ---------------------------------------------------------------- SSH auth.log

def ssh_line(ts: datetime, pid: int, message: str) -> str:
    # Формат syslog: "Sep 30 03:22:14 host sshd[1234]: ..." (день вирівняний пробілом)
    return f"{ts.strftime('%b')} {ts.day:>2} {ts.strftime('%H:%M:%S')} {HOSTNAME} sshd[{pid}]: {message}"


def generate_auth_log(rng: random.Random) -> list[tuple[datetime, str]]:
    entries = []

    # ~200 нормальних подій: переважно успішні входи, зрідка помилка в паролі
    for _ in range(200):
        ts = random_time(rng)
        user = rng.choice(list(SSH_USERS))
        ip = rng.choice(SSH_USERS[user])
        port = rng.randint(40000, 65000)
        pid = rng.randint(1000, 30000)
        if rng.random() < 0.08:
            msg = f"Failed password for {user} from {ip} port {port} ssh2"
        else:
            method = "publickey" if user in ("deploy", "jenkins") else "password"
            msg = f"Accepted {method} for {user} from {ip} port {port} ssh2"
        entries.append((ts, ssh_line(ts, pid, msg)))

    # Brute-force: 30 невдалих спроб за 2 хвилини з одного IP
    attack_start = datetime(2026, 9, 30, 3, 22, 0)
    offsets = sorted(rng.sample(range(0, 120), 30))
    for offset in offsets:
        ts = attack_start + timedelta(seconds=offset)
        user = rng.choice(BRUTE_FORCE_USERS)
        port = rng.randint(40000, 65000)
        pid = rng.randint(1000, 30000)
        if user in SSH_USERS:
            msg = f"Failed password for {user} from {BRUTE_FORCE_IP} port {port} ssh2"
        else:
            msg = f"Failed password for invalid user {user} from {BRUTE_FORCE_IP} port {port} ssh2"
        entries.append((ts, ssh_line(ts, pid, msg)))

    entries += generate_compromise(random.Random(SEED + 1))
    return entries


def generate_compromise(rng: random.Random) -> list[tuple[datetime, str]]:
    """Brute-force з COMPROMISE_IP: COMPROMISE_FAILS невдалих спроб за ~1.5 хв, потім успішний вхід admin.

    Окремий rng, щоб додавання сценарію не змінило решту згенерованих логів.
    """
    entries = []
    offsets = sorted(rng.sample(range(0, 90), COMPROMISE_FAILS))
    for offset in offsets:
        ts = COMPROMISE_START + timedelta(seconds=offset)
        user = rng.choice(COMPROMISE_USERS)
        invalid = "" if user in SSH_USERS else "invalid user "
        msg = f"Failed password for {invalid}{user} from {COMPROMISE_IP} port {rng.randint(40000, 65000)} ssh2"
        entries.append((ts, ssh_line(ts, rng.randint(1000, 30000), msg)))

    ts = COMPROMISE_START + timedelta(seconds=offsets[-1] + 4)
    msg = f"Accepted password for admin from {COMPROMISE_IP} port {rng.randint(40000, 65000)} ssh2"
    entries.append((ts, ssh_line(ts, rng.randint(1000, 30000), msg)))
    return entries


# ------------------------------------------------------------ nginx access.log

def web_line(ts: datetime, ip: str, method: str, path: str, status: int,
             size: int, ua: str, referer: str = "-") -> str:
    # nginx combined: ip - - [30/Sep/2026:03:22:14 +0000] "GET / HTTP/1.1" 200 512 "-" "UA"
    time_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{time_str}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'


def generate_access_log(rng: random.Random) -> list[tuple[datetime, str]]:
    entries = []

    # ~200 нормальних запитів
    for _ in range(200):
        ts = random_time(rng)
        ip = rng.choice(WEB_CLIENT_IPS)
        path, status = rng.choice(WEB_PATHS)
        method = "POST" if path == "/login" and rng.random() < 0.5 else "GET"
        size = rng.randint(200, 15000) if status == 200 else rng.randint(150, 600)
        referer = rng.choice(["-", "https://example.com/", "https://www.google.com/"])
        entries.append((ts, web_line(ts, ip, method, path, status, size, rng.choice(USER_AGENTS), referer)))

    # Сканування шляхів: 25 різних шляхів приблизно за хвилину
    scan_start = datetime(2026, 9, 30, 14, 5, 0)
    t = scan_start
    for path in SCAN_PATHS:
        t += timedelta(seconds=rng.randint(1, 3))
        status = 403 if path in ("/.git/config", "/.htaccess", "/server-status") else 404
        entries.append((t, web_line(t, SCANNER_IP, "GET", path, status, rng.randint(150, 300), SCANNER_UA)))

    # SQLi-спроба в параметрі запиту
    sqli_ts = datetime(2026, 9, 30, 19, 47, 33)
    sqli_path = f"/products?id={quote(SQLI_PAYLOAD)}"
    entries.append((sqli_ts, web_line(sqli_ts, SQLI_IP, "GET", sqli_path, 500, 1024, SQLI_UA)))

    return entries


# ------------------------------------------------------------- ufw firewall.log

def firewall_line(ts: datetime, rng: random.Random, src: str, dpt: int | None, proto: str) -> str:
    # ufw: "Sep 30 14:02:11 host kernel: [86531.204117] [UFW BLOCK] IN=eth0 OUT= ... SRC=... DPT=22 ..."
    uptime = FIREWALL_START_UPTIME + (ts - START_TIME).total_seconds() + rng.random()
    head = (f"{ts.strftime('%b')} {ts.day:>2} {ts.strftime('%H:%M:%S')} {HOSTNAME} kernel: "
            f"[{uptime:.6f}] [UFW BLOCK] IN={FIREWALL_IFACE} OUT= "
            f"MAC=52:54:00:12:34:56:52:54:00:65:43:21:08:00 SRC={src} DST={SERVER_EXT_IP} ")
    ttl, packet_id = rng.randint(40, 250), rng.randint(1, 65535)
    if proto == "ICMP":
        return head + f"LEN=84 TOS=0x00 PREC=0x00 TTL={ttl} ID={packet_id} PROTO=ICMP TYPE=8 CODE=0 ID={rng.randint(1, 65535)} SEQ=1"
    spt = rng.randint(1024, 65535)
    if proto == "UDP":
        return head + f"LEN=40 TOS=0x00 PREC=0x00 TTL={ttl} ID={packet_id} PROTO=UDP SPT={spt} DPT={dpt} LEN=20"
    return head + (f"LEN=44 TOS=0x00 PREC=0x00 TTL={ttl} ID={packet_id} PROTO=TCP SPT={spt} DPT={dpt} "
                   f"WINDOW=1024 RES=0x00 SYN URGP=0")


def generate_firewall_log(rng: random.Random) -> list[tuple[datetime, str]]:
    """Окремий rng (як у generate_compromise), щоб auth.log і access.log не змінились."""
    entries = []

    # ~200 блокувань інтернет-шуму: кілька десятків випадкових IP, кожен — 1-3 порти протягом доби
    noise_ips = [f"{net}.{rng.randint(2, 250)}" for net in ("192.0.2", "198.51.100", "203.0.113")
                 for _ in range(25)]
    noise_ips = [ip for ip in dict.fromkeys(noise_ips)
                 if ip not in (SERVER_EXT_IP, SCANNER_IP, SLOW_SCAN_IP, SINGLE_PORT_IP,
                               BRUTE_FORCE_IP, COMPROMISE_IP, SQLI_IP)]
    while len(entries) < 200:
        ip = rng.choice(noise_ips)
        for dpt, proto in rng.sample(NOISE_PORTS, rng.randint(1, 3)):
            ts = random_time(rng)
            entries.append((ts, firewall_line(ts, rng, ip, dpt, proto)))

    # Сканування портів: 25 портів приблизно за 25 секунд (SYN-скан, як nmap)
    t = PORT_SCAN_START
    for dpt in rng.sample(PORT_SCAN_PORTS, len(PORT_SCAN_PORTS)):
        t += timedelta(milliseconds=rng.randint(300, 1500))
        entries.append((t, firewall_line(t, rng, SCANNER_IP, dpt, "TCP")))

    # Повільний перебір: 12 різних портів, по одному на годину — не сканування за PORT_SCAN_WINDOW
    for hour, dpt in enumerate(PORT_SCAN_PORTS[:12]):
        ts = SLOW_SCAN_START + timedelta(hours=hour, seconds=rng.randint(0, 600))
        entries.append((ts, firewall_line(ts, rng, SLOW_SCAN_IP, dpt, "TCP")))

    # Один порт багато разів — це не сканування портів
    for offset in sorted(rng.sample(range(0, 180), 40)):
        ts = SINGLE_PORT_START + timedelta(seconds=offset)
        entries.append((ts, firewall_line(ts, rng, SINGLE_PORT_IP, 3389, "TCP")))

    return entries


def write_log(path: Path, entries: list[tuple[datetime, str]]) -> None:
    entries.sort(key=lambda e: e[0])
    path.write_text("\n".join(line for _, line in entries) + "\n", encoding="utf-8")
    print(f"{path}: {len(entries)} рядків")


def main() -> None:
    rng = random.Random(SEED)
    OUTPUT_DIR.mkdir(exist_ok=True)
    write_log(OUTPUT_DIR / "auth.log", generate_auth_log(rng))
    write_log(OUTPUT_DIR / "access.log", generate_access_log(rng))
    write_log(OUTPUT_DIR / "firewall.log", generate_firewall_log(random.Random(SEED + 2)))


if __name__ == "__main__":
    main()

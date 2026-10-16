"""Генератор синтетичних логів для розробки й демо SIEM-lite.

Створює:
  sample_logs/auth.log   — ~200 нормальних SSH-подій + brute-force атака
                           (30 невдалих спроб за 2 хвилини з одного IP)
  sample_logs/access.log — ~200 нормальних web-запитів (nginx combined)
                           + сканування шляхів + SQLi-спроба в параметрі

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


def write_log(path: Path, entries: list[tuple[datetime, str]]) -> None:
    entries.sort(key=lambda e: e[0])
    path.write_text("\n".join(line for _, line in entries) + "\n", encoding="utf-8")
    print(f"{path}: {len(entries)} рядків")


def main() -> None:
    rng = random.Random(SEED)
    OUTPUT_DIR.mkdir(exist_ok=True)
    write_log(OUTPUT_DIR / "auth.log", generate_auth_log(rng))
    write_log(OUTPUT_DIR / "access.log", generate_access_log(rng))


if __name__ == "__main__":
    main()

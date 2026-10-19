"""Симулятор атаки для демо live-режиму.

Дописує в live_logs/auth.log (SSH) і live_logs/access.log (nginx) рядки з
поточним часом, як їх писав би справжній сервер:
  - весь час: звичайний трафік, по рядку раз на 1-2 секунди (переважно web,
    інколи SSH-входи легітимних користувачів);
  - через --attack-after секунд: SSH brute-force з BRUTE_FORCE_IP
    (BRUTE_FORCE_FAILS невдалих спроб, по одній за ~0.5-1 с), після якого
    вхід admin успішний;
  - через --sqli-after секунд: кілька SQLi-запитів sqlmap з SQLI_IP.
Звичайний трафік триває й під час атак. Після --duration секунд (або Ctrl+C)
симулятор зупиняється.

Атакуючі IP — з документаційних діапазонів (RFC 5737), відмінні від sample_logs.
SSH-час місцевий (syslog), web-час у UTC (+0000), як у generate_logs.py.

Запуск (у другому терміналі після main.py live):
  py -3 simulate_attack.py --attack-after 20 --sqli-after 60
"""

import argparse
import heapq
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from generate_logs import (BRUTE_FORCE_USERS, SQLI_UA, SSH_USERS, USER_AGENTS, WEB_CLIENT_IPS, WEB_PATHS,
                           ssh_line, web_line)

OUTPUT_DIR = Path(__file__).parent / "live_logs"
AUTH_LOG = OUTPUT_DIR / "auth.log"
ACCESS_LOG = OUTPUT_DIR / "access.log"

BRUTE_FORCE_IP = "203.0.113.99"
BRUTE_FORCE_FAILS = 20
SQLI_IP = "192.0.2.150"
SQLI_PAYLOADS = [
    "1' OR '1'='1' -- ",
    "1 UNION SELECT username, password FROM users-- ",
    "1' AND SLEEP(5)-- ",
    "1; DROP TABLE users; -- ",
]

SSH_SHARE = 0.25  # частка SSH-рядків у звичайному трафіку


def normal_line(rng: random.Random) -> tuple[Path, str]:
    if rng.random() < SSH_SHARE:
        user = rng.choice(list(SSH_USERS))
        method = "publickey" if user in ("deploy", "jenkins") else "password"
        msg = f"Accepted {method} for {user} from {rng.choice(SSH_USERS[user])} port {rng.randint(40000, 65000)} ssh2"
        return AUTH_LOG, ssh_line(datetime.now(), rng.randint(1000, 30000), msg)
    path, status = rng.choice(WEB_PATHS)
    method = "POST" if path == "/login" and rng.random() < 0.5 else "GET"
    size = rng.randint(200, 15000) if status == 200 else rng.randint(150, 600)
    return ACCESS_LOG, web_line(datetime.now(timezone.utc), rng.choice(WEB_CLIENT_IPS), method, path, status,
                                size, rng.choice(USER_AGENTS), rng.choice(["-", "https://example.com/"]))


def brute_force_line(rng: random.Random, success: bool) -> tuple[Path, str]:
    port = rng.randint(40000, 65000)
    if success:
        msg = f"Accepted password for admin from {BRUTE_FORCE_IP} port {port} ssh2"
    else:
        user = rng.choice(BRUTE_FORCE_USERS)
        invalid = "" if user in SSH_USERS else "invalid user "
        msg = f"Failed password for {invalid}{user} from {BRUTE_FORCE_IP} port {port} ssh2"
    return AUTH_LOG, ssh_line(datetime.now(), rng.randint(1000, 30000), msg)


def sqli_line(payload: str) -> tuple[Path, str]:
    return ACCESS_LOG, web_line(datetime.now(timezone.utc), SQLI_IP, "GET", f"/products?id={quote(payload)}",
                                500, 1024, SQLI_UA)


def attack_schedule(rng: random.Random, attack_after: float, sqli_after: float) -> list[tuple[float, str, object]]:
    """Розклад атак: (секунда від старту, назва, генератор рядка)."""
    plan = []
    t = attack_after
    for _ in range(BRUTE_FORCE_FAILS):
        plan.append((t, "brute-force", lambda: brute_force_line(rng, success=False)))
        t += rng.uniform(0.5, 1.0)
    plan.append((t + 3, "brute-force: успішний вхід admin", lambda: brute_force_line(rng, success=True)))
    t = sqli_after
    for payload in SQLI_PAYLOADS:
        plan.append((t, "SQLi", lambda payload=payload: sqli_line(payload)))
        t += rng.uniform(1.5, 3.0)
    return plan


def append(path: Path, line: str) -> None:
    # Відкриття на кожен рядок, як у звичайного логера: читач (tail) бачить рядок одразу
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Симулятор трафіку й атак для main.py live")
    parser.add_argument("--attack-after", type=float, default=20, metavar="SEC",
                        help="через скільки секунд почати SSH brute-force (за замовчуванням 20)")
    parser.add_argument("--sqli-after", type=float, default=None, metavar="SEC",
                        help="через скільки секунд почати SQLi (за замовчуванням attack-after + 40)")
    parser.add_argument("--duration", type=float, default=None, metavar="SEC",
                        help="загальна тривалість (за замовчуванням sqli-after + 20)")
    parser.add_argument("--seed", type=int, default=None, help="seed для відтворюваного трафіку")
    args = parser.parse_args()
    sqli_after = args.sqli_after if args.sqli_after is not None else args.attack_after + 40
    duration = args.duration if args.duration is not None else max(args.attack_after, sqli_after) + 20

    rng = random.Random(args.seed)
    OUTPUT_DIR.mkdir(exist_ok=True)
    for path in (AUTH_LOG, ACCESS_LOG):
        path.touch()

    # Одна черга подій: звичайний трафік (kind 0) і атаки (kind 1), за часом від старту
    queue = [(offset, 1, i, name, make) for i, (offset, name, make) in
             enumerate(attack_schedule(rng, args.attack_after, sqli_after))]
    queue.append((rng.uniform(1, 2), 0, -1, "normal", None))
    heapq.heapify(queue)

    print(f"Симулятор: {AUTH_LOG}, {ACCESS_LOG}; brute-force з {BRUTE_FORCE_IP} через {args.attack_after:g} с, "
          f"SQLi з {SQLI_IP} через {sqli_after:g} с, зупинка через {duration:g} с", flush=True)
    started = time.monotonic()
    counts = {"normal": 0, "attack": 0}
    phase = None
    try:
        while queue:
            offset, kind, seq, name, make = heapq.heappop(queue)
            if offset > duration:
                break
            time.sleep(max(0.0, started + offset - time.monotonic()))
            if kind == 0:
                append(*normal_line(rng))
                counts["normal"] += 1
                heapq.heappush(queue, (offset + rng.uniform(1, 2), 0, -1, "normal", None))
                continue
            if name != phase:
                print(f"{datetime.now():%H:%M:%S} [+{offset:5.1f} с] {name}", flush=True)
                phase = name
            append(*make())
            counts["attack"] += 1
    except KeyboardInterrupt:
        pass
    print(f"{datetime.now():%H:%M:%S} Симулятор зупинено: звичайних рядків {counts['normal']}, "
          f"атакуючих {counts['attack']}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Тест live-режиму (live.py і main.py live) без мережі.

Запуск: py -3 test_live.py

Файли й база — у тимчасовій папці; history.db і live_logs не зачіпаються.
"""

import argparse
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import detector
import live
import main as siem
from generate_logs import ssh_line

START = datetime(2026, 10, 19, 12, 0, 0)


def fail(ts: datetime, ip: str = "203.0.113.99", user: str = "root") -> str:
    return ssh_line(ts, 1234, f"Failed password for {user} from {ip} port 50000 ssh2")


def success(ts: datetime, ip: str = "203.0.113.99") -> str:
    return ssh_line(ts, 1234, f"Accepted password for admin from {ip} port 50001 ssh2")


def write(path: Path, text: str) -> None:
    with open(path, "a", encoding="utf-8", newline="") as f:
        f.write(text)


def test_tail(tmp: Path) -> None:
    path = tmp / "auth.log"
    path.write_text("old line 1\nold line 2\n", encoding="utf-8")
    tail = live.LogTail(path)
    assert tail.read_lines() == [], "старі рядки не читаються — починаємо з кінця"

    write(path, "new 1\nnew 2\npart")
    assert tail.read_lines() == ["new 1", "new 2"], "незавершений рядок чекає на \\n"
    write(path, "ial\r\n\n")
    assert tail.read_lines() == ["partial"], "CRLF і порожні рядки"

    path.write_text("after rotation\n", encoding="utf-8")  # файл став коротшим
    assert tail.read_lines() == ["after rotation"]

    missing = live.LogTail(tmp / "later.log")
    assert missing.read_lines() == []
    write(tmp / "later.log", "first\n")
    assert missing.read_lines() == ["first"], "файл, створений після старту, читається з початку"


def test_window() -> None:
    window = live.EventWindow(span=timedelta(minutes=5))

    def event(ts: datetime, source: str) -> dict:
        return {"timestamp": ts.isoformat(), "log_source": source, "source_ip": "x", "event_type": "e", "meta": {}}

    window.add([event(START, "ssh"), event(START + timedelta(hours=-3), "web")])
    window.add([event(START + timedelta(minutes=6), "ssh")])
    times = [(e["log_source"], e["timestamp"]) for e in window.events]
    # SSH-подія старша за 5 хв від найновішої SSH випадає; web (інший часовий пояс) лишається
    assert ("ssh", START.isoformat()) not in times and len(window) == 2, times


def test_tracker() -> None:
    tracker = live.IncidentTracker()
    base = {"rule": "brute_force", "source_ip": "203.0.113.99", "first_seen": "2026-10-19T12:00:00",
            "last_seen": "2026-10-19T12:00:10", "event_count": 10, "severity": "High", "details": {}}
    assert [(n, kind) for n, _, kind in tracker.update([base])] == [(1, "new")]

    grown = {**base, "last_seen": "2026-10-19T12:00:20", "event_count": 15}
    assert tracker.update([grown]) == [], "атака триває — той самий інцидент, не новий"

    compromised = {**grown, "severity": "Critical", "event_count": 16}
    changes = tracker.update([compromised])
    assert [(n, kind) for n, _, kind in changes] == [(1, "escalated")]

    # Перші події випали з вікна: first_seen зсунувся, але це той самий інцидент
    shifted = {**compromised, "first_seen": "2026-10-19T12:00:05", "event_count": 9, "severity": "High"}
    assert tracker.update([shifted]) == []
    kept = tracker.all()[0]
    assert kept["first_seen"] == base["first_seen"] and kept["severity"] == "Critical" and kept["event_count"] == 16

    later = {**base, "first_seen": "2026-10-19T13:00:00", "last_seen": "2026-10-19T13:01:00"}
    other_ip = {**base, "source_ip": "192.0.2.1"}
    assert [n for n, _, _ in tracker.update([later, other_ip])] == [2, 3]


def live_args(tmp: Path, logs: list[Path], **kw) -> argparse.Namespace:
    defaults = dict(logs=logs, year=2026, history_db=tmp / "test.db", ai=False, dry_run=False,
                    notify=False, max_ai=None, poll=0.01, duration=None)
    return argparse.Namespace(**{**defaults, **kw})


def test_session_detects_during_attack(tmp: Path) -> None:
    """Brute-force виявляється на 10-й спробі, тобто ще під час атаки; AI — один раз на інцидент + ескалація."""
    auth = tmp / "live_auth.log"
    auth.write_text(ssh_line(START, 1, "Accepted password for alice from 10.0.1.15 port 40000 ssh2") + "\n",
                    encoding="utf-8")
    args = live_args(tmp, [auth], dry_run=True, notify=True)
    printed: list[str] = []
    siem.print_telegram_message = printed.append
    with siem.history.History(args.history_db) as db:
        session = siem.LiveSession(args, db)
        assert session.sources[0].format == "ssh"
        detected_at = None
        for i in range(20):
            write(auth, fail(START + timedelta(seconds=i)) + "\n")
            session.poll()
            if detected_at is None and session.tracker.all():
                detected_at = i + 1
        assert detected_at == detector.BRUTE_FORCE_MIN_FAILS, detected_at
        assert session.ai_done == 1, "атака тривала ще 10 спроб, але AI-аналіз один"
        assert len(printed) == 1 and "HIGH" in printed[0]

        write(auth, success(START + timedelta(seconds=25)) + "\n")
        session.poll()
        incidents = session.tracker.all()
        assert len(incidents) == 1 and incidents[0]["severity"] == "Critical"
        assert session.ai_done == 2, "ескалація High → Critical аналізується ще раз"
        assert len(printed) == 2 and "CRITICAL" in printed[1]
        assert db.ip_summary("203.0.113.99")["login_fail"] == 20, "події записані в history.db"


def test_ctrl_c(tmp: Path) -> None:
    """Ctrl+C (KeyboardInterrupt у циклі) — коректна зупинка з підсумком, код 0."""
    auth = tmp / "ctrlc.log"
    auth.touch()
    calls = []

    def sleep(seconds: float) -> None:
        calls.append(seconds)
        if len(calls) == 1:
            write(auth, "".join(fail(START + timedelta(seconds=i), ip="198.51.100.9") + "\n" for i in range(12)))
        else:
            raise KeyboardInterrupt

    with siem.console.capture() as captured:
        code = siem.run_live(live_args(tmp, [auth]), sleep=sleep)
    out = captured.get()
    assert code == 0 and "Live зупинено (Ctrl+C)" in out and "198.51.100.9" in out, out
    assert "оброблено подій: 12" in out and "знайдено інцидентів: 1" in out, out


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    with tempfile.TemporaryDirectory() as name:
        tmp = Path(name)
        test_tail(tmp)
        test_window()
        test_tracker()
        test_session_detects_during_attack(tmp)
        test_ctrl_c(tmp)
    print("OK: усі перевірки live пройдено")


if __name__ == "__main__":
    main()

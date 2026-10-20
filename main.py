"""Точка входу SIEM-lite.

Режими:
  batch — одноразовий прогін готових лог-файлів (для тестування й демо)
  live  — стеження за логами в реальному часі (як tail -f, з кінця файлів)

Приклад:
  py -3 main.py batch sample_logs/auth.log sample_logs/access.log sample_logs/firewall.log
  py -3 main.py batch sample_logs/*.log --ai              # + аналіз AI-агентом
  py -3 main.py batch sample_logs/*.log --ai --dry-run    # без реальних API-викликів
  py -3 main.py batch sample_logs/*.log --ai --rule brute_force
  py -3 main.py batch real_logs/OpenSSH_2k.log --ai --max-ai 3   # лише 3 найсерйозніші
  py -3 main.py batch sample_logs/*.log --notify --dry-run        # сповіщення в консоль, не в Telegram
  py -3 main.py batch sample_logs/*.log --ai --notify --ip 203.0.113.77
  py -3 main.py live live_logs/auth.log live_logs/access.log --dry-run --notify
  py -3 main.py live live_logs/*.log --ai --notify               # Ctrl+C — зупинка з підсумком

Усі події пишуться в history.db (історія по IP); агент отримує зведення по IP
разом з інцидентом. З --notify інциденти High/Critical надсилаються в Telegram
(без дублікатів між запусками); --dry-run друкує сповіщення замість відправки.

Формат кожного файлу (ssh / web / firewall) визначається автоматично за першими
рядками, тому порядок аргументів не важливий.

У live нові рядки парсяться, пишуться в history.db, а детектор щоразу
працює по ковзному вікну останніх подій (live.WINDOW). Кожен новий інцидент
(IP + правило + first_seen) AI-агент аналізує один раз, хоч би скільки атака
ще тривала; повторно — лише якщо severity детектора зросла (brute-force, після
якого вхід успішний: High → Critical).
"""

import argparse
import html
import json
import logging
import re
import sys
import time
from datetime import datetime
from functools import partial
from itertools import islice
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

import agent
import detector
import history
import live
import notifier
from parsers import firewall_parser, ssh_parser, web_parser

# Скільки перших непорожніх рядків дивитися, щоб визначити формат файлу
DETECT_SAMPLE_LINES = 20

SEVERITY_STYLE = {
    "Critical": "bold white on red",
    "High": "bold red",
    "Medium": "yellow",
    "Low": "green",
}

console = Console()


def get_parsers(year: int | None) -> dict[str, Callable[[str], dict | None]]:
    """Реєстр парсерів: назва формату → parse_line. Нове джерело логів — новий рядок тут."""
    return {
        "ssh": partial(ssh_parser.parse_line, year=year),
        "web": web_parser.parse_line,
        "firewall": partial(firewall_parser.parse_line, year=year),
    }


def detect_format(path: Path, parsers: dict[str, Callable]) -> str | None:
    """Обирає парсер, який розпізнав найбільше з перших рядків файлу."""
    with open(path, encoding="utf-8", errors="replace") as f:
        sample = list(islice((line for line in f if line.strip()), DETECT_SAMPLE_LINES))
    if not sample:
        return None
    scores = {name: sum(parse(line) is not None for line in sample) for name, parse in parsers.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else None


def load_events(paths: list[Path], year: int | None) -> tuple[list[dict], list[dict]]:
    """Парсить файли. Повертає (події, статистика по файлах)."""
    parsers = get_parsers(year)
    events, stats = [], []
    for path in paths:
        fmt = detect_format(path, parsers)
        if fmt is None:
            console.print(f"[yellow]Пропущено {path}: формат не розпізнано[/yellow]")
            stats.append({"path": path, "format": "?", "lines": 0, "events": 0})
            continue

        parse = parsers[fmt]
        lines = parsed = 0
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                lines += 1
                if (event := parse(line)) is not None:
                    events.append(event)
                    parsed += 1
        stats.append({"path": path, "format": fmt, "lines": lines, "events": parsed})
    return events, stats


def format_details(details: dict) -> str:
    parts = []
    for key, value in details.items():
        if isinstance(value, list):
            value = ", ".join(map(str, value))
        parts.append(f"{key}: {value}")
    return "\n".join(parts)


def short_time(iso: str) -> str:
    return iso.replace("T", " ")


def print_files(stats: list[dict]) -> None:
    table = Table(title="Оброблені файли", title_justify="left")
    table.add_column("Файл")
    table.add_column("Формат")
    table.add_column("Рядків", justify="right")
    table.add_column("Подій", justify="right")
    table.add_column("Нерозпізнано", justify="right")
    for s in stats:
        skipped = s["lines"] - s["events"]
        table.add_row(str(s["path"]), s["format"], str(s["lines"]), str(s["events"]),
                      f"[yellow]{skipped}[/yellow]" if skipped else "0")
    console.print(table)


def print_incidents(incidents: list[dict]) -> None:
    if not incidents:
        console.print("[green]Інцидентів не знайдено.[/green]")
        return

    table = Table(title="Інциденти", title_justify="left", show_lines=True)
    table.add_column("#", justify="right")
    table.add_column("Severity")
    table.add_column("Правило")
    table.add_column("IP")
    table.add_column("Перша подія")
    table.add_column("Остання подія")
    table.add_column("Подій", justify="right")
    table.add_column("Деталі")
    for n, inc in enumerate(incidents, 1):
        style = SEVERITY_STYLE.get(inc["severity"], "")
        table.add_row(
            str(n),
            f"[{style}]{inc['severity']}[/{style}]" if style else inc["severity"],
            inc["rule"],
            inc["source_ip"],
            short_time(inc["first_seen"]),
            short_time(inc["last_seen"]),
            str(inc["event_count"]),
            format_details(inc["details"]),
        )
    console.print(table)


def print_summary(event_count: int, incidents: list[dict]) -> None:
    by_severity = {}
    for inc in incidents:
        by_severity[inc["severity"]] = by_severity.get(inc["severity"], 0) + 1
    breakdown = ", ".join(
        f"[{SEVERITY_STYLE.get(sev, '')}]{sev}: {count}[/]"
        for sev, count in sorted(by_severity.items(), key=lambda kv: list(SEVERITY_STYLE).index(kv[0]))
    )
    console.print(
        f"\n[bold]Підсумок:[/bold] оброблено подій: [bold]{event_count}[/bold], "
        f"знайдено інцидентів: [bold]{len(incidents)}[/bold]"
        + (f" ({breakdown})" if breakdown else "")
    )


def severity_markup(severity: str) -> str:
    style = SEVERITY_STYLE.get(severity)
    return f"[{style}]{severity}[/{style}]" if style else severity


def format_history(summary: dict | None) -> str:
    if not summary or not summary["total_events"]:
        return "даних немає"
    text = (f"подій {summary['total_events']}, невдалих входів {summary['login_fail']}, "
            f"успішних {summary['login_success']}, {short_time(summary['first_seen'])} → "
            f"{short_time(summary['last_seen'])}")
    if summary.get("firewall_blocks"):
        text += f", заблоковано firewall-ом {summary['firewall_blocks']}"
    if detail := summary["success_after_failures_detail"]:
        text += (f"\n  [bold red]успішний вхід {escape(str(detail['user']))} о {short_time(detail['success_time'])} "
                 f"після {detail['failures_before']} невдалих поспіль[/bold red]")
    return text


def print_analysis(n: int, incident: dict, analysis: dict) -> None:
    """Ланцюжок: інцидент → tool calls → висновок.

    Текст від моделі й інструментів екранується: квадратні дужки в ньому
    rich інакше сприйняв би як свою розмітку.
    """
    lines = [
        f"[bold]Інцидент:[/bold] {incident['rule']} з {incident['source_ip']}, "
        f"подій: {incident['event_count']}, severity детектора: {severity_markup(incident['severity'])}",
        f"[bold]Історія IP:[/bold] {format_history(analysis['ip_history'])}",
        "",
    ]
    if analysis["tool_calls"]:
        for call in analysis["tool_calls"]:
            args = ", ".join(f"{k}={v!r}" for k, v in call["args"].items())
            lines.append(f"[bold cyan]Tool call:[/bold cyan] {escape(call['name'])}({escape(args)})")
            lines.append(f"  → {escape(json.dumps(call['result'], ensure_ascii=False))}")
    else:
        lines.append("[dim]Tool call: агент вирішив не перевіряти репутацію IP[/dim]")
    lines += [
        "",
        f"[bold]Тип загрози:[/bold] {escape(analysis['threat_type'])}",
        f"[bold]Severity (AI):[/bold] {severity_markup(analysis['severity'])}"
        + (f" [bold yellow]⚠ {escape(analysis['severity_note'])}[/bold yellow]" if analysis.get("severity_note") else ""),
        f"[bold]Пояснення:[/bold] {escape(analysis['explanation'])}",
        f"[bold]Рекомендація:[/bold] {escape(analysis['recommendation'])}",
    ]
    model = f"{analysis['provider']}/{analysis['model']}"
    console.print(Panel("\n".join(lines), title=f"AI-аналіз #{n}", subtitle=model, title_align="left"))


def most_serious(incidents: list[dict], limit: int | None) -> list[tuple[int, dict]]:
    """Найсерйозніші інциденти для AI-агента: за severity детектора, потім за кількістю подій.

    Повертає пари (номер у таблиці інцидентів, інцидент) у порядку таблиці,
    щоб номери в AI-аналізі збігалися з таблицею.
    """
    numbered = list(enumerate(incidents, 1))
    if limit is None or limit >= len(numbered):
        return numbered
    rank = list(SEVERITY_STYLE)  # Critical, High, Medium, Low
    by_seriousness = sorted(numbered, key=lambda ni: (rank.index(ni[1]["severity"]) if ni[1]["severity"] in rank
                                                      else len(rank), -ni[1]["event_count"]))
    return sorted(by_seriousness[:limit], key=lambda ni: ni[0])


def run_ai(incidents: list[tuple[int, dict]], dry_run: bool, db: history.History) -> dict[int, dict]:
    """Проганяє інциденти (номер, інцидент) через агента (+ історія IP); помилка на одному не зупиняє решту.

    Повертає {номер інциденту: AI-аналіз}.
    """
    try:
        provider = agent.get_provider(dry_run)
    except Exception as e:
        console.print(f"[red]AI-агент недоступний: {e}[/red]")
        return {}

    analyses = {}
    for n, incident in incidents:
        with console.status(f"AI-аналіз інциденту #{n} ({incident['rule']})..."):
            try:
                analysis = agent.analyze_incident(incident, provider=provider, dry_run=dry_run,
                                                  ip_history=db.ip_summary(incident["source_ip"]))
            except Exception as e:
                console.print(f"[red]AI-аналіз #{n} не вдався: {type(e).__name__}: {e}[/red]")
                continue
        print_analysis(n, incident, analysis)
        analyses[n] = analysis
    return analyses


def print_telegram_message(text: str) -> None:
    """Dry-run: повідомлення як його побачить людина в Telegram (без HTML-тегів)."""
    plain = html.unescape(re.sub(r"<[^>]+>", "", text))
    console.print(Panel(escape(plain), title="Telegram (dry-run)", title_align="left", expand=False))


def run_notify(incidents: list[dict], analyses: dict[int, dict], dry_run: bool, db: history.History) -> None:
    stats = notifier.notify(
        [(inc, analyses.get(n)) for n, inc in enumerate(incidents, 1)],
        sent_log=notifier.SentLog(db.conn), dry_run=dry_run, print_message=print_telegram_message,
    )
    parts = [f"надіслано {stats['sent']}"] if not dry_run else [f"dry-run, надруковано {stats['dry_run']}"]
    if stats["duplicate"]:
        parts.append(f"вже надсилались раніше {stats['duplicate']}")
    if stats["failed"]:
        parts.append(f"[yellow]не вдалося {stats['failed']}[/yellow]")
    parts.append(f"нижче порогу {notifier.NOTIFY_MIN_SEVERITY} {stats['below_threshold']}")
    console.print(f"Telegram-сповіщення: {', '.join(parts)}")


def run_batch(args: argparse.Namespace) -> int:
    missing = [p for p in args.logs if not p.is_file()]
    if missing:
        for p in missing:
            console.print(f"[red]Файл не знайдено: {p}[/red]")
        return 1

    events, stats = load_events(args.logs, args.year)
    incidents = detector.detect(events)
    if args.rule:
        incidents = [i for i in incidents if i["rule"] in args.rule]
    if args.ip:
        incidents = [i for i in incidents if i["source_ip"] in args.ip]

    print_files(stats)
    with history.History(args.history_db) as db:
        added = db.store_events(events)
        console.print(f"Історія IP ({args.history_db}): нових подій {added}, "
                      f"вже були в базі {len(events) - added}")
        console.print()
        print_incidents(incidents)

        analyses = {}
        if args.ai or args.dry_run:
            console.print()
            selected = most_serious(incidents, args.max_ai)
            if len(selected) < len(incidents):
                console.print(f"[dim]--max-ai {args.max_ai}: AI-агент аналізує {len(selected)} найсерйозніших "
                              f"(severity, потім кількість подій): "
                              f"#{', #'.join(str(n) for n, _ in selected)}[/dim]")
            analyses = run_ai(selected, dry_run=args.dry_run, db=db)
            console.print(f"\nAI-агент проаналізував {len(analyses)} з {len(incidents)} інцидентів"
                          + (" [dim](dry-run)[/dim]" if args.dry_run else ""))

        if args.notify:
            console.print()
            run_notify(incidents, analyses, dry_run=args.dry_run, db=db)

    print_summary(len(events), incidents)
    return 0


# ------------------------------------------------------------------ live

# Як часто перевіряти файли на нові рядки
LIVE_POLL_SECONDS = 0.5
# Без інтерактивного терміналу (вивід у файл) рядок статусу друкується раз на стільки секунд
LIVE_STATUS_EVERY = 10


def clock() -> str:
    return datetime.now().strftime("%H:%M:%S")


def print_detector_panel(n: int, incident: dict) -> None:
    """Панель нового інциденту без AI-аналізу — дані детектора."""
    details = format_details(incident["details"]).replace("\n", "; ")
    lines = [
        f"[bold]Правило:[/bold] {incident['rule']}   [bold]IP:[/bold] {incident['source_ip']}   "
        f"[bold]Severity:[/bold] {severity_markup(incident['severity'])}",
        f"[bold]Подій:[/bold] {incident['event_count']}   "
        f"[bold]Час:[/bold] {short_time(incident['first_seen'])} → {short_time(incident['last_seen'])}",
        f"[bold]Деталі:[/bold] {escape(details)}",
    ]
    console.print(Panel("\n".join(lines), title=f"Інцидент #{n} (детектор)", title_align="left"))


class LiveSession:
    """Стан main.py live і реакція на нові інциденти: AI-аналіз, Telegram, лічильники."""

    def __init__(self, args: argparse.Namespace, db: history.History):
        self.args, self.db = args, db
        self.started = time.monotonic()
        parsers = get_parsers(args.year)
        self.sources = [live.LiveSource(p, parsers, detect_format) for p in args.logs]
        self.window = live.EventWindow()
        self.tracker = live.IncidentTracker()
        self.ai_done = 0
        self.notify_stats = dict.fromkeys(["sent", "dry_run", "duplicate", "failed", "below_threshold"], 0)

        self.provider = None
        if args.ai or args.dry_run:
            try:
                self.provider = agent.get_provider(args.dry_run)
            except Exception as e:
                console.print(f"[red]AI-агент недоступний, далі лише детектор: {e}[/red]")
        self.sent_log = notifier.SentLog(db.conn) if args.notify else None
        self.telegram = notifier.TelegramNotifier() if args.notify and not args.dry_run else None

    def poll(self) -> int:
        """Один прохід: нові рядки → history.db → детектор по вікну → реакція. Повертає кількість подій."""
        events = [event for source in self.sources for event in source.poll()]
        if not events:
            return 0
        self.db.store_events(events)
        self.window.add(events)
        for n, incident, kind in self.tracker.update(detector.detect(self.window.events)):
            self.on_incident(n, incident, kind)
        return len(events)

    def on_incident(self, n: int, incident: dict, kind: str) -> None:
        label = "[bold]Новий інцидент[/bold]" if kind == "new" else "[bold yellow]Ескалація[/bold yellow]"
        console.print(f"\n[dim]{clock()}[/dim] {label} #{n}: {severity_markup(incident['severity'])} "
                      f"{incident['rule']} з {incident['source_ip']}, подій {incident['event_count']}, "
                      f"початок {short_time(incident['first_seen'])}")

        analysis = None
        if self.provider is not None:
            if self.args.max_ai is not None and self.ai_done >= self.args.max_ai:
                console.print(f"[dim]--max-ai {self.args.max_ai}: ліміт AI-аналізів сесії вичерпано[/dim]")
            else:
                analysis = self.analyze(n, incident)
        if analysis is None:
            print_detector_panel(n, incident)

        if self.sent_log is not None:
            stats = notifier.notify([(incident, analysis)], self.sent_log, dry_run=self.args.dry_run,
                                    notifier=self.telegram, print_message=print_telegram_message)
            for key, value in stats.items():
                self.notify_stats[key] += value
            if stats["sent"]:
                console.print(f"[dim]{clock()}[/dim] Telegram: надіслано сповіщення про #{n}")

    def analyze(self, n: int, incident: dict) -> dict | None:
        try:
            with console.status(f"AI-аналіз інциденту #{n} ({incident['rule']})..."):
                analysis = agent.analyze_incident(incident, provider=self.provider, dry_run=self.args.dry_run,
                                                  ip_history=self.db.ip_summary(incident["source_ip"]))
        except Exception as e:
            console.print(f"[red]AI-аналіз #{n} не вдався: {type(e).__name__}: {e}[/red]")
            return None
        self.ai_done += 1
        print_analysis(n, incident, analysis)
        return analysis

    def elapsed(self) -> int:
        return int(time.monotonic() - self.started)

    def status_text(self) -> str:
        incidents = self.tracker.all()
        by_severity = {}
        for inc in incidents:
            by_severity[inc["severity"]] = by_severity.get(inc["severity"], 0) + 1
        breakdown = ", ".join(f"{sev}: {by_severity[sev]}" for sev in SEVERITY_STYLE if sev in by_severity)
        text = (f"Live {self.elapsed()} с · рядків {sum(s.lines for s in self.sources)}, "
                f"подій {sum(s.events for s in self.sources)} (у вікні {len(self.window)}) · "
                f"інцидентів {len(incidents)}" + (f" ({breakdown})" if breakdown else ""))
        if self.provider is not None:
            text += f" · AI {self.ai_done}"
        if self.sent_log is not None:
            text += (f" · Telegram dry-run {self.notify_stats['dry_run']}" if self.args.dry_run
                     else f" · Telegram {self.notify_stats['sent']}")
        return text

    def print_report(self, reason: str) -> None:
        console.print(f"\n[bold]Live зупинено ({reason})[/bold] через {self.elapsed()} с")
        print_files([s.stats() for s in self.sources])
        incidents = self.tracker.all()
        print_incidents(incidents)
        if self.provider is not None:
            console.print(f"AI-агент проаналізував {self.ai_done} раз(и), інцидентів {len(incidents)}"
                          + (" [dim](dry-run)[/dim]" if self.args.dry_run else ""))
        if self.sent_log is not None:
            s = self.notify_stats
            parts = [f"dry-run, надруковано {s['dry_run']}" if self.args.dry_run else f"надіслано {s['sent']}"]
            if s["duplicate"]:
                parts.append(f"вже надсилались раніше {s['duplicate']}")
            if s["failed"]:
                parts.append(f"[yellow]не вдалося {s['failed']}[/yellow]")
            console.print(f"Telegram-сповіщення: {', '.join(parts)}")
        print_summary(sum(s.events for s in self.sources), incidents)


def run_live(args: argparse.Namespace, sleep: Callable[[float], None] = time.sleep) -> int:
    with history.History(args.history_db) as db:
        session = LiveSession(args, db)
        modes = [f"вікно детектора {int(live.WINDOW.total_seconds() // 60)} хв", f"історія {args.history_db}"]
        if session.provider is not None:
            modes.append("AI" + (" (dry-run)" if args.dry_run else ""))
        if args.notify:
            modes.append("Telegram" + (" (dry-run)" if args.dry_run else ""))
        console.print(f"[bold]SIEM-lite live[/bold]: {', '.join(modes)}")
        for source in session.sources:
            state = (f"формат {source.format or '?'}, з кінця файлу ({source.tail.pos} байт)"
                     if source.path.is_file() else "файлу ще немає, чекаю на нього")
            console.print(f"  стежу: {source.path} ({state})")
        console.print("[dim]Ctrl+C: зупинити з підсумком[/dim]")

        reason = "Ctrl+C"
        last_status = time.monotonic()
        try:
            with console.status(session.status_text()) as status:
                while args.duration is None or time.monotonic() - session.started < args.duration:
                    session.poll()
                    status.update(session.status_text())
                    # У файл spinner не пишеться, тому статус — окремим рядком час від часу
                    if not console.is_terminal and time.monotonic() - last_status >= LIVE_STATUS_EVERY:
                        console.print(f"[dim]{clock()} {escape(session.status_text())}[/dim]")
                        last_status = time.monotonic()
                    sleep(args.poll)
                reason = f"--duration {args.duration:g} с"
        except KeyboardInterrupt:
            pass
        session.print_report(reason)
    return 0


def positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("має бути цілим числом >= 1")
    return n


def positive_float(value: str) -> float:
    x = float(value)
    if x <= 0:
        raise argparse.ArgumentTypeError("має бути числом > 0")
    return x


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SIEM-lite: аналіз логів безпеки")
    modes = parser.add_subparsers(dest="mode", required=True)

    # Спільні прапорці batch і live
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("logs", nargs="+", type=Path, help="шляхи до лог-файлів (auth.log, access.log, ...)")
    common.add_argument("--year", type=int, default=None,
                        help="рік для syslog-логів без року (за замовчуванням — поточний)")
    common.add_argument("--history-db", type=Path, default=history.DEFAULT_DB,
                        help="SQLite-база історії по IP (за замовчуванням history.db)")
    common.add_argument("--ai", action="store_true", help="проаналізувати інциденти AI-агентом")
    common.add_argument("--dry-run", action="store_true",
                        help="без реальних API-викликів: AI-агент з тестовою відповіддю (вмикає --ai), "
                             "сповіщення друкуються в консоль замість Telegram")
    common.add_argument("--notify", action="store_true",
                        help=f"надіслати в Telegram інциденти з severity {notifier.NOTIFY_MIN_SEVERITY} і вище")

    batch = modes.add_parser("batch", parents=[common], help="одноразовий прогін готових лог-файлів")
    batch.add_argument("--rule", action="append", choices=[r.__name__ for r in detector.RULES],
                       help="показувати лише інциденти цього правила (можна кілька разів)")
    batch.add_argument("--ip", action="append", metavar="IP",
                       help="показувати лише інциденти з цього IP (можна кілька разів)")
    batch.add_argument("--max-ai", type=positive_int, default=None, metavar="N",
                       help="AI-агент аналізує лише N найсерйозніших інцидентів (ліміт безкоштовного API)")
    batch.set_defaults(func=run_batch)

    live_mode = modes.add_parser("live", parents=[common],
                                 help="стежити за лог-файлами в реальному часі (як tail -f)")
    live_mode.add_argument("--max-ai", type=positive_int, default=None, metavar="N",
                           help="не більше N AI-аналізів за сесію (ліміт безкоштовного API)")
    live_mode.add_argument("--poll", type=positive_float, default=LIVE_POLL_SECONDS, metavar="SEC",
                           help=f"як часто перевіряти файли, секунд (за замовчуванням {LIVE_POLL_SECONDS})")
    live_mode.add_argument("--duration", type=positive_float, default=None, metavar="SEC",
                           help="зупинитися через SEC секунд (для тестів; інакше — до Ctrl+C)")
    live_mode.set_defaults(func=run_live)
    return parser


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    # Попередження агента (повтори після 429 тощо) — у ту саму консоль
    logging.basicConfig(level=logging.WARNING, format="%(message)s",
                        handlers=[RichHandler(console=console, show_path=False)])
    args = build_arg_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

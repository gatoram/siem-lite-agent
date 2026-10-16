"""Точка входу SIEM-lite.

Режими:
  batch — одноразовий прогін готових лог-файлів (для тестування й демо)
  live  — стеження за логами в реальному часі (буде додано пізніше)

Приклад:
  py -3 main.py batch sample_logs/auth.log sample_logs/access.log
  py -3 main.py batch sample_logs/*.log --ai              # + аналіз AI-агентом
  py -3 main.py batch sample_logs/*.log --ai --dry-run    # без реальних API-викликів
  py -3 main.py batch sample_logs/*.log --ai --rule brute_force

Усі події пишуться в history.db (історія по IP); агент отримує зведення по IP
разом з інцидентом.

Формат кожного файлу (ssh / web) визначається автоматично за першими
рядками, тому порядок аргументів не важливий.
"""

import argparse
import json
import logging
import sys
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
from parsers import ssh_parser, web_parser

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


def print_summary(events: list[dict], incidents: list[dict]) -> None:
    by_severity = {}
    for inc in incidents:
        by_severity[inc["severity"]] = by_severity.get(inc["severity"], 0) + 1
    breakdown = ", ".join(
        f"[{SEVERITY_STYLE.get(sev, '')}]{sev}: {count}[/]"
        for sev, count in sorted(by_severity.items(), key=lambda kv: list(SEVERITY_STYLE).index(kv[0]))
    )
    console.print(
        f"\n[bold]Підсумок:[/bold] оброблено подій: [bold]{len(events)}[/bold], "
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


def run_ai(incidents: list[dict], dry_run: bool, db: history.History) -> list[dict]:
    """Проганяє інциденти через агента (+ історія IP); помилка на одному інциденті не зупиняє решту."""
    try:
        provider = agent.get_provider(dry_run)
    except Exception as e:
        console.print(f"[red]AI-агент недоступний: {e}[/red]")
        return []

    analyses = []
    for n, incident in enumerate(incidents, 1):
        with console.status(f"AI-аналіз інциденту #{n} ({incident['rule']})..."):
            try:
                analysis = agent.analyze_incident(incident, provider=provider, dry_run=dry_run,
                                                  ip_history=db.ip_summary(incident["source_ip"]))
            except Exception as e:
                console.print(f"[red]AI-аналіз #{n} не вдався: {type(e).__name__}: {e}[/red]")
                continue
        print_analysis(n, incident, analysis)
        analyses.append(analysis)
    return analyses


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

    print_files(stats)
    with history.History(args.history_db) as db:
        added = db.store_events(events)
        console.print(f"Історія IP ({args.history_db}): нових подій {added}, "
                      f"вже були в базі {len(events) - added}")
        console.print()
        print_incidents(incidents)

        if args.ai or args.dry_run:
            console.print()
            analyses = run_ai(incidents, dry_run=args.dry_run, db=db)
            console.print(f"\nAI-агент проаналізував {len(analyses)} з {len(incidents)} інцидентів"
                          + (" [dim](dry-run)[/dim]" if args.dry_run else ""))

    print_summary(events, incidents)
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SIEM-lite: аналіз логів безпеки")
    modes = parser.add_subparsers(dest="mode", required=True)

    batch = modes.add_parser("batch", help="одноразовий прогін готових лог-файлів")
    batch.add_argument("logs", nargs="+", type=Path, help="шляхи до лог-файлів (auth.log, access.log, ...)")
    batch.add_argument("--year", type=int, default=None,
                       help="рік для syslog-логів без року (за замовчуванням — поточний)")
    batch.add_argument("--rule", action="append", choices=[r.__name__ for r in detector.RULES],
                       help="показувати лише інциденти цього правила (можна кілька разів)")
    batch.add_argument("--history-db", type=Path, default=history.DEFAULT_DB,
                       help="SQLite-база історії по IP (за замовчуванням history.db)")
    batch.add_argument("--ai", action="store_true", help="проаналізувати інциденти AI-агентом")
    batch.add_argument("--dry-run", action="store_true",
                       help="AI-агент без реальних API-викликів, з тестовою відповіддю (вмикає --ai)")
    batch.set_defaults(func=run_batch)
    return parser


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    # Попередження агента (повтори після 429 тощо) — у ту саму консоль
    logging.basicConfig(level=logging.WARNING, format="%(message)s",
                        handlers=[RichHandler(console=console, show_path=False)])
    args = build_arg_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

"""Сповіщення в Telegram (компонент 6).

Для інцидентів із severity не нижче NOTIFY_MIN_SEVERITY надсилається коротке
повідомлення через Telegram Bot API (`sendMessage`). Якщо інцидент
проаналізував AI-агент, у повідомленні його висновок (severity, тип загрози,
пояснення, рекомендація); якщо ні — дані детектора.

Дублікати не надсилаються: інцидент ідентифікується за (IP, правило, час
першої події) і після успішної відправки записується в таблицю `notifications`
тієї ж SQLite-бази, що й історія IP, — тому повторний запуск його не повторить.
Виняток — ескалація: якщо той самий інцидент згодом отримав вищу severity
(у live-режимі brute-force спершу High, а після успішного входу — Critical),
сповіщення надсилається ще раз з новою severity.

Ключі з .env: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID.

Режим dry-run друкує повідомлення в консоль замість відправки і нічого не
позначає як надіслане. Якщо Telegram недоступний, програма не падає: пише
попередження, а інцидент лишається ненадісланим (спробує наступного запуску).
"""

import html
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Callable

import requests
from dotenv import load_dotenv

from agent import SEVERITIES

log = logging.getLogger("notifier")

# Мінімальна severity, для якої надсилається сповіщення (High і Critical)
NOTIFY_MIN_SEVERITY = "High"

TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"
HTTP_TIMEOUT = 15  # секунд
MAX_TEXT_LEN = 500  # обрізаємо довгі пояснення агента, щоб повідомлення читалося з телефона

SEVERITY_EMOJI = {
    "Critical": "🚨",
    "High": "🔴",
    "Medium": "🟠",
    "Low": "🟢",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS notifications (
    source_ip   TEXT NOT NULL,
    rule        TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    sent_at     TEXT NOT NULL,
    PRIMARY KEY (source_ip, rule, first_seen)
);
"""


def should_notify(severity: str) -> bool:
    return severity in SEVERITIES and SEVERITIES.index(severity) >= SEVERITIES.index(NOTIFY_MIN_SEVERITY)


def incident_key(incident: dict) -> tuple[str, str, str]:
    """Ідентичність інциденту для дедуплікації: IP + правило + час першої події."""
    return incident["source_ip"], incident["rule"], incident["first_seen"]


def _shorten(text: str, limit: int = MAX_TEXT_LEN) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _time_range(first: str, last: str) -> str:
    first, last = first.replace("T", " "), last.replace("T", " ")
    if first == last:
        return first
    # Той самий день — другу дату не повторюємо
    return f"{first} → {last[11:]}" if first[:10] == last[:10] else f"{first} → {last}"


def _detector_details(details: dict) -> str:
    parts = []
    for key, value in details.items():
        if isinstance(value, list):
            value = ", ".join(map(str, value))
        parts.append(f"{key}: {value}")
    return "; ".join(parts)


def format_message(incident: dict, analysis: dict | None = None) -> str:
    """Текст повідомлення (Telegram HTML). analysis — результат agent.analyze_incident або None."""
    e = html.escape
    severity = analysis["severity"] if analysis else incident["severity"]
    emoji = SEVERITY_EMOJI.get(severity, "⚠️")

    lines = [
        f"{emoji} <b>{e(severity.upper())}</b> · {e(incident['rule'])}",
        f"🌐 IP: <code>{e(incident['source_ip'])}</code>",
        f"📊 Подій: {incident['event_count']}",
        f"🕒 {e(_time_range(incident['first_seen'], incident['last_seen']))}",
        "",
    ]
    if analysis:
        lines += [
            f"<b>Загроза:</b> {e(analysis['threat_type'])}",
            f"<b>Пояснення:</b> {e(_shorten(analysis['explanation']))}",
            f"<b>Рекомендація:</b> {e(_shorten(analysis['recommendation']))}",
            "",
            f"<i>🤖 AI-аналіз: {e(analysis['provider'])}/{e(analysis['model'])}</i>",
        ]
    else:
        lines += [
            f"<b>Деталі:</b> {e(_shorten(_detector_details(incident['details'])))}",
            "",
            "<i>📋 Дані детектора (без AI-аналізу)</i>",
        ]
    return "\n".join(lines)


class SentLog:
    """Які інциденти вже надіслані (таблиця notifications у базі історії)."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(SCHEMA)

    def was_sent(self, incident: dict, severity: str | None = None) -> bool:
        """Чи надсилався інцидент; з severity — чи надсилався з такою або вищою severity."""
        row = self.conn.execute(
            "SELECT severity FROM notifications WHERE source_ip = ? AND rule = ? AND first_seen = ?",
            incident_key(incident)).fetchone()
        if row is None or severity is None:
            return row is not None
        return row[0] in SEVERITIES and SEVERITIES.index(row[0]) >= SEVERITIES.index(severity)

    def mark_sent(self, incident: dict, severity: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO notifications (source_ip, rule, first_seen, severity, sent_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (*incident_key(incident), severity, datetime.now(timezone.utc).isoformat(timespec="seconds")))
        self.conn.commit()


class TelegramNotifier:
    def __init__(self, token: str | None = None, chat_id: str | None = None):
        load_dotenv()
        self.token = (token or os.environ.get("TELEGRAM_BOT_TOKEN", "")).strip()
        self.chat_id = (chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")).strip()

    @property
    def configured(self) -> bool:
        return bool(self.token and self.chat_id)

    def _hide_token(self, text: str) -> str:
        # Помилки requests містять URL, а в ньому — токен бота
        return text.replace(self.token, "***") if self.token else text

    def send(self, text: str) -> bool:
        """Надсилає повідомлення. Помилки не прокидаються: попередження в лог і False."""
        if not self.configured:
            log.warning("Telegram: не задано TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID у .env — сповіщення не надіслано")
            return False
        try:
            response = requests.post(
                TELEGRAM_API_URL.format(token=self.token),
                json={"chat_id": self.chat_id, "text": text, "parse_mode": "HTML",
                      "disable_web_page_preview": True},
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as error:
            log.warning("Telegram недоступний: %s: %s", type(error).__name__, self._hide_token(str(error)))
            return False
        if not response.ok:
            try:
                description = response.json().get("description", "")
            except ValueError:
                description = response.text[:200]
            log.warning("Telegram відхилив повідомлення: HTTP %s %s", response.status_code,
                        self._hide_token(description))
            return False
        return True


def notify(incidents: list[tuple[dict, dict | None]], sent_log: SentLog, dry_run: bool = False,
           notifier: TelegramNotifier | None = None,
           print_message: Callable[[str], None] = print) -> dict[str, int]:
    """Надсилає сповіщення для пар (інцидент, AI-аналіз або None).

    Severity береться з AI-аналізу, якщо він є (агент не опускає її нижче
    детектора), інакше — від детектора. Повертає лічильники:
    sent / dry_run / duplicate / failed / below_threshold.
    """
    stats = dict.fromkeys(["sent", "dry_run", "duplicate", "failed", "below_threshold"], 0)
    if not dry_run:
        notifier = notifier or TelegramNotifier()
    for incident, analysis in incidents:
        severity = analysis["severity"] if analysis else incident["severity"]
        if not should_notify(severity):
            stats["below_threshold"] += 1
            continue
        if sent_log.was_sent(incident, severity):
            stats["duplicate"] += 1
            continue
        text = format_message(incident, analysis)
        if dry_run:
            print_message(text)
            stats["dry_run"] += 1
        elif notifier.send(text):
            sent_log.mark_sent(incident, severity)
            stats["sent"] += 1
        else:
            stats["failed"] += 1
    return stats

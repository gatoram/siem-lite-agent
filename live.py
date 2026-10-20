"""Логіка live-режиму (компонент 7): tail -f по лог-файлах, ковзне вікно подій, трекінг інцидентів.

Тут немає консольного виводу — лише стан, який main.py live оновлює в циклі:

  LogTail        — читає нові рядки файлу (як tail -f), починаючи з кінця;
                   переживає відсутній файл (чекає на нього) і обрізання/ротацію.
  LiveSource     — LogTail + парсер; формат файлу визначається за наявними
                   рядками, а для порожнього файлу — за першим розпізнаним рядком.
  EventWindow    — події за останні WINDOW: детектор щоразу працює лише по них,
                   а не по всій історії.
  IncidentTracker — який інцидент новий, а який уже відомий. Ключ — IP + правило +
                   first_seen; поки атака триває, детектор щоразу повертає той самий
                   інцидент з більшою кількістю подій, і він не вважається новим.
"""

from datetime import datetime
from pathlib import Path
from typing import Callable

import detector
from agent import SEVERITIES

# Вікно має вмістити найдовше правило: серія brute-force + час, протягом якого
# успішний вхід після неї ще вважається зламом
WINDOW = max(detector.BRUTE_FORCE_WINDOW + detector.BRUTE_FORCE_SUCCESS_WINDOW, detector.SCAN_WINDOW)
# Запобіжник пам'яті при дуже інтенсивному лозі: найстаріші події відкидаються
WINDOW_MAX_EVENTS = 20_000


class LogTail:
    """Нові рядки файлу між викликами read_lines(). Незавершений рядок чекає на свій \\n."""

    def __init__(self, path: Path, from_end: bool = True):
        self.path = path
        try:
            # Файлу ще немає — все, що в ньому з'явиться, нове
            self.pos = path.stat().st_size if from_end else 0
        except FileNotFoundError:
            self.pos = 0
        self._partial = b""

    def read_lines(self) -> list[str]:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            self.pos, self._partial = 0, b""
            return []
        if size < self.pos:  # файл обрізали або підмінили (ротація) — читаємо спочатку
            self.pos, self._partial = 0, b""
        if size == self.pos:
            return []
        with open(self.path, "rb") as f:
            f.seek(self.pos)
            data = f.read()
            self.pos = f.tell()
        *lines, self._partial = (self._partial + data).split(b"\n")
        return [text for line in lines if (text := line.decode("utf-8", errors="replace").rstrip("\r")).strip()]


class LiveSource:
    """Один лог-файл: нові рядки → події в уніфікованому форматі."""

    def __init__(self, path: Path, parsers: dict[str, Callable[[str], dict | None]],
                 detect_format: Callable[[Path, dict], str | None], from_end: bool = True):
        self.path = path
        self.parsers = parsers
        self.format = detect_format(path, parsers) if path.is_file() else None
        self.tail = LogTail(path, from_end)
        self.lines = self.events = 0

    def poll(self) -> list[dict]:
        events = []
        for line in self.tail.read_lines():
            self.lines += 1
            if (event := self._parse(line)) is not None:
                events.append(event)
        self.events += len(events)
        return events

    def _parse(self, line: str) -> dict | None:
        if self.format is not None:
            return self.parsers[self.format](line)
        for name, parse in self.parsers.items():
            if (event := parse(line)) is not None:
                self.format = name
                return event
        return None

    def stats(self) -> dict:
        return {"path": self.path, "format": self.format or "?", "lines": self.lines, "events": self.events}


class EventWindow:
    """Події за останні WINDOW.

    Межа вікна рахується від найновішої події окремо для кожного джерела
    (ssh / web / firewall): SSH- і firewall-логи (syslog) пишуть місцевий час,
    а web-парсер переводить у UTC, тож порівнювати час між джерелами не можна.
    """

    def __init__(self, span=WINDOW, max_events: int = WINDOW_MAX_EVENTS):
        self.span, self.max_events = span, max_events
        self.events: list[dict] = []
        self._latest: dict[str, datetime] = {}

    def add(self, events: list[dict]) -> None:
        for event in events:
            ts = datetime.fromisoformat(event["timestamp"])
            source = event["log_source"]
            if source not in self._latest or ts > self._latest[source]:
                self._latest[source] = ts
        self.events += events
        self.events = [e for e in self.events
                       if datetime.fromisoformat(e["timestamp"]) >= self._latest[e["log_source"]] - self.span]
        del self.events[:-self.max_events]

    def __len__(self) -> int:
        return len(self.events)


def _rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else -1


class IncidentTracker:
    """Відомі інциденти live-сесії, щоб реагувати (AI, Telegram) лише на нові.

    update() повертає пари (номер, інцидент, "new" | "escalated"):
      new       — такого IP + правило + first_seen ще не було;
      escalated — відомий інцидент, але severity детектора зросла
                  (brute-force High → Critical після успішного входу).
    Інцидент, що лише виріс у кількості подій, нічого не повертає.

    Якщо атака триває довше за вікно, її перші події випадають з нього і
    first_seen зсувається. Тому інцидент того ж IP і правила, що починається
    до кінця вже відомого, вважається тим самим: йому повертається початковий
    first_seen (на ньому тримається й дедуплікація Telegram).
    """

    def __init__(self):
        self.incidents: dict[tuple[str, str, str], dict] = {}  # ключ → остання версія інциденту
        self.numbers: dict[tuple[str, str, str], int] = {}

    def _known_key(self, incident: dict) -> tuple[str, str, str] | None:
        ip, rule, first_seen = incident["source_ip"], incident["rule"], incident["first_seen"]
        if (ip, rule, first_seen) in self.incidents:
            return ip, rule, first_seen
        for key, known in self.incidents.items():
            if key[:2] == (ip, rule) and known["first_seen"] <= first_seen <= known["last_seen"]:
                return key
        return None

    def update(self, incidents: list[dict]) -> list[tuple[int, dict, str]]:
        changes = []
        for incident in incidents:
            key = self._known_key(incident)
            if key is None:
                key = (incident["source_ip"], incident["rule"], incident["first_seen"])
                self.numbers[key] = len(self.numbers) + 1
                self.incidents[key] = incident
                changes.append((self.numbers[key], incident, "new"))
                continue
            known = self.incidents[key]
            escalated = _rank(incident["severity"]) > _rank(known["severity"])
            # Події, що випали з вікна, не зменшують ні кількість, ні severity відомого інциденту
            incident = {**incident, "first_seen": key[2],
                        "event_count": max(incident["event_count"], known["event_count"])}
            if not escalated:
                incident["severity"] = known["severity"]
            self.incidents[key] = incident
            if escalated:
                changes.append((self.numbers[key], incident, "escalated"))
        return changes

    def all(self) -> list[dict]:
        """Усі інциденти сесії (остання версія кожного) у порядку виявлення."""
        return [self.incidents[key] for key in sorted(self.numbers, key=self.numbers.get)]

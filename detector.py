"""Rule-based детектор: перший фільтр перед AI-агентом.

Кожне правило — окрема функція `rule(events) -> list[incident]`, яка
працює з подіями в уніфікованому форматі (див. PROJECT_BRIEF.md) і не
залежить від того, з якого лог-файлу вони прийшли. Щоб додати правило,
напиши функцію і додай її в RULES.

Інцидент:
  {
    "rule": "brute_force",
    "source_ip": "203.0.113.45",
    "first_seen": "2026-09-30T03:22:03",
    "last_seen": "2026-09-30T03:23:58",
    "event_count": 30,
    "severity": "High",          # попередня оцінка правила; остаточну дає агент
    "details": {...},            # специфічні для правила дані
    "examples": [event, ...],    # кілька подій для контексту
  }
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable

# ------------------------------------------------------------------ пороги

BRUTE_FORCE_MIN_FAILS = 10
BRUTE_FORCE_WINDOW = timedelta(minutes=5)

SCAN_MIN_UNIQUE_PATHS = 15
SCAN_WINDOW = timedelta(minutes=5)
SCAN_ERROR_STATUSES = {403, 404}
SCAN_MIN_ERROR_RATIO = 0.5  # "більшість" відповідей — 403/404

MAX_EXAMPLES = 3

SEVERITY = {
    "brute_force": "High",
    "path_scanning": "Medium",
    "sqli": "High",
    "xss": "Medium",
}

# Патерни шукаються в декодованому URL (meta["url"]), без урахування регістру
SQLI_PATTERNS = {
    "or_tautology": r"'\s*or\s+'?\w+'?\s*=\s*'?\w+",   # ' OR '1'='1, ' or 1=1
    "numeric_tautology": r"\bor\s+\d+\s*=\s*\d+",      # id=1 OR 1=1
    "union_select": r"\bunion(\s+all)?\s+select\b",
    "quote_comment": r"'\s*(--|#|/\*)",                # закриття рядка + коментар
    "trailing_comment": r"--\s*$",
    "time_based": r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(",
    "stacked_query": r";\s*(drop|delete|insert|update|exec)\s",
    "schema_probe": r"\b(information_schema|xp_cmdshell)\b",
}
XSS_PATTERNS = {
    "script_tag": r"<\s*script",
    "javascript_uri": r"javascript\s*:",
    "event_handler": r"\bon(error|load|mouseover|focus)\s*=",
}

_SQLI_RE = {name: re.compile(p, re.IGNORECASE) for name, p in SQLI_PATTERNS.items()}
_XSS_RE = {name: re.compile(p, re.IGNORECASE) for name, p in XSS_PATTERNS.items()}


# ---------------------------------------------------------- допоміжні функції

def _ts(event: dict) -> datetime:
    return datetime.fromisoformat(event["timestamp"])


def _group_by_ip(events: list[dict]) -> dict[str, list[dict]]:
    groups = defaultdict(list)
    for event in events:
        groups[event["source_ip"]].append(event)
    for ip_events in groups.values():
        ip_events.sort(key=_ts)
    return groups


def _find_bursts(events: list[dict], window: timedelta,
                 is_suspicious: Callable[[list[dict]], bool]) -> list[list[dict]]:
    """Ковзне вікно по відсортованих подіях одного IP.

    Позначає всі події, що потрапили хоча б в одне "підозріле" вікно, і
    склеює їх у сплески (сусідні позначені події з проміжком <= window).
    Так 30 спроб brute-force дають один інцидент, а не 21 вікно.
    """
    marked = [False] * len(events)
    left = 0
    for right in range(len(events)):
        while _ts(events[right]) - _ts(events[left]) > window:
            left += 1
        if is_suspicious(events[left:right + 1]):
            for i in range(left, right + 1):
                marked[i] = True

    bursts: list[list[dict]] = []
    for event, is_marked in zip(events, marked):
        if not is_marked:
            continue
        if bursts and _ts(event) - _ts(bursts[-1][-1]) <= window:
            bursts[-1].append(event)
        else:
            bursts.append([event])
    return bursts


def _make_incident(rule: str, events: list[dict], details: dict) -> dict:
    return {
        "rule": rule,
        "source_ip": events[0]["source_ip"],
        "first_seen": events[0]["timestamp"],
        "last_seen": events[-1]["timestamp"],
        "event_count": len(events),
        "severity": SEVERITY[rule],
        "details": details,
        "examples": events[:MAX_EXAMPLES],
    }


def _match_patterns(text: str, patterns: dict[str, re.Pattern]) -> list[str]:
    return [name for name, regex in patterns.items() if regex.search(text)]


# ------------------------------------------------------------------ правила

def brute_force(events: list[dict]) -> list[dict]:
    """BRUTE_FORCE_MIN_FAILS+ невдалих логінів з одного IP за BRUTE_FORCE_WINDOW."""
    fails = [e for e in events if e["event_type"] == "login_fail"]
    incidents = []
    for ip_events in _group_by_ip(fails).values():
        for burst in _find_bursts(ip_events, BRUTE_FORCE_WINDOW,
                                  lambda w: len(w) >= BRUTE_FORCE_MIN_FAILS):
            users = sorted({e["meta"].get("user") for e in burst} - {None})
            incidents.append(_make_incident("brute_force", burst, {"targeted_users": users}))
    return incidents


def _is_scan_window(window: list[dict]) -> bool:
    paths = {e["meta"]["path"] for e in window}
    if len(paths) < SCAN_MIN_UNIQUE_PATHS:
        return False
    errors = sum(e["meta"]["status_code"] in SCAN_ERROR_STATUSES for e in window)
    return errors / len(window) > SCAN_MIN_ERROR_RATIO


def path_scanning(events: list[dict]) -> list[dict]:
    """SCAN_MIN_UNIQUE_PATHS+ різних шляхів з одного IP за SCAN_WINDOW, більшість — 403/404."""
    requests = [e for e in events if e["event_type"] == "http_request"]
    incidents = []
    for ip_events in _group_by_ip(requests).values():
        for burst in _find_bursts(ip_events, SCAN_WINDOW, _is_scan_window):
            errors = sum(e["meta"]["status_code"] in SCAN_ERROR_STATUSES for e in burst)
            incidents.append(_make_incident("path_scanning", burst, {
                "unique_paths": len({e["meta"]["path"] for e in burst}),
                "error_ratio": round(errors / len(burst), 2),
            }))
    return incidents


def _pattern_rule(rule: str, events: list[dict], patterns: dict[str, re.Pattern]) -> list[dict]:
    """Спільна логіка для правил-сигнатур: один інцидент на IP з усіма збігами."""
    matched_by_ip = defaultdict(list)
    names_by_ip = defaultdict(set)
    for event in events:
        if event["event_type"] != "http_request":
            continue
        names = _match_patterns(event["meta"]["url"], patterns)
        if names:
            matched_by_ip[event["source_ip"]].append(event)
            names_by_ip[event["source_ip"]].update(names)

    incidents = []
    for ip, ip_events in matched_by_ip.items():
        ip_events.sort(key=_ts)
        incidents.append(_make_incident(rule, ip_events, {"matched_patterns": sorted(names_by_ip[ip])}))
    return incidents


def sqli(events: list[dict]) -> list[dict]:
    """SQL-ін'єкції в декодованому URL."""
    return _pattern_rule("sqli", events, _SQLI_RE)


def xss(events: list[dict]) -> list[dict]:
    """XSS-пейлоади в декодованому URL."""
    return _pattern_rule("xss", events, _XSS_RE)


RULES = [brute_force, path_scanning, sqli, xss]


def detect(events: list[dict]) -> list[dict]:
    """Проганяє всі правила; інциденти відсортовані за first_seen."""
    incidents = [incident for rule in RULES for incident in rule(events)]
    return sorted(incidents, key=lambda i: i["first_seen"])

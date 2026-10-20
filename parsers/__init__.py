"""Парсери логів у уніфікований формат події (див. PROJECT_BRIEF.md).

Кожен парсер має однаковий інтерфейс:
  parse_line(line) -> dict | None   — одна подія або None, якщо рядок не розпізнано
  parse_file(path) -> list[dict]    — усі розпізнані події з файлу
"""

from parsers import firewall_parser, ssh_parser, web_parser

__all__ = ["firewall_parser", "ssh_parser", "web_parser"]

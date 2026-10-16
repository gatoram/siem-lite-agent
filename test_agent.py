"""Офлайн-тест AI-агента (без реальних API-викликів).

Запуск: py -3 test_agent.py

Перевіряє: dry-run на інцидентах із sample_logs (з історією IP), повтор
після 429/503, розбір JSON-відповіді моделі, цикл tool use через фейкового
провайдера і те, що агент не може поставити severity нижче за детектор.
"""

import json
import sys
from pathlib import Path

import requests

import agent
import detector
import history
from parsers import ssh_parser, web_parser

LOGS_DIR = Path(__file__).parent / "sample_logs"


def load_events() -> list[dict]:
    return (ssh_parser.parse_file(LOGS_DIR / "auth.log", year=2026)
            + web_parser.parse_file(LOGS_DIR / "access.log"))


class FixedProvider(agent.LLMProvider):
    """Фейковий провайдер, що завжди повертає задану severity без виклику інструментів."""

    name = model = "fixed"

    def __init__(self, severity: str):
        self.severity = severity

    def run(self, system_prompt, user_prompt, tools, trace):
        return json.dumps({"threat_type": "X", "severity": self.severity, "explanation": "e", "recommendation": "r"})


class ScriptedProvider(agent.LLMProvider):
    """Фейковий провайдер: спершу викликає інструмент, потім повертає відповідь у ```json."""

    name = model = "scripted"

    def run(self, system_prompt, user_prompt, tools, trace):
        self.call_tool(tools, "check_ip_reputation", {"ip": "203.0.113.45"}, trace)
        self.call_tool(tools, "no_such_tool", {}, trace)
        return '```json\n{"threat_type": "X", "severity": "critical", "explanation": "e", "recommendation": "r"}\n```'


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")

    # Будь-який мережевий запит у dry-run — помилка тесту
    def no_network(*args, **kwargs):
        raise AssertionError("dry-run не має ходити в мережу")
    requests.get = requests.post = no_network

    # --- dry-run на всіх інцидентах, з історією IP ---
    events = load_events()
    incidents = detector.detect(events)
    db = history.History(":memory:")
    db.store_events(events)
    results = {}
    for incident in incidents:
        result = agent.analyze_incident(incident, dry_run=True, ip_history=db.ip_summary(incident["source_ip"]))
        results[(incident["rule"], incident["source_ip"])] = result
        assert result["ip_history"]["ip"] == incident["source_ip"]
        assert set(result) >= {"threat_type", "severity", "explanation", "recommendation", "tool_calls"}
        assert result["severity"] in agent.SEVERITIES
        assert result["dry_run"] and result["provider"] == "dry-run"
        assert result["tool_calls"][0]["name"] == "check_ip_reputation"
        assert result["tool_calls"][0]["args"] == {"ip": incident["source_ip"]}
    print("dry-run, приклад відповіді:")
    print(json.dumps(result, ensure_ascii=False, indent=2))

    # Два brute-force: без успіху — High, з успішним входом — Critical
    assert results[("brute_force", "203.0.113.45")]["severity"] == "High"
    assert results[("brute_force", "203.0.113.77")]["severity"] == "Critical"

    # В історію IP і в промпт потрапляє ознака успішного brute-force
    prompt = agent.build_user_prompt(incidents[0], db.ip_summary("203.0.113.77"))
    assert '"success_after_failures": true' in prompt

    # --- severity не нижче за детектор ---
    plain_bf = next(i for i in incidents if i["source_ip"] == "203.0.113.45")
    lowered = agent.analyze_incident(plain_bf, provider=FixedProvider("Medium"), dry_run=True)
    assert lowered["severity"] == "High" and lowered["model_severity"] == "Medium"
    assert lowered["severity_note"] and "Medium" in lowered["severity_note"]
    raised = agent.analyze_incident(plain_bf, provider=FixedProvider("Critical"), dry_run=True)
    assert raised["severity"] == "Critical" and raised["severity_note"] is None

    # --- повтор після 429 / 503 ---
    sleeps = []
    attempts = iter([agent.RetryableError("ліміт", 429, retry_after=17),
                     agent.RetryableError("перевантаження", 503), "ok"])

    def flaky():
        value = next(attempts)
        if isinstance(value, Exception):
            raise value
        return value

    assert agent.with_retry(flaky, "test", sleep=sleeps.append) == "ok"
    assert sleeps == [17, agent.RETRY_BASE_DELAY * 2], sleeps  # підказка сервера, потім backoff

    # Після MAX_RETRIES повторів помилка все ж прокидається
    sleeps.clear()
    def always_429():
        raise agent.RetryableError("ліміт", 429)
    try:
        agent.with_retry(always_429, "test", sleep=sleeps.append)
        raise AssertionError("мав прокинути RetryableError")
    except agent.RetryableError:
        pass
    assert len(sleeps) == agent.MAX_RETRIES
    assert max(sleeps) <= agent.RETRY_MAX_DELAY

    assert agent._parse_seconds("17s") == 17 and agent._parse_seconds("2.5s") == 2.5
    assert agent._parse_seconds(None) is None

    # --- цикл tool use + розбір JSON у ```json і нормалізація severity ---
    result = agent.analyze_incident(incidents[0], provider=ScriptedProvider(), dry_run=True)
    assert result["severity"] == "Critical"
    assert [c["name"] for c in result["tool_calls"]] == ["check_ip_reputation", "no_such_tool"]
    assert "error" in result["tool_calls"][1]["result"]

    # Некоректна severity → беремо від детектора
    verdict = agent.parse_verdict('{"severity": "Катастрофа"}', fallback_severity="High")
    assert verdict["severity"] == "High"

    print("\nУсі перевірки пройдено.")


if __name__ == "__main__":
    main()

"""AI-агент-аналітик (компонент 4): аналізує інцидент від детектора.

Агент отримує інцидент і має інструмент `check_ip_reputation` (AbuseIPDB).
Чи викликати інструмент, вирішує сама модель. На виході JSON:
  {"threat_type", "severity", "explanation", "recommendation"}
+ службові поля: "tool_calls" (ланцюжок викликів), "provider", "model", "dry_run".

LLM-провайдер змінний: усі провайдери реалізують інтерфейс `LLMProvider`.
Вибір через LLM_PROVIDER у .env (поки є лише "gemini"). Щоб додати Ollama,
треба написати клас з методом `run()` і додати його в PROVIDERS.

Режим dry-run (`analyze_incident(..., dry_run=True)`) не робить жодних
мережевих викликів: замість LLM працює DryRunProvider, а замість AbuseIPDB
повертаються фіктивні дані.

Помилки ліміту (429) і тимчасової недоступності (500/503) не валять
програму: виклик повторюється з паузою (див. `with_retry`).
"""

import json
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable

import requests
from dotenv import load_dotenv

log = logging.getLogger("agent")

# ------------------------------------------------------------------ налаштування

# Актуальна Flash-модель, доступна на безкоштовному тарифі Gemini API
GEMINI_MODEL = "gemini-3.8-flash"

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS = 90
HTTP_TIMEOUT = 20  # секунд

MAX_RETRIES = 4            # повторів після першої невдалої спроби
RETRY_BASE_DELAY = 5.0     # секунд; далі подвоюється: 5, 10, 20, 40
RETRY_MAX_DELAY = 60.0
RETRYABLE_STATUS = {429, 500, 502, 503, 504}

MAX_TOOL_ROUNDS = 3        # скільки разів поспіль модель може викликати інструменти

SEVERITIES = ["Low", "Medium", "High", "Critical"]

# Поля відповіді AbuseIPDB, які передаються моделі (решта — шум)
ABUSEIPDB_FIELDS = [
    "ipAddress", "isPublic", "isWhitelisted", "abuseConfidenceScore", "countryCode",
    "usageType", "isp", "domain", "isTor", "totalReports", "numDistinctUsers", "lastReportedAt",
]

SYSTEM_PROMPT = """\
Ти — досвідчений SOC-аналітик. Тобі надходить інцидент від rule-based детектора
SIEM-системи: правило, що спрацювало, IP джерела, час, кількість подій,
деталі та кілька прикладів сирих рядків логу.

Оціни інцидент: що це за загроза, наскільки вона серйозна і що робити.
У тебе є інструмент check_ip_reputation (AbuseIPDB). Викликай його, коли
репутація IP може вплинути на оцінку; не викликай без потреби. Зважай, що для
приватних і зарезервованих адрес AbuseIPDB даних про зловживання не має.

Severity, яку дав детектор, — лише попередня оцінка; можеш її змінити.
Шкала: Low, Medium, High, Critical.

Фінальна відповідь — ЛИШЕ JSON-об'єкт без markdown, з полями:
  "threat_type": коротка назва загрози англійською (напр. "SSH brute-force"),
  "severity": одне з Low | Medium | High | Critical,
  "explanation": 2-4 речення українською: чому такий висновок, на які факти спираєшся,
  "recommendation": 1-3 конкретні дії українською.
"""


# ------------------------------------------------------------------ повтори

class RetryableError(Exception):
    """Тимчасова помилка (ліміт / перевантаження), після якої варто повторити."""

    def __init__(self, message: str, status: int, retry_after: float | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def with_retry(func: Callable[[], Any], what: str, sleep: Callable[[float], None] = time.sleep) -> Any:
    """Викликає func(); на RetryableError чекає і повторює до MAX_RETRIES разів.

    Пауза береться з підказки сервера (Retry-After / retryDelay), а якщо її
    немає — експоненційно від RETRY_BASE_DELAY.
    """
    for attempt in range(MAX_RETRIES + 1):
        try:
            return func()
        except RetryableError as e:
            if attempt == MAX_RETRIES:
                raise
            delay = e.retry_after if e.retry_after is not None else RETRY_BASE_DELAY * 2 ** attempt
            delay = min(delay, RETRY_MAX_DELAY)
            log.warning("%s: HTTP %s, повтор %d/%d через %.0f с", what, e.status,
                        attempt + 1, MAX_RETRIES, delay)
            sleep(delay)


def _parse_seconds(value: str | None) -> float | None:
    """'17s' / '17.5s' / '17' -> 17.0"""
    if not value:
        return None
    m = re.match(r"^\s*(\d+(?:\.\d+)?)s?\s*$", str(value))
    return float(m.group(1)) if m else None


# ------------------------------------------------------------------ інструменти

@dataclass
class Tool:
    """Опис інструменту, незалежний від провайдера."""
    name: str
    description: str
    parameters: dict  # JSON Schema аргументів
    func: Callable[..., dict]


IP_REPUTATION_DESCRIPTION = (
    "Перевіряє репутацію IPv4/IPv6-адреси в AbuseIPDB: abuseConfidenceScore (0-100), "
    "кількість скарг, країну, провайдера, тип використання, чи це Tor."
)
IP_REPUTATION_PARAMS = {
    "type": "object",
    "properties": {"ip": {"type": "string", "description": "IP-адреса для перевірки"}},
    "required": ["ip"],
}


def check_ip_reputation(ip: str) -> dict:
    """Реальний запит до AbuseIPDB. Помилки повертаються як {"error": ...}, щоб агент міг їх врахувати."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY не задано"}

    def request() -> dict:
        resp = requests.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code in RETRYABLE_STATUS:
            raise RetryableError(f"AbuseIPDB {resp.status_code}", resp.status_code,
                                 _parse_seconds(resp.headers.get("Retry-After")))
        resp.raise_for_status()
        return resp.json()["data"]

    try:
        data = with_retry(request, "AbuseIPDB")
    except (requests.RequestException, RetryableError, KeyError, ValueError) as e:
        return {"error": f"AbuseIPDB недоступний: {type(e).__name__}"}
    return {k: data.get(k) for k in ABUSEIPDB_FIELDS}


def fake_ip_reputation(ip: str) -> dict:
    """Фіктивна відповідь для dry-run — без мережі."""
    return {
        "ipAddress": ip, "isPublic": True, "isWhitelisted": False, "abuseConfidenceScore": 87,
        "countryCode": "XX", "usageType": "Data Center/Web Hosting/Transit", "isp": "Dry-Run Hosting",
        "domain": "example.net", "isTor": False, "totalReports": 154, "numDistinctUsers": 41,
        "lastReportedAt": "2026-09-29T21:14:00+00:00", "dry_run": True,
    }


def make_tools(dry_run: bool) -> list[Tool]:
    return [Tool("check_ip_reputation", IP_REPUTATION_DESCRIPTION, IP_REPUTATION_PARAMS,
                 fake_ip_reputation if dry_run else check_ip_reputation)]


# ------------------------------------------------------------------ провайдери

class LLMProvider(ABC):
    """Спільний інтерфейс LLM-провайдера з підтримкою tool use."""

    name: str
    model: str

    @abstractmethod
    def run(self, system_prompt: str, user_prompt: str, tools: list[Tool], trace: list[dict]) -> str:
        """Веде діалог з моделлю, виконуючи її виклики інструментів (через `call_tool`).

        Кожен виклик інструменту додається в trace. Повертає фінальний текст моделі.
        """

    @staticmethod
    def call_tool(tools: list[Tool], name: str, args: dict, trace: list[dict]) -> dict:
        tool = next((t for t in tools if t.name == name), None)
        if tool is None:
            result = {"error": f"невідомий інструмент {name}"}
        else:
            try:
                result = tool.func(**args)
            except TypeError as e:
                result = {"error": f"некоректні аргументи: {e}"}
        trace.append({"name": name, "args": args, "result": result})
        return result


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self, model: str = GEMINI_MODEL):
        from google import genai  # імпорт тут: dry-run і тести не потребують бібліотеки

        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY не задано в .env")
        self.model = model
        self._client = genai.Client(api_key=api_key)

    def _generate(self, contents: list, config) -> Any:
        from google.genai import errors

        def request():
            try:
                return self._client.models.generate_content(model=self.model, contents=contents, config=config)
            except errors.APIError as e:
                if e.code in RETRYABLE_STATUS:
                    raise RetryableError(str(e)[:200], e.code, self._retry_delay(e)) from e
                raise

        return with_retry(request, f"Gemini {self.model}")

    @staticmethod
    def _retry_delay(error) -> float | None:
        """Gemini у відповіді 429 підказує паузу: details[].retryDelay = '17s'."""
        details = getattr(error, "details", None) or {}
        for item in (details.get("error", {}) or {}).get("details", []) or []:
            if isinstance(item, dict) and "retryDelay" in item:
                return _parse_seconds(item["retryDelay"])
        return None

    def run(self, system_prompt: str, user_prompt: str, tools: list[Tool], trace: list[dict]) -> str:
        from google.genai import types

        declarations = [types.FunctionDeclaration(name=t.name, description=t.description,
                                                  parameters_json_schema=t.parameters) for t in tools]

        def config(allow_tools: bool):
            return types.GenerateContentConfig(
                system_instruction=system_prompt,
                tools=[types.Tool(function_declarations=declarations)],
                # Цикл tool use ведемо самі, щоб бачити й логувати кожен виклик
                automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                tool_config=types.ToolConfig(function_calling_config=types.FunctionCallingConfig(
                    mode="AUTO" if allow_tools else "NONE")),
            )

        contents = [types.Content(role="user", parts=[types.Part(text=user_prompt)])]
        for round_no in range(MAX_TOOL_ROUNDS + 1):
            response = self._generate(contents, config(allow_tools=round_no < MAX_TOOL_ROUNDS))
            calls = response.function_calls or []
            if not calls:
                return response.text or ""

            # Відповідь моделі додається цілком — з thought signatures, яких вимагає Gemini 3
            contents.append(response.candidates[0].content)
            parts = [types.Part.from_function_response(
                        name=call.name, response={"result": self.call_tool(tools, call.name, dict(call.args or {}), trace)})
                     for call in calls]
            contents.append(types.Content(role="user", parts=parts))
        raise RuntimeError("модель не дала фінальної відповіді")


class DryRunProvider(LLMProvider):
    """Імітація LLM для тестів і демо: без мережі, з передбачуваною відповіддю."""

    name = "dry-run"
    model = "dry-run"

    CANNED = {
        "brute_force": ("SSH brute-force", "Заблокувати IP на firewall/fail2ban; перевірити, чи не було успішних входів з цього IP."),
        "path_scanning": ("Web path scanning", "Заблокувати IP на WAF; переконатися, що .env, .git та бекапи недоступні ззовні."),
        "sqli": ("SQL injection attempt", "Заблокувати IP; перевірити параметризацію запитів в ендпоінті та логи БД."),
        "xss": ("Reflected XSS attempt", "Заблокувати IP; перевірити екранування виводу та Content-Security-Policy."),
    }

    def run(self, system_prompt: str, user_prompt: str, tools: list[Tool], trace: list[dict]) -> str:
        incident = json.loads(user_prompt.split("\n", 1)[1])
        reputation = self.call_tool(tools, "check_ip_reputation", {"ip": incident["source_ip"]}, trace)
        threat_type, recommendation = self.CANNED.get(
            incident["rule"], ("Suspicious activity", "Перевірити активність IP вручну."))
        return json.dumps({
            "threat_type": threat_type,
            "severity": incident["severity"],
            "explanation": (f"[dry-run] Правило {incident['rule']} спрацювало на {incident['event_count']} подіях "
                            f"з {incident['source_ip']}; abuseConfidenceScore = {reputation.get('abuseConfidenceScore')}."),
            "recommendation": recommendation,
        }, ensure_ascii=False)


PROVIDERS: dict[str, Callable[[], LLMProvider]] = {
    "gemini": GeminiProvider,
    # "ollama": OllamaProvider,  — наступний кандидат
}


def get_provider(dry_run: bool = False) -> LLMProvider:
    if dry_run:
        return DryRunProvider()
    load_dotenv()
    name = os.environ.get("LLM_PROVIDER", "gemini").strip().lower()
    if name not in PROVIDERS:
        raise RuntimeError(f"Невідомий LLM_PROVIDER={name!r}; доступні: {', '.join(PROVIDERS)}")
    return PROVIDERS[name]()


# ------------------------------------------------------------------ агент

def build_user_prompt(incident: dict) -> str:
    # Перший рядок — інструкція, далі інцидент у JSON (DryRunProvider на це спирається)
    return "Проаналізуй інцидент:\n" + json.dumps(incident, ensure_ascii=False, indent=2)


def parse_verdict(text: str, fallback_severity: str) -> dict:
    """Дістає JSON з відповіді моделі (навіть якщо вона загорнула його в ```json)."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"у відповіді моделі немає JSON: {text[:200]!r}")
    data = json.loads(match.group(0))

    severity = str(data.get("severity", "")).strip().capitalize()
    if severity not in SEVERITIES:
        log.warning("Модель повернула некоректну severity %r — беру %s від детектора",
                    data.get("severity"), fallback_severity)
        severity = fallback_severity
    return {
        "threat_type": str(data.get("threat_type", "Unknown")),
        "severity": severity,
        "explanation": str(data.get("explanation", "")),
        "recommendation": str(data.get("recommendation", "")),
    }


def analyze_incident(incident: dict, provider: LLMProvider | None = None, dry_run: bool = False) -> dict:
    """Аналізує один інцидент. Повертає вердикт + ланцюжок tool calls."""
    provider = provider or get_provider(dry_run)
    trace: list[dict] = []
    text = provider.run(SYSTEM_PROMPT, build_user_prompt(incident), make_tools(dry_run), trace)
    verdict = parse_verdict(text, fallback_severity=incident["severity"])
    return {
        **verdict,
        "tool_calls": trace,
        "provider": provider.name,
        "model": provider.model,
        "dry_run": dry_run,
    }

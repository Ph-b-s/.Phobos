"""AI reasoning layer for Phobos security scanning.

The model acts as a constrained security-planning brain. It can select from
registered Phobos security modules and explain prioritization, but it cannot
change scope, execute shell commands, invent arbitrary requests, or directly
report a vulnerability without evidence from the scanners.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from security_modules import module_index

MODEL_NAME = "venice-uncensored"
DEFAULT_BASE_URL = "https://api.venice.ai/api/v1/chat/completions"
MAX_REQUEST_CHARS = 8_000
MAX_RESPONSE_BYTES = 1_000_000
MAX_REASON_CHARS = 800
MAX_MODULES = 16
SUPPORTED_ACTIONS = frozenset({"plan_scan", "refuse"})
REQUIRED_DECISION_KEYS = frozenset({"action", "modules", "reason"})


class AIError(RuntimeError):
    """Raised when the AI provider cannot be used safely."""


@dataclass(frozen=True, slots=True)
class AIConfig:
    base_url: str = DEFAULT_BASE_URL
    model: str = MODEL_NAME
    api_key: str = ""
    timeout: float = 30.0

    @classmethod
    def from_env(cls) -> "AIConfig":
        base_url = os.environ.get("PHOBOS_AI_URL", DEFAULT_BASE_URL).strip()
        model = os.environ.get("PHOBOS_AI_MODEL", MODEL_NAME).strip()
        api_key = os.environ.get("VENICE_API_KEY", "").strip()
        if not base_url.startswith("https://"):
            raise AIError("PHOBOS_AI_URL must use https")
        if not model:
            raise AIError("PHOBOS_AI_MODEL must not be empty")
        if not api_key:
            raise AIError("VENICE_API_KEY is not set")
        return cls(base_url=base_url, model=model, api_key=api_key)


_MODULE_SUMMARY = "\n".join(
    f"- {item.id}: {item.name} — {item.description}"
    for item in module_index().values()
)

SYSTEM_PROMPT = f"""You are the reasoning component of Phobos, a general web-security scanner for web applications that contain AI functionality.

Your job is to plan which existing Phobos security modules should investigate a target. The scanner is broad: it can assess normal web vulnerabilities as well as AI-specific vulnerabilities.

You may ONLY select modules from this catalog:
{_MODULE_SUMMARY}

Rules:
- The explicit target and scope are controlled by Phobos, not by you.
- Never produce shell commands, arbitrary URLs, raw request bodies, credentials, exploit scripts, or custom tool arguments.
- Do not claim that a vulnerability exists merely because a module is relevant.
- Prefer broad coverage first, then prioritize modules using discovered evidence.
- Nmap is optional supporting reconnaissance, not the core of Phobos.

Return exactly one JSON object:
{{"action":"plan_scan","modules":["web.headers"],"reason":"brief prioritization rationale"}}
"""


def _extract_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str) and content.strip():
                    return content.strip()
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    raise AIError("AI response contained no text")


def _parse_decision(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise AIError("AI returned invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != REQUIRED_DECISION_KEYS:
        raise AIError("AI decision must contain exactly action, modules, and reason")
    action = value.get("action")
    modules = value.get("modules")
    reason = value.get("reason")
    if action not in SUPPORTED_ACTIONS or not isinstance(modules, list) or not isinstance(reason, str):
        raise AIError("AI decision has invalid fields")
    if action == "refuse":
        return {"action": "refuse", "modules": [], "reason": reason[:MAX_REASON_CHARS]}
    if not modules or len(modules) > MAX_MODULES:
        raise AIError("AI selected an invalid number of modules")
    catalog = module_index()
    selected: list[str] = []
    for item in modules:
        if not isinstance(item, str) or item not in catalog:
            raise AIError(f"AI selected unsupported module: {item}")
        if item not in selected:
            selected.append(item)
    if not reason.strip():
        raise AIError("AI decision reason must not be empty")
    return {"action": action, "modules": selected, "reason": reason.strip()[:MAX_REASON_CHARS]}


class VeniceClient:
    """Minimal standard-library client for the Venice OpenAI-compatible API."""

    def __init__(self, config: AIConfig):
        if config.timeout <= 0:
            raise AIError("AI timeout must be positive")
        self.config = config

    def plan(self, context: str) -> dict[str, Any]:
        context = context.strip()
        if not context:
            raise AIError("planning context must not be empty")
        if len(context) > MAX_REQUEST_CHARS:
            raise AIError(f"planning context exceeds the {MAX_REQUEST_CHARS:,}-character limit")
        body = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": context},
            ],
            "temperature": 0.1,
            "max_tokens": 400,
            "stream": False,
        }
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = Request(
            self.config.base_url,
            data=encoded,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Phobos/0.4",
            },
        )
        try:
            with urlopen(request, timeout=self.config.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            detail = exc.read(8_192).decode("utf-8", errors="replace")
            raise AIError(f"AI provider returned HTTP {exc.code}: {detail[:500]}") from exc
        except (URLError, TimeoutError) as exc:
            raise AIError(f"AI request failed: {exc}") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise AIError("AI provider response exceeds the configured size limit")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AIError("AI provider returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise AIError("AI provider returned an invalid response")
        return _parse_decision(_extract_text(payload))

    def decide(self, request_text: str) -> dict[str, Any]:
        """Compatibility wrapper for older callers."""
        return self.plan(request_text)


OpenAIResponsesClient = VeniceClient

"""Venice AI command planner for the first Phobos agent build.

Phobos uses Venice's OpenAI-compatible API with the Dolphin Mistral 24B
Venice Edition, exposed by Venice as ``venice-uncensored``. The model never
gets shell access; it can only select the single supported reconnaissance
action.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MODEL_NAME = "venice-uncensored"
DEFAULT_BASE_URL = "https://api.venice.ai/api/v1/chat/completions"


class AIError(RuntimeError):
    """Raised when the configured AI provider cannot be used safely."""


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


SYSTEM_PROMPT = """You are the planning component of Phobos, an authorized security-testing tool.
Your ONLY supported action is a simple TCP top-ports reconnaissance scan using nmap.
You must never produce shell commands, nmap arguments, scripts, pipelines, or code.
Return exactly one JSON object and nothing else:
{"action":"nmap_top_ports","reason":"brief explanation"}
If the user request is unrelated to this action, refuse it with:
{"action":"refuse","reason":"brief explanation"}
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

    pieces: list[str] = []
    for item in payload.get("output", []) if isinstance(payload.get("output"), list) else []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []) if isinstance(item.get("content"), list) else []:
            if isinstance(content, dict) and isinstance(content.get("text"), str):
                pieces.append(content["text"])
    text = "\n".join(pieces).strip()
    if text:
        return text
    raise AIError("AI response contained no text")


def _parse_decision(text: str) -> dict[str, str]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise AIError("AI returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise AIError("AI returned an invalid decision")
    action = value.get("action")
    reason = value.get("reason", "")
    if not isinstance(action, str) or not isinstance(reason, str):
        raise AIError("AI decision has invalid fields")
    if action not in {"nmap_top_ports", "refuse"}:
        raise AIError("AI requested an unsupported action")
    return {"action": action, "reason": reason[:500]}


class VeniceClient:
    """Minimal standard-library client for the Venice OpenAI-compatible API."""

    def __init__(self, config: AIConfig):
        self.config = config

    def decide(self, request_text: str) -> dict[str, str]:
        request_text = request_text.strip()
        if not request_text:
            raise AIError("request must not be empty")
        body = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": request_text[:4000]},
            ],
            "temperature": 0.15,
            "max_tokens": 200,
            "stream": False,
        }
        encoded = json.dumps(body).encode("utf-8")
        request = Request(
            self.config.base_url,
            data=encoded,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Phobos/0.1",
            },
        )
        try:
            with urlopen(request, timeout=self.config.timeout) as response:
                raw = response.read(1_000_000)
        except HTTPError as exc:
            detail = exc.read(8_192).decode("utf-8", errors="replace")
            raise AIError(f"AI provider returned HTTP {exc.code}: {detail[:500]}") from exc
        except (URLError, TimeoutError) as exc:
            raise AIError(f"AI request failed: {exc}") from exc

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AIError("AI provider returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise AIError("AI provider returned an invalid response")
        return _parse_decision(_extract_text(payload))


# Compatibility alias for the earlier first-build API name.
OpenAIResponsesClient = VeniceClient

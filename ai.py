"""Venice AI planner for safe, web-focused Phobos actions.

The model plans only between predefined Phobos capabilities. It never receives
shell access, target selection authority, HTTP execution authority, or the
ability to provide arbitrary tool arguments.
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
MAX_REQUEST_CHARS = 4_000
MAX_RESPONSE_BYTES = 1_000_000
MAX_REASON_CHARS = 500
SUPPORTED_ACTIONS = frozenset({"web_recon", "ai_surface_discovery", "refuse"})
REQUIRED_DECISION_KEYS = frozenset({"action", "reason"})


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


SYSTEM_PROMPT = """You are the planning component of Phobos, an authorized web and AI security testing tool.
Your ONLY supported actions are:
- web_recon: scoped passive web reconnaissance of the explicit target
- ai_surface_discovery: scoped passive discovery of likely AI endpoints, agent signals, and AI inputs
- refuse: when the request is unrelated or asks for an unsupported capability
You must never produce shell commands, URLs, request bodies, credentials, exploit payloads, scripts, or tool arguments.
The target is supplied separately by Phobos and cannot be changed by you.
Return exactly one JSON object with exactly these two keys:
{"action":"web_recon","reason":"brief explanation"}
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
    output = payload.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content_items = item.get("content")
            if not isinstance(content_items, list):
                continue
            for content in content_items:
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
    if set(value) != REQUIRED_DECISION_KEYS:
        raise AIError("AI decision must contain exactly action and reason")
    action = value["action"]
    reason = value["reason"]
    if not isinstance(action, str) or not isinstance(reason, str):
        raise AIError("AI decision has invalid fields")
    action = action.strip()
    reason = reason.strip()
    if action not in SUPPORTED_ACTIONS:
        raise AIError("AI requested an unsupported action")
    if not reason:
        raise AIError("AI decision reason must not be empty")
    return {"action": action, "reason": reason[:MAX_REASON_CHARS]}


class VeniceClient:
    """Minimal standard-library client for the Venice OpenAI-compatible API."""

    def __init__(self, config: AIConfig):
        if config.timeout <= 0:
            raise AIError("AI timeout must be positive")
        self.config = config

    def decide(self, request_text: str) -> dict[str, str]:
        request_text = request_text.strip()
        if not request_text:
            raise AIError("request must not be empty")
        if len(request_text) > MAX_REQUEST_CHARS:
            raise AIError(f"request exceeds the {MAX_REQUEST_CHARS:,}-character limit")
        body = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": request_text},
            ],
            "temperature": 0.1,
            "max_tokens": 200,
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
                "User-Agent": "Phobos/0.2",
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


# Backward-compatible name for integrations that imported the old class.
OpenAIResponsesClient = VeniceClient

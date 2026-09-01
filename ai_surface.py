"""Passive discovery of likely AI-powered web surfaces."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class AISurfaceCandidate:
    """A passive signal that a web surface may involve an AI component."""

    kind: str
    url: str
    confidence: float
    evidence: tuple[str, ...]

    def key(self) -> tuple[str, str]:
        return self.kind, self.url


_AI_ENDPOINT_PATTERNS = (
    (re.compile(r"/(?:v1/)?chat/completions(?:[/?#]|$)", re.I), "chat_completion_endpoint", 0.96),
    (re.compile(r"/(?:v1/)?responses(?:[/?#]|$)", re.I), "responses_endpoint", 0.94),
    (re.compile(r"/(?:v1/)?messages(?:[/?#]|$)", re.I), "message_endpoint", 0.88),
    (re.compile(r"/(?:v1/)?generate(?:content|text)?(?:[/?#]|$)", re.I), "generation_endpoint", 0.88),
    (re.compile(r"/api/(?:chat|generate|completion|completions)(?:[/?#]|$)", re.I), "ai_api_endpoint", 0.86),
)

_VENDOR_HINTS = (
    "openai",
    "anthropic",
    "claude",
    "gemini",
    "vertexai",
    "ollama",
    "mistral",
    "cohere",
    "groq",
    "together.ai",
    "huggingface",
)

_AGENT_HINTS = (
    "tool_calls",
    "function_call",
    "function_calling",
    "agent",
    "assistant",
    "tools",
)

_INPUT_HINTS = (
    "prompt",
    "instruction",
    "system_prompt",
    "message",
    "question",
    "query",
    "input",
)


def _endpoint_candidate(url: str) -> AISurfaceCandidate | None:
    parsed = urlparse(url)
    path = parsed.path or "/"
    for pattern, kind, confidence in _AI_ENDPOINT_PATTERNS:
        if pattern.search(path):
            return AISurfaceCandidate(kind, url, confidence, (f"URL path matched {kind}",))
    return None


def detect_ai_surfaces(
    page_url: str,
    html: str,
    *,
    links: Iterable[str] = (),
    scripts: Iterable[str] = (),
    forms: Iterable[dict] = (),
) -> tuple[AISurfaceCandidate, ...]:
    """Extract conservative, passive AI-related signals from already-fetched HTML."""
    found: dict[tuple[str, str], AISurfaceCandidate] = {}

    def add(candidate: AISurfaceCandidate) -> None:
        key = candidate.key()
        existing = found.get(key)
        if existing is None:
            found[key] = candidate
            return
        evidence = tuple(dict.fromkeys((*existing.evidence, *candidate.evidence)))
        found[key] = AISurfaceCandidate(
            existing.kind,
            existing.url,
            max(existing.confidence, candidate.confidence),
            evidence,
        )

    for url in (*links, *scripts):
        candidate = _endpoint_candidate(url)
        if candidate is not None:
            add(candidate)

    lowered = html.lower()
    for hint in _VENDOR_HINTS:
        if hint in lowered:
            add(AISurfaceCandidate("provider_signal", page_url, 0.72, (f"page references {hint}",)))

    for hint in _AGENT_HINTS:
        if re.search(rf"\b{re.escape(hint)}\b", lowered):
            add(AISurfaceCandidate("agent_signal", page_url, 0.70, (f"page contains {hint}",)))

    for form in forms:
        action = form.get("action") or page_url
        names = [str(item.get("name", "")).lower() for item in form.get("inputs", ())]
        matched = [hint for hint in _INPUT_HINTS if any(hint == name or hint in name for name in names)]
        if matched:
            add(
                AISurfaceCandidate(
                    "ai_input",
                    action,
                    0.66,
                    (f"form input matched: {', '.join(sorted(set(matched)))}",),
                )
            )

    return tuple(sorted(found.values(), key=lambda item: (item.kind, item.url)))

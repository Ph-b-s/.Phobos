"""High-level browser interaction primitives used by Phobos workflows.

This layer sits above the low-level Playwright adapter. It provides bounded,
reusable interactions without allowing callers to bypass the adapter's scope
and request controls.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from browser_adapter import BrowserAdapterError, BrowserPageSnapshot, BrowserSession

MAX_TEXT_MATCHES = 100
MAX_SELECTOR_LENGTH = 500
MAX_VALUE_LENGTH = 4_000
MAX_WEBSOCKET_PROTOCOLS = 8
MAX_WEBSOCKET_HEADER_VALUE = 8_000


class BrowserInteractionError(RuntimeError):
    """Raised when a high-level browser action cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class InteractionResult:
    action: str
    url: str
    success: bool
    detail: str = ""
    data: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "url": self.url, "success": self.success, "detail": self.detail, "data": self.data or {}}


class BrowserInteractor:
    """Perform deterministic browser actions through a BrowserSession."""

    def __init__(self, session: BrowserSession) -> None:
        self.session = session

    def open(self, url: str) -> InteractionResult:
        try:
            final_url = self.session.goto(url)
        except Exception as exc:
            raise BrowserInteractionError(f"navigation failed: {exc}") from exc
        return InteractionResult("navigate", final_url, True)

    def fill(self, selector: str, value: str) -> InteractionResult:
        _validate_selector(selector)
        _validate_value(value)
        try:
            self.session.fill(selector, value)
        except Exception as exc:
            raise BrowserInteractionError(f"fill failed: {exc}") from exc
        return InteractionResult("fill", _current_url(self.session), True, data={"selector": selector})

    def click(self, selector: str) -> InteractionResult:
        _validate_selector(selector)
        try:
            self.session.click(selector)
        except Exception as exc:
            raise BrowserInteractionError(f"click failed: {exc}") from exc
        return InteractionResult("click", _current_url(self.session), True, data={"selector": selector})

    def snapshot(self) -> BrowserPageSnapshot:
        try:
            return self.session.snapshot()
        except BrowserAdapterError as exc:
            raise BrowserInteractionError(str(exc)) from exc

    def snapshot_dict(self) -> dict[str, Any]:
        snapshot = self.snapshot()
        return {"url": snapshot.url, "title": snapshot.title, "text": snapshot.text,
                "links": list(snapshot.links), "forms": list(snapshot.forms),
                "scripts": list(snapshot.scripts), "storage_keys": list(snapshot.storage_keys)}

    def websocket_handshake(self, url: str, *, headers: Mapping[str, str] | None = None, protocols: Sequence[str] = ()) -> dict[str, Any]:
        """Perform one handshake-only WebSocket connection through the adapter."""
        try:
            result = self.session.websocket_handshake(url, headers=headers, protocols=protocols)
        except (BrowserAdapterError, ValueError, TypeError) as exc:
            raise BrowserInteractionError(f"WebSocket handshake failed: {exc}") from exc
        return dict(result)

    def find_text(self, needles: Iterable[str]) -> tuple[str, ...]:
        text = self.session.text()
        lowered = text.casefold()
        matches: list[str] = []
        for needle in needles:
            value = needle.strip()
            if value and value.casefold() in lowered and value not in matches:
                matches.append(value)
            if len(matches) >= MAX_TEXT_MATCHES:
                break
        return tuple(matches)

    def links_matching(self, keywords: Iterable[str]) -> tuple[str, ...]:
        snapshot = self.snapshot()
        lowered_keywords = tuple(item.strip().casefold() for item in keywords if item and item.strip())
        if not lowered_keywords:
            return ()
        result: list[str] = []
        for link in snapshot.links:
            if any(keyword in link.casefold() for keyword in lowered_keywords) and link not in result:
                result.append(link)
            if len(result) >= MAX_TEXT_MATCHES:
                break
        return tuple(result)

    def form_inputs(self) -> tuple[dict[str, Any], ...]:
        return self.snapshot().forms


def _validate_selector(selector: str) -> None:
    if not isinstance(selector, str) or not selector.strip():
        raise ValueError("selector must not be empty")
    if len(selector) > MAX_SELECTOR_LENGTH:
        raise ValueError("selector exceeds size limit")


def _validate_value(value: str) -> None:
    if not isinstance(value, str):
        raise TypeError("browser form values must be strings")
    if len(value) > MAX_VALUE_LENGTH:
        raise ValueError("browser form value exceeds size limit")


def _current_url(session: BrowserSession) -> str:
    snapshot = session.snapshot()
    return urlparse(snapshot.url)._replace(query="", fragment="").geturl()
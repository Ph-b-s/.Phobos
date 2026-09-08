"""Scoped browser execution primitives for authorized Phobos assessments.

The browser adapter is the dynamic-Web boundary for Phobos. It provides a
real browser/JavaScript runtime, scope enforcement on every intercepted
request, bounded request accounting, session isolation, DOM/runtime evidence,
and sanitized network observations. Playwright remains optional and is
imported lazily.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from ai_testing import Observation
from scope import ScopeError, ScopeValidator

MAX_NETWORK_RECORDS = 2_000
MAX_DOM_TEXT = 200_000
MAX_SCRIPT_RESULT = 50_000


class BrowserAdapterError(RuntimeError):
    """Raised when browser execution cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class BrowserLimits:
    """Hard limits applied to a browser session."""

    max_requests: int = 2_000
    navigation_timeout_ms: int = 15_000

    def __post_init__(self) -> None:
        if not 1 <= self.max_requests <= MAX_NETWORK_RECORDS:
            raise ValueError(f"max_requests must be between 1 and {MAX_NETWORK_RECORDS}")
        if not 100 <= self.navigation_timeout_ms <= 120_000:
            raise ValueError("navigation_timeout_ms must be between 100 and 120000")


@dataclass(frozen=True, slots=True)
class NetworkRecord:
    """Sanitized browser-network observation without credentials or query data."""

    event: str
    method: str
    url: str
    resource_type: str = ""
    status: int | None = None
    error: str | None = None

    def to_observation(self) -> Observation:
        safe_url = _safe_url(self.url)
        detail = f"{self.event}: {self.method} {safe_url}"
        if self.status is not None:
            detail += f" [{self.status}]"
        if self.error:
            detail += f" ({self.error})"
        return Observation(
            kind="browser_network",
            description=detail,
            source="browser_adapter",
            metadata={
                "event": self.event,
                "method": self.method,
                "url": safe_url,
                "resource_type": self.resource_type,
                "status": self.status,
            },
        )


@dataclass(frozen=True, slots=True)
class BrowserPageSnapshot:
    """Bounded dynamic-page observations after JavaScript execution."""

    url: str
    title: str
    text: str
    links: tuple[str, ...]
    forms: tuple[dict[str, Any], ...]
    scripts: tuple[str, ...]
    storage_keys: tuple[str, ...]

    def to_observations(self) -> tuple[Observation, ...]:
        return (
            Observation(
                kind="browser_dom",
                description=f"Rendered DOM observed at {_safe_url(self.url)}",
                source="browser_adapter",
                metadata={
                    "url": _safe_url(self.url),
                    "title": self.title[:500],
                    "links": list(self.links),
                    "forms": list(self.forms),
                    "scripts": list(self.scripts),
                    "storage_keys": list(self.storage_keys),
                },
            ),
        )


class BrowserSession(Protocol):
    """Minimal browser contract consumed by assessment adapters."""

    def goto(self, url: str) -> str: ...
    def title(self) -> str: ...
    def text(self) -> str: ...
    def fill(self, selector: str, value: str) -> None: ...
    def click(self, selector: str) -> None: ...
    def snapshot(self) -> BrowserPageSnapshot: ...
    def run_probe(self, script: str) -> Any: ...
    def network_observations(self) -> tuple[Observation, ...]: ...
    def close(self) -> None: ...


def _safe_url(url: str) -> str:
    """Remove query/fragment data so secrets are not written into evidence."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _bounded_string(value: Any, *, limit: int) -> str:
    text = str(value)
    return text[:limit]


class PlaywrightBrowserSession:
    """A scope-enforced Playwright session using one isolated BrowserContext."""

    def __init__(
        self,
        scope: ScopeValidator,
        *,
        limits: BrowserLimits | None = None,
        headless: bool = True,
        browser_name: str = "chromium",
        user_agent: str = "Phobos/0.4.1",
    ) -> None:
        self.scope = scope
        self.limits = limits or BrowserLimits()
        self._closed = False
        self._requests_seen = 0
        self._records: list[NetworkRecord] = []
        self._blocked_reason: str | None = None
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None

        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise BrowserAdapterError(
                "Playwright is not installed; install the optional 'browser' dependency"
            ) from exc

        if browser_name not in {"chromium", "firefox", "webkit"}:
            raise ValueError("browser_name must be chromium, firefox, or webkit")
        if not user_agent.strip():
            raise ValueError("user_agent must not be empty")

        self._playwright = sync_playwright().start()
        browser_type = getattr(self._playwright, browser_name)
        try:
            self._browser = browser_type.launch(headless=headless)
            self._context = self._browser.new_context(
                user_agent=user_agent,
                service_workers="block",
            )
            self._page = self._context.new_page()
            self._context.set_default_navigation_timeout(self.limits.navigation_timeout_ms)
            self._context.set_default_timeout(self.limits.navigation_timeout_ms)
        except Exception:
            self.close()
            raise

        self._context.route("**/*", self._route)
        self._page.on("response", self._on_response)
        self._page.on("requestfailed", self._on_request_failed)

    def _route(self, route: Any) -> None:
        request = route.request
        self._requests_seen += 1
        if self._requests_seen > self.limits.max_requests:
            self._blocked_reason = "browser request limit exceeded"
            route.abort("blockedbyclient")
            return
        try:
            self.scope.validate(request.url)
        except ScopeError as exc:
            self._blocked_reason = f"browser request blocked: {exc}"
            route.abort("blockedbyclient")
            return
        route.continue_()

    def _check_blocked(self) -> None:
        if self._blocked_reason:
            reason = self._blocked_reason
            self._blocked_reason = None
            raise BrowserAdapterError(reason)

    def _on_response(self, response: Any) -> None:
        if len(self._records) >= MAX_NETWORK_RECORDS:
            return
        request = response.request
        self._records.append(
            NetworkRecord(
                event="response",
                method=request.method,
                url=response.url,
                resource_type=request.resource_type,
                status=response.status,
            )
        )

    def _on_request_failed(self, request: Any) -> None:
        if len(self._records) >= MAX_NETWORK_RECORDS:
            return
        self._records.append(
            NetworkRecord(
                event="request_failed",
                method=request.method,
                url=request.url,
                resource_type=request.resource_type,
                error=request.failure,
            )
        )

    def _require_open(self) -> Any:
        if self._closed or self._page is None:
            raise BrowserAdapterError("browser session is closed")
        self._check_blocked()
        return self._page

    def goto(self, url: str) -> str:
        page = self._require_open()
        try:
            validated = self.scope.validate(url)
            response = page.goto(validated, wait_until="domcontentloaded")
            self._check_blocked()
            if response is None:
                self.scope.validate(page.url)
                return page.url
            self.scope.validate(page.url)
            return page.url
        except (ScopeError, BrowserAdapterError):
            raise
        except Exception as exc:
            raise BrowserAdapterError(f"navigation failed: {exc}") from exc

    def title(self) -> str:
        return self._require_open().title()

    def text(self) -> str:
        return self._require_open().locator("body").inner_text(timeout=self.limits.navigation_timeout_ms)[:MAX_DOM_TEXT]

    def fill(self, selector: str, value: str) -> None:
        if not selector.strip():
            raise ValueError("selector must not be empty")
        self._require_open().locator(selector).fill(value)
        self._check_blocked()

    def click(self, selector: str) -> None:
        if not selector.strip():
            raise ValueError("selector must not be empty")
        self._require_open().locator(selector).click()
        self._check_blocked()

    def snapshot(self) -> BrowserPageSnapshot:
        page = self._require_open()
        try:
            payload = page.evaluate(
                """
                () => ({
                    url: location.href,
                    title: document.title || "",
                    text: (document.body?.innerText || "").slice(0, 200000),
                    links: Array.from(document.querySelectorAll('a[href]')).map(a => a.href),
                    scripts: Array.from(document.querySelectorAll('script[src]')).map(s => s.src),
                    forms: Array.from(document.forms).map(form => ({
                        action: form.action || location.href,
                        method: (form.method || 'GET').toUpperCase(),
                        inputs: Array.from(form.elements).map(el => ({
                            name: el.name || '',
                            type: el.type || el.tagName.toLowerCase()
                        })).filter(item => item.name)
                    })),
                    storage_keys: [
                        ...Object.keys(window.localStorage || {}),
                        ...Object.keys(window.sessionStorage || {})
                    ].slice(0, 500)
                })
                """
            )
            self._check_blocked()
        except Exception as exc:
            raise BrowserAdapterError(f"dynamic DOM snapshot failed: {exc}") from exc

        if not isinstance(payload, dict):
            raise BrowserAdapterError("browser returned an invalid DOM snapshot")
        return BrowserPageSnapshot(
            url=str(payload.get("url") or page.url),
            title=_bounded_string(payload.get("title", ""), limit=500),
            text=_bounded_string(payload.get("text", ""), limit=MAX_DOM_TEXT),
            links=tuple(str(item) for item in payload.get("links", ()) if item),
            forms=tuple(item for item in payload.get("forms", ()) if isinstance(item, dict)),
            scripts=tuple(str(item) for item in payload.get("scripts", ()) if item),
            storage_keys=tuple(str(item) for item in payload.get("storage_keys", ()) if item),
        )

    def run_probe(self, script: str) -> Any:
        """Run a bounded, caller-supplied browser probe in the target page.

        The AI planner never receives this primitive directly. Security modules
        provide fixed probe scripts and validate the returned data before using it.
        """
        if not script.strip():
            raise ValueError("script must not be empty")
        result = self._require_open().evaluate(script)
        self._check_blocked()
        if isinstance(result, str):
            return result[:MAX_SCRIPT_RESULT]
        if isinstance(result, (list, tuple)):
            return result[:500]
        if isinstance(result, dict):
            return {str(k): v for k, v in list(result.items())[:500]}
        return result

    def network_observations(self) -> tuple[Observation, ...]:
        return tuple(record.to_observation() for record in self._records)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for resource in (self._context, self._browser):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                pass

"""Passive discovery of API-like routes embedded in HTML and JavaScript."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse


@dataclass(frozen=True, slots=True)
class APIEndpointCandidate:
    """A conservative signal that a route may be an application API endpoint."""

    url: str
    method: str
    evidence: tuple[str, ...]
    confidence: float = 0.70

    def key(self) -> tuple[str, str]:
        return self.method.upper(), self.url


_HTTP_METHOD = r"(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)"
_METHOD_URL_RE = re.compile(
    rf"\b({_HTTP_METHOD})\s*\(\s*['\"]([^'\"]+)['\"]",
    re.I,
)
_FETCH_RE = re.compile(r"\bfetch\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
_AXIOS_RE = re.compile(
    r"\baxios\s*\.\s*(get|post|put|patch|delete|options|head)\s*\(\s*['\"]([^'\"]+)['\"]",
    re.I,
)
_URLISH_RE = re.compile(
    r"['\"]((?:https?:)?//[^'\"]+|/(?:api|graphql|rest|v[0-9]+)(?:/[^'\"]*)?)['\"]",
    re.I,
)


def _normalize_candidate(base_url: str, raw_url: str) -> str | None:
    candidate = raw_url.strip()
    if not candidate or candidate.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
        return None
    absolute = urljoin(base_url, candidate)
    parsed = urlparse(absolute)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    return parsed._replace(fragment="").geturl()


def discover_api_endpoints(page_url: str, source: str) -> tuple[APIEndpointCandidate, ...]:
    """Extract likely API endpoints without executing or requesting discovered routes."""
    found: dict[tuple[str, str], APIEndpointCandidate] = {}

    def add(raw_url: str, method: str, evidence: str, confidence: float) -> None:
        url = _normalize_candidate(page_url, raw_url)
        if url is None:
            return
        candidate = APIEndpointCandidate(url, method.upper(), (evidence,), confidence)
        key = candidate.key()
        existing = found.get(key)
        if existing is None:
            found[key] = candidate
            return
        merged = tuple(dict.fromkeys((*existing.evidence, *candidate.evidence)))
        found[key] = APIEndpointCandidate(
            url,
            candidate.method,
            merged,
            max(existing.confidence, candidate.confidence),
        )

    for match in _METHOD_URL_RE.finditer(source):
        add(match.group(2), match.group(1), "explicit HTTP method call", 0.82)

    for match in _FETCH_RE.finditer(source):
        add(match.group(1), "GET", "fetch() call", 0.76)

    for match in _AXIOS_RE.finditer(source):
        add(match.group(2), match.group(1), "axios method call", 0.80)

    for match in _URLISH_RE.finditer(source):
        raw_url = match.group(1)
        if "/api/" in raw_url.lower() or "/graphql" in raw_url.lower() or re.search(r"/v\d+(?:/|$)", raw_url, re.I):
            add(raw_url, "GET", "API-like route literal", 0.68)

    return tuple(sorted(found.values(), key=lambda item: (item.url, item.method)))

"""Centralized URL scope enforcement.

All outbound requests in Phobos must pass through this validator.
"""

from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a URL cannot be used for the current scan scope."""


class ScopeValidator:
    """Validate every target URL against an explicit hostname allow-list."""

    def __init__(self, allowed_domains: tuple[str, ...] | list[str]) -> None:
        normalized: set[str] = set()
        for domain in allowed_domains:
            value = domain.strip().lower().rstrip(".")
            if value:
                normalized.add(value)
        if not normalized:
            raise ValueError("at least one allowed domain is required")
        self._allowed_domains = frozenset(normalized)

    @property
    def allowed_domains(self) -> tuple[str, ...]:
        return tuple(sorted(self._allowed_domains))

    def is_in_scope(self, url: str) -> bool:
        try:
            self.validate(url)
        except ScopeError:
            return False
        return True

    def validate(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeError("only http and https URLs are allowed")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeError("URLs containing userinfo are not allowed")
        host = parsed.hostname
        if not host:
            raise ScopeError("URL has no hostname")

        normalized_host = host.lower().rstrip(".")
        if not self._host_matches_scope(normalized_host):
            raise ScopeError(f"out-of-scope host: {host}")
        return url

    def _host_matches_scope(self, host: str) -> bool:
        try:
            parsed_ip = ip_address(host)
        except ValueError:
            parsed_ip = None

        if parsed_ip is not None:
            return host in self._allowed_domains

        return any(host == domain or host.endswith(f".{domain}") for domain in self._allowed_domains)

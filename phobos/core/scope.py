"""Centralized URL and network scope enforcement."""

from __future__ import annotations

import socket
from ipaddress import ip_address
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a URL cannot be used for the current scan scope."""


class ScopeValidator:
    """Validate target URLs against an explicit hostname allow-list."""

    def __init__(
        self,
        allowed_domains: tuple[str, ...] | list[str],
        *,
        allow_private_targets: bool = False,
    ) -> None:
        normalized: set[str] = set()
        for domain in allowed_domains:
            value = domain.strip().lower().rstrip(".")
            if value:
                normalized.add(value)
        if not normalized:
            raise ValueError("at least one allowed domain is required")
        self._allowed_domains = frozenset(normalized)
        self.allow_private_targets = allow_private_targets
        self._resolution_cache: dict[str, frozenset] = {}

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
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ScopeError("only http and https URLs are allowed")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeError("URLs containing userinfo are not allowed")
        if parsed.fragment:
            parsed = parsed._replace(fragment="")
            url = parsed.geturl()
        host = parsed.hostname
        if not host:
            raise ScopeError("URL has no hostname")

        normalized_host = host.lower().rstrip(".")
        if not self._host_matches_scope(normalized_host):
            raise ScopeError(f"out-of-scope host: {host}")
        if not self.allow_private_targets:
            self._validate_public_destination(normalized_host)
        return url

    def _host_matches_scope(self, host: str) -> bool:
        try:
            parsed_ip = ip_address(host)
        except ValueError:
            parsed_ip = None

        if parsed_ip is not None:
            return host in self._allowed_domains

        return any(host == domain or host.endswith(f".{domain}") for domain in self._allowed_domains)

    def _validate_public_destination(self, host: str) -> None:
        try:
            addresses = self._resolution_cache.get(host)
            if addresses is None:
                resolved = {
                    ip_address(result[4][0])
                    for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                }
                addresses = frozenset(resolved)
                self._resolution_cache[host] = addresses
        except OSError:
            return

        if not addresses:
            return
        blocked = [address for address in addresses if not address.is_global]
        if blocked:
            raise ScopeError("destination resolves to a non-public IP address")

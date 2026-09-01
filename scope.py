"""Centralized URL/network scope boundary."""
from __future__ import annotations

import socket
from ipaddress import ip_address
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a target violates the configured network scope."""


class ScopeValidator:
    """Validate HTTP(S) destinations against an explicit scope policy."""

    def __init__(self, allowed_domains: tuple[str, ...] | list[str], *, allow_private_targets: bool = False):
        normalized = {d.strip().lower().rstrip('.') for d in allowed_domains if d.strip()}
        if not normalized:
            raise ValueError("at least one allowed domain is required")
        self._allowed_domains = frozenset(normalized)
        self.allow_private_targets = allow_private_targets
        self._cache: dict[str, frozenset] = {}

    @property
    def allowed_domains(self) -> tuple[str, ...]:
        return tuple(sorted(self._allowed_domains))

    def is_in_scope(self, url: str) -> bool:
        try:
            self.validate(url)
            return True
        except ScopeError:
            return False

    def validate(self, url: str) -> str:
        p = urlparse(url)
        if p.scheme.lower() not in {"http", "https"}:
            raise ScopeError("only http and https URLs are allowed")
        if p.username is not None or p.password is not None:
            raise ScopeError("URLs containing userinfo are not allowed")
        if p.fragment:
            p = p._replace(fragment="")
            url = p.geturl()

        host = p.hostname
        if not host:
            raise ScopeError("URL has no hostname")
        host = host.lower().rstrip(".")
        if not self._matches(host):
            raise ScopeError(f"out-of-scope host: {host}")
        if not self.allow_private_targets:
            self._public_destination(host)
        return url

    def _matches(self, host: str) -> bool:
        try:
            ip = ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            return host in self._allowed_domains
        return any(host == domain or host.endswith("." + domain) for domain in self._allowed_domains)

    def _public_destination(self, host: str) -> None:
        try:
            addresses = self._cache.get(host)
            if addresses is None:
                addresses = frozenset(
                    ip_address(result[4][0])
                    for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                )
                if not addresses:
                    raise ScopeError("destination has no resolvable address")
                self._cache[host] = addresses
        except ScopeError:
            raise
        except OSError as exc:
            raise ScopeError(f"could not resolve destination safely: {host}") from exc

        if any(not address.is_global for address in addresses):
            raise ScopeError("destination resolves to a non-public IP address")

"""Centralized URL and network-scope boundary."""
from __future__ import annotations

import socket
from ipaddress import IPv4Address, IPv6Address, ip_address
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a destination violates the configured scope policy."""


class ScopeValidator:
    """Validate HTTP(S) destinations against an explicit host/network scope."""

    def __init__(
        self,
        allowed_domains: tuple[str, ...] | list[str],
        *,
        allow_private_targets: bool = False,
    ):
        normalized = {
            self._normalize_scope(value)
            for value in allowed_domains
            if value.strip()
        }
        if not normalized:
            raise ValueError("at least one allowed domain is required")
        self._allowed_domains = frozenset(normalized)
        self.allow_private_targets = allow_private_targets
        self._cache: dict[str, frozenset[IPv4Address | IPv6Address]] = {}

    @staticmethod
    def _normalize_scope(value: str) -> str:
        candidate = value.strip().lower().rstrip(".")
        if "://" in candidate or "/" in candidate or "@" in candidate:
            raise ValueError("scope entries must be hostnames or IP addresses")
        try:
            ip_address(candidate)
            return candidate
        except ValueError:
            pass
        if not candidate or any(label == "" for label in candidate.split(".")):
            raise ValueError("scope entry is not a valid hostname")
        return candidate

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
        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ScopeError("only http and https URLs are allowed")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeError("URLs containing userinfo are not allowed")
        if not parsed.hostname:
            raise ScopeError("URL has no hostname")
        try:
            host = parsed.hostname.lower().rstrip(".")
        except AttributeError as exc:
            raise ScopeError("URL has an invalid hostname") from exc
        if not self._matches(host):
            raise ScopeError(f"out-of-scope host: {host}")
        if not self.allow_private_targets:
            self._public_destination(host)

        normalized = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            fragment="",
        )
        return normalized.geturl()

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
            literal = ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if not literal.is_global:
                raise ScopeError("destination resolves to a non-public IP address")
            return

        addresses = self._cache.get(host)
        if addresses is None:
            try:
                addresses = frozenset(
                    ip_address(result[4][0])
                    for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                )
            except OSError as exc:
                raise ScopeError(f"could not resolve destination safely: {host}") from exc
            if not addresses:
                raise ScopeError("destination has no resolvable address")
            self._cache[host] = addresses

        if any(not address.is_global for address in addresses):
            raise ScopeError("destination resolves to a non-public IP address")

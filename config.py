"""Validated scan configuration."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


PHOBOS_VERSION = "0.3.2"
DEFAULT_USER_AGENT = f"Phobos/{PHOBOS_VERSION}"


@dataclass(frozen=True, slots=True)
class ScanConfig:
    target: str
    scopes: tuple[str, ...] = ()
    output_dir: Path = Path(".phobos")
    timeout: float = 10.0
    max_redirects: int = 5
    max_pages: int = 100
    max_discovered_urls: int = 5_000
    user_agent: str = DEFAULT_USER_AGENT
    max_response_bytes: int = 2_000_000
    allow_private_targets: bool = False
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        parsed = urlparse(self.target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target must be an absolute http(s) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("target must not contain userinfo")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if not 0 <= self.max_redirects <= 20:
            raise ValueError("max_redirects must be between 0 and 20")
        if not 1 <= self.max_pages <= 10_000:
            raise ValueError("max_pages must be between 1 and 10000")
        if not self.max_pages <= self.max_discovered_urls <= 50_000:
            raise ValueError("max_discovered_urls must be between max_pages and 50000")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if not self.user_agent.strip():
            raise ValueError("user_agent must not be empty")

    @property
    def normalized_scopes(self) -> tuple[str, ...]:
        values = self.scopes or (urlparse(self.target).hostname or "",)
        normalized = {value.strip().lower().rstrip(".") for value in values if value.strip()}
        if not normalized:
            raise ValueError("at least one non-empty scope is required")
        return tuple(sorted(normalized))

    @classmethod
    def from_cli(
        cls,
        target: str,
        scopes: tuple[str, ...] = (),
        output_dir: str = ".phobos",
        *,
        timeout: float = 10.0,
        max_pages: int = 100,
        max_discovered_urls: int = 5_000,
        user_agent: str = DEFAULT_USER_AGENT,
        allow_private_targets: bool = False,
    ) -> "ScanConfig":
        return cls(
            target=target,
            scopes=scopes,
            output_dir=Path(output_dir),
            timeout=timeout,
            max_pages=max_pages,
            max_discovered_urls=max_discovered_urls,
            user_agent=user_agent,
            allow_private_targets=allow_private_targets,
        )

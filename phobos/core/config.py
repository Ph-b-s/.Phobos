"""Configuration for a Phobos scan."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class ScanConfig:
    target: str
    scopes: tuple[str, ...] = ()
    output_dir: Path = Path(".phobos")
    timeout: float = 10.0
    max_redirects: int = 5
    user_agent: str = "Phobos/0.1"
    max_response_bytes: int = 2_000_000
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        parsed = urlparse(self.target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target must be an absolute http(s) URL")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.max_redirects < 0:
            raise ValueError("max_redirects cannot be negative")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")

    @property
    def normalized_scopes(self) -> tuple[str, ...]:
        values = self.scopes or (urlparse(self.target).hostname or "",)
        return tuple(sorted({value.strip().lower().rstrip(".") for value in values if value.strip()}))

    @classmethod
    def from_cli(
        cls,
        target: str,
        scopes: tuple[str, ...] = (),
        output_dir: str = ".phobos",
    ) -> "ScanConfig":
        return cls(target=target, scopes=scopes, output_dir=Path(output_dir))

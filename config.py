"""Scan configuration."""
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
    max_pages: int = 100
    user_agent: str = "Phobos/0.1"
    max_response_bytes: int = 2_000_000
    allow_private_targets: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    def __post_init__(self) -> None:
        p = urlparse(self.target)
        if p.scheme.lower() not in {"http", "https"} or not p.hostname: raise ValueError("target must be an absolute http(s) URL")
        if self.timeout <= 0: raise ValueError("timeout must be positive")
        if self.max_redirects < 0: raise ValueError("max_redirects cannot be negative")
        if self.max_pages < 1: raise ValueError("max_pages must be at least 1")
        if self.max_response_bytes <= 0: raise ValueError("max_response_bytes must be positive")
    @property
    def normalized_scopes(self) -> tuple[str, ...]:
        values = self.scopes or (urlparse(self.target).hostname or "",)
        return tuple(sorted({v.strip().lower().rstrip(".") for v in values if v.strip()}))
    @classmethod
    def from_cli(cls, target: str, scopes: tuple[str, ...] = (), output_dir: str = ".phobos", *, timeout: float = 10.0, max_pages: int = 100, allow_private_targets: bool = False) -> "ScanConfig":
        return cls(target, scopes, Path(output_dir), timeout, 5, max_pages, "Phobos/0.1", 2_000_000, allow_private_targets)

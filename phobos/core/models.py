"""Shared data models for Phobos scans."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    """A normalized security finding produced by a scanner."""

    scanner: str
    category: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanResult:
    """Result of one scanner execution."""

    scanner: str
    target: str
    findings: tuple[Finding, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def vulnerable(self) -> bool:
        return bool(self.findings)

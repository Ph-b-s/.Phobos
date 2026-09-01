"""Scanner interface used by all Phobos security modules."""

from abc import ABC, abstractmethod
from typing import Any

from .models import Finding, ScanResult


class Scanner(ABC):
    """Base class for deterministic, composable security scanners."""

    name = "unnamed"

    @abstractmethod
    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Run the scanner against an authorized target."""
        raise NotImplementedError

    @staticmethod
    def finding(
        *,
        category: str,
        title: str,
        severity: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        from .models import Severity

        return Finding(
            scanner="",
            category=category,
            title=title,
            severity=Severity(severity),
            description=description,
            evidence=evidence,
            remediation=remediation,
            metadata=metadata or {},
        )

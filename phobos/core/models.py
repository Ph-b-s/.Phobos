"""Unified data models used across the Phobos core."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AssetType(StrEnum):
    WEBSITE = "website"
    PAGE = "page"
    ENDPOINT = "endpoint"
    FORM = "form"
    INPUT = "input"
    API = "api"
    JAVASCRIPT = "javascript"
    AI_AGENT = "ai_agent"
    TOOL = "tool"
    RESOURCE = "resource"
    DATABASE = "database"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Asset:
    """Normalized representation of anything Phobos discovers."""

    id: str
    type: AssetType
    name: str
    url: str = ""
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("asset id cannot be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("asset confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
            "url": self.url,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class InputAsset(Asset):
    """A normalized web input or request parameter."""

    parameter_type: str = "text"
    location: str = "query"
    method: str = "GET"

    def __post_init__(self) -> None:
        Asset.__post_init__(self)
        if self.type is not AssetType.INPUT:
            raise ValueError("InputAsset must use AssetType.INPUT")

    def to_dict(self) -> dict[str, Any]:
        data = Asset.to_dict(self)
        data.update(
            {
                "parameter_type": self.parameter_type,
                "location": self.location,
                "method": self.method,
            }
        )
        return data


@dataclass(frozen=True, slots=True)
class EndpointAsset(Asset):
    """A discovered HTTP endpoint."""

    method: str = "GET"
    status_code: int | None = None

    def __post_init__(self) -> None:
        Asset.__post_init__(self)
        if self.type is not AssetType.ENDPOINT:
            raise ValueError("EndpointAsset must use AssetType.ENDPOINT")

    def to_dict(self) -> dict[str, Any]:
        data = Asset.to_dict(self)
        data.update({"method": self.method, "status_code": self.status_code})
        return data


@dataclass(frozen=True, slots=True)
class FormAsset(Asset):
    """A discovered HTML form and its inputs."""

    method: str = "GET"
    inputs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        Asset.__post_init__(self)
        if self.type is not AssetType.FORM:
            raise ValueError("FormAsset must use AssetType.FORM")

    def to_dict(self) -> dict[str, Any]:
        data = Asset.to_dict(self)
        data.update({"method": self.method, "inputs": list(self.inputs)})
        return data


@dataclass(frozen=True, slots=True)
class Finding:
    """A normalized security finding with traceable evidence references."""

    id: str
    type: str
    confidence: float
    evidence: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("finding id cannot be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("finding confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "metadata": self.metadata,
        }

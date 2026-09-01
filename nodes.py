"""Graph node and edge definitions."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class GraphNode:
    id: str
    type: str
    label: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("graph node id cannot be empty")
        if not self.type.strip():
            raise ValueError("graph node type cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "attributes": self.attributes,
        }


@dataclass(frozen=True, slots=True)
class GraphEdge:
    source: str
    target: str
    relationship: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source.strip() or not self.target.strip():
            raise ValueError("graph edge source and target cannot be empty")
        if not self.relationship.strip():
            raise ValueError("graph edge relationship cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "attributes": self.attributes,
        }

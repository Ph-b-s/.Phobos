"""Graph node and edge data structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class GraphNode:
    id: str
    type: str
    label: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "type": self.type, "label": self.label, "attributes": self.attributes}


@dataclass(frozen=True, slots=True)
class GraphEdge:
    source: str
    target: str
    relationship: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "attributes": self.attributes,
        }

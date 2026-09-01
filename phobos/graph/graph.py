"""Small in-memory graph engine used as Phobos' first execution graph."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .nodes import GraphEdge, GraphNode


class Graph:
    """Directed graph with deterministic serialization and duplicate protection."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[tuple[str, str, str], GraphEdge] = {}

    @property
    def nodes(self) -> tuple[GraphNode, ...]:
        return tuple(self._nodes.values())

    @property
    def edges(self) -> tuple[GraphEdge, ...]:
        return tuple(self._edges.values())

    def add_node(
        self,
        *,
        id: str,
        type: str,
        label: str = "",
        attributes: dict[str, Any] | None = None,
    ) -> GraphNode:
        if not id.strip():
            raise ValueError("node id cannot be empty")
        existing = self._nodes.get(id)
        node = GraphNode(id=id, type=type, label=label, attributes=attributes or {})
        if existing and existing != node:
            raise ValueError(f"node already exists with different data: {id}")
        self._nodes[id] = node
        return node

    def add_edge(
        self,
        *,
        source: str,
        target: str,
        relationship: str,
        attributes: dict[str, Any] | None = None,
    ) -> GraphEdge:
        if source not in self._nodes or target not in self._nodes:
            raise KeyError("both source and target nodes must exist before adding an edge")
        if not relationship.strip():
            raise ValueError("edge relationship cannot be empty")
        edge = GraphEdge(source=source, target=target, relationship=relationship, attributes=attributes or {})
        self._edges[(source, target, relationship)] = edge
        return edge

    def extend_nodes(self, nodes: Iterable[GraphNode]) -> None:
        for node in nodes:
            self.add_node(id=node.id, type=node.type, label=node.label, attributes=node.attributes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }

    def __len__(self) -> int:
        return len(self._nodes)

"""Deterministic in-memory directed execution graph."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from nodes import GraphEdge, GraphNode


class Graph:
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
        node_id = id.strip()
        node_type = type.strip()
        if not node_id:
            raise ValueError("node id cannot be empty")
        if not node_type:
            raise ValueError("node type cannot be empty")
        node = GraphNode(node_id, node_type, label, dict(attributes or {}))
        existing = self._nodes.get(node_id)
        if existing is not None and existing != node:
            raise ValueError(f"node already exists with different data: {node_id}")
        self._nodes[node_id] = node
        return node

    def add_edge(
        self,
        *,
        source: str,
        target: str,
        relationship: str,
        attributes: dict[str, Any] | None = None,
    ) -> GraphEdge:
        source = source.strip()
        target = target.strip()
        relationship = relationship.strip()
        if source not in self._nodes or target not in self._nodes:
            raise KeyError("both source and target nodes must exist")
        if not relationship:
            raise ValueError("edge relationship cannot be empty")
        edge = GraphEdge(source, target, relationship, dict(attributes or {}))
        key = (source, target, relationship)
        existing = self._edges.get(key)
        if existing is not None and existing != edge:
            raise ValueError(f"edge already exists with different data: {source}->{target} ({relationship})")
        self._edges[key] = edge
        return edge

    def extend_nodes(self, nodes: Iterable[GraphNode]) -> None:
        for node in nodes:
            self.add_node(id=node.id, type=node.type, label=node.label, attributes=node.attributes)

    def to_dict(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: str) -> bool:
        return node_id in self._nodes

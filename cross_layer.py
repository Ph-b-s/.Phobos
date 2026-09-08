"""Cross-layer Web <-> AI attack-path correlation primitives.

The cross-layer layer correlates evidence already discovered by Web and AI
modules. It does not replace those scanners and does not perform arbitrary
requests. Its job is to identify plausible trust/data/control-flow chains that
merit a targeted follow-up test.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable

from graph import Graph


_WEB_TYPES = {"website", "page", "endpoint", "form", "input", "javascript", "api", "resource"}
_AI_TYPES = {"ai_agent", "tool"}


@dataclass(frozen=True, slots=True)
class AttackPath:
    """A bounded graph path spanning at least Web and AI surfaces."""

    id: str
    nodes: tuple[str, ...]
    relationships: tuple[str, ...]
    pattern: str
    confidence: float
    rationale: str
    metadata: dict[str, Any]


def _node_types(graph: Graph) -> dict[str, str]:
    return {node.id: node.type for node in graph.nodes}


def _adjacency(graph: Graph) -> dict[str, tuple[tuple[str, str], ...]]:
    adjacency: dict[str, list[tuple[str, str]]] = {node.id: [] for node in graph.nodes}
    for edge in graph.edges:
        adjacency.setdefault(edge.source, []).append((edge.target, edge.relationship))
    return {key: tuple(value) for key, value in adjacency.items()}


def correlate_attack_paths(
    graph: Graph,
    *,
    max_hops: int = 6,
    max_paths: int = 100,
) -> tuple[AttackPath, ...]:
    """Find short Web/AI-spanning paths for deterministic follow-up planning."""
    if max_hops < 2:
        raise ValueError("max_hops must be at least 2")
    if max_paths < 1:
        raise ValueError("max_paths must be at least 1")

    types = _node_types(graph)
    adjacency = _adjacency(graph)
    paths: list[AttackPath] = []
    seen: set[tuple[str, ...]] = set()

    starts = sorted(node_id for node_id, node_type in types.items() if node_type in _WEB_TYPES)
    for start in starts:
        queue = deque([(start, (start,), ())])
        while queue and len(paths) < max_paths:
            current, nodes, relationships = queue.popleft()
            if len(nodes) > max_hops + 1:
                continue
            for target, relationship in adjacency.get(current, ()):
                if target in nodes:
                    continue
                new_nodes = (*nodes, target)
                new_relationships = (*relationships, relationship)
                domain_sequence = ["ai" if types.get(node) in _AI_TYPES else "web" for node in new_nodes]
                has_web = "web" in domain_sequence
                has_ai = "ai" in domain_sequence
                if has_web and has_ai and len(new_nodes) >= 3:
                    signature = tuple(new_nodes)
                    if signature not in seen:
                        seen.add(signature)
                        first_ai = next(i for i, value in enumerate(domain_sequence) if value == "ai")
                        last_ai = len(domain_sequence) - 1 - next(
                            i for i, value in enumerate(reversed(domain_sequence)) if value == "ai"
                        )
                        pattern = _pattern(domain_sequence, first_ai, last_ai)
                        confidence = 0.55 + min(0.35, 0.07 * (len(new_nodes) - 2))
                        paths.append(
                            AttackPath(
                                id=f"attack_path_{len(paths) + 1:04d}",
                                nodes=new_nodes,
                                relationships=new_relationships,
                                pattern=pattern,
                                confidence=confidence,
                                rationale=_rationale(pattern, domain_sequence),
                                metadata={
                                    "node_types": [types.get(node, "unknown") for node in new_nodes],
                                },
                            )
                        )
                if len(new_nodes) <= max_hops:
                    queue.append((target, new_nodes, new_relationships))

    return tuple(paths)


def _pattern(sequence: list[str], first_ai: int, last_ai: int) -> str:
    left = "web_to_ai" if first_ai > 0 else "ai_origin"
    right = "ai_to_web" if last_ai < len(sequence) - 1 else "ai_terminal"
    if left == "web_to_ai" and right == "ai_to_web":
        return "web_to_ai_to_web"
    if left == "web_to_ai":
        return "web_to_ai"
    if right == "ai_to_web":
        return "ai_to_web"
    return "ai_internal"


def _rationale(pattern: str, sequence: Iterable[str]) -> str:
    if pattern == "web_to_ai_to_web":
        return "A discovered Web surface can reach AI functionality and then another Web/backend capability."
    if pattern == "web_to_ai":
        return "A discovered Web surface can influence or reach AI functionality."
    if pattern == "ai_to_web":
        return "AI functionality can reach another Web/backend capability."
    return "The graph contains an AI-mediated path worth contextual review."

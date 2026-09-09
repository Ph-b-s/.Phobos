"""Deterministic Web <-> AI evidence correlation.

Cross-layer analysis never declares a vulnerability from a graph edge alone.
It produces bounded, traceable correlations and follow-up candidates from
already discovered assets, graph edges, observations, and findings.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from graph import Graph
from knowledge_store import KnowledgeStore, SecurityObservation

_WEB_TYPES = {"website", "page", "endpoint", "form", "input", "javascript", "api", "resource"}
_AI_TYPES = {"ai_agent", "tool"}
_WEB_SOURCE_PREFIXES = ("web.", "browser.", "recon.")
_AI_SOURCE_PREFIXES = ("ai.", "llm.", "agent.")


@dataclass(frozen=True, slots=True)
class AttackPath:
    id: str
    nodes: tuple[str, ...]
    relationships: tuple[str, ...]
    pattern: str
    confidence: float
    rationale: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Correlation:
    """Evidence-backed relationship candidate across Web and AI domains."""

    id: str
    kind: str
    asset_ids: tuple[str, ...]
    observation_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    attack_path_id: str | None = None
    confidence: float = 0.0
    rationale: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CrossLayerAnalysis:
    attack_paths: tuple[AttackPath, ...]
    correlations: tuple[Correlation, ...]
    follow_ups: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_paths": [_attack_path_dict(item) for item in self.attack_paths],
            "correlations": [_correlation_dict(item) for item in self.correlations],
            "follow_ups": list(self.follow_ups),
        }


def correlate_attack_paths(graph: Graph, *, max_hops: int = 6, max_paths: int = 100) -> tuple[AttackPath, ...]:
    if max_hops < 2:
        raise ValueError("max_hops must be at least 2")
    if max_paths < 1:
        raise ValueError("max_paths must be at least 1")

    types = {node.id: node.type for node in graph.nodes}
    adjacency: dict[str, tuple[tuple[str, str], ...]] = defaultdict(tuple)
    mutable: dict[str, list[tuple[str, str]]] = {node.id: [] for node in graph.nodes}
    for edge in graph.edges:
        mutable.setdefault(edge.source, []).append((edge.target, edge.relationship))
    adjacency = {key: tuple(value) for key, value in mutable.items()}

    paths: list[AttackPath] = []
    seen: set[tuple[str, ...]] = set()
    starts = sorted(node_id for node_id, node_type in types.items() if node_type in _WEB_TYPES)

    for start in starts:
        queue = deque([(start, (start,), ())])
        while queue and len(paths) < max_paths:
            current, nodes, relationships = queue.popleft()
            for target, relationship in adjacency.get(current, ()):
                if target in nodes:
                    continue
                new_nodes = (*nodes, target)
                new_relationships = (*relationships, relationship)
                if len(new_nodes) > max_hops + 1:
                    continue

                domains = tuple("ai" if types.get(node) in _AI_TYPES else "web" for node in new_nodes)
                if "ai" in domains and "web" in domains and new_nodes not in seen:
                    seen.add(new_nodes)
                    first_ai = domains.index("ai")
                    last_ai = len(domains) - 1 - tuple(reversed(domains)).index("ai")
                    pattern = _pattern(domains, first_ai, last_ai)
                    confidence = min(0.95, 0.55 + 0.06 * max(0, len(new_nodes) - 2))
                    paths.append(
                        AttackPath(
                            id=f"attack_path_{len(paths) + 1:04d}",
                            nodes=new_nodes,
                            relationships=new_relationships,
                            pattern=pattern,
                            confidence=confidence,
                            rationale=_rationale(pattern),
                            metadata={"node_types": [types.get(node, "unknown") for node in new_nodes]},
                        )
                    )
                if len(new_nodes) <= max_hops:
                    queue.append((target, new_nodes, new_relationships))
    return tuple(paths)


def correlate_observations(
    knowledge: KnowledgeStore,
    *,
    max_correlations: int = 200,
) -> tuple[Correlation, ...]:
    """Join observations that reference the same assets across Web and AI sources."""
    if max_correlations < 1:
        raise ValueError("max_correlations must be at least 1")

    by_asset: dict[str, list[SecurityObservation]] = defaultdict(list)
    for observation in knowledge.observations:
        for asset_id in observation.asset_ids:
            by_asset[asset_id].append(observation)

    result: list[Correlation] = []
    seen: set[tuple[str, ...]] = set()
    for asset_id in sorted(by_asset):
        observations = by_asset[asset_id]
        web = [item for item in observations if _is_web_source(item.source)]
        ai = [item for item in observations if _is_ai_source(item.source)]
        if not web or not ai:
            continue
        observation_ids = tuple(sorted({item.id for item in (*web, *ai)}))
        signature = (asset_id, *observation_ids)
        if signature in seen:
            continue
        seen.add(signature)
        confidence = min(0.95, (sum(item.confidence for item in (*web, *ai)) / len((*web, *ai))) + 0.10)
        result.append(
            Correlation(
                id=f"correlation_{len(result) + 1:04d}",
                kind="shared_asset_web_ai",
                asset_ids=(asset_id,),
                observation_ids=observation_ids,
                confidence=confidence,
                rationale="Web and AI observations independently reference the same discovered asset.",
            )
        )
        if len(result) >= max_correlations:
            return tuple(result)
    return tuple(result)


def correlate_findings(knowledge: KnowledgeStore, *, max_correlations: int = 200) -> tuple[Correlation, ...]:
    """Correlate findings with observations using asset/evidence references where available."""
    if max_correlations < 1:
        raise ValueError("max_correlations must be at least 1")
    observations = {item.id: item for item in knowledge.observations}
    result: list[Correlation] = []
    for finding in knowledge.findings:
        referenced = tuple(item for item in finding.evidence if item in observations)
        if not referenced:
            continue
        asset_ids = tuple(sorted({asset for item_id in referenced for asset in observations[item_id].asset_ids}))
        if not asset_ids:
            continue
        result.append(
            Correlation(
                id=f"finding_correlation_{len(result) + 1:04d}",
                kind="finding_evidence_bridge",
                asset_ids=asset_ids,
                observation_ids=referenced,
                finding_ids=(finding.id,),
                confidence=finding.confidence,
                rationale="A finding is explicitly linked to structured observations on the same assets.",
            )
        )
        if len(result) >= max_correlations:
            break
    return tuple(result)


def analyze_cross_layer(
    graph: Graph,
    knowledge: KnowledgeStore,
    *,
    max_hops: int = 6,
    max_paths: int = 100,
    max_correlations: int = 200,
) -> CrossLayerAnalysis:
    paths = correlate_attack_paths(graph, max_hops=max_hops, max_paths=max_paths)
    correlations = list(correlate_observations(knowledge, max_correlations=max_correlations))
    remaining = max(0, max_correlations - len(correlations))
    if remaining:
        correlations.extend(correlate_findings(knowledge, max_correlations=remaining))

    follow_ups = _build_follow_ups(paths, correlations)
    return CrossLayerAnalysis(paths, tuple(correlations), follow_ups)


def _build_follow_ups(paths: Iterable[AttackPath], correlations: Iterable[Correlation]) -> tuple[dict[str, Any], ...]:
    result: list[dict[str, Any]] = []
    for path in paths:
        module_id = {
            "web_to_ai": "cross_layer.web_to_ai",
            "ai_to_web": "cross_layer.ai_to_web",
            "web_to_ai_to_web": "cross_layer.attack_path",
            "ai_internal": "cross_layer.control_flow",
        }.get(path.pattern, "cross_layer.attack_path")
        result.append({
            "module_id": module_id,
            "priority": round(path.confidence, 3),
            "correlation_type": "attack_path",
            "correlation_id": path.id,
            "asset_ids": list(path.nodes),
            "reason": path.rationale,
        })
    for correlation in correlations:
        result.append({
            "module_id": "cross_layer.data_flow",
            "priority": round(correlation.confidence, 3),
            "correlation_type": correlation.kind,
            "correlation_id": correlation.id,
            "asset_ids": list(correlation.asset_ids),
            "reason": correlation.rationale,
        })
    return tuple(sorted(result, key=lambda item: (-item["priority"], item["correlation_id"])))


def _is_web_source(source: str) -> bool:
    return source.startswith(_WEB_SOURCE_PREFIXES) or source in {"crawler", "browser"}


def _is_ai_source(source: str) -> bool:
    return source.startswith(_AI_SOURCE_PREFIXES) or source in {"ai", "llm"}


def _pattern(sequence: tuple[str, ...], first_ai: int, last_ai: int) -> str:
    if first_ai > 0 and last_ai < len(sequence) - 1:
        return "web_to_ai_to_web"
    if first_ai > 0:
        return "web_to_ai"
    if last_ai < len(sequence) - 1:
        return "ai_to_web"
    return "ai_internal"


def _rationale(pattern: str) -> str:
    return {
        "web_to_ai_to_web": "A Web surface reaches AI functionality and the same graph continues to a Web/backend capability.",
        "web_to_ai": "A Web surface can reach or influence AI functionality.",
        "ai_to_web": "AI functionality can reach another Web/backend capability.",
        "ai_internal": "The graph contains an AI-mediated path that crosses an internal trust boundary.",
    }[pattern]


def _attack_path_dict(path: AttackPath) -> dict[str, Any]:
    return {
        "id": path.id,
        "nodes": list(path.nodes),
        "relationships": list(path.relationships),
        "pattern": path.pattern,
        "confidence": path.confidence,
        "rationale": path.rationale,
        "metadata": path.metadata,
    }


def _correlation_dict(item: Correlation) -> dict[str, Any]:
    return {
        "id": item.id,
        "kind": item.kind,
        "asset_ids": list(item.asset_ids),
        "observation_ids": list(item.observation_ids),
        "finding_ids": list(item.finding_ids),
        "attack_path_id": item.attack_path_id,
        "confidence": item.confidence,
        "rationale": item.rationale,
        "metadata": item.metadata,
    }

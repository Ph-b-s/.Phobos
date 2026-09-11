"""Bounded authorization-focused modules for API, WebSocket, and object flows."""
from __future__ import annotations

from hashlib import sha256
from typing import Any, Mapping

from knowledge_store import SecurityObservation
from models import AssetType, Finding
from security_modules import ModuleContext
from workflow_engine import WorkflowContext, WorkflowEngine, WorkflowStep, WorkflowState

MAX_PAIRS = 24
MAX_STEPS = 24


def _id(prefix: str, value: str) -> str:
    return f"{prefix}:{sha256(value.encode('utf-8', errors='replace')).hexdigest()[:12]}"


def _digest(text: str) -> str:
    normalized = " ".join(text.split())
    return sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def _safe_url(url: str) -> str:
    from urllib.parse import urlsplit, urlunsplit
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _steps(raw: Any) -> tuple[WorkflowStep, ...]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("workflow must be a non-empty list")
    if len(raw) > MAX_STEPS:
        raise ValueError("workflow exceeds the step limit")
    result = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise TypeError("workflow contains a non-object step")
        result.append(WorkflowStep(
            id=str(item.get("id", "")),
            action=str(item.get("action", "")),
            description=str(item.get("description", "")),
            depends_on=tuple(str(dep) for dep in item.get("depends_on", ()) if dep),
            metadata=dict(item.get("metadata", {})) if isinstance(item.get("metadata", {}), Mapping) else {},
        ))
    return tuple(result)


def run_web_object_authorization(context: ModuleContext):
    """Compare explicitly configured owned/peer object URLs under one low-privilege workflow."""
    from module_runner import ModuleResult

    config = context.metadata.get("object_authorization")
    if not isinstance(config, Mapping):
        raise RuntimeError("web.object_authorization requires object_authorization configuration")
    if context.interactor is None or context.accounts is None or context.workflow is None:
        raise RuntimeError("web.object_authorization requires interactor, accounts, and workflow capabilities")
    pairs = config.get("pairs", ())
    if not isinstance(pairs, list) or not pairs:
        raise ValueError("object_authorization.pairs must be a non-empty list")
    engine = context.workflow if isinstance(context.workflow, WorkflowEngine) else None
    if engine is None:
        raise RuntimeError("web.object_authorization requires WorkflowEngine capability")
    workflow_id = str(config.get("low_workflow_id", "object-low-privilege"))
    steps = _steps(config.get("low_workflow"))
    result = engine.run(workflow_id, steps, WorkflowContext(
        target=context.target, browser=context.interactor, accounts=context.accounts,
        applications=tuple(context.applications),
    ))
    if result.state is not WorkflowState.COMPLETED:
        raise RuntimeError(f"object authorization workflow did not complete: {result.state.value}")

    observations = []
    findings = []
    for index, pair in enumerate(pairs[:MAX_PAIRS]):
        if not isinstance(pair, Mapping):
            raise TypeError("object_authorization pair must be an object")
        owned = str(pair.get("owned_url", "")).strip()
        peer = str(pair.get("peer_url", "")).strip()
        if not owned or not peer:
            raise ValueError("object_authorization pairs require owned_url and peer_url")
        first = context.interactor.open(owned)
        first_snapshot = context.interactor.snapshot()
        second = context.interactor.open(peer)
        second_snapshot = context.interactor.snapshot()
        same_signature = (
            _digest(first_snapshot.text) == _digest(second_snapshot.text)
            and len(first_snapshot.text) == len(second_snapshot.text)
        )
        oid = _id("web.object_authorization.observation", f"{owned}|{peer}")
        observations.append(SecurityObservation(
            id=oid, kind="web.object_authorization.object_pair", source="web.object_authorization",
            description="Explicitly configured owned and peer object resources compared under the same low-privilege session",
            data={"owned": _safe_url(owned), "peer": _safe_url(peer), "same_response_signature": same_signature},
            confidence=0.92,
        ))
        if same_signature:
            findings.append(Finding(
                id=_id("web.object_authorization.finding", f"{owned}|{peer}"),
                type="potential_idor_object_authorization_failure", confidence=0.78, evidence=(oid,),
                metadata={"severity": "high", "status": "needs_object_ownership_confirmation"},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_graphql_auth_surface(context: ModuleContext):
    """Identify GraphQL auth-sensitive fields/routes for later configured validation."""
    from module_runner import ModuleResult
    import re
    pattern = re.compile(r"(?:viewer|user|account|tenant|role|admin|permission|owner|organization|private|secret)", re.I)
    observations = []
    findings = []
    for asset in context.assets:
        if asset.type not in {AssetType.API, AssetType.ENDPOINT, AssetType.PAGE}:
            continue
        text = " ".join((asset.name, asset.url, str(asset.metadata))) if isinstance(asset.metadata, dict) else f"{asset.name} {asset.url}"
        if "graphql" not in text.lower() or not pattern.search(text):
            continue
        oid = _id("web.graphql_auth.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid, kind="web.graphql.auth_surface", source="web.graphql_auth_surface",
            description="GraphQL endpoint contains authorization-sensitive field or route hints",
            asset_ids=(asset.id,), data={"authorization_hints_present": True}, confidence=0.84,
        ))
        findings.append(Finding(
            id=_id("web.graphql_auth.finding", asset.id), type="graphql_authorization_surface",
            confidence=0.76, evidence=(oid,), metadata={"severity": "medium", "status": "requires_read_only_role_comparison"},
        ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_websocket_auth_surface(context: ModuleContext):
    """Identify WebSocket authentication signals without opening a socket or sending messages."""
    from module_runner import ModuleResult
    import re
    auth = re.compile(r"(?:auth|authorization|bearer|cookie|session|token|subprotocol|origin|csrf)", re.I)
    observations = []
    findings = []
    for asset in context.assets:
        if asset.type not in {AssetType.ENDPOINT, AssetType.API, AssetType.AI_AGENT} and not asset.url.startswith(("ws://", "wss://")):
            continue
        metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
        text = " ".join((asset.name, asset.url, str(metadata.get("source", "")), str(metadata.get("description", "")), str(metadata.get("headers", ""))))
        if not (asset.url.startswith(("ws://", "wss://")) or "websocket" in text.lower()):
            continue
        hints = sorted(set(auth.findall(text.lower())))
        oid = _id("web.websocket_auth.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid, kind="web.websocket.auth_surface", source="web.websocket_auth_surface",
            description="WebSocket authentication-related signals inventoried without connecting",
            asset_ids=(asset.id,), data={"auth_signals": hints[:12], "auth_metadata_observed": bool(hints)}, confidence=0.86,
        ))
        if not hints:
            findings.append(Finding(
                id=_id("web.websocket_auth.finding", asset.id), type="websocket_authentication_requires_review",
                confidence=0.68, evidence=(oid,), metadata={"severity": "medium", "status": "active_protocol_test_required"},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_ai_tool_rag_bridge(context: ModuleContext):
    """Connect AI tool and RAG surfaces when their descriptors share meaningful identifiers."""
    from module_runner import ModuleResult
    import re
    ai = [asset for asset in context.assets if asset.type in {AssetType.AI_AGENT, AssetType.TOOL, AssetType.RESOURCE, AssetType.API}]
    tools = [asset for asset in ai if re.search(r"tool|function|plugin|action|connector", f"{asset.name} {asset.metadata}", re.I)]
    rag = [asset for asset in ai if re.search(r"rag|retriev|vector|embedding|document|knowledge", f"{asset.name} {asset.metadata}", re.I)]
    observations = []
    follow_ups = []
    for left in tools[:16]:
        left_terms = set(re.findall(r"[a-z][a-z0-9_-]{3,}", f"{left.name} {left.url}".lower()))
        for right in rag[:16]:
            right_terms = set(re.findall(r"[a-z][a-z0-9_-]{3,}", f"{right.name} {right.url}".lower()))
            overlap = sorted(left_terms & right_terms - {"https", "http", "agent", "tool"})
            if not overlap:
                continue
            oid = _id("ai.tool_rag.observation", f"{left.id}:{right.id}")
            observations.append(SecurityObservation(
                id=oid, kind="ai.tool_rag.bridge", source="ai.tool_rag_bridge",
                description="AI tool and retrieval surfaces share application identifiers and may form a compound trust boundary",
                asset_ids=(left.id, right.id), data={"shared_terms": overlap[:8]}, confidence=0.80,
            ))
            follow_ups.append({"module_id": "cross_layer.auth_boundary", "priority": 0.80,
                               "asset_ids": [left.id, right.id], "reason": "tool and retrieval surfaces share identifiers; validate authorization propagation"})
            follow_ups.append({"module_id": "cross_layer.data_flow", "priority": 0.78,
                               "asset_ids": [left.id, right.id], "reason": "tool and retrieval surfaces share identifiers; review data movement"})
    return ModuleResult(observations=tuple(observations[:64]), follow_ups=tuple(follow_ups[:128]))

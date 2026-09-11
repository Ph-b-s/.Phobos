"""Bounded authorization-focused modules for API, WebSocket, and object flows."""
from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from knowledge_store import SecurityObservation
from models import AssetType, Finding
from security_modules import ModuleContext
from workflow_engine import WorkflowContext, WorkflowEngine, WorkflowStep, WorkflowState

MAX_PAIRS = 24
MAX_STEPS = 24
MAX_GRAPHQL_ENDPOINTS = 8
MAX_QUERY_CHARS = 8_000
MAX_BODY_CHARS = 160_000


def _id(prefix: str, value: str) -> str:
    return f"{prefix}:{sha256(value.encode('utf-8', errors='replace')).hexdigest()[:12]}"


def _digest(text: str) -> str:
    normalized = " ".join(text.split())
    return sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def _safe_url(url: str) -> str:
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
        context.interactor.open(owned)
        first_snapshot = context.interactor.snapshot()
        context.interactor.open(peer)
        second_snapshot = context.interactor.snapshot()
        same_signature = (_digest(first_snapshot.text) == _digest(second_snapshot.text)
                          and len(first_snapshot.text) == len(second_snapshot.text))
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
    """Identify GraphQL auth-sensitive fields and optionally run a configured read-only role comparison."""
    from module_runner import ModuleResult
    config = context.metadata.get("graphql_auth")
    if config is not None:
        return _run_graphql_auth_comparison(context, config)

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


def _graphql_headers(raw: Any, label: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise TypeError(f"{label} must be an object")
    result = {}
    for key, value in raw.items():
        name = str(key).strip()
        if not name or len(name) > 128:
            raise ValueError(f"{label} contains an invalid header name")
        result[name] = str(value)[:8_000]
    return result


def _run_graphql_auth_comparison(context: ModuleContext, config: Any) -> ModuleResult:
    from module_runner import ModuleResult
    if not isinstance(config, Mapping):
        raise TypeError("graphql_auth must be an object")
    requests = context.metadata.get("request_manager")
    if requests is None:
        raise RuntimeError("web.graphql_auth_surface requires request_manager for configured active validation")
    endpoints = tuple(dict.fromkeys(str(url).strip() for url in config.get("endpoints", ()) if str(url).strip()))[:MAX_GRAPHQL_ENDPOINTS]
    if not endpoints:
        raise ValueError("graphql_auth.endpoints must contain at least one endpoint")
    query = str(config.get("query", "")).strip()
    if not query or len(query) > MAX_QUERY_CHARS:
        raise ValueError("graphql_auth.query must be non-empty and within the query limit")
    if any(token in query.casefold() for token in ("mutation", "subscription")):
        raise ValueError("graphql_auth.query must be read-only; mutations and subscriptions are not allowed")
    low_headers = _graphql_headers(config.get("low_headers"), "low_headers")
    high_headers = _graphql_headers(config.get("high_headers"), "high_headers")
    body = json.dumps({"query": query}, separators=(",", ":")).encode("utf-8")
    observations = []
    findings = []
    for index, url in enumerate(endpoints):
        low = requests.request("POST", url, headers={**low_headers, "Content-Type": "application/json", "Accept": "application/json"}, body=body)
        high = requests.request("POST", url, headers={**high_headers, "Content-Type": "application/json", "Accept": "application/json"}, body=body)
        low_text, high_text = low.text[:MAX_BODY_CHARS], high.text[:MAX_BODY_CHARS]
        same = low.status == high.status and _digest(low_text) == _digest(high_text) and len(low_text) == len(high_text)
        oid = _id("web.graphql_auth.comparison", f"{url}:{query}")
        observations.append(SecurityObservation(
            id=oid, kind="web.graphql.authorization_comparison", source="web.graphql_auth_surface",
            description="Configured low/high GraphQL role requests compared with a read-only query",
            data={"url": _safe_url(url),
                  "low": {"status": low.status, "body_digest": _digest(low_text), "body_length": len(low_text)},
                  "high": {"status": high.status, "body_digest": _digest(high_text), "body_length": len(high_text)},
                  "same_response_signature": same}, confidence=0.94,
        ))
        if same:
            findings.append(Finding(
                id=_id("web.graphql_auth.finding", f"{url}:{index}"), type="potential_graphql_authorization_failure",
                confidence=0.77, evidence=(oid,), metadata={"severity": "high", "url": _safe_url(url),
                "validation": "low/high GraphQL role requests returned identical normalized signatures",
                "status": "needs_context_confirmation"},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_websocket_auth_surface(context: ModuleContext):
    """Identify WebSocket authentication signals without opening a socket or sending messages."""
    from module_runner import ModuleResult
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

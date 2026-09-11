"""Passive surface-to-procedure analysis for Web and AI security coverage."""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from knowledge_store import SecurityObservation
from models import AssetType, Finding

MAX_ASSETS = 96
MAX_SIGNALS_PER_ASSET = 12
MAX_RAG_ENDPOINTS = 8
MAX_RAG_QUERY_CHARS = 2_000
MAX_RAG_RESPONSE_CHARS = 80_000
MAX_RAG_MARKERS = 16

_SSRF_NAMES = re.compile(r"(?<![a-z0-9])(?:url|uri|href|src|callback|webhook|redirect|return|next|image|fetch|proxy)(?![a-z0-9])", re.I)
_COMMAND_NAMES = re.compile(r"(?<![a-z0-9])(?:cmd|command|exec|execute|shell|script|ping|host)(?![a-z0-9])", re.I)
_XML_HINTS = re.compile(r"(?:application/xml|text/xml|xmlrpc|soap|xsd|xmlns|<\?xml)", re.I)
_SERIALIZATION_HINTS = re.compile(r"(?:pickle|deserialize|serialization|serialized|marshal|yaml|objectinputstream|base64)(?:[^a-z]|$)", re.I)
_BUSINESS_HINTS = re.compile(r"(?:checkout|purchase|transfer|withdraw|redeem|coupon|invite|role|permission|approval|refund|reset|change[-_ ]email|change[-_ ]password)", re.I)
_RAG_HINTS = re.compile(r"(?:rag|retriev|knowledge base|documents?|vector|embedding|semantic search|grounding)", re.I)
_VECTOR_HINTS = re.compile(r"(?:vector|embedding|pinecone|weaviate|qdrant|milvus|faiss)", re.I)
_MULTI_AGENT_HINTS = re.compile(r"(?:agent[-_ ]to[-_ ]agent|multi[-_ ]agent|handoff|delegat(?:e|ion)|subagent|worker[-_ ]agent)", re.I)
_TOOL_HINTS = re.compile(r"(?:tool[_ -]?call|function[_ -]?call|plugin|action|connector|integration|browser automation)", re.I)


def _id(prefix: str, asset_id: str, detail: str = "") -> str:
    return f"{prefix}:{hashlib.sha256(f'{asset_id}:{detail}'.encode()).hexdigest()[:12]}"


def _text(asset) -> str:
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    return " ".join((asset.name, asset.url, str(metadata.get("source", "")), str(metadata.get("description", "")), str(metadata.get("route", "")), str(metadata.get("parameter", "")), str(metadata.get("parameters", "")), str(metadata.get("capabilities", ""))))[:12_000]


def _input_names(asset) -> tuple[str, ...]:
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    values = metadata.get("inputs") or metadata.get("fields") or metadata.get("parameters") or ()
    if isinstance(values, dict):
        values = values.keys()
    if not isinstance(values, (list, tuple, set)) and not hasattr(values, "__iter__"):
        values = ()
    result: list[str] = []
    for value in values:
        name = value.get("name") or value.get("id") or "" if isinstance(value, dict) else value
        name = str(name).strip()
        if name and name not in result:
            result.append(name)
        if len(result) >= 16:
            break
    parameter = str(metadata.get("parameter", "")).strip()
    if parameter and parameter not in result:
        result.append(parameter)
    return tuple(result)


def _emit_surface(context, module_id: str, finding_type: str, patterns, *, severity: str = "medium"):
    from module_runner import ModuleResult
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for asset in context.assets[:MAX_ASSETS]:
        names = _input_names(asset)
        combined = " ".join((*names, _text(asset)))
        matched = list(dict.fromkeys(pattern.pattern for pattern in patterns if pattern.search(combined)))[:MAX_SIGNALS_PER_ASSET]
        if not matched:
            continue
        oid = _id(f"{module_id}.observation", asset.id, "|".join(matched))
        observations.append(SecurityObservation(id=oid, kind=f"{module_id}.surface", source=module_id, description=f"Potential {module_id} surface discovered on {asset.name}", asset_ids=(asset.id,), data={"signals": matched, "input_names": list(names)[:16], "url_path": urlsplit(asset.url).path if asset.url else ""}, confidence=0.84))
        findings.append(Finding(id=_id(f"{module_id}.finding", asset.id, "|".join(matched)), type=finding_type, confidence=0.72, evidence=(oid,), metadata={"severity": severity, "status": "surface_identified_requires_active_validation"}))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_ssrf(context): return _emit_surface(context, "web.ssrf", "potential_ssrf_sink", (_SSRF_NAMES,), severity="medium")
def run_web_command_injection(context): return _emit_surface(context, "web.command_injection", "potential_command_execution_sink", (_COMMAND_NAMES,), severity="high")
def run_web_xxe(context): return _emit_surface(context, "web.xxe", "potential_xml_processing_surface", (_XML_HINTS,), severity="medium")
def run_web_deserialization(context): return _emit_surface(context, "web.deserialization", "potential_unsafe_deserialization_surface", (_SERIALIZATION_HINTS,), severity="high")
def run_web_business_logic(context): return _emit_surface(context, "web.business_logic", "business_logic_workflow_candidate", (_BUSINESS_HINTS,), severity="medium")


def _emit_ai_surface(context, module_id: str, finding_type: str, patterns, description: str):
    from module_runner import ModuleResult
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for asset in context.assets[:MAX_ASSETS]:
        if asset.type not in {AssetType.AI_AGENT, AssetType.TOOL, AssetType.RESOURCE, AssetType.API, AssetType.ENDPOINT}:
            continue
        combined = _text(asset)
        matched = list(dict.fromkeys(pattern.pattern for pattern in patterns if pattern.search(combined)))[:MAX_SIGNALS_PER_ASSET]
        if not matched:
            continue
        oid = _id(f"{module_id}.observation", asset.id, "|".join(matched))
        observations.append(SecurityObservation(id=oid, kind=f"{module_id}.surface", source=module_id, description=description, asset_ids=(asset.id,), data={"signals": matched, "asset_type": asset.type.value}, confidence=0.86))
        findings.append(Finding(id=_id(f"{module_id}.finding", asset.id, "|".join(matched)), type=finding_type, confidence=0.74, evidence=(oid,), metadata={"severity": "medium", "status": "surface_identified_requires_boundary_validation"}))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def _rag_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _rag_headers(raw, label: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise TypeError(f"{label} must be an object")
    result = {}
    for key, value in raw.items():
        name = str(key).strip()
        if not name or len(name) > 128:
            raise ValueError(f"{label} contains an invalid header name")
        result[name] = str(value)[:8_000]
    return result


def _run_configured_rag(context, config):
    from module_runner import ModuleResult
    if not isinstance(config, dict):
        raise TypeError("rag_validation must be an object")
    if config.get("read_only") is not True:
        raise ValueError("rag_validation requires explicit read_only=true")
    requests = context.metadata.get("request_manager")
    if requests is None:
        raise RuntimeError("ai.rag configured validation requires request_manager")
    endpoints = tuple(dict.fromkeys(str(item).strip() for item in config.get("endpoints", ()) if str(item).strip()))[:MAX_RAG_ENDPOINTS]
    if not endpoints:
        raise ValueError("rag_validation.endpoints must contain at least one endpoint")
    query = str(config.get("query", "")).strip()
    if not query or len(query) > MAX_RAG_QUERY_CHARS:
        raise ValueError("rag_validation.query must be non-empty and within the query limit")
    method = str(config.get("method", "POST")).upper()
    if method not in {"GET", "POST"}:
        raise ValueError("rag_validation.method must be GET or POST")
    low_headers = _rag_headers(config.get("low_headers"), "low_headers")
    high_headers = _rag_headers(config.get("high_headers"), "high_headers")
    forbidden = tuple(dict.fromkeys(str(item) for item in config.get("forbidden_markers", ()) if str(item)))[:MAX_RAG_MARKERS]
    allowed = tuple(dict.fromkeys(str(item) for item in config.get("allowed_markers", ()) if str(item)))[:MAX_RAG_MARKERS]
    observations = []
    findings = []
    for index, endpoint in enumerate(endpoints):
        if method == "GET":
            safe_query = json.dumps({"query": query}, separators=(",", ":"))
            suffix = "&" if "?" in endpoint else "?"
            request_url = endpoint + suffix + "q=" + __import__("urllib.parse", fromlist=["quote"]).quote(query, safe="")
            low = requests.get(request_url, headers=low_headers)
            high = requests.get(request_url, headers=high_headers)
        else:
            body = json.dumps({"query": query}, separators=(",", ":")).encode("utf-8")
            low = requests.request("POST", endpoint, headers={**low_headers, "Content-Type": "application/json", "Accept": "application/json"}, body=body)
            high = requests.request("POST", endpoint, headers={**high_headers, "Content-Type": "application/json", "Accept": "application/json"}, body=body)
        low_text = low.text[:MAX_RAG_RESPONSE_CHARS]
        high_text = high.text[:MAX_RAG_RESPONSE_CHARS]
        identical = low.status == high.status and _rag_digest(low_text) == _rag_digest(high_text) and len(low_text) == len(high_text)
        forbidden_low = tuple(marker for marker in forbidden if marker in low_text)
        forbidden_high = tuple(marker for marker in forbidden if marker in high_text)
        allowed_low = tuple(marker for marker in allowed if marker in low_text)
        allowed_high = tuple(marker for marker in allowed if marker in high_text)
        oid = _id("ai.rag.validation", context.target, f"{endpoint}:{query}:{index}")
        observations.append(SecurityObservation(id=oid, kind="ai.rag.authorization_grounding_validation", source="ai.rag", description="Configured low/high RAG retrieval responses compared with explicit authorization and grounding markers.", data={"endpoint": urlsplit(endpoint)._replace(query="", fragment="").geturl(), "method": method, "query_digest": _rag_digest(query), "low": {"status": low.status, "body_digest": _rag_digest(low_text), "body_length": len(low_text), "forbidden_markers_observed": list(forbidden_low), "allowed_markers_observed": list(allowed_low)}, "high": {"status": high.status, "body_digest": _rag_digest(high_text), "body_length": len(high_text), "forbidden_markers_observed": list(forbidden_high), "allowed_markers_observed": list(allowed_high)}, "identical_response_signature": identical}, confidence=0.94))
        if forbidden_low:
            findings.append(Finding(id=_id("ai.rag.finding", endpoint, f"auth:{index}"), type="ai_rag_authorization_failure", confidence=0.88, evidence=(oid,), metadata={"severity": "high", "status": "forbidden_rag_content_observed_for_low_privilege"}))
        if forbidden_high and not forbidden_low:
            findings.append(Finding(id=_id("ai.rag.finding", endpoint, f"grounding:{index}"), type="ai_rag_grounding_boundary_signal", confidence=0.84, evidence=(oid,), metadata={"severity": "medium", "status": "configured_high_privilege_source_observed"}))
        if identical and not findings:
            findings.append(Finding(id=_id("ai.rag.finding", endpoint, f"comparison:{index}"), type="ai_rag_authorization_consistency_signal", confidence=0.72, evidence=(oid,), metadata={"severity": "medium", "status": "low_high_retrieval_signatures_identical_requires_context_confirmation"}))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_ai_rag(context):
    configured = context.metadata.get("rag_validation")
    if configured is not None:
        return _run_configured_rag(context, configured)
    return _emit_ai_surface(context, "ai.rag", "rag_surface_detected", (_RAG_HINTS,), "RAG/retrieval-related AI surface discovered and queued for authorization/grounding validation.")


def run_ai_vector(context): return _emit_ai_surface(context, "ai.vector", "vector_store_surface_detected", (_VECTOR_HINTS,), "Vector/embedding-related surface discovered and queued for isolation and authorization validation.")
def run_ai_multi_agent(context): return _emit_ai_surface(context, "ai.multi_agent", "multi_agent_surface_detected", (_MULTI_AGENT_HINTS,), "Multi-agent or agent-handoff surface discovered and queued for trust-boundary validation.")
def run_ai_tool_abuse(context): return _emit_ai_surface(context, "ai.tool_abuse", "ai_tool_surface_detected", (_TOOL_HINTS,), "Model-controlled tool or action surface discovered and queued for authorization-boundary validation.")
def run_ai_data_poisoning(context): return _emit_ai_surface(context, "ai.data_poisoning", "untrusted_ai_context_source_detected", (_RAG_HINTS, _TOOL_HINTS), "Potential untrusted content source feeding AI context discovered and queued for poisoning/influence validation.")


def run_ai_unbounded_consumption(context):
    from module_runner import ModuleResult
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for asset in context.assets[:MAX_ASSETS]:
        if asset.type not in {AssetType.AI_AGENT, AssetType.API, AssetType.ENDPOINT}: continue
        metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
        text = _text(asset)
        if not (_TOOL_HINTS.search(text) or _RAG_HINTS.search(text) or asset.type is AssetType.AI_AGENT): continue
        has_limits = any(metadata.get(key) not in (None, "", 0, False) for key in ("max_tokens", "timeout", "rate_limit", "request_limit", "budget_limit"))
        oid = _id("ai.unbounded_consumption.observation", asset.id)
        observations.append(SecurityObservation(id=oid, kind="ai.unbounded_consumption.surface", source="ai.unbounded_consumption", description="AI-capable surface inspected for explicit resource-consumption controls.", asset_ids=(asset.id,), data={"explicit_limits_observed": has_limits}, confidence=0.82))
        if not has_limits: findings.append(Finding(id=_id("ai.unbounded_consumption.finding", asset.id), type="ai_resource_limits_not_observed", confidence=0.68, evidence=(oid,), metadata={"severity": "low", "status": "requires_runtime_rate_and_cost_validation"}))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

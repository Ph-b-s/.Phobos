"""Passive surface-to-procedure analysis for Web and AI security coverage."""
from __future__ import annotations

import re
from hashlib import sha256
from urllib.parse import urlsplit

from knowledge_store import SecurityObservation
from models import AssetType, Finding

MAX_ASSETS = 96
MAX_SIGNALS_PER_ASSET = 12

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
    return f"{prefix}:{sha256(f'{asset_id}:{detail}'.encode()).hexdigest()[:12]}"


def _text(asset) -> str:
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    return " ".join(
        (
            asset.name,
            asset.url,
            str(metadata.get("source", "")),
            str(metadata.get("description", "")),
            str(metadata.get("route", "")),
            str(metadata.get("parameter", "")),
            str(metadata.get("parameters", "")),
            str(metadata.get("capabilities", "")),
        )
    )[:12_000]


def _input_names(asset) -> tuple[str, ...]:
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    values = metadata.get("inputs") or metadata.get("fields") or metadata.get("parameters") or ()
    if isinstance(values, dict):
        values = values.keys()
    if not isinstance(values, (list, tuple, set)) and not hasattr(values, "__iter__"):
        values = ()
    result: list[str] = []
    for value in values:
        if isinstance(value, dict):
            name = value.get("name") or value.get("id") or ""
        else:
            name = value
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
        observations.append(SecurityObservation(
            id=oid, kind=f"{module_id}.surface", source=module_id,
            description=f"Potential {module_id} surface discovered on {asset.name}",
            asset_ids=(asset.id,),
            data={"signals": matched, "input_names": list(names)[:16],
                  "url_path": urlsplit(asset.url).path if asset.url else ""},
            confidence=0.84,
        ))
        findings.append(Finding(
            id=_id(f"{module_id}.finding", asset.id, "|".join(matched)),
            type=finding_type, confidence=0.72, evidence=(oid,),
            metadata={"severity": severity, "status": "surface_identified_requires_active_validation"},
        ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_ssrf(context):
    return _emit_surface(context, "web.ssrf", "potential_ssrf_sink", (_SSRF_NAMES,), severity="medium")


def run_web_command_injection(context):
    return _emit_surface(context, "web.command_injection", "potential_command_execution_sink", (_COMMAND_NAMES,), severity="high")


def run_web_xxe(context):
    return _emit_surface(context, "web.xxe", "potential_xml_processing_surface", (_XML_HINTS,), severity="medium")


def run_web_deserialization(context):
    return _emit_surface(context, "web.deserialization", "potential_unsafe_deserialization_surface", (_SERIALIZATION_HINTS,), severity="high")


def run_web_business_logic(context):
    return _emit_surface(context, "web.business_logic", "business_logic_workflow_candidate", (_BUSINESS_HINTS,), severity="medium")


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
        observations.append(SecurityObservation(
            id=oid, kind=f"{module_id}.surface", source=module_id,
            description=description, asset_ids=(asset.id,),
            data={"signals": matched, "asset_type": asset.type.value}, confidence=0.86,
        ))
        findings.append(Finding(
            id=_id(f"{module_id}.finding", asset.id, "|".join(matched)),
            type=finding_type, confidence=0.74, evidence=(oid,),
            metadata={"severity": "medium", "status": "surface_identified_requires_boundary_validation"},
        ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_ai_rag(context):
    return _emit_ai_surface(context, "ai.rag", "rag_surface_detected", (_RAG_HINTS,), "RAG/retrieval-related AI surface discovered and queued for authorization/grounding validation.")


def run_ai_vector(context):
    return _emit_ai_surface(context, "ai.vector", "vector_store_surface_detected", (_VECTOR_HINTS,), "Vector/embedding-related surface discovered and queued for isolation and authorization validation.")


def run_ai_multi_agent(context):
    return _emit_ai_surface(context, "ai.multi_agent", "multi_agent_surface_detected", (_MULTI_AGENT_HINTS,), "Multi-agent or agent-handoff surface discovered and queued for trust-boundary validation.")


def run_ai_tool_abuse(context):
    return _emit_ai_surface(context, "ai.tool_abuse", "ai_tool_surface_detected", (_TOOL_HINTS,), "Model-controlled tool or action surface discovered and queued for authorization-boundary validation.")


def run_ai_data_poisoning(context):
    return _emit_ai_surface(context, "ai.data_poisoning", "untrusted_ai_context_source_detected", (_RAG_HINTS, _TOOL_HINTS), "Potential untrusted content source feeding AI context discovered and queued for poisoning/influence validation.")


def run_ai_unbounded_consumption(context):
    from module_runner import ModuleResult

    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for asset in context.assets[:MAX_ASSETS]:
        if asset.type not in {AssetType.AI_AGENT, AssetType.API, AssetType.ENDPOINT}:
            continue
        metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
        text = _text(asset)
        if not (_TOOL_HINTS.search(text) or _RAG_HINTS.search(text) or asset.type is AssetType.AI_AGENT):
            continue
        has_limits = any(metadata.get(key) not in (None, "", 0, False) for key in ("max_tokens", "timeout", "rate_limit", "request_limit", "budget_limit"))
        oid = _id("ai.unbounded_consumption.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid, kind="ai.unbounded_consumption.surface", source="ai.unbounded_consumption",
            description="AI-capable surface inspected for explicit resource-consumption controls.", asset_ids=(asset.id,),
            data={"explicit_limits_observed": has_limits}, confidence=0.82,
        ))
        if not has_limits:
            findings.append(Finding(
                id=_id("ai.unbounded_consumption.finding", asset.id),
                type="ai_resource_limits_not_observed", confidence=0.68, evidence=(oid,),
                metadata={"severity": "low", "status": "requires_runtime_rate_and_cost_validation"},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

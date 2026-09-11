"""Small passive modules that connect discovered Web and AI surfaces."""
from __future__ import annotations

import re
from hashlib import sha256
from urllib.parse import parse_qsl, urlsplit

from knowledge_store import SecurityObservation
from models import AssetType, Finding

MAX_ASSETS = 128
MAX_ITEMS = 64


def _id(prefix: str, value: str) -> str:
    return f"{prefix}:{sha256(value.encode('utf-8', errors='replace')).hexdigest()[:12]}"


def _text(asset) -> str:
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    parts = [asset.name, asset.url]
    for key in ("description", "source", "route", "parameter", "parameters", "capabilities", "content_type"):
        value = metadata.get(key)
        if value:
            parts.append(str(value))
    return " ".join(parts)


def _redact_url(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _web_assets(context):
    allowed = {AssetType.PAGE, AssetType.ENDPOINT, AssetType.API, AssetType.FORM, AssetType.INPUT, AssetType.JAVASCRIPT}
    return tuple(asset for asset in context.assets if asset.type in allowed and len(asset.url) <= 2048)[:MAX_ASSETS]


def _finding(type_: str, key: str, evidence: str, severity: str, confidence: float, **metadata):
    return Finding(
        id=_id(f"integration.{type_}", key),
        type=type_,
        confidence=confidence,
        evidence=(evidence,),
        metadata={"severity": severity, **metadata},
    )


def run_web_openapi(context):
    """Identify OpenAPI/Swagger surfaces for bounded follow-up validation."""
    from module_runner import ModuleResult

    observations = []
    findings = []
    pattern = re.compile(r"(?:openapi|swagger)(?:\.json|\.ya?ml|/|$)", re.I)
    for asset in _web_assets(context):
        text = _text(asset)
        if not pattern.search(text):
            continue
        oid = _id("web.openapi.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid,
            kind="web.openapi.surface",
            source="web.openapi",
            description="OpenAPI/Swagger surface identified for structured API follow-up",
            asset_ids=(asset.id,),
            data={"url": _redact_url(asset.url)},
            confidence=0.92,
        ))
        findings.append(_finding("openapi_surface_detected", asset.id, oid, "informational", 0.92, requires_api_validation=True))
    return ModuleResult(observations=tuple(observations[:MAX_ITEMS]), findings=tuple(findings[:MAX_ITEMS]))


def run_web_open_redirect(context):
    """Identify likely open-redirect parameters without issuing redirect probes."""
    from module_runner import ModuleResult

    candidates = re.compile(r"^(?:next|url|uri|redirect|redirect_url|return|return_url|continue|dest|destination|target|to)$", re.I)
    observations = []
    findings = []
    for asset in _web_assets(context):
        names = []
        names.extend(str(item) for item in ((asset.metadata or {}).get("parameters", ()) if isinstance(asset.metadata, dict) else ()))
        for name, _ in parse_qsl(urlsplit(asset.url).query, keep_blank_values=True):
            names.append(name)
        if not any(candidates.fullmatch(name.strip()) for name in names[:32]):
            continue
        oid = _id("web.redirect.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid,
            kind="web.redirect.parameter",
            source="web.open_redirect",
            description="Redirect-like parameter identified; no external redirect was requested",
            asset_ids=(asset.id,),
            data={"parameter_names": sorted({name.lower() for name in names if candidates.fullmatch(name.strip())})[:8]},
            confidence=0.86,
        ))
        findings.append(_finding("open_redirect_candidate", asset.id, oid, "low", 0.80, requires_redirect_validation=True))
    return ModuleResult(observations=tuple(observations[:MAX_ITEMS]), findings=tuple(findings[:MAX_ITEMS]))


def run_web_source_maps(context):
    """Identify JavaScript source-map exposure candidates."""
    from module_runner import ModuleResult

    observations = []
    findings = []
    for asset in context.assets:
        if asset.type is not AssetType.JAVASCRIPT and asset.type is not AssetType.PAGE:
            continue
        text = _text(asset)
        if not (re.search(r"\.map(?:$|[?#])", asset.url, re.I) or re.search(r"sourceMappingURL\s*=", text, re.I)):
            continue
        oid = _id("web.sourcemap.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid,
            kind="web.sourcemap.surface",
            source="web.source_maps",
            description="JavaScript source-map reference identified",
            asset_ids=(asset.id,),
            data={"url": _redact_url(asset.url)},
            confidence=0.90,
        ))
        findings.append(_finding("source_map_exposure_candidate", asset.id, oid, "low", 0.86, requires_exposure_validation=True))
    return ModuleResult(observations=tuple(observations[:MAX_ITEMS]), findings=tuple(findings[:MAX_ITEMS]))


def run_web_sensitive_inputs(context):
    """Inventory sensitive-looking input names without retaining their values."""
    from module_runner import ModuleResult

    pattern = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|session)", re.I)
    observations = []
    findings = []
    for asset in _web_assets(context):
        names = []
        if isinstance(asset.metadata, dict):
            for key in ("parameters", "inputs", "fields"):
                value = asset.metadata.get(key, ())
                if isinstance(value, dict):
                    names.extend(str(item) for item in value)
                elif isinstance(value, (list, tuple, set)):
                    for item in value:
                        names.append(str(item.get("name", item) if isinstance(item, dict) else item))
        names.extend(name for name, _ in parse_qsl(urlsplit(asset.url).query, keep_blank_values=True))
        matches = sorted({name.lower() for name in names if pattern.search(name)})[:12]
        if not matches:
            continue
        oid = _id("web.sensitive_inputs.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid,
            kind="web.sensitive_input.surface",
            source="web.sensitive_inputs",
            description="Sensitive-looking input names identified without storing values",
            asset_ids=(asset.id,),
            data={"parameter_names": matches},
            confidence=0.90,
        ))
        findings.append(_finding("sensitive_input_surface", asset.id, oid, "informational", 0.88, value_storage=False))
    return ModuleResult(observations=tuple(observations[:MAX_ITEMS]), findings=tuple(findings[:MAX_ITEMS]))


def run_ai_memory(context):
    """Identify likely persistent memory/session context surfaces."""
    from module_runner import ModuleResult

    pattern = re.compile(r"(?:memory|conversation|chat history|history|session context|persistent context|long[- ]term)", re.I)
    observations = []
    findings = []
    for asset in context.assets:
        if asset.type not in {AssetType.AI_AGENT, AssetType.ENDPOINT, AssetType.API, AssetType.PAGE}:
            continue
        if not pattern.search(_text(asset)):
            continue
        oid = _id("ai.memory.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid,
            kind="ai.memory.surface",
            source="ai.memory",
            description="AI memory or persistent context surface identified",
            asset_ids=(asset.id,),
            data={"url": _redact_url(asset.url)},
            confidence=0.88,
        ))
        findings.append(_finding("ai_memory_surface_detected", asset.id, oid, "low", 0.82, requires_cross_user_isolation_test=True))
    return ModuleResult(observations=tuple(observations[:MAX_ITEMS]), findings=tuple(findings[:MAX_ITEMS]))


def run_ai_identity(context):
    """Identify AI surfaces carrying user, tenant, role, or identity context."""
    from module_runner import ModuleResult

    pattern = re.compile(r"(?:user[_ -]?id|tenant[_ -]?id|account[_ -]?id|role|admin|privilege|permission|identity|organization)", re.I)
    observations = []
    findings = []
    for asset in context.assets:
        if asset.type not in {AssetType.AI_AGENT, AssetType.ENDPOINT, AssetType.API, AssetType.INPUT}:
            continue
        text = _text(asset)
        if not pattern.search(text):
            continue
        oid = _id("ai.identity.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid,
            kind="ai.identity.surface",
            source="ai.identity",
            description="AI identity/privilege context identified for boundary validation",
            asset_ids=(asset.id,),
            data={"identity_context_present": True},
            confidence=0.86,
        ))
        findings.append(_finding("ai_identity_boundary_candidate", asset.id, oid, "medium", 0.80, requires_authorization_validation=True))
    return ModuleResult(observations=tuple(observations[:MAX_ITEMS]), findings=tuple(findings[:MAX_ITEMS]))


def run_ai_trust_boundary(context):
    """Connect AI assets to nearby Web assets using shared identifiers and routes."""
    from module_runner import ModuleResult

    ai_assets = [asset for asset in context.assets if asset.type in {AssetType.AI_AGENT, AssetType.TOOL}]
    web_assets = [asset for asset in context.assets if asset.type in {AssetType.ENDPOINT, AssetType.API, AssetType.FORM, AssetType.PAGE}]
    observations = []
    follow_ups = []
    for ai in ai_assets[:32]:
        ai_text = _text(ai).lower()
        for web in web_assets[:MAX_ASSETS]:
            web_text = _text(web).lower()
            overlap = set(re.findall(r"[a-z][a-z0-9_-]{3,}", ai_text)) & set(re.findall(r"[a-z][a-z0-9_-]{3,}", web_text))
            meaningful = {item for item in overlap if item not in {"https", "http", "example", "agent", "page", "endpoint", "api"}}
            if not meaningful:
                continue
            oid = _id("ai.trust_boundary.observation", f"{ai.id}:{web.id}")
            observations.append(SecurityObservation(
                id=oid,
                kind="cross_layer.shared_identifier",
                source="ai.trust_boundary",
                description="AI and Web assets share identifiers or route terms that may cross a trust boundary",
                asset_ids=(ai.id, web.id),
                data={"shared_terms": sorted(meaningful)[:8]},
                confidence=0.74,
            ))
            follow_ups.append({
                "module_id": "cross_layer.auth_boundary",
                "reason": "AI/Web assets share application identifiers; review authorization propagation",
                "asset_ids": [ai.id, web.id],
                "priority": 0.74,
            })
            if len(observations) >= MAX_ITEMS:
                break
        if len(observations) >= MAX_ITEMS:
            break
    return ModuleResult(observations=tuple(observations), follow_ups=tuple(follow_ups[:MAX_ITEMS]))

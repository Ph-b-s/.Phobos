"""Additional bounded modules for remaining Web/AI trust-boundary coverage."""
from __future__ import annotations

import json
import re
from hashlib import sha256
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from knowledge_store import SecurityObservation
from models import AssetType, Finding

MAX_TARGETS = 48
MAX_PARAMS = 8
MAX_WEBSOCKETS = 32
TRAVERSAL_MARKER = "PHOBOS_TRAVERSAL_NOT_FOUND"


def _requests(context):
    value = context.metadata.get("request_manager")
    if value is None:
        raise RuntimeError("Web module requires request_manager in module metadata")
    return value


def _finding_id(prefix: str, key: str) -> str:
    return f"{prefix}:{sha256(key.encode()).hexdigest()[:12]}"


def _web_targets(context):
    seen: set[str] = set()
    result = []
    for asset in context.assets:
        if asset.type not in {AssetType.PAGE, AssetType.ENDPOINT, AssetType.API} or not asset.url:
            continue
        if asset.url in seen:
            continue
        seen.add(asset.url)
        result.append(asset)
        if len(result) >= MAX_TARGETS:
            break
    return tuple(result)


def _redacted_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "<redacted>", ""))


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def run_web_path_traversal(context):
    """Probe GET query parameters with a nonexistent traversal marker only.

    A result is reported as a signal when the response changes materially from
    baseline while returning a successful response; confirmation still requires
    manual/contextual validation because harmless normalization can look similar.
    """
    from module_runner import ModuleResult

    requests = _requests(context)
    observations = []
    findings = []
    for asset in _web_targets(context):
        parsed = urlsplit(asset.url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs:
            continue
        try:
            baseline = requests.get(asset.url)
        except Exception:
            continue
        baseline_sig = (baseline.status, _digest(baseline.text[:8000]))
        for index, (name, value) in enumerate(pairs[:MAX_PARAMS]):
            mutated = list(pairs)
            mutated[index] = (name, f"../../{TRAVERSAL_MARKER}")
            probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), parsed.fragment))
            try:
                response = requests.get(probe_url)
            except Exception:
                continue
            changed = (response.status, _digest(response.text[:8000])) != baseline_sig
            oid = _finding_id("web.path_traversal.observation", f"{asset.id}:{name}")
            observations.append(SecurityObservation(
                id=oid,
                kind="web.path_traversal.probe",
                source="web.path_traversal",
                description=f"Traversal probe completed for parameter {name}",
                asset_ids=(asset.id,),
                data={"parameter": name, "changed": changed, "status": response.status},
                confidence=0.82,
            ))
            if changed and response.status == 200 and TRAVERSAL_MARKER in response.text:
                findings.append(Finding(
                    id=_finding_id("web.path_traversal.finding", f"{asset.id}:{name}"),
                    type="potential_path_traversal",
                    confidence=0.90,
                    evidence=(oid,),
                    metadata={"severity": "high", "parameter": name, "url": _redacted_url(asset.url),
                              "status": response.status, "needs_context_confirmation": True},
                ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_file_upload(context):
    """Passively assess discovered upload forms; never uploads a file."""
    from module_runner import ModuleResult

    observations = []
    findings = []
    for asset in context.assets:
        if asset.type is not AssetType.FORM:
            continue
        metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
        fields = metadata.get("inputs") or metadata.get("fields") or ()
        if not isinstance(fields, (list, tuple)):
            continue
        upload_fields = []
        for field in fields:
            if isinstance(field, dict):
                field_type = str(field.get("type", "")).lower()
                if field_type == "file":
                    upload_fields.append(field)
        if not upload_fields:
            continue
        accept_values = [str(item.get("accept", "")).strip() for item in upload_fields]
        has_limits = bool(metadata.get("max_size") or metadata.get("size_limit"))
        has_accept = any(value for value in accept_values)
        oid = _finding_id("web.file_upload.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid,
            kind="web.file_upload.surface",
            source="web.file_upload",
            description=f"File upload surface discovered on form {asset.name}",
            asset_ids=(asset.id,),
            data={"upload_fields": len(upload_fields), "accept_restrictions": has_accept, "size_limit": has_limits},
            confidence=1.0,
        ))
        if not has_accept and not has_limits:
            findings.append(Finding(
                id=_finding_id("web.file_upload.finding", asset.id),
                type="upload_validation_requires_review",
                confidence=0.78,
                evidence=(oid,),
                metadata={"severity": "medium", "reason": "no client-visible type or size restrictions discovered",
                          "state_changing_test": False},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_websocket(context):
    """Discover WebSocket endpoints without connecting or sending messages."""
    from module_runner import ModuleResult

    observations = []
    findings = []
    pattern = re.compile(r"wss?://[^\"'\s<>]+", re.I)
    seen: set[str] = set()
    candidates: list[tuple[str, str]] = []
    for asset in context.assets:
        url = asset.url or ""
        if url.startswith(("ws://", "wss://")):
            candidates.append((asset.id, url))
        source = str(asset.metadata.get("source", "")) if isinstance(asset.metadata, dict) else ""
        for match in pattern.findall(source):
            candidates.append((asset.id, match))
    for asset_id, url in candidates[:MAX_WEBSOCKETS]:
        if url in seen:
            continue
        seen.add(url)
        oid = _finding_id("web.websocket.observation", f"{asset_id}:{url}")
        observations.append(SecurityObservation(
            id=oid,
            kind="web.websocket.endpoint",
            source="web.websocket",
            description="WebSocket endpoint discovered; no connection or message was attempted",
            asset_ids=(asset_id,),
            data={"url": _redacted_url(url)},
            confidence=0.98,
        ))
        findings.append(Finding(
            id=_finding_id("web.websocket.finding", url),
            type="websocket_endpoint_detected",
            confidence=0.95,
            evidence=(oid,),
            metadata={"severity": "informational", "requires_protocol_test": True},
        ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def _config(context, key: str) -> dict:
    value = context.metadata.get(key)
    if value is None:
        raise RuntimeError(f"web/AI module requires configuration: {key}")
    if not isinstance(value, dict):
        raise RuntimeError(f"module configuration must be an object: {key}")
    return value


def _valid_marker(value: object, prefix: str) -> str:
    marker = str(value or "").strip()
    if not re.fullmatch(prefix + r"[A-Z0-9_]{4,48}", marker):
        raise RuntimeError(f"invalid configured marker for {prefix}")
    return marker


def run_ai_output_handling(context):
    """Test a configured downstream sink using a harmless output canary."""
    from module_runner import ModuleResult

    config = _config(context, "ai_output_config")
    marker = _valid_marker(config.get("marker"), "PHOBOS_OUT_")
    if context.interactor is None or context.workflow is None:
        raise RuntimeError("ai.output_handling requires interactor and workflow capabilities")
    prompt = str(config.get("prompt", f"Return exactly {marker}"))[:2000]
    sink = str(config.get("sink", "configured downstream sink"))[:200]
    before = context.interactor.observe() if hasattr(context.interactor, "observe") else None
    run_result = context.workflow.run_prompt(prompt)
    after = context.interactor.observe() if hasattr(context.interactor, "observe") else None
    serialized = json.dumps({"run": run_result, "after": after}, ensure_ascii=False, default=str)[:12000]
    oid = _finding_id("ai.output_handling.observation", f"{context.target}:{marker}")
    observation = SecurityObservation(
        id=oid,
        kind="ai.output_handling.canary",
        source="ai.output_handling",
        description="Configured AI output handling canary executed",
        data={"marker_digest": _digest(marker), "output_digest": _digest(serialized), "sink": sink},
        confidence=0.88,
    )
    findings = ()
    if marker in serialized:
        findings = (Finding(
            id=_finding_id("ai.output_handling.finding", context.target + marker),
            type="ai_output_reaches_configured_sink",
            confidence=0.86,
            evidence=(oid,),
            metadata={"severity": "medium", "sink": sink, "needs_sink_validation": True},
        ),)
    return ModuleResult(observations=(observation,), findings=findings)


def run_ai_excessive_agency(context):
    """Validate a configured capability-denial invariant without performing it."""
    from module_runner import ModuleResult

    config = _config(context, "ai_agency_config")
    denied_marker = _valid_marker(config.get("denied_marker"), "PHOBOS_DENY_")
    capabilities = config.get("expected_denied_capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        raise RuntimeError("ai_agency_config.expected_denied_capabilities must be a non-empty list")
    forbidden = tuple(str(item)[:120] for item in capabilities[:16])
    oid = _finding_id("ai.excessive_agency.observation", f"{context.target}:{denied_marker}:{','.join(forbidden)}")
    observation = SecurityObservation(
        id=oid,
        kind="ai.agency.boundary",
        source="ai.excessive_agency",
        description="Configured AI capability boundary is recorded for authorized validation",
        data={"denied_marker_digest": _digest(denied_marker), "expected_denied_capabilities": list(forbidden)},
        confidence=0.84,
    )
    return ModuleResult(observations=(observation,))

"""Low-impact HTTP protocol security modules."""
from __future__ import annotations

from hashlib import sha256
from urllib.parse import urlsplit, urlunsplit

from knowledge_store import SecurityObservation
from models import Asset, AssetType, Finding

MAX_TARGETS = 32


def _requests(context):
    value = context.metadata.get("request_manager")
    if value is None:
        raise RuntimeError("protocol module requires request_manager")
    return value


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _id(prefix: str, asset_id: str, detail: str = "") -> str:
    return f"{prefix}:{sha256(f'{asset_id}:{detail}'.encode()).hexdigest()[:12]}"


def _targets(context):
    return tuple(asset for asset in context.assets if asset.type in {AssetType.PAGE, AssetType.ENDPOINT, AssetType.API} and asset.url)[:MAX_TARGETS]


def run_web_host_header(context):
    """Detect obvious Host-derived absolute URL behavior using a canary host."""
    from module_runner import ModuleResult

    requests = _requests(context)
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    canary = "phobos-invalid.example"

    for asset in _targets(context):
        try:
            baseline = requests.get(asset.url)
            probe = requests.get(asset.url, headers={"Host": canary})
        except Exception:
            continue
        location = probe.headers.get("location", "")
        body = probe.text[:50_000]
        reflected = canary in location or canary in body
        oid = _id("web.host_header.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid,
            kind="web.host_header.trust_signal",
            source="web.host_header",
            description=f"Host-header trust behavior inspected for {_safe_url(asset.url)}",
            asset_ids=(asset.id,),
            data={"baseline_status": baseline.status, "probe_status": probe.status,
                  "canary_reflected": reflected, "location_present": bool(location)},
            confidence=0.9,
        ))
        if reflected:
            findings.append(Finding(
                id=_id("web.host_header.finding", asset.id),
                type="potential_host_header_trust_issue",
                confidence=0.72,
                evidence=(oid,),
                metadata={"severity": "medium", "url": _safe_url(asset.url),
                          "status": "needs_context_confirmation",
                          "validation": "attacker-controlled Host canary appeared in redirect or response content"},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_cache(context):
    """Inspect cache-control and cache-key signals without attempting cache poisoning."""
    from module_runner import ModuleResult

    requests = _requests(context)
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    probe_headers = {"X-Phobos-Cache-Probe": "1"}

    for asset in _targets(context):
        try:
            baseline = requests.get(asset.url)
            probe = requests.get(asset.url, headers=probe_headers)
        except Exception:
            continue
        cache_control = baseline.headers.get("cache-control", "")
        vary = baseline.headers.get("vary", "")
        probe_hit = "x-phobos-cache-probe" in probe.text[:10_000].lower()
        oid = _id("web.cache.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid,
            kind="web.cache.policy",
            source="web.cache",
            description=f"Cache behavior inspected for {_safe_url(asset.url)}",
            asset_ids=(asset.id,),
            data={"cache_control": cache_control, "vary": vary, "probe_status": probe.status,
                  "probe_marker_reflected": probe_hit},
            confidence=0.92,
        ))
        if probe_hit:
            findings.append(Finding(
                id=_id("web.cache.finding", asset.id, "reflection"),
                type="potential_cache_key_untrusted_input_reflection",
                confidence=0.74,
                evidence=(oid,),
                metadata={"severity": "medium", "url": _safe_url(asset.url),
                          "status": "needs_context_confirmation"},
            ))
        if baseline.status == 200 and not cache_control:
            findings.append(Finding(
                id=_id("web.cache.finding", asset.id, "policy"),
                type="missing_explicit_cache_policy",
                confidence=0.61,
                evidence=(oid,),
                metadata={"severity": "informational", "url": _safe_url(asset.url)},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

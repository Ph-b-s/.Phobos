"""Deterministic, bounded Web security baseline modules."""
from __future__ import annotations

import re
from hashlib import sha256
from urllib.parse import urlsplit, urlunsplit

from knowledge_store import SecurityObservation
from models import Asset, AssetType, Finding

MAX_TARGETS_PER_MODULE = 64
MAX_EXPOSURE_PATHS = 12


def _requests(context):
    value = context.metadata.get("request_manager")
    if value is None:
        raise RuntimeError("Web module requires request_manager in module metadata")
    return value


def _targets(context) -> tuple[Asset, ...]:
    seen: set[str] = set()
    result: list[Asset] = []
    for asset in context.assets:
        if asset.type not in {AssetType.PAGE, AssetType.ENDPOINT, AssetType.API} or not asset.url:
            continue
        if asset.url in seen:
            continue
        seen.add(asset.url)
        result.append(asset)
        if len(result) >= MAX_TARGETS_PER_MODULE:
            break
    if not result and context.target:
        result.append(Asset("target_001", AssetType.WEBSITE, context.target, context.target))
    return tuple(result)


def _finding_id(prefix: str, asset_id: str, detail: str = "") -> str:
    token = sha256(f"{prefix}:{asset_id}:{detail}".encode()).hexdigest()[:12]
    return f"{prefix}:{token}"


def _base_origin(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def run_web_headers(context):
    from module_runner import ModuleResult
    requests = _requests(context)
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for asset in _targets(context):
        if urlsplit(asset.url).scheme != "https":
            continue
        try:
            response = requests.get(asset.url)
        except Exception:
            continue
        expected = {
            "strict-transport-security": "HSTS",
            "content-security-policy": "CSP",
            "x-content-type-options": "X-Content-Type-Options",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }
        missing: list[str] = []
        for key, label in expected.items():
            present = bool(response.headers.get(key, "").strip())
            oid = _finding_id("web.headers.observation", asset.id, key)
            observations.append(SecurityObservation(
                id=oid, kind="web.headers.check", source="web.headers",
                description=f"{label} {'present' if present else 'missing'} on {asset.url}",
                asset_ids=(asset.id,), data={"header": key, "present": present}, confidence=1.0,
            ))
            if not present:
                missing.append(label)
        if missing:
            evidence = tuple(item.id for item in observations if item.asset_ids == (asset.id,)
                             and item.kind == "web.headers.check" and not item.data.get("present"))
            findings.append(Finding(
                id=_finding_id("web.headers.finding", asset.id, ",".join(missing)),
                type="missing_security_headers", confidence=0.92, evidence=evidence,
                metadata={"severity": "low", "headers": missing, "url": asset.url},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_cookies(context):
    from module_runner import ModuleResult
    requests = _requests(context)
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    cookie_re = re.compile(r"^\s*([^=;\s]+)=([^;]*)(.*)$", re.S)
    sensitive_name = re.compile(r"(?:session|auth|token|sid|jwt)", re.I)
    for asset in _targets(context):
        try:
            response = requests.get(asset.url)
        except Exception:
            continue
        raw = response.headers.get("set-cookie", "")
        if not raw:
            continue
        match = cookie_re.match(raw)
        if not match:
            continue
        name, _, tail = match.groups()
        attrs = tail.lower()
        secure = "secure" in attrs
        httponly = "httponly" in attrs
        samesite = "samesite=" in attrs
        oid = _finding_id("web.cookies.observation", asset.id, name)
        observations.append(SecurityObservation(
            id=oid, kind="web.cookies.check", source="web.cookies",
            description=f"Cookie {name} observed on {asset.url}", asset_ids=(asset.id,),
            data={"name": name, "secure": secure, "httponly": httponly, "samesite": samesite}, confidence=1.0,
        ))
        missing: list[str] = []
        if not secure and urlsplit(asset.url).scheme == "https": missing.append("Secure")
        if not httponly and sensitive_name.search(name): missing.append("HttpOnly")
        if not samesite: missing.append("SameSite")
        if missing:
            findings.append(Finding(
                id=_finding_id("web.cookies.finding", asset.id, name + ":" + ",".join(missing)),
                type="insecure_cookie_attributes", confidence=0.94, evidence=(oid,),
                metadata={"severity": "medium" if sensitive_name.search(name) else "low", "cookie": name, "missing": missing},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_exposure(context):
    from module_runner import ModuleResult
    requests = _requests(context)
    origin = _base_origin(context.target)
    paths = ("/.git/HEAD", "/.env", "/.env.local", "/server-status", "/phpinfo.php",
             "/actuator/env", "/debug", "/swagger.json", "/openapi.json", "/api/swagger.json",
             "/.well-known/security.txt", "/config.json")[:MAX_EXPOSURE_PATHS]
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    target_asset_id = next((a.id for a in context.assets if a.type is AssetType.WEBSITE), "target_001")
    for path in paths:
        url = origin + path
        try:
            response = requests.get(url)
        except Exception:
            continue
        if response.status not in {200, 206}:
            continue
        oid = _finding_id("web.exposure.observation", target_asset_id, path)
        observations.append(SecurityObservation(
            id=oid, kind="web.exposure.hit", source="web.exposure",
            description=f"Potentially sensitive path returned HTTP {response.status}: {path}",
            asset_ids=(target_asset_id,), data={"url": url, "status": response.status, "bytes": len(response.body)}, confidence=0.95,
        ))
        findings.append(Finding(
            id=_finding_id("web.exposure.finding", target_asset_id, path),
            type="potential_sensitive_file_exposure", confidence=0.91, evidence=(oid,),
            metadata={"severity": "medium", "path": path, "status": response.status, "bytes": len(response.body)},
        ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_methods(context):
    from module_runner import ModuleResult
    requests = _requests(context)
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for asset in _targets(context):
        try:
            response = requests.request("OPTIONS", asset.url)
        except Exception:
            continue
        allow = response.headers.get("allow", "")
        oid = _finding_id("web.methods.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid, kind="web.methods.allow", source="web.methods",
            description=f"HTTP method policy observed for {asset.url}", asset_ids=(asset.id,),
            data={"allow": allow, "status": response.status}, confidence=1.0,
        ))
        methods = {part.strip().upper() for part in allow.split(",") if part.strip()}
        if "TRACE" in methods:
            findings.append(Finding(
                id=_finding_id("web.methods.finding", asset.id, "TRACE"),
                type="trace_method_enabled", confidence=0.97, evidence=(oid,),
                metadata={"severity": "medium", "allow": sorted(methods)},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_config(context):
    from module_runner import ModuleResult
    requests = _requests(context)
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for asset in _targets(context):
        try:
            response = requests.get(asset.url)
        except Exception:
            continue
        server = response.headers.get("server", "").strip()
        powered = response.headers.get("x-powered-by", "").strip()
        if server:
            oid = _finding_id("web.config.server", asset.id)
            observations.append(SecurityObservation(
                id=oid, kind="web.config.server", source="web.config",
                description=f"Server technology disclosure observed on {asset.url}", asset_ids=(asset.id,),
                data={"server": server}, confidence=1.0,
            ))
            findings.append(Finding(
                id=_finding_id("web.config.finding.server", asset.id, server),
                type="server_banner_disclosure", confidence=0.94, evidence=(oid,),
                metadata={"severity": "informational", "server": server},
            ))
        if powered:
            oid = _finding_id("web.config.powered", asset.id)
            observations.append(SecurityObservation(
                id=oid, kind="web.config.powered_by", source="web.config",
                description=f"X-Powered-By disclosure observed on {asset.url}", asset_ids=(asset.id,),
                data={"x_powered_by": powered}, confidence=1.0,
            ))
            findings.append(Finding(
                id=_finding_id("web.config.finding.powered", asset.id, powered),
                type="x_powered_by_disclosure", confidence=0.96, evidence=(oid,),
                metadata={"severity": "low", "x_powered_by": powered},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_cors(context):
    from module_runner import ModuleResult
    requests = _requests(context)
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for asset in _targets(context):
        try:
            response = requests.get(asset.url, headers={"Origin": "https://phobos.invalid"})
        except Exception:
            continue
        allow_origin = response.headers.get("access-control-allow-origin", "").strip()
        allow_credentials = response.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
        if not allow_origin:
            continue
        oid = _finding_id("web.cors.observation", asset.id)
        observations.append(SecurityObservation(
            id=oid, kind="web.cors.policy", source="web.cors",
            description=f"CORS policy observed on {asset.url}", asset_ids=(asset.id,),
            data={"allow_origin": allow_origin, "allow_credentials": allow_credentials}, confidence=1.0,
        ))
        reflected = allow_origin == "https://phobos.invalid" or allow_origin == "*"
        if reflected and allow_credentials:
            findings.append(Finding(
                id=_finding_id("web.cors.finding", asset.id, allow_origin),
                type="permissive_cors_with_credentials", confidence=0.98, evidence=(oid,),
                metadata={"severity": "high", "allow_origin": allow_origin, "allow_credentials": True},
            ))
        elif reflected:
            findings.append(Finding(
                id=_finding_id("web.cors.finding", asset.id, allow_origin + ":public"),
                type="permissive_cors_policy", confidence=0.90, evidence=(oid,),
                metadata={"severity": "medium", "allow_origin": allow_origin, "allow_credentials": False},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

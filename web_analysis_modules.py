"""Passive/low-impact analysis modules for modern Web attack surfaces."""
from __future__ import annotations

import base64
import json
import re
import time
from hashlib import sha256
from urllib.parse import urlsplit, urlunsplit

from knowledge_store import SecurityObservation
from models import AssetType, Finding

MAX_JAVASCRIPT_ASSETS = 32
MAX_SOURCE_CHARS = 160_000
MAX_GRAPHQL_ENDPOINTS = 16
MAX_JWT_TOKENS = 32
MAX_JWT_POLICY_FIELDS = 16

_DOM_SOURCES = (
    re.compile(r"location\.(?:search|hash|href|pathname)", re.I),
    re.compile(r"document\.(?:URL|referrer)", re.I),
    re.compile(r"(?:event|e)\.data", re.I),
    re.compile(r"URLSearchParams", re.I),
)
_DOM_SINKS = (
    re.compile(r"\.innerHTML\s*=", re.I),
    re.compile(r"\.outerHTML\s*=", re.I),
    re.compile(r"insertAdjacentHTML\s*\(", re.I),
    re.compile(r"document\.write\s*\(", re.I),
    re.compile(r"(?:window\.)?eval\s*\(", re.I),
    re.compile(r"new\s+Function\s*\(", re.I),
)
_JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b")
_GRAPHQL_PATH_RE = re.compile(r"/(?:api/)?graphql(?:/|$)", re.I)


def _requests(context):
    requests = context.metadata.get("request_manager")
    if requests is None:
        raise RuntimeError("Web analysis module requires request_manager")
    return requests


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _finding_id(prefix: str, asset_id: str, detail: str = "") -> str:
    return f"{prefix}:{sha256(f'{asset_id}:{detail}'.encode()).hexdigest()[:12]}"


def _jwt_header(token: str) -> dict[str, object] | None:
    first = token.split(".", 1)[0]
    padding = "=" * (-len(first) % 4)
    try:
        value = base64.urlsafe_b64decode((first + padding).encode()).decode("utf-8")
        header = json.loads(value)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, base64.binascii.Error):
        return None
    return header if isinstance(header, dict) else None


def _jwt_payload(token: str) -> dict[str, object] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    padding = "=" * (-len(parts[1]) % 4)
    try:
        value = base64.urlsafe_b64decode((parts[1] + padding).encode()).decode("utf-8")
        payload = json.loads(value)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, base64.binascii.Error):
        return None
    return payload if isinstance(payload, dict) else None


def _jwt_claims_issue(payload: dict[str, object], policy: object) -> list[str]:
    if not isinstance(policy, dict):
        raise TypeError("jwt_policy must be an object")
    issues: list[str] = []
    required = policy.get("required_claims", ())
    if not isinstance(required, list) or len(required) > MAX_JWT_POLICY_FIELDS:
        raise ValueError("jwt_policy.required_claims must be a bounded list")
    for claim in required:
        name = str(claim).strip()
        if name and name not in payload:
            issues.append(f"missing:{name}")

    expected_issuer = policy.get("issuer")
    if expected_issuer is not None and payload.get("iss") != str(expected_issuer):
        issues.append("issuer_mismatch")

    expected_audience = policy.get("audience")
    if expected_audience is not None:
        audience = payload.get("aud")
        values = audience if isinstance(audience, list) else [audience]
        if str(expected_audience) not in {str(item) for item in values if item is not None}:
            issues.append("audience_mismatch")

    now = time.time()
    raw_leeway = policy.get("leeway_seconds", 0)
    try:
        leeway = float(raw_leeway)
    except (TypeError, ValueError) as exc:
        raise ValueError("jwt_policy.leeway_seconds must be numeric") from exc
    if not 0 <= leeway <= 300:
        raise ValueError("jwt_policy.leeway_seconds must be between 0 and 300")

    for claim, comparison in (("exp", "expired"), ("nbf", "not_yet_valid"), ("iat", "issued_in_future")):
        if claim not in payload:
            continue
        value = payload[claim]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            issues.append(f"invalid:{claim}")
            continue
        if claim == "exp" and float(value) < now - leeway:
            issues.append(comparison)
        elif claim == "nbf" and float(value) > now + leeway:
            issues.append(comparison)
        elif claim == "iat" and float(value) > now + leeway:
            issues.append(comparison)
    return issues


def _jwt_policy_result(header: dict[str, object], payload: dict[str, object], policy: object) -> tuple[list[str], list[str]]:
    if not isinstance(policy, dict):
        raise TypeError("jwt_policy must be an object")
    raw_algs = policy.get("allowed_algorithms", ())
    if not isinstance(raw_algs, list) or not raw_algs or len(raw_algs) > MAX_JWT_POLICY_FIELDS:
        raise ValueError("jwt_policy.allowed_algorithms must be a bounded non-empty list")
    allowed_algs = {str(item).upper().strip() for item in raw_algs if str(item).strip()}
    algorithm = str(header.get("alg", "")).upper()
    issues: list[str] = []
    if algorithm not in allowed_algs:
        issues.append("algorithm_not_allowed")
    if algorithm == "NONE":
        issues.append("none_algorithm")
    return issues, _jwt_claims_issue(payload, policy)


def _run_configured_jwt_policy(context, config):
    from module_runner import ModuleResult
    if not isinstance(config, dict):
        raise TypeError("jwt_policy must be an object")
    raw_tokens = config.get("tokens", ())
    if not isinstance(raw_tokens, list) or not raw_tokens:
        raise ValueError("jwt_policy.tokens must contain at least one explicit token")
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for index, token in enumerate(raw_tokens[:MAX_JWT_TOKENS]):
        value = str(token).strip()
        if not value or len(value) > 20_000 or not _JWT_RE.fullmatch(value):
            raise ValueError("jwt_policy.tokens contains an invalid JWT value")
        digest = sha256(value.encode()).hexdigest()[:16]
        header = _jwt_header(value)
        payload = _jwt_payload(value)
        if header is None or payload is None:
            raise ValueError("jwt_policy.tokens contains a malformed JWT")
        algorithm_issues, claim_issues = _jwt_policy_result(header, payload, config)
        all_issues = algorithm_issues + claim_issues
        oid = _finding_id("web.jwt.policy", context.target, f"{digest}:{index}")
        observations.append(SecurityObservation(
            id=oid, kind="web.jwt.policy_validation", source="web.jwt",
            description="Explicit JWT validated against a configured algorithm and claim policy; token material is not retained",
            data={"token_digest": digest, "algorithm": str(header.get("alg", "")).upper(),
                  "header_keys": sorted(str(key) for key in header)[:MAX_JWT_POLICY_FIELDS],
                  "claim_keys": sorted(str(key) for key in payload)[:MAX_JWT_POLICY_FIELDS],
                  "policy_issues": all_issues}, confidence=0.96,
        ))
        if algorithm_issues:
            findings.append(Finding(
                id=_finding_id("web.jwt.policy.finding", context.target, f"{digest}:algorithm"),
                type="jwt_algorithm_policy_failure", confidence=0.96, evidence=(oid,),
                metadata={"severity": "high", "status": "configured_algorithm_policy_rejected_token", "issues": algorithm_issues},
            ))
        if claim_issues:
            findings.append(Finding(
                id=_finding_id("web.jwt.policy.finding", context.target, f"{digest}:claims"),
                type="jwt_claim_policy_failure", confidence=0.90, evidence=(oid,),
                metadata={"severity": "medium", "status": "configured_claim_policy_rejected_token", "issues": claim_issues},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_client_javascript(context):
    from module_runner import ModuleResult
    requests = _requests(context)
    javascript = tuple(asset for asset in context.assets if asset.type is AssetType.JAVASCRIPT and asset.url)[:MAX_JAVASCRIPT_ASSETS]
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for asset in javascript:
        try:
            response = requests.get(asset.url)
        except Exception:
            continue
        source = response.text[:MAX_SOURCE_CHARS]
        sources = [pattern.pattern for pattern in _DOM_SOURCES if pattern.search(source)]
        sinks = [pattern.pattern for pattern in _DOM_SINKS if pattern.search(source)]
        oid = _finding_id("web.client_js.observation", asset.id)
        observations.append(SecurityObservation(id=oid, kind="web.client_javascript.analysis", source="web.client_javascript", description=f"Client-side JavaScript source analyzed for attacker-controlled DOM sources and dangerous sinks: {_safe_url(asset.url)}", asset_ids=(asset.id,), data={"source_signals": sources, "sink_signals": sinks, "source_count": len(sources), "sink_count": len(sinks)}, confidence=0.86))
        if sources and sinks:
            findings.append(Finding(id=_finding_id("web.client_js.finding", asset.id, "dom-xss"), type="potential_dom_xss_source_sink", confidence=0.70, evidence=(oid,), metadata={"severity": "high", "url": _safe_url(asset.url), "source_signals": sources, "sink_signals": sinks, "status": "needs_dataflow_confirmation"}))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_jwt(context):
    from module_runner import ModuleResult
    configured = context.metadata.get("jwt_policy")
    if configured is not None:
        return _run_configured_jwt_policy(context, configured)
    requests = _requests(context)
    targets = tuple(asset for asset in context.assets if asset.type in {AssetType.PAGE, AssetType.ENDPOINT, AssetType.API} and asset.url)[:32]
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for asset in targets:
        try:
            response = requests.get(asset.url)
        except Exception:
            continue
        raw_cookie = response.headers.get("set-cookie", "")
        candidates = list(_JWT_RE.findall(raw_cookie)) + list(_JWT_RE.findall(response.text[:MAX_SOURCE_CHARS]))
        seen: set[str] = set()
        for token in candidates:
            digest = sha256(token.encode()).hexdigest()[:16]
            if digest in seen:
                continue
            seen.add(digest)
            header = _jwt_header(token)
            if header is None:
                continue
            payload = _jwt_payload(token) or {}
            alg = str(header.get("alg", "")).upper()
            claim_keys = sorted(str(key) for key in payload)
            missing_time_claims = [key for key in ("exp",) if key not in payload]
            oid = _finding_id("web.jwt.observation", asset.id, digest)
            observations.append(SecurityObservation(id=oid, kind="web.jwt.token_observed", source="web.jwt", description=f"JWT-like token observed on {_safe_url(asset.url)}; token material is not retained", asset_ids=(asset.id,), data={"token_digest": digest, "algorithm": alg, "header_keys": sorted(str(key) for key in header), "claim_keys": claim_keys, "missing_recommended_claims": missing_time_claims}, confidence=0.95))
            if alg == "NONE":
                findings.append(Finding(id=_finding_id("web.jwt.finding", asset.id, digest), type="jwt_none_algorithm_signal", confidence=0.98, evidence=(oid,), metadata={"severity": "high", "algorithm": alg, "url": _safe_url(asset.url)}))
            elif missing_time_claims:
                findings.append(Finding(id=_finding_id("web.jwt.finding", asset.id, digest + ":claims"), type="jwt_missing_exp_claim_signal", confidence=0.58, evidence=(oid,), metadata={"severity": "low", "url": _safe_url(asset.url), "status": "requires_token_lifetime_policy_validation"}))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_graphql(context):
    from module_runner import ModuleResult
    requests = _requests(context)
    endpoints = tuple(dict.fromkeys(asset.url for asset in context.assets if asset.url and (asset.type in {AssetType.API, AssetType.ENDPOINT} or _GRAPHQL_PATH_RE.search(urlsplit(asset.url).path or ""))))
    endpoints = tuple(url for url in endpoints if _GRAPHQL_PATH_RE.search(urlsplit(url).path or ""))[:MAX_GRAPHQL_ENDPOINTS]
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    introspection_query = "query { __schema { queryType { name } } }"
    for url in endpoints:
        try:
            response = requests.request("POST", url, headers={"Content-Type": "application/json", "Accept": "application/json"}, body=json.dumps({"query": introspection_query}, separators=(",", ":")).encode("utf-8"))
        except Exception:
            continue
        body = response.text[:MAX_SOURCE_CHARS]
        introspection_enabled = "__schema" in body and "queryType" in body
        oid = _finding_id("web.graphql.observation", sha256(_safe_url(url).encode()).hexdigest()[:12])
        observations.append(SecurityObservation(id=oid, kind="web.graphql.introspection", source="web.graphql", description=f"GraphQL introspection behavior observed on {_safe_url(url)}", data={"status": response.status, "introspection_enabled": introspection_enabled, "content_type": response.headers.get("content-type", "")}, confidence=0.95))
        if introspection_enabled:
            findings.append(Finding(id=_finding_id("web.graphql.finding", oid), type="graphql_introspection_enabled", confidence=0.97, evidence=(oid,), metadata={"severity": "low", "url": _safe_url(url), "validation": "bounded read-only introspection query accepted"}))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

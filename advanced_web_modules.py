"""Bounded active Web vulnerability probes for the Phobos module runner.

The probes are deliberately non-destructive. They use unique markers and
error-signature comparisons rather than destructive payloads or out-of-band
callbacks. A positive result represents evidence for a follow-up finding, not
permission to perform arbitrary exploitation.
"""
from __future__ import annotations

import html
import re
from hashlib import sha256
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from knowledge_store import SecurityObservation
from models import Asset, AssetType, Finding

MAX_TARGETS = 32
MAX_PARAMS_PER_TARGET = 8
MAX_BODY_CHARS = 120_000

_SQL_ERROR_PATTERNS = (
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning:\s*mysql", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\s*\(\)", re.I),
    re.compile(r"postgresql.*error", re.I),
    re.compile(r"sqlite3\.operationalerror", re.I),
    re.compile(r"ora-\d{4,5}", re.I),
    re.compile(r"microsoft sql server.*error", re.I),
)

_SECRET_PATTERNS = (
    (re.compile(r"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"), "credential-like token"),
    (re.compile(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private-key material"),
    (re.compile(r"(?i)aws(.{0,20})(?:AKIA|ASIA)[A-Z0-9]{16}"), "AWS credential-like material"),
)


def _requests(context):
    requests = context.metadata.get("request_manager")
    if requests is None:
        raise RuntimeError("advanced Web module requires request_manager")
    return requests


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
        if len(result) >= MAX_TARGETS:
            break
    return tuple(result)


def _finding_id(prefix: str, asset_id: str, detail: str) -> str:
    token = sha256(f"{prefix}:{asset_id}:{detail}".encode()).hexdigest()[:12]
    return f"{prefix}:{token}"


def _query_variants(url: str, param: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    changed = [(name, value if name == param else current) for name, current in pairs]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.fragment and "" or "", urlencode(changed), ""))


def _params(url: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)))[:MAX_PARAMS_PER_TARGET]


def run_web_xss(context):
    """Detect reflected HTML injection with a harmless, non-script marker."""
    from module_runner import ModuleResult

    requests = _requests(context)
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    marker_base = "PHOBOSXSS"
    payload = '\"><phobos-xss>PHOBOSXSS</phobos-xss>'
    safe_marker = "PHOBOSXSS"

    for asset in _targets(context):
        for param in _params(asset.url):
            probe_url = _query_variants(asset.url, param, payload)
            try:
                response = requests.get(probe_url)
            except Exception:
                continue
            body = response.text[:MAX_BODY_CHARS]
            reflected = payload in body
            encoded = html.escape(payload, quote=True) in body
            plain_marker = safe_marker in body
            oid = _finding_id("web.xss.observation", asset.id, param)
            observations.append(SecurityObservation(
                id=oid,
                kind="web.xss.reflection",
                source="web.xss",
                description=f"Reflected XSS canary checked for parameter {param} on {asset.url}",
                asset_ids=(asset.id,),
                data={"parameter": param, "status": response.status, "reflected_raw": reflected,
                      "reflected_encoded": encoded, "marker_present": plain_marker},
                confidence=1.0,
            ))
            if reflected and not encoded:
                findings.append(Finding(
                    id=_finding_id("web.xss.finding", asset.id, param),
                    type="potential_reflected_xss",
                    confidence=0.96,
                    evidence=(oid,),
                    metadata={"severity": "high", "parameter": param, "url": asset.url,
                              "validation": "raw HTML metacharacters reflected without HTML encoding"},
                ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_sqli(context):
    """Detect error-based SQL injection signals without modifying application state."""
    from module_runner import ModuleResult

    requests = _requests(context)
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []

    for asset in _targets(context):
        for param in _params(asset.url):
            baseline_url = _query_variants(asset.url, param, "phobos")
            probe_url = _query_variants(asset.url, param, "phobos'")
            try:
                baseline = requests.get(baseline_url)
                probe = requests.get(probe_url)
            except Exception:
                continue
            probe_body = probe.text[:MAX_BODY_CHARS]
            errors = [pattern.pattern for pattern in _SQL_ERROR_PATTERNS if pattern.search(probe_body)]
            status_delta = baseline.status != probe.status
            body_delta = abs(len(baseline.body) - len(probe.body))
            oid = _finding_id("web.sqli.observation", asset.id, param)
            observations.append(SecurityObservation(
                id=oid,
                kind="web.sqli.differential",
                source="web.sqli",
                description=f"Non-destructive SQL error differential checked for parameter {param} on {asset.url}",
                asset_ids=(asset.id,),
                data={"parameter": param, "baseline_status": baseline.status, "probe_status": probe.status,
                      "status_changed": status_delta, "body_length_delta": body_delta,
                      "error_signatures": errors},
                confidence=1.0,
            ))
            if errors:
                findings.append(Finding(
                    id=_finding_id("web.sqli.finding", asset.id, param + ":errors"),
                    type="potential_sql_injection_error_signal",
                    confidence=0.93,
                    evidence=(oid,),
                    metadata={"severity": "high", "parameter": param,
                              "error_signatures": errors, "url": asset.url},
                ))
            elif status_delta and body_delta > 256:
                findings.append(Finding(
                    id=_finding_id("web.sqli.finding", asset.id, param + ":differential"),
                    type="sql_injection_differential_signal",
                    confidence=0.68,
                    evidence=(oid,),
                    metadata={"severity": "medium", "parameter": param,
                              "body_length_delta": body_delta, "url": asset.url},
                ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_info_disclosure(context):
    """Detect obvious credential/private-key patterns in bounded responses."""
    from module_runner import ModuleResult

    requests = _requests(context)
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []

    for asset in _targets(context):
        try:
            response = requests.get(asset.url)
        except Exception:
            continue
        text = response.text[:MAX_BODY_CHARS]
        for pattern, label in _SECRET_PATTERNS:
            match = pattern.search(text)
            if not match:
                continue
            start = max(0, match.start() - 40)
            end = min(len(text), match.end() + 40)
            snippet = text[start:end]
            oid = _finding_id("web.info_disclosure.observation", asset.id, label)
            observations.append(SecurityObservation(
                id=oid,
                kind="web.info_disclosure.secret_pattern",
                source="web.info_disclosure",
                description=f"Potential {label} pattern observed in a bounded response body",
                asset_ids=(asset.id,),
                data={"pattern": label, "context": snippet[:256]},
                confidence=0.88,
            ))
            findings.append(Finding(
                id=_finding_id("web.info_disclosure.finding", asset.id, label),
                type="potential_sensitive_information_disclosure",
                confidence=0.78,
                evidence=(oid,),
                metadata={"severity": "high", "pattern": label, "url": asset.url},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))


def run_web_api(context):
    """Assess discovered API responses for basic machine-readable hardening signals."""
    from module_runner import ModuleResult

    requests = _requests(context)
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for asset in _targets(context):
        if asset.type not in {AssetType.API, AssetType.ENDPOINT}:
            continue
        try:
            response = requests.get(asset.url)
        except Exception:
            continue
        content_type = response.headers.get("content-type", "").lower()
        body = response.text[:MAX_BODY_CHARS]
        is_json = "json" in content_type or body.lstrip().startswith(("{", "["))
        oid = _finding_id("web.api.observation", asset.id, "baseline")
        observations.append(SecurityObservation(
            id=oid,
            kind="web.api.baseline",
            source="web.api",
            description=f"API baseline observed for {asset.url}",
            asset_ids=(asset.id,),
            data={"status": response.status, "content_type": content_type, "json_like": is_json,
                  "allow_origin": response.headers.get("access-control-allow-origin", "")},
            confidence=1.0,
        ))
        if is_json and response.status == 200 and not response.headers.get("cache-control"):
            findings.append(Finding(
                id=_finding_id("web.api.finding", asset.id, "cache"),
                type="api_cache_policy_missing",
                confidence=0.63,
                evidence=(oid,),
                metadata={"severity": "low", "url": asset.url},
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

"""Read-only, configuration-gated GraphQL authorization validation."""
from __future__ import annotations

import json
from hashlib import sha256
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from knowledge_store import SecurityObservation
from models import Finding
from module_runner import ModuleResult
from security_modules import ModuleContext

MAX_ENDPOINTS = 8
MAX_QUERY_CHARS = 8_000
MAX_BODY_CHARS = 160_000


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _digest(text: str) -> str:
    return sha256(" ".join(text.split()).encode("utf-8", errors="replace")).hexdigest()[:16]


def _headers(raw: Any, label: str) -> dict[str, str]:
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


def run_web_graphql_auth(context: ModuleContext) -> ModuleResult:
    config = context.metadata.get("graphql_auth")
    if not isinstance(config, Mapping):
        raise RuntimeError("web.graphql_auth requires graphql_auth configuration")
    requests = context.metadata.get("request_manager")
    if requests is None:
        raise RuntimeError("web.graphql_auth requires request_manager capability")

    urls = tuple(dict.fromkeys(
        str(url).strip() for url in config.get("endpoints", ()) if str(url).strip()
    ))[:MAX_ENDPOINTS]
    if not urls:
        raise ValueError("graphql_auth.endpoints must contain at least one endpoint")

    query = str(config.get("query", "")).strip()
    if not query or len(query) > MAX_QUERY_CHARS:
        raise ValueError("graphql_auth.query must be non-empty and within the query limit")
    if any(token in query.casefold() for token in ("mutation", "subscription")):
        raise ValueError("graphql_auth.query must be read-only; mutations and subscriptions are not allowed")

    low_headers = _headers(config.get("low_headers"), "low_headers")
    high_headers = _headers(config.get("high_headers"), "high_headers")
    observations = []
    findings = []
    body = json.dumps({"query": query}, separators=(",", ":")).encode("utf-8")

    for index, url in enumerate(urls):
        low = requests.request("POST", url, headers={**low_headers, "Content-Type": "application/json", "Accept": "application/json"}, body=body)
        high = requests.request("POST", url, headers={**high_headers, "Content-Type": "application/json", "Accept": "application/json"}, body=body)
        low_text = low.text[:MAX_BODY_CHARS]
        high_text = high.text[:MAX_BODY_CHARS]
        same = low.status == high.status and _digest(low_text) == _digest(high_text) and len(low_text) == len(high_text)
        oid = f"web.graphql_auth:comparison:{sha256(_safe_url(url).encode()).hexdigest()[:12]}"
        observations.append(SecurityObservation(
            id=oid,
            kind="web.graphql.authorization_comparison",
            source="web.graphql_auth",
            description="Explicitly configured low/high-privilege GraphQL requests compared with a read-only query",
            data={
                "url": _safe_url(url),
                "low": {"status": low.status, "body_digest": _digest(low_text), "body_length": len(low_text)},
                "high": {"status": high.status, "body_digest": _digest(high_text), "body_length": len(high_text)},
                "same_response_signature": same,
            },
            confidence=0.94,
        ))
        if same:
            findings.append(Finding(
                id=f"web.graphql_auth:finding:{index}",
                type="potential_graphql_authorization_failure",
                confidence=0.77,
                evidence=(oid,),
                metadata={
                    "severity": "high",
                    "url": _safe_url(url),
                    "validation": "low/high GraphQL role requests returned identical normalized signatures",
                    "status": "needs_context_confirmation",
                },
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

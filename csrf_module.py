"""Passive CSRF protection analysis over already-discovered forms.

This module does not submit forms or mutate application state. It evaluates the
structure discovered by the Web recon layer and reports likely missing
anti-CSRF tokens as a review signal that should be confirmed in-context.
"""
from __future__ import annotations

from hashlib import sha256

from knowledge_store import SecurityObservation
from models import Asset, AssetType, Finding

_MAX_FORMS = 64
_TOKEN_NAMES = {
    "csrf",
    "csrf_token",
    "csrf-token",
    "csrftoken",
    "csrfmiddlewaretoken",
    "xsrf",
    "xsrf_token",
    "xsrf-token",
    "_token",
    "authenticity_token",
    "anti_csrf_token",
}
_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def _finding_id(prefix: str, asset_id: str) -> str:
    return f"{prefix}:{sha256(asset_id.encode()).hexdigest()[:12]}"


def _has_csrf_token(inputs: tuple[str, ...]) -> bool:
    normalized = {item.strip().casefold() for item in inputs if item.strip()}
    return any(name in _TOKEN_NAMES or name.endswith("_csrf") or name.endswith("-csrf") for name in normalized)


def run_web_csrf(context) -> "ModuleResult":
    from module_runner import ModuleResult

    forms = tuple(asset for asset in context.assets if asset.type is AssetType.FORM)[:_MAX_FORMS]
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []

    for form in forms:
        method = str(form.metadata.get("method", "" ) or getattr(form, "method", "GET")).upper()
        if method not in _STATE_CHANGING:
            continue
        inputs = tuple(getattr(form, "inputs", ()))
        has_token = _has_csrf_token(inputs)
        oid = _finding_id("web.csrf.observation", form.id)
        observations.append(SecurityObservation(
            id=oid,
            kind="web.csrf.form_policy",
            source="web.csrf",
            description=f"State-changing form policy inspected for {form.name}",
            asset_ids=(form.id,),
            data={"method": method, "action": form.url, "input_count": len(inputs), "anti_csrf_token_present": has_token},
            confidence=0.92,
        ))
        if not has_token:
            findings.append(Finding(
                id=_finding_id("web.csrf.finding", form.id),
                type="potential_missing_csrf_protection",
                confidence=0.72,
                evidence=(oid,),
                metadata={
                    "severity": "medium",
                    "method": method,
                    "action": form.url.split("?", 1)[0],
                    "validation": "no recognized anti-CSRF token was present in the discovered form inputs",
                    "status": "needs_context_confirmation",
                },
            ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

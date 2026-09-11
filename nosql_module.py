"""Low-impact NoSQL injection differential testing."""
from __future__ import annotations

import json
from hashlib import sha256
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from knowledge_store import SecurityObservation
from models import Asset, AssetType, Finding

MAX_TARGETS = 32
MAX_PARAMS = 8
MAX_BODY_CHARS = 80_000

_PROBES = (
    ("ne", {"$ne": None}),
    ("regex", {"$regex": ".*"}),
)


def _requests(context):
    value = context.metadata.get("request_manager")
    if value is None:
        raise RuntimeError("web.nosqli requires request_manager")
    return value


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _params(url: str):
    return tuple(dict.fromkeys(name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)))[:MAX_PARAMS]


def _variant(url: str, parameter: str, value: object) -> str:
    parsed = urlsplit(url)
    if isinstance(value, dict):
        encoded = json.dumps(value, separators=(",", ":"))
    else:
        encoded = str(value)
    pairs = [(name, encoded if name == parameter else current) for name, current in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.fragment if False else urlencode_pairs(pairs), ""))


def urlencode_pairs(pairs):
    return "&".join(f"{quote(name, safe='')}={quote(value, safe='')}" for name, value in pairs)


def _id(prefix: str, asset_id: str, parameter: str, probe: str = "") -> str:
    return f"{prefix}:{sha256(f'{asset_id}:{parameter}:{probe}'.encode()).hexdigest()[:12]}"


def run_web_nosqli(context):
    from module_runner import ModuleResult

    requests = _requests(context)
    targets = tuple(asset for asset in context.assets if asset.type in {AssetType.PAGE, AssetType.ENDPOINT, AssetType.API} and asset.url)[:MAX_TARGETS]
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []

    for asset in targets:
        for parameter in _params(asset.url):
            baseline_url = _variant(asset.url, parameter, "phobos-nosql")
            try:
                baseline = requests.get(baseline_url)
            except Exception:
                continue
            for probe_name, probe_value in _PROBES:
                probe_url = _variant(asset.url, parameter, probe_value)
                try:
                    probe = requests.get(probe_url)
                except Exception:
                    continue
                body_delta = abs(len(baseline.body) - len(probe.body))
                status_delta = baseline.status != probe.status
                oid = _id("web.nosqli.observation", asset.id, parameter, probe_name)
                observations.append(SecurityObservation(
                    id=oid,
                    kind="web.nosqli.differential",
                    source="web.nosqli",
                    description=f"NoSQL operator differential checked for parameter {parameter} on {_safe_url(asset.url)}",
                    asset_ids=(asset.id,),
                    data={"parameter": parameter, "probe": probe_name, "baseline_status": baseline.status,
                          "probe_status": probe.status, "status_changed": status_delta,
                          "body_length_delta": body_delta,
                          "baseline_body_length": min(len(baseline.body), MAX_BODY_CHARS),
                          "probe_body_length": min(len(probe.body), MAX_BODY_CHARS)},
                    confidence=0.82,
                ))
                if status_delta or body_delta > 512:
                    findings.append(Finding(
                        id=_id("web.nosqli.finding", asset.id, parameter, probe_name),
                        type="potential_nosql_injection_differential",
                        confidence=0.62,
                        evidence=(oid,),
                        metadata={"severity": "medium", "parameter": parameter,
                                  "probe": probe_name, "url": _safe_url(asset.url),
                                  "status": "needs_context_confirmation"},
                    ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

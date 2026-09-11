"""Low-impact server-side template injection signal detection."""
from __future__ import annotations

from hashlib import sha256
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from knowledge_store import SecurityObservation
from models import Asset, AssetType, Finding

MAX_TARGETS = 32
MAX_PARAMS = 8

# These are arithmetic-only expressions. A positive result means the server
# evaluated a template expression rather than merely reflecting text.
_TESTS = (
    ("PHOBOSTPL_A", "{{7*7}}", "49"),
    ("PHOBOSTPL_B", "${7*7}", "49"),
    ("PHOBOSTPL_C", "<%= 7*7 %>", "49"),
    ("PHOBOSTPL_D", "#{7*7}", "49"),
)


def _requests(context):
    value = context.metadata.get("request_manager")
    if value is None:
        raise RuntimeError("web.ssti requires request_manager")
    return value


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _params(url: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)))[:MAX_PARAMS]


def _variant(url: str, parameter: str, value: str) -> str:
    parsed = urlsplit(url)
    changed = [(name, value if name == parameter else current) for name, current in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(changed), ""))


def _finding_id(prefix: str, asset_id: str, parameter: str) -> str:
    return f"{prefix}:{sha256(f'{asset_id}:{parameter}'.encode()).hexdigest()[:12]}"


def run_web_ssti(context):
    from module_runner import ModuleResult

    requests = _requests(context)
    targets = tuple(asset for asset in context.assets if asset.type in {AssetType.PAGE, AssetType.ENDPOINT, AssetType.API} and asset.url)[:MAX_TARGETS]
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []

    for asset in targets:
        for parameter in _params(asset.url):
            for marker, expression, result_value in _TESTS:
                url = _variant(asset.url, parameter, expression)
                try:
                    response = requests.get(url)
                except Exception:
                    continue
                body = response.text[:120_000]
                evaluated = result_value in body and expression not in body
                marker_present = marker in body
                oid = _finding_id("web.ssti.observation", asset.id, parameter + marker)
                observations.append(SecurityObservation(
                    id=oid,
                    kind="web.ssti.template_probe",
                    source="web.ssti",
                    description=f"Arithmetic-only template expression checked for parameter {parameter} on {_safe_url(asset.url)}",
                    asset_ids=(asset.id,),
                    data={"parameter": parameter, "expression": expression, "evaluated_to_expected_value": evaluated,
                          "marker_present": marker_present, "status": response.status},
                    confidence=0.95,
                ))
                if evaluated:
                    findings.append(Finding(
                        id=_finding_id("web.ssti.finding", asset.id, parameter + marker),
                        type="potential_server_side_template_injection",
                        confidence=0.86,
                        evidence=(oid,),
                        metadata={"severity": "high", "parameter": parameter, "expression_family": marker,
                                  "url": _safe_url(asset.url), "validation": "arithmetic expression evaluated to expected value"},
                    ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

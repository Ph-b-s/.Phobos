"""Discovery of related web applications used by multi-step workflows.

A discovered application is a candidate, never an implicit authorization grant.
Phobos may record an out-of-scope supporting site as a workflow dependency, but
all subsequent browser/HTTP access still passes the central scope boundary.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from graph import Graph
from models import Asset, AssetType

MAX_APPLICATIONS = 200
EMAIL_HINTS = ("mail", "email", "inbox", "message", "verification", "confirm", "otp", "reset")
AUTH_HINTS = ("login", "signin", "sign-in", "account", "register", "signup", "sign-up", "password")


@dataclass(frozen=True, slots=True)
class ApplicationCandidate:
    url: str
    hostname: str
    kind: str
    confidence: float
    evidence: tuple[str, ...] = ()
    source_urls: tuple[str, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {"url": self.url, "hostname": self.hostname, "kind": self.kind,
                "confidence": self.confidence, "evidence": list(self.evidence),
                "source_urls": list(self.source_urls), "metadata": self.metadata}


def discover_related_applications(
    target: str,
    links: tuple[str, ...] | list[str] = (),
    pages: tuple[dict[str, object], ...] | list[dict[str, object]] = (),
    *,
    same_registrable_domain: bool = False,
    max_results: int = MAX_APPLICATIONS,
) -> tuple[ApplicationCandidate, ...]:
    """Identify supporting web applications from explicit workflow signals."""
    if max_results < 1:
        raise ValueError("max_results must be positive")
    target_host = urlparse(target).hostname or ""
    target_root = _registrable_hint(target_host)
    candidates: dict[str, ApplicationCandidate] = {}
    for raw_url in links:
        _consider(candidates, target_host, target_root, raw_url, target, None, same_registrable_domain)
    for page in pages:
        raw_url = str(page.get("url", ""))
        text = str(page.get("text", ""))
        for candidate_url in _urls_in_text(text):
            _consider(candidates, target_host, target_root, candidate_url, raw_url, text, same_registrable_domain)
        _consider(candidates, target_host, target_root, raw_url, raw_url, text, same_registrable_domain)
    return tuple(sorted(candidates.values(), key=lambda item: (-item.confidence, item.hostname, item.url))[:max_results])


def merge_applications_into_graph(graph: Graph, target_asset_id: str, applications: tuple[ApplicationCandidate, ...]) -> tuple[Asset, ...]:
    """Add candidate supporting applications as graph nodes without granting access."""
    assets: list[Asset] = []
    existing_ids = {node.id for node in graph.nodes}
    for index, item in enumerate(applications, start=1):
        asset_id = f"application_{index:04d}"
        while asset_id in existing_ids:
            index += 1
            asset_id = f"application_{index:04d}"
        existing_ids.add(asset_id)
        asset = Asset(id=asset_id, type=AssetType.WEBSITE, name=item.hostname, url=item.url,
                      confidence=item.confidence,
                      metadata={"application_kind": item.kind, "evidence": list(item.evidence),
                                "supporting_application": True, "access_requires_scope": True})
        graph.add_node(id=asset.id, type=asset.type.value, label=asset.name, attributes=asset.metadata)
        graph.add_edge(source=target_asset_id, target=asset.id, relationship="uses_supporting_application")
        assets.append(asset)
    return tuple(assets)


def _urls_in_text(text: str) -> tuple[str, ...]:
    if not text:
        return ()
    found = re.findall(r"https?://[^\s<>\"']+", text, re.I)
    return tuple(dict.fromkeys(item.rstrip(".,);]}") for item in found))


def _consider(candidates: dict[str, ApplicationCandidate], target_host: str, target_root: str,
              raw_url: str, source_url: str, text: str | None, same_registrable_domain: bool) -> None:
    parsed = urlparse(raw_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return
    host = parsed.hostname.lower().rstrip(".")
    if host == target_host:
        return
    root = _registrable_hint(host)
    same_root = bool(target_root and root == target_root)
    if same_registrable_domain and not same_root:
        return
    path_text = f"{parsed.path} {parsed.query}".casefold()
    evidence: list[str] = []
    kind = "supporting_web_application"
    score = 0.55 if same_root else 0.40
    for hint in EMAIL_HINTS:
        if hint in path_text or (text and re.search(rf"\b{re.escape(hint)}\b", text, re.I)):
            evidence.append(f"email/workflow hint: {hint}")
            kind = "email_or_message_application"
            score += 0.06
    for hint in AUTH_HINTS:
        if hint in path_text or (text and re.search(rf"\b{re.escape(hint)}\b", text, re.I)):
            evidence.append(f"identity/workflow hint: {hint}")
            score += 0.03
    if not evidence and not same_root:
        return
    normalized = parsed._replace(query="", fragment="").geturl()
    previous = candidates.get(host)
    if previous is None:
        candidates[host] = ApplicationCandidate(normalized, host, kind, min(0.95, score),
            tuple(dict.fromkeys(evidence)) or ("related web application",), (source_url,),
            {"same_registrable_domain": same_root})
        return
    candidates[host] = ApplicationCandidate(previous.url, host,
        "email_or_message_application" if kind == "email_or_message_application" else previous.kind,
        min(0.99, max(previous.confidence, score)),
        tuple(dict.fromkeys((*previous.evidence, *evidence))),
        tuple(dict.fromkeys((*previous.source_urls, source_url))), previous.metadata)


def _registrable_hint(host: str) -> str:
    labels = [item for item in host.split(".") if item]
    return ".".join(labels[-2:]) if len(labels) >= 2 else host

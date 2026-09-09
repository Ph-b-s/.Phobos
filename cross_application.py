"""Discovery of related web applications used by multi-step workflows."""
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
    """A discovered secondary web application that may participate in a workflow."""

    url: str
    hostname: str
    kind: str
    confidence: float
    evidence: tuple[str, ...] = ()
    source_urls: tuple[str, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "hostname": self.hostname,
            "kind": self.kind,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "source_urls": list(self.source_urls),
            "metadata": self.metadata,
        }


def discover_related_applications(
    target: str,
    links: tuple[str, ...] | list[str] = (),
    pages: tuple[dict[str, object], ...] | list[dict[str, object]] = (),
    *,
    same_registrable_domain: bool = True,
    max_results: int = MAX_APPLICATIONS,
) -> tuple[ApplicationCandidate, ...]:
    """Identify supporting web applications without deciding that they are trusted."""
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
        _consider(candidates, target_host, target_root, raw_url, raw_url, text, same_registrable_domain)

    return tuple(sorted(candidates.values(), key=lambda item: (-item.confidence, item.hostname, item.url))[:max_results])


def merge_applications_into_graph(
    graph: Graph,
    target_asset_id: str,
    applications: tuple[ApplicationCandidate, ...],
) -> tuple[Asset, ...]:
    """Add discovered supporting applications to the shared attack-surface graph."""
    assets: list[Asset] = []
    for index, item in enumerate(applications, start=1):
        asset = Asset(
            id=f"application_{index:04d}",
            type=AssetType.WEBSITE,
            name=item.hostname,
            url=item.url,
            confidence=item.confidence,
            metadata={"application_kind": item.kind, "evidence": list(item.evidence), "supporting_application": True},
        )
        graph.add_node(id=asset.id, type=asset.type.value, label=asset.name, attributes=asset.metadata)
        graph.add_edge(source=target_asset_id, target=asset.id, relationship="uses_supporting_application")
        assets.append(asset)
    return tuple(assets)


def _consider(
    candidates: dict[str, ApplicationCandidate],
    target_host: str,
    target_root: str,
    raw_url: str,
    source_url: str,
    text: str | None,
    same_registrable_domain: bool,
) -> None:
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
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
    normalized = parsed._replace(fragment="", query="").geturl()
    previous = candidates.get(host)
    if previous is None:
        candidates[host] = ApplicationCandidate(
            normalized,
            host,
            kind,
            min(0.95, score),
            tuple(dict.fromkeys(evidence)) or ("related web application",),
            (source_url,),
            {"same_registrable_domain": same_root},
        )
        return
    candidates[host] = ApplicationCandidate(
        previous.url,
        host,
        "email_or_message_application" if kind == "email_or_message_application" else previous.kind,
        min(0.99, max(previous.confidence, score)),
        tuple(dict.fromkeys((*previous.evidence, *evidence))),
        tuple(dict.fromkeys((*previous.source_urls, source_url))),
        previous.metadata,
    )


def _registrable_hint(host: str) -> str:
    labels = [item for item in host.split(".") if item]
    return ".".join(labels[-2:]) if len(labels) >= 2 else host

"""Scoped, bounded HTML reconnaissance crawler with passive AI-surface discovery."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from ai_surface import detect_ai_surfaces
from graph import Graph
from models import Asset, AssetType, EndpointAsset, FormAsset, InputAsset
from request_manager import RequestError, RequestManager

_SKIP = {"mailto", "tel", "javascript", "data", "blob"}


def normalize_url(base_url: str, raw_url: str) -> str | None:
    if not raw_url or not raw_url.strip():
        return None
    candidate = urljoin(base_url, raw_url.strip())
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse(
        (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", query, "")
    )


@dataclass(slots=True)
class ParsedPage:
    links: set[str] = field(default_factory=set)
    scripts: set[str] = field(default_factory=set)
    forms: list[dict] = field(default_factory=list)


class _Parser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.result = ParsedPage()
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        mapping = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "a" and mapping.get("href"):
            raw = mapping["href"]
            if urlparse(raw).scheme.lower() not in _SKIP:
                url = normalize_url(self.base_url, raw)
                if url:
                    self.result.links.add(url)
        elif tag == "script" and mapping.get("src"):
            url = normalize_url(self.base_url, mapping["src"])
            if url:
                self.result.scripts.add(url)
        elif tag == "form":
            action = normalize_url(self.base_url, mapping.get("action") or self.base_url)
            self._form = {
                "action": action or self.base_url,
                "method": (mapping.get("method") or "GET").upper(),
                "inputs": [],
            }
            self.result.forms.append(self._form)
        elif tag in {"input", "textarea", "select", "button"} and self._form is not None:
            self._form["inputs"].append(
                {"name": mapping.get("name", ""), "type": mapping.get("type", tag)}
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._form = None


@dataclass(frozen=True, slots=True)
class ReconResult:
    pages: tuple[Asset, ...]
    endpoints: tuple[EndpointAsset, ...]
    forms: tuple[FormAsset, ...]
    inputs: tuple[InputAsset, ...]
    javascript: tuple[Asset, ...]
    ai_surfaces: tuple[Asset, ...]
    errors: tuple[str, ...]

    @property
    def assets(self) -> tuple[Asset, ...]:
        return (
            *self.pages,
            *self.endpoints,
            *self.forms,
            *self.inputs,
            *self.javascript,
            *self.ai_surfaces,
        )


class ReconCrawler:
    def __init__(
        self,
        request_manager: RequestManager,
        *,
        max_pages: int = 100,
        max_discovered_urls: int = 5000,
    ):
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        if max_discovered_urls < max_pages:
            raise ValueError("max_discovered_urls must be at least max_pages")
        self.request_manager = request_manager
        self.max_pages = max_pages
        self.max_discovered_urls = max_discovered_urls

    def crawl(self, target: str, *, graph: Graph | None = None) -> ReconResult:
        start = normalize_url(target, target) or target
        queue = deque([start])
        discovered = {start}
        visited: set[str] = set()
        seen_endpoints: set[str] = set()
        seen_js: set[str] = set()
        seen_query_inputs: set[tuple[str, str]] = set()
        seen_ai: set[tuple[str, str]] = set()
        counters = {
            kind: 0
            for kind in ("page", "endpoint", "form", "input", "javascript", "ai_surface")
        }
        pages: list[Asset] = []
        endpoints: list[EndpointAsset] = []
        forms: list[FormAsset] = []
        inputs: list[InputAsset] = []
        js: list[Asset] = []
        ai_surfaces: list[Asset] = []
        errors: list[str] = []
        queue_limit_reported = False

        while queue and len(visited) < self.max_pages:
            url = queue.popleft()
            if url in visited or not self.request_manager.scope.is_in_scope(url):
                continue
            visited.add(url)
            try:
                response = self.request_manager.get(url)
            except RequestError as exc:
                errors.append(f"{url}: {exc}")
                continue

            content_type = response.headers.get("content-type", "").lower()
            if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                continue

            counters["page"] += 1
            page = Asset(
                f"page_{counters['page']:04d}",
                AssetType.PAGE,
                response.url,
                response.url,
                1.0,
                {"status_code": response.status, "content_type": content_type},
            )
            pages.append(page)
            if graph is not None:
                graph.add_node(id=page.id, type=page.type.value, label=page.name, attributes=page.metadata)

            parser = _Parser(response.url)
            try:
                parser.feed(response.text)
                parser.close()
            except Exception as exc:
                errors.append(f"{response.url}: parser error: {exc}")
                continue

            for link in sorted(parser.result.links):
                if not self.request_manager.scope.is_in_scope(link):
                    continue
                if link not in visited and link not in discovered:
                    if len(discovered) >= self.max_discovered_urls:
                        if not queue_limit_reported:
                            errors.append("discovery queue limit reached; additional URLs were ignored")
                            queue_limit_reported = True
                    else:
                        queue.append(link)
                        discovered.add(link)
                if link in seen_endpoints:
                    continue
                seen_endpoints.add(link)
                counters["endpoint"] += 1
                endpoint = EndpointAsset(
                    f"endpoint_{counters['endpoint']:04d}",
                    AssetType.ENDPOINT,
                    link,
                    link,
                    0.95,
                    {},
                    "GET",
                    None,
                )
                endpoints.append(endpoint)
                if graph is not None:
                    graph.add_node(id=endpoint.id, type=endpoint.type.value, label=endpoint.name)
                    graph.add_edge(source=page.id, target=endpoint.id, relationship="links_to")
                for name, _ in parse_qsl(urlparse(link).query, keep_blank_values=True):
                    key = (link, name)
                    if not name or key in seen_query_inputs:
                        continue
                    seen_query_inputs.add(key)
                    counters["input"] += 1
                    input_asset = InputAsset(
                        f"input_{counters['input']:04d}",
                        AssetType.INPUT,
                        name,
                        link,
                        1.0,
                        {"source_endpoint": link, "source_page": response.url},
                        "query",
                        "query",
                        "GET",
                    )
                    inputs.append(input_asset)
                    if graph is not None:
                        graph.add_node(
                            id=input_asset.id,
                            type=input_asset.type.value,
                            label=input_asset.name,
                            attributes=input_asset.metadata,
                        )
                        graph.add_edge(source=endpoint.id, target=input_asset.id, relationship="accepts")

            for script in sorted(parser.result.scripts):
                if not self.request_manager.scope.is_in_scope(script) or script in seen_js:
                    continue
                seen_js.add(script)
                counters["javascript"] += 1
                asset = Asset(
                    f"javascript_{counters['javascript']:04d}",
                    AssetType.JAVASCRIPT,
                    script,
                    script,
                    0.98,
                    {"source_page": response.url},
                )
                js.append(asset)
                if graph is not None:
                    graph.add_node(
                        id=asset.id,
                        type=asset.type.value,
                        label=asset.name,
                        attributes=asset.metadata,
                    )
                    graph.add_edge(source=page.id, target=asset.id, relationship="loads")

            for index, form_data in enumerate(parser.result.forms, 1):
                if not self.request_manager.scope.is_in_scope(form_data["action"]):
                    continue
                counters["form"] += 1
                named = tuple(item["name"] for item in form_data["inputs"] if item["name"])
                form = FormAsset(
                    f"form_{counters['form']:04d}",
                    AssetType.FORM,
                    f"{response.url}#{index}",
                    form_data["action"],
                    1.0,
                    {"source_page": response.url},
                    form_data["method"],
                    named,
                )
                forms.append(form)
                if graph is not None:
                    graph.add_node(id=form.id, type=form.type.value, label=form.name, attributes=form.metadata)
                    graph.add_edge(source=page.id, target=form.id, relationship="contains")
                for item in form_data["inputs"]:
                    if not item["name"]:
                        continue
                    counters["input"] += 1
                    input_asset = InputAsset(
                        f"input_{counters['input']:04d}",
                        AssetType.INPUT,
                        item["name"],
                        form_data["action"],
                        1.0,
                        {"source_form": form.id, "source_page": response.url},
                        item["type"] or "text",
                        "form",
                        form_data["method"],
                    )
                    inputs.append(input_asset)
                    if graph is not None:
                        graph.add_node(
                            id=input_asset.id,
                            type=input_asset.type.value,
                            label=input_asset.name,
                            attributes=input_asset.metadata,
                        )
                        graph.add_edge(source=form.id, target=input_asset.id, relationship="accepts")

            for candidate in detect_ai_surfaces(
                response.url,
                response.text,
                links=parser.result.links,
                scripts=parser.result.scripts,
                forms=parser.result.forms,
            ):
                if not self.request_manager.scope.is_in_scope(candidate.url):
                    continue
                if candidate.key() in seen_ai:
                    continue
                seen_ai.add(candidate.key())
                counters["ai_surface"] += 1
                asset = Asset(
                    f"ai_surface_{counters['ai_surface']:04d}",
                    AssetType.AI_AGENT,
                    candidate.kind,
                    candidate.url,
                    candidate.confidence,
                    {"source_page": response.url, "evidence": list(candidate.evidence)},
                )
                ai_surfaces.append(asset)
                if graph is not None:
                    graph.add_node(
                        id=asset.id,
                        type=asset.type.value,
                        label=asset.name,
                        attributes=asset.metadata,
                    )
                    graph.add_edge(source=page.id, target=asset.id, relationship="signals")

        return ReconResult(
            tuple(pages),
            tuple(endpoints),
            tuple(forms),
            tuple(inputs),
            tuple(js),
            tuple(ai_surfaces),
            tuple(errors),
        )

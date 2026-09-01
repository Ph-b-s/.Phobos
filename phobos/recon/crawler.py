"""Scoped, bounded HTML reconnaissance crawler."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from phobos.core.models import Asset, AssetType, EndpointAsset, FormAsset, InputAsset
from phobos.core.request_manager import RequestError, RequestManager, HTTPResponseData
from phobos.graph.graph import Graph


_SKIP_SCHEMES = {"mailto", "tel", "javascript", "data", "blob"}


def normalize_url(base_url: str, raw_url: str) -> str | None:
    candidate = urljoin(base_url, raw_url.strip())
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    path = parsed.path or "/"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))


@dataclass(slots=True)
class ParsedPage:
    links: set[str] = field(default_factory=set)
    scripts: set[str] = field(default_factory=set)
    forms: list[dict] = field(default_factory=list)
    inputs: list[dict] = field(default_factory=list)


class _HTMLDiscoveryParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.result = ParsedPage()
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()

        if tag == "a" and attrs_map.get("href"):
            value = attrs_map["href"]
            if urlparse(value).scheme.lower() not in _SKIP_SCHEMES:
                normalized = normalize_url(self.base_url, value)
                if normalized:
                    self.result.links.add(normalized)
        elif tag == "script" and attrs_map.get("src"):
            normalized = normalize_url(self.base_url, attrs_map["src"])
            if normalized:
                self.result.scripts.add(normalized)
        elif tag == "form":
            action = normalize_url(self.base_url, attrs_map.get("action") or self.base_url)
            self._form = {
                "action": action or self.base_url,
                "method": (attrs_map.get("method") or "GET").upper(),
                "inputs": [],
            }
            self.result.forms.append(self._form)
        elif tag in {"input", "textarea", "select", "button"}:
            item = {
                "name": attrs_map.get("name", ""),
                "type": attrs_map.get("type", tag),
                "value": attrs_map.get("value", ""),
            }
            self.result.inputs.append(item)
            if self._form is not None:
                self._form["inputs"].append(item)

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
    errors: tuple[str, ...]

    @property
    def assets(self) -> tuple[Asset, ...]:
        return (*self.pages, *self.endpoints, *self.forms, *self.inputs, *self.javascript)


class ReconCrawler:
    """Discover reachable web assets without leaving the configured scope."""

    def __init__(self, request_manager: RequestManager, *, max_pages: int = 100) -> None:
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        self.request_manager = request_manager
        self.max_pages = max_pages

    def crawl(self, target: str, *, graph: Graph | None = None) -> ReconResult:
        queue: deque[str] = deque([normalize_url(target, target) or target])
        visited: set[str] = set()
        pages: list[Asset] = []
        endpoints: list[EndpointAsset] = []
        forms: list[FormAsset] = []
        inputs: list[InputAsset] = []
        javascript: list[Asset] = []
        errors: list[str] = []
        counters = {key: 0 for key in ("page", "endpoint", "form", "input", "javascript")}

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
            page_id = f"page_{counters['page']:04d}"
            page = Asset(
                id=page_id,
                type=AssetType.PAGE,
                name=response.url,
                url=response.url,
                metadata={"status_code": response.status, "content_type": content_type},
            )
            pages.append(page)
            if graph:
                graph.add_node(id=page.id, type=page.type.value, label=page.name, attributes=page.metadata)

            parsed = _HTMLDiscoveryParser(response.url)
            try:
                parsed.feed(response.text)
            except Exception as exc:
                errors.append(f"{response.url}: parser error: {exc}")
                continue

            for link in sorted(parsed.links):
                if link not in visited and self.request_manager.scope.is_in_scope(link):
                    queue.append(link)
                counters["endpoint"] += 1
                endpoint_id = f"endpoint_{counters['endpoint']:04d}"
                endpoint = EndpointAsset(
                    id=endpoint_id,
                    type=AssetType.ENDPOINT,
                    name=link,
                    url=link,
                    method="GET",
                    confidence=0.95,
                )
                endpoints.append(endpoint)
                if graph:
                    graph.add_node(id=endpoint.id, type=endpoint.type.value, label=endpoint.name, attributes=endpoint.metadata)
                    graph.add_edge(source=page.id, target=endpoint.id, relationship="links_to")

            for index, script in enumerate(sorted(parsed.scripts), start=1):
                counters["javascript"] += 1
                script_id = f"javascript_{counters['javascript']:04d}"
                asset = Asset(
                    id=script_id,
                    type=AssetType.JAVASCRIPT,
                    name=script,
                    url=script,
                    confidence=0.98,
                    metadata={"source_page": response.url},
                )
                javascript.append(asset)
                if graph:
                    graph.add_node(id=asset.id, type=asset.type.value, label=asset.name, attributes=asset.metadata)
                    graph.add_edge(source=page.id, target=asset.id, relationship="loads")

            for form_index, form_data in enumerate(parsed.forms, start=1):
                counters["form"] += 1
                form_id = f"form_{counters['form']:04d}"
                form = FormAsset(
                    id=form_id,
                    type=AssetType.FORM,
                    name=f"{response.url}#{form_index}",
                    url=form_data["action"],
                    method=form_data["method"],
                    inputs=tuple(item["name"] for item in form_data["inputs"] if item["name"]),
                    metadata={"source_page": response.url},
                )
                forms.append(form)
                if graph:
                    graph.add_node(id=form.id, type=form.type.value, label=form.name, attributes=form.metadata)
                    graph.add_edge(source=page.id, target=form.id, relationship="contains")

                for item in form_data["inputs"]:
                    if not item["name"]:
                        continue
                    counters["input"] += 1
                    input_id = f"input_{counters['input']:04d}"
                    input_asset = InputAsset(
                        id=input_id,
                        type=AssetType.INPUT,
                        name=item["name"],
                        url=form_data["action"],
                        parameter_type=item["type"] or "text",
                        location="form",
                        method=form_data["method"],
                        metadata={"source_form": form.id, "source_page": response.url},
                    )
                    inputs.append(input_asset)
                    if graph:
                        graph.add_node(id=input_asset.id, type=input_asset.type.value, label=input_asset.name, attributes=input_asset.metadata)
                        graph.add_edge(source=form.id, target=input_asset.id, relationship="accepts")

            for link in sorted(parsed.links):
                query_params = parse_qsl(urlparse(link).query, keep_blank_values=True)
                for name, _ in query_params:
                    if not name:
                        continue
                    counters["input"] += 1
                    input_id = f"input_{counters['input']:04d}"
                    input_asset = InputAsset(
                        id=input_id,
                        type=AssetType.INPUT,
                        name=name,
                        url=link,
                        parameter_type="query",
                        location="query",
                        method="GET",
                        metadata={"source_endpoint": link, "source_page": response.url},
                    )
                    inputs.append(input_asset)
                    if graph:
                        graph.add_node(id=input_asset.id, type=input_asset.type.value, label=input_asset.name, attributes=input_asset.metadata)
                        endpoint = next((item for item in endpoints if item.url == link), None)
                        if endpoint:
                            graph.add_edge(source=endpoint.id, target=input_asset.id, relationship="accepts")

        return ReconResult(tuple(pages), tuple(endpoints), tuple(forms), tuple(inputs), tuple(javascript), tuple(errors))

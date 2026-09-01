"""Scoped, bounded HTML reconnaissance crawler."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from graph import Graph
from models import Asset, AssetType, EndpointAsset, FormAsset, InputAsset
from request_manager import HTTPResponseData, RequestError, RequestManager

_SKIP = {"mailto", "tel", "javascript", "data", "blob"}


def normalize_url(base_url: str, raw_url: str) -> str | None:
    candidate = urljoin(base_url, raw_url.strip())
    p = urlparse(candidate)
    if p.scheme.lower() not in {"http", "https"} or not p.hostname:
        return None
    q = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path or "/", "", q, ""))


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
        self._form = None

    def handle_starttag(self, tag: str, attrs):
        mapping = {k.lower(): v or "" for k, v in attrs}
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
            self._form["inputs"].append({"name": mapping.get("name", ""), "type": mapping.get("type", tag)})

    def handle_endtag(self, tag: str):
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
    def assets(self):
        return (*self.pages, *self.endpoints, *self.forms, *self.inputs, *self.javascript)


class ReconCrawler:
    def __init__(self, request_manager: RequestManager, *, max_pages: int = 100):
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        self.request_manager = request_manager
        self.max_pages = max_pages

    def crawl(self, target: str, *, graph: Graph | None = None) -> ReconResult:
        queue = deque([normalize_url(target, target) or target])
        visited = set()
        seen_ep = set()
        seen_js = set()
        seen_q = set()
        counters = {k: 0 for k in ("page", "endpoint", "form", "input", "javascript")}
        pages = []
        endpoints = []
        forms = []
        inputs = []
        js = []
        errors = []

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
            ctype = response.headers.get("content-type", "").lower()
            if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
                continue

            counters["page"] += 1
            page = Asset(
                f"page_{counters['page']:04d}",
                AssetType.PAGE,
                response.url,
                response.url,
                1.0,
                {"status_code": response.status, "content_type": ctype},
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
                if link not in visited:
                    queue.append(link)
                if link not in seen_ep:
                    seen_ep.add(link)
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
                        if not name or key in seen_q:
                            continue
                        seen_q.add(key)
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
                            graph.add_node(id=input_asset.id, type=input_asset.type.value, label=input_asset.name, attributes=input_asset.metadata)
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
                    graph.add_node(id=asset.id, type=asset.type.value, label=asset.name, attributes=asset.metadata)
                    graph.add_edge(source=page.id, target=asset.id, relationship="loads")

            for idx, form_data in enumerate(parser.result.forms, 1):
                if not self.request_manager.scope.is_in_scope(form_data["action"]):
                    continue
                counters["form"] += 1
                named = tuple(item["name"] for item in form_data["inputs"] if item["name"])
                form = FormAsset(
                    f"form_{counters['form']:04d}",
                    AssetType.FORM,
                    f"{response.url}#{idx}",
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
                        graph.add_node(id=input_asset.id, type=input_asset.type.value, label=input_asset.name, attributes=input_asset.metadata)
                        graph.add_edge(source=form.id, target=input_asset.id, relationship="accepts")

        return ReconResult(tuple(pages), tuple(endpoints), tuple(forms), tuple(inputs), tuple(js), tuple(errors))

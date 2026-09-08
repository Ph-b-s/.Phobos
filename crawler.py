"""Scoped, bounded Web reconnaissance with optional JavaScript execution."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from ai_surface import detect_ai_surfaces
from browser_adapter import BrowserAdapterError, BrowserSession
from graph import Graph
from models import Asset, AssetType, EndpointAsset, FormAsset, InputAsset
from request_manager import RequestError, RequestManager
from web_surface import discover_api_endpoints

_SKIP = {"mailto", "tel", "javascript", "data", "blob"}


def normalize_url(base_url: str, raw_url: str) -> str | None:
    if not raw_url or not raw_url.strip():
        return None
    candidate = urljoin(base_url, raw_url.strip())
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", query, ""))


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
            self._form = {"action": action or self.base_url, "method": (mapping.get("method") or "GET").upper(), "inputs": []}
            self.result.forms.append(self._form)
        elif tag in {"input", "textarea", "select", "button"} and self._form is not None:
            self._form["inputs"].append({"name": mapping.get("name", ""), "type": mapping.get("type", tag)})

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
    browser_observations: tuple[object, ...]
    errors: tuple[str, ...]

    @property
    def assets(self) -> tuple[Asset, ...]:
        return (*self.pages, *self.endpoints, *self.forms, *self.inputs, *self.javascript, *self.ai_surfaces)


class ReconCrawler:
    def __init__(self, request_manager: RequestManager, *, max_pages: int = 100, max_discovered_urls: int = 5000, browser: BrowserSession | None = None):
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        if max_discovered_urls < max_pages:
            raise ValueError("max_discovered_urls must be at least max_pages")
        self.request_manager = request_manager
        self.max_pages = max_pages
        self.max_discovered_urls = max_discovered_urls
        self.browser = browser

    def crawl(self, target: str, *, graph: Graph | None = None) -> ReconResult:
        start = normalize_url(target, target) or target
        queue = deque([start])
        discovered = {start}
        visited: set[str] = set()
        seen_endpoints: set[tuple[str, str]] = set()
        seen_js: set[str] = set()
        seen_query_inputs: set[tuple[str, str]] = set()
        seen_ai: set[tuple[str, str]] = set()
        counters = {kind: 0 for kind in ("page", "endpoint", "form", "input", "javascript", "ai_surface")}
        pages: list[Asset] = []
        endpoints: list[EndpointAsset] = []
        forms: list[FormAsset] = []
        inputs: list[InputAsset] = []
        javascript: list[Asset] = []
        ai_surfaces: list[Asset] = []
        browser_observations: list[object] = []
        errors: list[str] = []
        queue_limit_reported = False

        def add_endpoint(*, page: Asset, url: str, method: str, confidence: float, metadata: dict, relationship: str) -> None:
            normalized = normalize_url(page.url, url)
            if not normalized or not self.request_manager.scope.is_in_scope(normalized):
                return
            method = method.upper().strip()
            key = (method, normalized)
            if key in seen_endpoints:
                return
            seen_endpoints.add(key)
            counters["endpoint"] += 1
            endpoint = EndpointAsset(
                f"endpoint_{counters['endpoint']:04d}", AssetType.ENDPOINT, normalized, normalized,
                confidence, metadata, method, None,
            )
            endpoints.append(endpoint)
            if graph is not None:
                graph.add_node(id=endpoint.id, type=endpoint.type.value, label=endpoint.name, attributes=endpoint.metadata)
                graph.add_edge(source=page.id, target=endpoint.id, relationship=relationship)
            for name, _ in parse_qsl(urlparse(normalized).query, keep_blank_values=True):
                input_key = (normalized, name)
                if not name or input_key in seen_query_inputs:
                    continue
                seen_query_inputs.add(input_key)
                counters["input"] += 1
                input_asset = InputAsset(
                    f"input_{counters['input']:04d}", AssetType.INPUT, name, normalized, 1.0,
                    {"source_endpoint": normalized, "source_page": page.url}, "query", "query", method,
                )
                inputs.append(input_asset)
                if graph is not None:
                    graph.add_node(id=input_asset.id, type=input_asset.type.value, label=input_asset.name, attributes=input_asset.metadata)
                    graph.add_edge(source=endpoint.id, target=input_asset.id, relationship="accepts")

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
                f"page_{counters['page']:04d}", AssetType.PAGE, response.url, response.url, 1.0,
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

            discovered_links = set(parser.result.links)
            discovered_scripts = set(parser.result.scripts)
            discovered_forms = list(parser.result.forms)
            rendered_text = response.text
            browser_snapshot = None
            if self.browser is not None:
                try:
                    rendered_url = self.browser.goto(response.url)
                    browser_snapshot = self.browser.snapshot()
                    browser_observations.extend(browser_snapshot.to_observations())
                    discovered_links.update(browser_snapshot.links)
                    discovered_scripts.update(browser_snapshot.scripts)
                    discovered_forms.extend(browser_snapshot.forms)
                    rendered_text = browser_snapshot.text or rendered_text
                    if rendered_url != response.url:
                        discovered_links.add(rendered_url)
                except BrowserAdapterError as exc:
                    errors.append(f"{response.url}: browser error: {exc}")

            for link in sorted(discovered_links):
                normalized = normalize_url(response.url, link)
                if not normalized or not self.request_manager.scope.is_in_scope(normalized):
                    continue
                if normalized not in visited and normalized not in discovered:
                    if len(discovered) >= self.max_discovered_urls:
                        if not queue_limit_reported:
                            errors.append("discovery queue limit reached; additional URLs were ignored")
                            queue_limit_reported = True
                    else:
                        queue.append(normalized)
                        discovered.add(normalized)
                dynamic = link not in parser.result.links
                add_endpoint(page=page, url=normalized, method="GET", confidence=0.92 if dynamic else 0.95,
                             metadata={"discovery": "browser_dom" if dynamic else "html_link"},
                             relationship="dynamic_link" if dynamic else "links_to")

            for candidate in discover_api_endpoints(response.url, rendered_text):
                add_endpoint(page=page, url=candidate.url, method=candidate.method, confidence=candidate.confidence,
                             metadata={"discovery": "embedded_api_reference", "evidence": list(candidate.evidence)},
                             relationship="references_api")

            for script in sorted(discovered_scripts):
                if not self.request_manager.scope.is_in_scope(script) or script in seen_js:
                    continue
                seen_js.add(script)
                counters["javascript"] += 1
                dynamic = script not in parser.result.scripts
                asset = Asset(
                    f"javascript_{counters['javascript']:04d}", AssetType.JAVASCRIPT, script, script,
                    0.90 if dynamic else 0.98,
                    {"source_page": response.url, "discovery": "dynamic_dom" if dynamic else "html_script"},
                )
                javascript.append(asset)
                if graph is not None:
                    graph.add_node(id=asset.id, type=asset.type.value, label=asset.name, attributes=asset.metadata)
                    graph.add_edge(source=page.id, target=asset.id, relationship="loads")

                # Fetch same-scope JavaScript as data, never as executable Python.
                try:
                    js_response = self.request_manager.get(script)
                    js_type = js_response.headers.get("content-type", "").lower()
                    if "javascript" in js_type or "ecmascript" in js_type or script.lower().split("?", 1)[0].endswith(".js"):
                        for candidate in discover_api_endpoints(script, js_response.text):
                            add_endpoint(page=page, url=candidate.url, method=candidate.method,
                                         confidence=max(0.65, candidate.confidence - 0.05),
                                         metadata={"discovery": "javascript_source", "javascript": script,
                                                   "evidence": list(candidate.evidence)},
                                         relationship="javascript_references_api")
                except RequestError as exc:
                    errors.append(f"{script}: JavaScript fetch error: {exc}")

            for index, form_data in enumerate(discovered_forms, 1):
                action = normalize_url(response.url, str(form_data.get("action") or response.url))
                if not action or not self.request_manager.scope.is_in_scope(action):
                    continue
                counters["form"] += 1
                raw_inputs = form_data.get("inputs", ())
                named = tuple(str(item.get("name", "")) for item in raw_inputs if isinstance(item, dict) and item.get("name"))
                dynamic = form_data not in parser.result.forms
                form = FormAsset(
                    f"form_{counters['form']:04d}", AssetType.FORM, f"{response.url}#{index}", action, 1.0,
                    {"source_page": response.url, "discovery": "browser_dom" if dynamic else "html"},
                    str(form_data.get("method") or "GET").upper(), named,
                )
                forms.append(form)
                if graph is not None:
                    graph.add_node(id=form.id, type=form.type.value, label=form.name, attributes=form.metadata)
                    graph.add_edge(source=page.id, target=form.id, relationship="contains")
                for item in raw_inputs:
                    if not isinstance(item, dict) or not item.get("name"):
                        continue
                    counters["input"] += 1
                    input_asset = InputAsset(
                        f"input_{counters['input']:04d}", AssetType.INPUT, str(item["name"]), action, 1.0,
                        {"source_form": form.id, "source_page": response.url}, str(item.get("type") or "text"), "form", form.method,
                    )
                    inputs.append(input_asset)
                    if graph is not None:
                        graph.add_node(id=input_asset.id, type=input_asset.type.value, label=input_asset.name, attributes=input_asset.metadata)
                        graph.add_edge(source=form.id, target=input_asset.id, relationship="accepts")

            for candidate in detect_ai_surfaces(
                response.url, rendered_text, links=discovered_links, scripts=discovered_scripts, forms=discovered_forms,
            ):
                if not self.request_manager.scope.is_in_scope(candidate.url) or candidate.key() in seen_ai:
                    continue
                seen_ai.add(candidate.key())
                counters["ai_surface"] += 1
                asset = Asset(
                    f"ai_surface_{counters['ai_surface']:04d}", AssetType.AI_AGENT, candidate.kind, candidate.url,
                    candidate.confidence, {"source_page": response.url, "evidence": list(candidate.evidence)},
                )
                ai_surfaces.append(asset)
                if graph is not None:
                    graph.add_node(id=asset.id, type=asset.type.value, label=asset.name, attributes=asset.metadata)
                    graph.add_edge(source=page.id, target=asset.id, relationship="signals")

        if self.browser is not None:
            browser_observations.extend(self.browser.network_observations())

        return ReconResult(tuple(pages), tuple(endpoints), tuple(forms), tuple(inputs), tuple(javascript), tuple(ai_surfaces), tuple(browser_observations), tuple(errors))

from dataclasses import dataclass

from phobos.core.scope import ScopeValidator
from phobos.core.request_manager import HTTPResponseData
from phobos.graph.graph import Graph
from phobos.recon.crawler import ReconCrawler


@dataclass
class FakeRequestManager:
    scope: ScopeValidator
    pages: dict[str, HTTPResponseData]

    def get(self, url: str, *, headers=None) -> HTTPResponseData:
        return self.pages[url]


def test_crawler_discovers_links_forms_inputs_and_scripts():
    root = "https://example.com/"
    about = "https://example.com/about"
    script = "https://example.com/app.js"
    response = HTTPResponseData(
        url=root,
        status=200,
        headers={"content-type": "text/html; charset=utf-8"},
        body=(
            b'<html><a href="/about">About</a>'
            b'<script src="/app.js"></script>'
            b'<form action="/comments" method="POST">'
            b'<input name="comment" type="text">'
            b'</form></html>'
        ),
    )
    manager = FakeRequestManager(ScopeValidator(("example.com",)), {root: response, about: response})
    graph = Graph()

    result = ReconCrawler(manager, max_pages=10).crawl(root, graph=graph)

    assert len(result.pages) == 2
    assert len(result.forms) == 2
    assert len(result.inputs) == 2
    assert len(result.javascript) == 2
    assert any(asset.name == about for asset in result.endpoints)
    assert len(graph.nodes) > 0
    assert len(graph.edges) > 0

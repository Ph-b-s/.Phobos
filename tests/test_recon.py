from dataclasses import dataclass

from phobos.core.request_manager import HTTPResponseData
from phobos.core.scope import ScopeValidator
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
    assert len(result.javascript) == 1
    assert len(result.endpoints) == 1
    assert any(asset.name == about for asset in result.endpoints)
    assert len(graph.nodes) > 0
    assert len(graph.edges) > 0


def test_crawler_deduplicates_query_inputs():
    root = "https://example.com/"
    first = "https://example.com/search?q=one"
    second = "https://example.com/search?q=two"
    response = HTTPResponseData(
        url=root,
        status=200,
        headers={"content-type": "text/html"},
        body=(
            b'<a href="/search?q=one">one</a>'
            b'<a href="/search?q=two">two</a>'
        ),
    )
    page = HTTPResponseData(
        url=first,
        status=200,
        headers={"content-type": "text/html"},
        body=b"<html></html>",
    )
    manager = FakeRequestManager(
        ScopeValidator(("example.com",)),
        {root: response, first: page, second: page},
    )
    result = ReconCrawler(manager, max_pages=10).crawl(root)

    assert len(result.endpoints) == 2
    assert {asset.name for asset in result.inputs} == {"q"}
    assert len(result.inputs) == 2

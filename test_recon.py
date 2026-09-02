from dataclasses import dataclass

from ai_surface import detect_ai_surfaces
from crawler import ReconCrawler
from graph import Graph
from request_manager import HTTPResponseData, RequestError
from scope import ScopeValidator


@dataclass
class FakeRequestManager:
    scope: ScopeValidator
    pages: dict[str, HTTPResponseData]

    def get(self, url, *, headers=None):
        try:
            return self.pages[url]
        except KeyError as exc:
            raise RequestError(f"fake page not found: {url}") from exc


def test_recon_discovers_core_assets_and_ai_surface():
    root = "https://example.com/"
    about = "https://example.com/about"
    response = HTTPResponseData(
        root,
        200,
        {"content-type": "text/html; charset=utf-8"},
        b'<a href="/about?next=1">About</a><script src="/app.js"></script><form action="/comment" method="POST"><input name="comment" type="text"></form><div>openai tool_calls</div>',
    )
    response_about = HTTPResponseData(about, 200, {"content-type": "text/html"}, b"<p>about</p>")
    manager = FakeRequestManager(
        ScopeValidator(("example.com",), allow_private_targets=True),
        {root: response, "https://example.com/about?next=1": response_about},
    )
    graph = Graph()
    result = ReconCrawler(manager, max_pages=10).crawl(root, graph=graph)
    assert len(result.pages) == 2
    assert len(result.forms) == 1
    assert len(result.inputs) == 2
    assert len(result.javascript) == 1
    assert len(result.ai_surfaces) >= 1
    assert any(asset.name == "agent_signal" for asset in result.ai_surfaces)
    assert any(edge.relationship == "signals" for edge in graph.edges)


def test_ai_surface_detector_finds_known_ai_endpoints_and_inputs():
    candidates = detect_ai_surfaces(
        "https://example.com/chat",
        "<div>Prompt the assistant</div>",
        links=("https://example.com/v1/chat/completions",),
        forms=(
            {
                "action": "https://example.com/chat",
                "inputs": [{"name": "prompt", "type": "text"}],
            },
        ),
    )
    kinds = {candidate.kind for candidate in candidates}
    assert "chat_completion_endpoint" in kinds
    assert "ai_input" in kinds


def test_recon_queue_is_bounded():
    root = "https://example.com/"
    links = "".join(f'<a href="/p{i}">p{i}</a>' for i in range(20))
    response = HTTPResponseData(root, 200, {"content-type": "text/html"}, links.encode())
    manager = FakeRequestManager(
        ScopeValidator(("example.com",), allow_private_targets=True),
        {root: response},
    )
    result = ReconCrawler(manager, max_pages=5, max_discovered_urls=5).crawl(root)
    assert len(result.pages) == 1
    assert any("fake page not found" in error for error in result.errors)
    assert any("discovery queue limit reached" in error for error in result.errors)


def test_recon_queue_limit_must_cover_page_budget():
    manager = FakeRequestManager(
        ScopeValidator(("example.com",), allow_private_targets=True),
        {},
    )
    try:
        ReconCrawler(manager, max_pages=5, max_discovered_urls=4)
    except ValueError as exc:
        assert "at least max_pages" in str(exc)
    else:
        raise AssertionError("expected ValueError")

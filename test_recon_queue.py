from dataclasses import dataclass

from crawler import ReconCrawler
from request_manager import HTTPResponseData
from scope import ScopeValidator


@dataclass
class FakeRequestManager:
    scope: ScopeValidator
    pages: dict[str, HTTPResponseData]

    def get(self, url, *, headers=None):
        return self.pages[url]


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

from types import SimpleNamespace

from graph import Graph
from knowledge_store import KnowledgeStore
from models import Asset, AssetType
from module_runner import default_module_registry
from security_modules import ModuleContext


class FakeResponse:
    def __init__(self, headers, status=200, body=b"ok"):
        self.headers = {key.lower(): value for key, value in headers.items()}
        self.status = status
        self.body = body


class FakeRequests:
    def __init__(self, response):
        self.response = response
        self.calls = []
        self.scope = SimpleNamespace()

    def get(self, url, *, headers=None):
        self.calls.append(("GET", url, headers or {}))
        return self.response

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("headers", {})))
        return self.response


def _context(requests):
    asset = Asset("page_1", AssetType.PAGE, "https://example.com/", "https://example.com/")
    return ModuleContext(
        target="https://example.com/",
        assets=(asset,),
        knowledge=KnowledgeStore(),
        graph=Graph(),
        metadata={"request_manager": requests},
    )


def test_default_registry_contains_phase_modules():
    registry = default_module_registry()
    for module_id in (
        "web.headers", "web.cookies", "web.exposure", "web.methods", "web.config", "web.cors",
        "web.nmap", "ai.indirect_prompt_injection",
    ):
        assert module_id in registry.ids()


def test_web_headers_emits_finding_for_missing_headers():
    requests = FakeRequests(FakeResponse({"content-type": "text/html"}))
    result = default_module_registry().get("web.headers")(_context(requests))
    assert result.findings
    assert any(item.type == "missing_security_headers" for item in result.findings)


def test_web_cors_detects_reflected_origin_with_credentials():
    requests = FakeRequests(FakeResponse({
        "access-control-allow-origin": "https://phobos.invalid",
        "access-control-allow-credentials": "true",
    }))
    result = default_module_registry().get("web.cors")(_context(requests))
    assert any(item.type == "permissive_cors_with_credentials" for item in result.findings)

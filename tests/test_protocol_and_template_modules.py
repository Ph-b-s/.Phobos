from graph import Graph
from knowledge_store import KnowledgeStore
from models import Asset, AssetType
from module_runner import default_module_registry
from security_modules import ModuleContext


class FakeResponse:
    def __init__(self, body="ok", status=200, headers=None):
        self.body = body.encode()
        self.status = status
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}

    @property
    def text(self):
        return self.body.decode()


class FakeRequests:
    def __init__(self, responder):
        self.responder = responder

    def get(self, url, *, headers=None):
        return self.responder("GET", url, headers or {}, None)

    def request(self, method, url, *, headers=None, body=None):
        return self.responder(method, url, headers or {}, body)


def _context(requests, url="https://example.com/search?q=test", asset_type=AssetType.ENDPOINT):
    asset = Asset("asset_1", asset_type, "target", url)
    return ModuleContext(target="https://example.com", assets=(asset,), knowledge=KnowledgeStore(), graph=Graph(), metadata={"request_manager": requests})


def test_ssti_flags_arithmetic_template_evaluation():
    requests = FakeRequests(lambda method, url, headers, body: FakeResponse("result 49") if "7%2A7" in url else FakeResponse("normal"))
    result = default_module_registry().get("web.ssti")(_context(requests))
    assert any(item.type == "potential_server_side_template_injection" for item in result.findings)


def test_host_header_flags_canary_reflection():
    requests = FakeRequests(lambda method, url, headers, body: FakeResponse(
        body="https://phobos-invalid.example/account" if headers.get("Host") == "phobos-invalid.example" else "ok"
    ))
    result = default_module_registry().get("web.host_header")(_context(requests, "https://example.com/"))
    assert any(item.type == "potential_host_header_trust_issue" for item in result.findings)


def test_cache_module_records_missing_policy():
    requests = FakeRequests(lambda method, url, headers, body: FakeResponse("ok", headers={}))
    result = default_module_registry().get("web.cache")(_context(requests, "https://example.com/"))
    assert any(item.type == "missing_explicit_cache_policy" for item in result.findings)


def test_request_smuggling_records_ambiguous_framing_without_payload():
    requests = FakeRequests(lambda method, url, headers, body: FakeResponse(
        "ok", headers={"Transfer-Encoding": "chunked", "Content-Length": "12"}
    ))
    result = default_module_registry().get("web.request_smuggling")(_context(requests, "https://example.com/"))
    assert any(item.type == "ambiguous_http_framing_headers" for item in result.findings)

from graph import Graph
from knowledge_store import KnowledgeStore
from models import Asset, AssetType
from module_runner import default_module_registry
from security_modules import ModuleContext


class FakeResponse:
    def __init__(self, body: str = "ok", status: int = 200, headers=None):
        self.body = body.encode()
        self.status = status
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}

    @property
    def text(self):
        return self.body.decode()


class FakeRequests:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def get(self, url, *, headers=None):
        self.calls.append(("GET", url, headers or {}))
        return self.responder(url, headers or {})


def _context(requests, url="https://example.com/search?q=test"):
    asset = Asset("endpoint_1", AssetType.ENDPOINT, "search", url)
    return ModuleContext(
        target="https://example.com/",
        assets=(asset,),
        knowledge=KnowledgeStore(),
        graph=Graph(),
        metadata={"request_manager": requests},
    )


def test_xss_flags_raw_html_reflection():
    requests = FakeRequests(lambda url, headers: FakeResponse(
        body='result: "><phobos-xss>PHOBOSXSS</phobos-xss>' if "PHOBOSXSS" in url else "ok"
    ))
    result = default_module_registry().get("web.xss")(_context(requests))
    assert any(item.type == "potential_reflected_xss" for item in result.findings)


def test_xss_does_not_flag_encoded_reflection():
    requests = FakeRequests(lambda url, headers: FakeResponse(
        body='result: &quot;&gt;&lt;phobos-xss&gt;PHOBOSXSS&lt;/phobos-xss&gt;' if "PHOBOSXSS" in url else "ok"
    ))
    result = default_module_registry().get("web.xss")(_context(requests))
    assert not any(item.type == "potential_reflected_xss" for item in result.findings)


def test_sqli_flags_database_error_signature():
    def responder(url, headers):
        if "phobos%27" in url or "phobos'" in url:
            return FakeResponse("SQLSTATE[42000]: You have an error in your SQL syntax")
        return FakeResponse("normal result")

    requests = FakeRequests(responder)
    result = default_module_registry().get("web.sqli")(_context(requests))
    assert any(item.type == "potential_sql_injection_error_signal" for item in result.findings)


def test_information_disclosure_detects_private_key_marker_without_storing_secret():
    secret = "-----BEGIN PRIVATE KEY-----"
    requests = FakeRequests(lambda url, headers: FakeResponse(secret if "/search" in url else "ok"))
    result = default_module_registry().get("web.info_disclosure")(_context(requests, "https://example.com/search?q=test"))
    finding = next(item for item in result.findings if item.type == "potential_sensitive_information_disclosure")
    observation = next(item for item in result.observations if item.kind == "web.info_disclosure.secret_pattern")
    assert finding.metadata["pattern"] == "private-key material"
    assert "context" not in observation.data
    assert "-----BEGIN PRIVATE KEY-----" not in repr(observation.data)


def test_api_baseline_records_json_surface():
    requests = FakeRequests(lambda url, headers: FakeResponse(
        '{"id": 1}', headers={"content-type": "application/json"}
    ))
    asset = Asset("api_1", AssetType.API, "api", "https://example.com/api/item?id=1")
    context = ModuleContext(
        target="https://example.com/",
        assets=(asset,),
        knowledge=KnowledgeStore(),
        graph=Graph(),
        metadata={"request_manager": requests},
    )
    result = default_module_registry().get("web.api")(context)
    assert result.observations[0].kind == "web.api.baseline"

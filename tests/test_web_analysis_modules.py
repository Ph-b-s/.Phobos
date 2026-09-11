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
        self.calls = []

    def get(self, url, *, headers=None):
        self.calls.append(("GET", url, headers or {}))
        return self.responder("GET", url, headers or {}, None)

    def request(self, method, url, *, headers=None, body=None):
        self.calls.append((method, url, headers or {}, body))
        return self.responder(method, url, headers or {}, body)


def _jwt(header, payload):
    import base64
    enc = lambda value: base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    return f"{enc(header)}.{enc(payload)}.signature"


def test_client_javascript_flags_source_sink_combination():
    source = "const x = location.search; element.innerHTML = x;"
    requests = FakeRequests(lambda method, url, headers, body: FakeResponse(source))
    asset = Asset("js_1", AssetType.JAVASCRIPT, "app.js", "https://example.com/app.js")
    context = ModuleContext(target="https://example.com", assets=(asset,), knowledge=KnowledgeStore(), graph=Graph(), metadata={"request_manager": requests})
    result = default_module_registry().get("web.client_javascript")(context)
    assert any(item.type == "potential_dom_xss_source_sink" for item in result.findings)


def test_jwt_module_flags_none_algorithm_without_storing_token():
    header = "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0"
    token = f"{header}.payload.signature"
    requests = FakeRequests(lambda method, url, headers, body: FakeResponse(token))
    asset = Asset("page_1", AssetType.PAGE, "page", "https://example.com/page")
    context = ModuleContext(target="https://example.com", assets=(asset,), knowledge=KnowledgeStore(), graph=Graph(), metadata={"request_manager": requests})
    result = default_module_registry().get("web.jwt")(context)
    assert any(item.type == "jwt_none_algorithm_signal" for item in result.findings)
    assert all(token not in repr(item.data) for item in result.observations)


def test_jwt_module_flags_missing_exp_as_limited_signal():
    token = _jwt('{"alg":"HS256","typ":"JWT"}', '{"sub":"123"}')
    requests = FakeRequests(lambda method, url, headers, body: FakeResponse(token))
    asset = Asset("page_1", AssetType.PAGE, "page", "https://example.com/page")
    context = ModuleContext(target="https://example.com", assets=(asset,), knowledge=KnowledgeStore(), graph=Graph(), metadata={"request_manager": requests})
    result = default_module_registry().get("web.jwt")(context)
    assert any(item.type == "jwt_missing_exp_claim_signal" for item in result.findings)


def test_configured_jwt_policy_accepts_valid_read_only_claim_set():
    token = _jwt('{"alg":"RS256","typ":"JWT"}', '{"sub":"123","iss":"issuer-a","aud":"api","exp":4102444800,"nbf":1700000000,"iat":1700000000}')
    metadata = {"jwt_policy": {"tokens": [token], "allowed_algorithms": ["RS256"], "issuer": "issuer-a", "audience": "api", "required_claims": ["sub", "exp"]}}
    context = ModuleContext(target="https://example.com", knowledge=KnowledgeStore(), graph=Graph(), metadata=metadata)
    result = default_module_registry().get("web.jwt")(context)
    assert result.observations
    assert result.findings == ()
    assert token not in repr(result.observations)


def test_configured_jwt_policy_flags_algorithm_and_claim_failures():
    token = _jwt('{"alg":"HS256","typ":"JWT"}', '{"sub":"123","iss":"wrong","aud":"other","exp":1}')
    metadata = {"jwt_policy": {"tokens": [token], "allowed_algorithms": ["RS256"], "issuer": "issuer-a", "audience": "api", "required_claims": ["sub", "role"]}}
    context = ModuleContext(target="https://example.com", knowledge=KnowledgeStore(), graph=Graph(), metadata=metadata)
    result = default_module_registry().get("web.jwt")(context)
    types = {item.type for item in result.findings}
    assert "jwt_algorithm_policy_failure" in types
    assert "jwt_claim_policy_failure" in types
    assert all("wrong" not in repr(item.data) for item in result.observations)


def test_configured_jwt_policy_requires_explicit_algorithm_allowlist():
    token = _jwt('{"alg":"HS256","typ":"JWT"}', '{"sub":"123"}')
    metadata = {"jwt_policy": {"tokens": [token]}}
    context = ModuleContext(target="https://example.com", knowledge=KnowledgeStore(), graph=Graph(), metadata=metadata)
    try:
        default_module_registry().get("web.jwt")(context)
    except ValueError as exc:
        assert "allowed_algorithms" in str(exc)
    else:
        raise AssertionError("JWT policy accepted without an algorithm allowlist")


def test_graphql_module_flags_enabled_introspection():
    requests = FakeRequests(lambda method, url, headers, body: FakeResponse(
        '{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
        headers={"content-type": "application/json"},
    ))
    asset = Asset("graphql_1", AssetType.API, "graphql", "https://example.com/graphql")
    context = ModuleContext(target="https://example.com", assets=(asset,), knowledge=KnowledgeStore(), graph=Graph(), metadata={"request_manager": requests})
    result = default_module_registry().get("web.graphql")(context)
    assert any(item.type == "graphql_introspection_enabled" for item in result.findings)
    assert requests.calls[0][0] == "POST"


def test_graphql_module_ignores_non_graphql_api_routes():
    requests = FakeRequests(lambda method, url, headers, body: FakeResponse())
    asset = Asset("api_1", AssetType.API, "api", "https://example.com/api/users")
    context = ModuleContext(target="https://example.com", assets=(asset,), knowledge=KnowledgeStore(), graph=Graph(), metadata={"request_manager": requests})
    result = default_module_registry().get("web.graphql")(context)
    assert result.findings == ()
    assert requests.calls == []

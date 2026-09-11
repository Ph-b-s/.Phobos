from graph import Graph
from knowledge_store import KnowledgeStore
from models import Asset, AssetType
from module_runner import default_module_registry
from security_modules import ModuleContext


def _context(assets, metadata=None):
    return ModuleContext(target="https://example.com", assets=tuple(assets), knowledge=KnowledgeStore(), graph=Graph(), metadata=metadata or {})


class _Response:
    def __init__(self, text, status=200):
        self.text = text
        self.status = status
        self.headers = {"content-type": "application/json"}


class _Requests:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def get(self, url, *, headers=None):
        self.calls.append(("GET", url, headers or {}))
        return self.responder("GET", url, headers or {})

    def request(self, method, url, *, headers=None, body=None):
        self.calls.append((method, url, headers or {}, body))
        return self.responder(method, url, headers or {})


def test_web_ssrf_sink_is_identified_without_networking():
    asset = Asset("e1", AssetType.ENDPOINT, "fetch", "https://example.com/fetch?url=https://example.org")
    result = default_module_registry().get("web.ssrf")(_context((asset,)))
    assert result.findings[0].type == "potential_ssrf_sink"
    assert result.findings[0].metadata["status"] == "surface_identified_requires_active_validation"


def test_web_command_and_xml_surfaces_are_detected():
    cmd = Asset("e1", AssetType.ENDPOINT, "exec", "https://example.com/run?command=test")
    xml = Asset("e2", AssetType.ENDPOINT, "soap", "https://example.com/soap", metadata={"description": "application/xml SOAP service"})
    registry = default_module_registry()
    assert registry.get("web.command_injection")(_context((cmd,))).findings[0].type == "potential_command_execution_sink"
    assert registry.get("web.xxe")(_context((xml,))).findings[0].type == "potential_xml_processing_surface"


def test_ai_surface_modules_consume_discovered_asset_metadata():
    agent = Asset("a1", AssetType.AI_AGENT, "support agent", "https://example.com/agent", metadata={"description": "RAG knowledge base with vector search and agent handoff", "capabilities": "tool call"})
    registry = default_module_registry()
    assert registry.get("ai.rag")(_context((agent,))).findings[0].type == "rag_surface_detected"
    assert registry.get("ai.vector")(_context((agent,))).findings[0].type == "vector_store_surface_detected"
    assert registry.get("ai.multi_agent")(_context((agent,))).findings[0].type == "multi_agent_surface_detected"
    assert registry.get("ai.tool_abuse")(_context((agent,))).findings[0].type == "ai_tool_surface_detected"


def test_ai_resource_module_records_limits_without_claiming_exhaustion():
    agent = Asset("a1", AssetType.AI_AGENT, "agent", "https://example.com/agent")
    result = default_module_registry().get("ai.unbounded_consumption")(_context((agent,)))
    assert result.findings[0].type == "ai_resource_limits_not_observed"
    assert result.findings[0].metadata["severity"] == "low"


def test_surface_module_does_not_fetch_urls():
    class FailRequests:
        def get(self, *args, **kwargs):
            raise AssertionError("surface analysis must not make HTTP requests")

    context = _context((Asset("e1", AssetType.ENDPOINT, "fetch", "https://example.com/fetch?url=x"),), {"request_manager": FailRequests()})
    result = default_module_registry().get("web.ssrf")(context)
    assert result.findings


def test_configured_rag_validation_compares_low_high_and_records_only_digests():
    def respond(method, url, headers):
        marker = "PUBLIC_DOC" if headers.get("Authorization") == "Bearer LOW" else "PRIVATE_DOC"
        return _Response('{"documents":[{"source":"%s"}]}' % marker)

    requests = _Requests(respond)
    metadata = {"rag_validation": {"read_only": True, "endpoints": ["https://example.com/api/retrieve"], "method": "POST", "query": "customer handbook", "low_headers": {"Authorization": "Bearer LOW"}, "high_headers": {"Authorization": "Bearer HIGH"}, "allowed_markers": ["PUBLIC_DOC"], "forbidden_markers": ["PRIVATE_DOC"]}, "request_manager": requests}
    result = default_module_registry().get("ai.rag")(_context((), metadata))
    assert result.observations
    assert result.findings == ()
    assert requests.calls[0][0] == "POST"
    data = result.observations[0].data
    assert "PRIVATE_DOC" not in repr(data)
    assert data["high"]["forbidden_markers_observed"] == ["PRIVATE_DOC"]


def test_configured_rag_validation_flags_forbidden_content_for_low_privilege():
    def respond(method, url, headers):
        return _Response('{"source":"PRIVATE_DOC"}')

    requests = _Requests(respond)
    metadata = {"rag_validation": {"read_only": True, "endpoints": ["https://example.com/api/retrieve"], "query": "private document", "forbidden_markers": ["PRIVATE_DOC"]}, "request_manager": requests}
    result = default_module_registry().get("ai.rag")(_context((), metadata))
    assert result.findings[0].type == "ai_rag_authorization_failure"


def test_configured_rag_requires_explicit_read_only_gate():
    metadata = {"rag_validation": {"endpoints": ["https://example.com/api/retrieve"], "query": "test"}, "request_manager": _Requests(lambda *args: _Response("ok"))}
    try:
        default_module_registry().get("ai.rag")(_context((), metadata))
    except ValueError as exc:
        assert "read_only=true" in str(exc)
    else:
        raise AssertionError("RAG validation ran without an explicit read-only gate")

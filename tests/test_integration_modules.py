from graph import Graph
from knowledge_store import KnowledgeStore
from models import Asset, AssetType
from module_runner import default_module_registry
from scanner import default_module_selection
from security_modules import ModuleContext
from workflow_engine import WorkflowEngine


def _context(assets, metadata=None, interactor=None, accounts=None, workflow=None):
    return ModuleContext(target="https://example.com", assets=tuple(assets), knowledge=KnowledgeStore(), graph=Graph(), metadata=metadata or {}, interactor=interactor, accounts=accounts, workflow=workflow)


def test_default_plan_includes_integrated_modules_in_web_ai_stage():
    ids = {item.module_id for item in default_module_selection().selections}
    assert {"web.openapi", "web.open_redirect", "web.source_maps", "web.sensitive_inputs"} <= ids
    assert {"web.graphql_auth_surface", "web.websocket_auth_surface", "web.object_authorization"} <= ids
    assert {"ai.memory", "ai.identity", "ai.trust_boundary", "ai.tool_rag_bridge"} <= ids


def test_openapi_and_redirect_surfaces_are_identified_without_networking():
    assets = (Asset("a1", AssetType.API, "swagger", "https://example.com/docs/openapi.json"), Asset("a2", AssetType.ENDPOINT, "login", "https://example.com/login?next=/dashboard"))
    registry = default_module_registry()
    assert registry.get("web.openapi")(_context(assets)).findings[0].type == "openapi_surface_detected"
    assert registry.get("web.open_redirect")(_context(assets)).findings[0].type == "open_redirect_candidate"


def test_source_map_and_sensitive_input_modules_do_not_store_values():
    assets = (Asset("js", AssetType.JAVASCRIPT, "app.js", "https://example.com/static/app.js", metadata={"source": "//# sourceMappingURL=app.js.map"}), Asset("form", AssetType.FORM, "login", "https://example.com/login?password=secret", metadata={"fields": [{"name": "api_key", "type": "text"}]}))
    registry = default_module_registry()
    assert registry.get("web.source_maps")(_context(assets)).findings[0].type == "source_map_exposure_candidate"
    sensitive = registry.get("web.sensitive_inputs")(_context(assets))
    assert sensitive.findings[0].type == "sensitive_input_surface"
    assert all("secret" not in repr(item.data).lower() for item in sensitive.observations)


def test_ai_memory_and_identity_surfaces_are_connected():
    assets = (Asset("ai", AssetType.AI_AGENT, "support-memory", "https://example.com/agent", metadata={"description": "persistent conversation memory"}), Asset("api", AssetType.API, "tenant-agent", "https://example.com/api/agent", metadata={"parameters": ["tenant_id", "role"]}))
    registry = default_module_registry()
    assert registry.get("ai.memory")(_context(assets)).findings[0].type == "ai_memory_surface_detected"
    assert registry.get("ai.identity")(_context(assets)).findings[0].type == "ai_identity_boundary_candidate"


def test_ai_trust_boundary_emits_bounded_auth_followups():
    assets = (Asset("ai", AssetType.AI_AGENT, "customer agent", "https://example.com/agent/customer"), Asset("api", AssetType.API, "customer profile endpoint", "https://example.com/api/customer/profile"))
    result = default_module_registry().get("ai.trust_boundary")(_context(assets))
    assert result.observations and result.follow_ups
    assert all(item["module_id"] == "cross_layer.auth_boundary" for item in result.follow_ups)


def test_graphql_and_websocket_auth_surfaces_are_passive():
    assets = (Asset("gql", AssetType.API, "graphql viewer query", "https://example.com/api/graphql", metadata={"description": "viewer account tenant permissions"}), Asset("ws", AssetType.ENDPOINT, "notifications websocket", "wss://example.com/socket", metadata={"description": "websocket"}))
    registry = default_module_registry()
    assert registry.get("web.graphql_auth_surface")(_context(assets)).findings[0].type == "graphql_authorization_surface"
    assert registry.get("web.websocket_auth_surface")(_context(assets)).findings[0].type == "websocket_authentication_requires_review"


def test_tool_rag_bridge_emits_bounded_followups():
    assets = (Asset("tool", AssetType.TOOL, "customer search tool", "https://example.com/tools/customer", metadata={"description": "tool function customer profile"}), Asset("rag", AssetType.RESOURCE, "customer knowledge documents", "https://example.com/knowledge/customer", metadata={"description": "RAG retrieval customer profile"}))
    result = default_module_registry().get("ai.tool_rag_bridge")(_context(assets))
    assert result.observations
    assert {item["module_id"] for item in result.follow_ups} == {"cross_layer.auth_boundary", "cross_layer.data_flow"}


class _Snapshot:
    def __init__(self, text):
        self.text = text
        self.url = "https://example.com"


class _Interactor:
    def __init__(self):
        self.current = ""
    def open(self, url):
        self.current = url
        return True
    def snapshot(self):
        return _Snapshot("same protected object content")


class _Response:
    def __init__(self, status, text):
        self.status = status
        self.text = text


class _Requests:
    def request(self, method, url, *, headers, body):
        assert method == "POST"
        assert url == "https://example.com/api/graphql"
        return _Response(200, '{"data":{"viewer":{"id":"same"}}}')


def test_object_authorization_compares_explicit_owned_and_peer_objects():
    engine = WorkflowEngine()
    engine.register_action("noop", lambda context, step: None)
    metadata = {"object_authorization": {"low_workflow": [{"id": "session", "action": "noop", "description": "establish low privilege session"}], "pairs": [{"owned_url": "https://example.com/api/items/1", "peer_url": "https://example.com/api/items/2"}]}}
    result = default_module_registry().get("web.object_authorization")(_context((), metadata, _Interactor(), object(), engine))
    assert result.observations
    assert result.findings[0].type == "potential_idor_object_authorization_failure"


def test_configured_graphql_auth_compares_low_high_read_only_requests():
    metadata = {
        "graphql_auth": {
            "endpoints": ["https://example.com/api/graphql"],
            "query": "query Viewer { viewer { id } }",
            "low_headers": {"Authorization": "Bearer LOW"},
            "high_headers": {"Authorization": "Bearer HIGH"},
        },
        "request_manager": _Requests(),
    }
    result = default_module_registry().get("web.graphql_auth_surface")(_context((), metadata))
    assert result.observations
    assert result.findings[0].type == "potential_graphql_authorization_failure"


def test_configured_graphql_auth_rejects_mutations():
    metadata = {
        "graphql_auth": {"endpoints": ["https://example.com/api/graphql"], "query": "mutation Update { updateUser { id } }"},
        "request_manager": _Requests(),
    }
    try:
        default_module_registry().get("web.graphql_auth_surface")(_context((), metadata))
    except ValueError as exc:
        assert "read-only" in str(exc)
    else:
        raise AssertionError("mutation query was not rejected")

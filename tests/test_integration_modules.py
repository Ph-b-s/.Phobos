from graph import Graph
from knowledge_store import KnowledgeStore
from models import Asset, AssetType
from module_runner import default_module_registry
from scanner import default_module_selection
from security_modules import ModuleContext


def _context(assets):
    return ModuleContext(target="https://example.com", assets=tuple(assets), knowledge=KnowledgeStore(), graph=Graph())


def test_default_plan_includes_integrated_modules_in_web_ai_stage():
    ids = {item.module_id for item in default_module_selection().selections}
    assert {"web.openapi", "web.open_redirect", "web.source_maps", "web.sensitive_inputs"} <= ids
    assert {"ai.memory", "ai.identity", "ai.trust_boundary"} <= ids


def test_openapi_and_redirect_surfaces_are_identified_without_networking():
    assets = (
        Asset("a1", AssetType.API, "swagger", "https://example.com/docs/openapi.json"),
        Asset("a2", AssetType.ENDPOINT, "login", "https://example.com/login?next=/dashboard"),
    )
    registry = default_module_registry()
    openapi = registry.get("web.openapi")(_context(assets))
    redirect = registry.get("web.open_redirect")(_context(assets))
    assert openapi.findings[0].type == "openapi_surface_detected"
    assert redirect.findings[0].type == "open_redirect_candidate"


def test_source_map_and_sensitive_input_modules_do_not_store_values():
    assets = (
        Asset("js", AssetType.JAVASCRIPT, "app.js", "https://example.com/static/app.js", metadata={"source": "//# sourceMappingURL=app.js.map"}),
        Asset("form", AssetType.FORM, "login", "https://example.com/login?password=secret", metadata={"fields": [{"name": "api_key", "type": "text"}]}),
    )
    registry = default_module_registry()
    source_maps = registry.get("web.source_maps")(_context(assets))
    sensitive = registry.get("web.sensitive_inputs")(_context(assets))
    assert source_maps.findings[0].type == "source_map_exposure_candidate"
    assert sensitive.findings[0].type == "sensitive_input_surface"
    assert all("secret" not in repr(item.data).lower() for item in sensitive.observations)


def test_ai_memory_and_identity_surfaces_are_connected():
    assets = (
        Asset("ai", AssetType.AI_AGENT, "support-memory", "https://example.com/agent", metadata={"description": "persistent conversation memory"}),
        Asset("api", AssetType.API, "tenant-agent", "https://example.com/api/agent", metadata={"parameters": ["tenant_id", "role"]}),
    )
    registry = default_module_registry()
    memory = registry.get("ai.memory")(_context(assets))
    identity = registry.get("ai.identity")(_context(assets))
    assert memory.findings[0].type == "ai_memory_surface_detected"
    assert identity.findings[0].type == "ai_identity_boundary_candidate"


def test_ai_trust_boundary_emits_bounded_auth_followups():
    assets = (
        Asset("ai", AssetType.AI_AGENT, "customer agent", "https://example.com/agent/customer"),
        Asset("api", AssetType.API, "customer profile endpoint", "https://example.com/api/customer/profile"),
    )
    result = default_module_registry().get("ai.trust_boundary")(_context(assets))
    assert result.observations
    assert result.follow_ups
    assert all(item["module_id"] == "cross_layer.auth_boundary" for item in result.follow_ups)

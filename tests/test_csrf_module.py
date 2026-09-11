from graph import Graph
from knowledge_store import KnowledgeStore
from models import FormAsset, AssetType
from module_runner import default_module_registry
from security_modules import ModuleContext


def _context(forms):
    return ModuleContext(
        target="https://example.com/",
        assets=tuple(forms),
        knowledge=KnowledgeStore(),
        graph=Graph(),
    )


def test_csrf_flags_state_changing_form_without_token():
    form = FormAsset(
        "form_1", AssetType.FORM, "checkout", "https://example.com/checkout", 1.0,
        {"source_page": "https://example.com/checkout"}, "POST", ("email", "amount")
    )
    result = default_module_registry().get("web.csrf")(_context((form,)))
    assert any(item.type == "potential_missing_csrf_protection" for item in result.findings)


def test_csrf_does_not_flag_form_with_recognized_token():
    form = FormAsset(
        "form_1", AssetType.FORM, "checkout", "https://example.com/checkout", 1.0,
        {"source_page": "https://example.com/checkout"}, "POST", ("email", "csrf_token")
    )
    result = default_module_registry().get("web.csrf")(_context((form,)))
    assert not any(item.type == "potential_missing_csrf_protection" for item in result.findings)


def test_csrf_ignores_safe_get_forms():
    form = FormAsset(
        "form_1", AssetType.FORM, "search", "https://example.com/search", 1.0,
        {"source_page": "https://example.com/search"}, "GET", ("q",)
    )
    result = default_module_registry().get("web.csrf")(_context((form,)))
    assert result.findings == ()

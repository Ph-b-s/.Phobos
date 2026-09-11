from graph import Graph
from knowledge_store import KnowledgeStore
from models import Asset, AssetType
from scanner import ScanPlan, ModuleSelection, build_planner_context, execute_plan


class FakeResponse:
    status = 200
    headers = {"content-type": "text/html"}
    body = b"ok"


class FakeRequests:
    def get(self, url, *, headers=None):
        return FakeResponse()

    def request(self, method, url, **kwargs):
        return FakeResponse()


class FakeScope:
    allow_private_targets = False


def test_execute_plan_reuses_shared_knowledge_state():
    asset = Asset("page_1", AssetType.PAGE, "home", "https://example.com/")
    store = KnowledgeStore()
    graph = Graph()
    graph.add_node(id=asset.id, type=asset.type.value, label=asset.name)
    plan = ScanPlan((ModuleSelection("web.headers"), ModuleSelection("web.config")))
    from module_runner import default_module_registry
    result = execute_plan(
        "https://example.com/", (asset,), plan,
        runners=default_module_registry(), knowledge=store, graph=graph,
        capabilities={"metadata": {"request_manager": FakeRequests(), "scope": FakeScope()}},
    )
    assert result.knowledge is store
    assert result.module_run is not None
    assert len(store.observations) >= 1


def test_planner_context_exposes_only_implemented_modules():
    context = build_planner_context("https://example.com", KnowledgeStore(), completed_modules=())
    assert "web.headers" in context
    assert "web.sqli" not in context

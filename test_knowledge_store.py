from knowledge_store import KnowledgeStore, SecurityFact, SecurityObservation
from models import Asset, AssetType, Finding


def test_modules_can_share_observations_and_facts():
    store = KnowledgeStore()
    asset = Asset("page-1", AssetType.PAGE, "https://example.com")
    store.add_asset(asset)
    store.add_observation(
        SecurityObservation(
            "obs-1",
            "api_discovered",
            "web.api",
            "Discovered application API",
            (asset.id,),
            {"method": "POST", "path": "/api/chat"},
            0.9,
        )
    )
    store.add_fact(SecurityFact("ai.endpoint", "/api/chat", "web.api", 0.9, ("obs-1",)))

    assert store.observations_by_kind("api_discovered")[0].asset_ids == ("page-1",)
    assert store.get_fact("ai.endpoint") == "/api/chat"


def test_findings_are_shared_and_context_is_bounded():
    store = KnowledgeStore()
    finding = Finding("finding-1", "xss", 0.8, ("reflection",))
    store.add_finding(finding)
    context = store.context(max_items=10)

    assert store.findings_by_type("xss") == (finding,)
    assert context["findings"][0]["id"] == "finding-1"
    assert set(context) == {"assets", "observations", "facts", "findings"}


def test_duplicate_ids_cannot_conflict():
    store = KnowledgeStore()
    first = SecurityObservation("obs-1", "signal", "a", "one")
    store.add_observation(first)
    store.add_observation(first)
    try:
        store.add_observation(SecurityObservation("obs-1", "signal", "b", "two"))
    except ValueError:
        pass
    else:
        raise AssertionError("conflicting observation was accepted")

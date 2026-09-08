from models import Asset, AssetType
from scanner import (
    ModuleSelection,
    ScanPlan,
    default_module_selection,
    execute_plan,
    merge_module_selections,
    validate_plan,
)


def test_default_plan_keeps_nmap_as_last_optional_web_module():
    plan = default_module_selection()
    ids = [item.module_id for item in plan.selections]
    assert "web.headers" in ids
    assert "web.injection" not in ids
    assert "network.nmap" not in ids
    assert "web.nmap" not in ids

    nmap_plan = default_module_selection(include_nmap=True)
    nmap_ids = [item.module_id for item in nmap_plan.selections]
    assert nmap_ids[-1] == "web.nmap"


def test_plan_validation_rejects_unknown_modules():
    try:
        validate_plan(ScanPlan((ModuleSelection("no.such.module"),)))
    except ValueError as exc:
        assert "unknown security module" in str(exc)
    else:
        raise AssertionError("unknown module was accepted")


def test_plan_validation_deduplicates_modules():
    plan = validate_plan(
        ScanPlan((ModuleSelection("web.headers"), ModuleSelection("web.headers", "duplicate")))
    )
    assert [item.module_id for item in plan.selections] == ["web.headers"]


def test_merge_keeps_supplemental_modules_last():
    base = default_module_selection(include_nmap=True)
    merged = merge_module_selections(
        base,
        [ModuleSelection("web.xss", "AI-selected"), ModuleSelection("ai.rag", "AI-selected")],
    )
    ids = [item.module_id for item in merged.selections]
    assert ids[-1] == "web.nmap"
    assert ids.index("web.xss") < ids.index("web.nmap")
    assert ids.index("ai.rag") < ids.index("web.nmap")


def test_plan_validation_rejects_module_after_supplemental():
    plan = ScanPlan(
        (
            ModuleSelection("web.nmap"),
            ModuleSelection("web.xss"),
        )
    )
    try:
        validate_plan(plan)
    except ValueError as exc:
        assert "cannot run after a supplemental module" in str(exc)
    else:
        raise AssertionError("invalid stage ordering was accepted")


def test_execute_plan_is_module_driven():
    asset = Asset("page-1", AssetType.PAGE, "https://example.com")
    plan = ScanPlan((ModuleSelection("web.headers"),), source="ai")

    def fake_runner(context):
        assert context.target == "https://example.com"
        assert context.assets == (asset,)
        return ()

    result = execute_plan(
        "https://example.com",
        (asset,),
        plan,
        runners={"web.headers": fake_runner},
    )
    assert result.modules_run == ("web.headers",)
    assert result.findings == ()
    assert result.errors == ()

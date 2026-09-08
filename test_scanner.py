from models import Asset, AssetType
from scanner import ScanPlan, ModuleSelection, default_module_selection, execute_plan, validate_plan


def test_default_plan_is_broad_but_nmap_optional():
    plan = default_module_selection()
    ids = [item.module_id for item in plan.selections]
    assert "web.headers" in ids
    assert "web.injection" not in ids
    assert "network.nmap" not in ids

    nmap_plan = default_module_selection(include_nmap=True)
    assert "network.nmap" in [item.module_id for item in nmap_plan.selections]


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

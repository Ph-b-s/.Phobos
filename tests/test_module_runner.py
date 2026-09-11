import pytest

from knowledge_store import SecurityObservation
from module_runner import ModuleRegistry, ModuleResult, ModuleRunner, default_module_registry
from security_modules import module_index


def observation(identifier: str = "obs-1") -> SecurityObservation:
    return SecurityObservation(
        id=identifier,
        kind="test",
        source="test_module",
        description="test observation",
    )


def test_default_registry_matches_active_implemented_catalog():
    registry = default_module_registry()
    expected = {item.id for item in module_index().values() if item.active and item.implemented}
    assert registry.ids() == expected


def test_configured_module_without_configuration_fails_cleanly():
    run = ModuleRunner(default_module_registry()).run(
        "https://example.com",
        ["web.access_control"],
    )
    assert run.executions[0].status == "error"
    assert "configuration" in run.errors[0]


def test_unimplemented_module_is_not_executed():
    run = ModuleRunner(default_module_registry()).run(
        "https://example.com",
        ["web.browser_runtime"],
    )
    assert run.executions[0].status == "unimplemented"


def test_stage_order_is_enforced():
    with pytest.raises(ValueError, match="execution-stage ordering"):
        ModuleRunner(default_module_registry()).run(
            "https://example.com",
            ["web.nmap", "web.access_control"],
        )


def test_handler_errors_are_recorded_without_crashing_the_run():
    registry = ModuleRegistry()
    registry.register("web.access_control", lambda context: (_ for _ in ()).throw(RuntimeError("boom")))

    run = ModuleRunner(registry).run("https://example.com", ["web.access_control"])

    assert run.executions[0].status == "error"
    assert "RuntimeError: boom" in run.errors[0]


def test_structured_results_are_added_to_the_knowledge_store():
    registry = ModuleRegistry()
    registry.register("web.access_control", lambda context: ModuleResult(observations=(observation(),)))

    run = ModuleRunner(registry).run("https://example.com", ["web.access_control"])

    assert run.executions[0].status == "completed"
    assert run.executions[0].observations_added == 1
    assert run.knowledge.observations == (observation(),)

import pytest

from knowledge_store import SecurityObservation
from module_runner import ModuleRegistry, ModuleResult, ModuleRunner, default_module_registry


def observation(identifier: str = "obs-1") -> SecurityObservation:
    return SecurityObservation(
        id=identifier,
        kind="test",
        source="test_module",
        description="test observation",
    )


def test_default_registry_contains_all_currently_implemented_modules():
    registry = default_module_registry()
    assert registry.ids() == {
        "web.headers",
        "web.cookies",
        "web.exposure",
        "web.methods",
        "web.config",
        "web.cors",
        "web.nmap",
        "ai.indirect_prompt_injection",
        "cross_layer.web_to_ai",
        "cross_layer.ai_to_web",
        "cross_layer.auth_boundary",
        "cross_layer.data_flow",
        "cross_layer.control_flow",
        "cross_layer.capability_escalation",
        "cross_layer.attack_path",
    }


def test_active_unregistered_module_is_reported_as_unimplemented():
    run = ModuleRunner(default_module_registry()).run(
        "https://example.com",
        ["web.access_control"],
    )
    assert run.executions[0].status == "unimplemented"
    assert run.findings == ()


def test_inactive_module_is_not_executed():
    run = ModuleRunner(default_module_registry()).run(
        "https://example.com",
        ["web.info_disclosure"],
    )
    assert run.executions[0].status == "inactive"


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

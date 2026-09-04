import pytest

from assessment_engine import AssessmentEngine
from ai_testing import INDIRECT_PROMPT_INJECTION_PROCEDURE, Observation, new_canary


def _obs(kind: str, description: str = "evidence", **metadata) -> Observation:
    return Observation(kind, description, evidence=(description,), metadata=metadata)


def _handlers(canary: str):
    return {
        "discover_chat": lambda _: [_obs("chat_surface", "chat discovered")],
        "map_ai_api": lambda _: [_obs("tool_inventory", "state-changing tool observed")],
        "map_tool_arguments": lambda _: [_obs("tool_arguments", "arguments observed")],
        "establish_auth_boundary": lambda _: [
            _obs("authenticated_tool_execution", "controlled action succeeded")
        ],
        "discover_indirect_input": lambda _: [
            _obs("indirect_input_source", "stored review is consumed by chat")
        ],
        "seed_canary": lambda _: [_obs("canary_seeded", "canary stored", canary=canary)],
        "prove_influence": lambda _: [
            _obs("baseline_compared", "clean baseline did not contain canary"),
            _obs("canary_observed", "exact canary returned", canary=canary),
        ],
        "validate_impact": lambda _: [
            _obs("state_change_validated", "controlled state change followed", canary=canary)
        ],
    }


def test_engine_runs_procedure_and_correlates_result():
    canary = new_canary()
    run = AssessmentEngine().run(
        INDIRECT_PROMPT_INJECTION_PROCEDURE,
        _handlers(canary),
        canary=canary,
    )
    assert run.result.status == "confirmed"
    assert run.result.confidence == 0.95
    assert all(step.status == "completed" for step in run.steps[:-1])
    assert run.steps[-1].step_id == "validate_impact"
    assert run.steps[-1].status == "blocked"


def test_engine_requires_explicit_state_change_permission():
    canary = new_canary()
    run = AssessmentEngine().run(
        INDIRECT_PROMPT_INJECTION_PROCEDURE,
        _handlers(canary),
        canary=canary,
        allow_state_change=False,
    )
    impact_step = next(step for step in run.steps if step.step_id == "validate_impact")
    assert impact_step.status == "blocked"
    assert run.result.confidence == 0.95
    assert run.errors


def test_engine_allows_state_change_only_when_explicitly_enabled():
    canary = new_canary()
    run = AssessmentEngine().run(
        INDIRECT_PROMPT_INJECTION_PROCEDURE,
        _handlers(canary),
        canary=canary,
        allow_state_change=True,
    )
    assert run.result.confidence == 0.99
    assert run.result.metadata["state_change_validated"] is True


def test_missing_handler_stops_by_default():
    run = AssessmentEngine().run(
        INDIRECT_PROMPT_INJECTION_PROCEDURE,
        {"discover_chat": lambda _: [_obs("chat_surface")]},
    )
    assert run.steps[-1].status == "missing"
    assert run.result.status == "not_confirmed"


def test_bad_handler_output_is_rejected():
    run = AssessmentEngine(stop_on_error=True).run(
        INDIRECT_PROMPT_INJECTION_PROCEDURE,
        {"discover_chat": lambda _: ["not-an-observation"]},
    )
    assert run.steps[-1].status == "error"
    assert "Observation" in run.steps[-1].error
    assert run.result.status == "not_confirmed"


def test_step_must_emit_its_declared_observation():
    run = AssessmentEngine().run(
        INDIRECT_PROMPT_INJECTION_PROCEDURE,
        {"discover_chat": lambda _: [_obs("wrong_kind")]},
    )
    assert run.steps[-1].status == "error"
    assert "required observations" in run.steps[-1].error
    assert run.observations == ()
    assert run.result.status == "not_confirmed"


def test_later_step_can_rely_on_prior_observation():
    """A procedure can deliberately capture baseline evidence before induced evidence."""
    canary = new_canary()
    handlers = _handlers(canary)
    handlers["discover_chat"] = lambda _: [
        _obs("chat_surface", "chat discovered"),
        _obs("baseline_compared", "clean baseline captured first"),
    ]
    handlers["prove_influence"] = lambda _: [
        _obs("canary_observed", "exact canary returned", canary=canary),
    ]

    run = AssessmentEngine().run(
        INDIRECT_PROMPT_INJECTION_PROCEDURE,
        handlers,
        canary=canary,
    )

    prove_step = next(step for step in run.steps if step.step_id == "prove_influence")
    assert prove_step.status == "completed"
    assert run.result.status == "confirmed"


def test_observation_input_is_hardened():
    with pytest.raises(ValueError):
        Observation("x", "a" * 4_001)
    with pytest.raises(ValueError):
        Observation("x", "ok", evidence=("a" * 4_001,))
    with pytest.raises(TypeError):
        Observation("x", "ok", evidence=(1,))
    with pytest.raises(TypeError):
        Observation("x", "ok", metadata=[])


def test_engine_limits_are_validated():
    with pytest.raises(ValueError):
        AssessmentEngine(max_steps=0)
    with pytest.raises(ValueError):
        AssessmentEngine(max_observations=0)

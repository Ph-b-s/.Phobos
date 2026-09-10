import pytest

from assessment_engine import AssessmentEngine
from ai_testing import AssessmentProcedure, AssessmentStep, Observation


def test_required_observations_are_inherited_between_steps():
    procedure = AssessmentProcedure(
        id="test.inheritance",
        title="Observation inheritance",
        steps=(
            AssessmentStep("baseline", "Baseline", "Capture the baseline.", ("baseline",)),
            AssessmentStep("compare", "Compare", "Use the baseline.", ("baseline", "comparison")),
        ),
    )

    def emit_baseline(context):
        return [Observation(kind="baseline", description="clean baseline")]

    def emit_comparison(context):
        return [Observation(kind="comparison", description="changed response")]

    run = AssessmentEngine().run(
        procedure,
        {"baseline": emit_baseline, "compare": emit_comparison},
    )

    assert [step.status for step in run.steps] == ["completed", "completed"]
    assert {item.kind for item in run.observations} == {"baseline", "comparison"}
    assert run.errors == ()


def test_missing_required_observation_fails_the_step():
    procedure = AssessmentProcedure(
        id="test.missing",
        title="Missing evidence",
        steps=(AssessmentStep("check", "Check", "Require evidence.", ("required",)),),
    )

    run = AssessmentEngine().run(
        procedure,
        {"check": lambda context: [Observation(kind="other", description="wrong evidence")]},
    )

    assert run.steps[0].status == "error"
    assert "required" in run.errors[0]


def test_state_changing_validation_requires_explicit_opt_in():
    procedure = AssessmentProcedure(
        id="test.state_change",
        title="State change",
        steps=(
            AssessmentStep("validate_impact", "Validate", "Test impact.", ("state_change_validated",)),
        ),
    )

    called = False

    def handler(context):
        nonlocal called
        called = True
        return [Observation(kind="state_change_validated", description="changed")]

    run = AssessmentEngine().run(procedure, {"validate_impact": handler})

    assert not called
    assert run.steps[0].status == "blocked"
    assert "allow_state_change=True" in run.steps[0].error
    assert run.result.status == "not_confirmed"


def test_step_and_observation_limits_are_bounded():
    procedure = AssessmentProcedure(
        id="test.limit",
        title="Limit",
        steps=tuple(
            AssessmentStep(f"step-{index}", f"Step {index}", "Test limit.", ("obs",))
            for index in range(2)
        ),
    )

    engine = AssessmentEngine(max_steps=1)
    with pytest.raises(ValueError, match="execution limit"):
        engine.run(procedure, {})

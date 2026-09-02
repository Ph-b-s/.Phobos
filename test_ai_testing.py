import pytest

from ai_testing import (
    INDIRECT_PROMPT_INJECTION_PROCEDURE,
    IndirectPromptInjectionAnalyzer,
    Observation,
    build_indirect_canary,
    build_test_queries,
    new_canary,
)


def _obs(kind: str, description: str = "evidence", **metadata) -> Observation:
    return Observation(kind, description, evidence=(description,), metadata=metadata)


def _complete(canary: str, *, state_change: bool = False):
    observations = [
        _obs("chat_surface", "live chat discovered"),
        _obs("tool_inventory", "delete_account observed"),
        _obs("tool_arguments", "account id inferred from session"),
        _obs("authenticated_tool_execution", "controlled account action succeeded"),
        _obs("indirect_input_source", "product review is consumed by chat"),
        _obs("canary_seeded", "canary stored in review", canary=canary),
        _obs("baseline_compared", "baseline response did not contain canary"),
        _obs("canary_observed", "exact canary returned by LLM", canary=canary),
    ]
    if state_change:
        observations.append(
            _obs("state_change_validated", "controlled state change followed induced path", canary=canary)
        )
    return observations


def test_procedure_is_well_formed():
    INDIRECT_PROMPT_INJECTION_PROCEDURE.validate()
    assert INDIRECT_PROMPT_INJECTION_PROCEDURE.id == "llm.indirect_prompt_injection"
    assert len(INDIRECT_PROMPT_INJECTION_PROCEDURE.steps) == 8


def test_canary_format_and_queries():
    canary = new_canary()
    assert canary.startswith("PHOBOS-")
    assert len(canary) == len("PHOBOS-") + 16
    assert canary in build_indirect_canary(canary)
    queries = build_test_queries("umbrella")
    assert len(queries) == 2
    assert all("umbrella" in query.lower() for query in queries)


def test_invalid_canary_is_rejected():
    with pytest.raises(ValueError):
        build_indirect_canary("not-a-canary")


def test_exact_canary_and_baseline_are_required_for_confirmation():
    canary = new_canary()
    result = IndirectPromptInjectionAnalyzer().analyze(_complete(canary), canary=canary)
    assert result.status == "confirmed"
    assert result.finding_type == "indirect_prompt_injection"
    assert result.confidence == 0.95
    assert result.metadata["canary"] == canary
    assert result.metadata["state_change_validated"] is False


def test_state_change_validation_raises_confidence_without_changing_finding_class():
    canary = new_canary()
    result = IndirectPromptInjectionAnalyzer().analyze(
        _complete(canary, state_change=True), canary=canary
    )
    assert result.status == "confirmed"
    assert result.confidence == 0.99
    assert result.metadata["state_change_validated"] is True


def test_wrong_canary_cannot_prove_influence():
    seeded = new_canary()
    observed = new_canary()
    result = IndirectPromptInjectionAnalyzer().analyze(
        [
            _obs("chat_surface"),
            _obs("indirect_input_source"),
            _obs("canary_seeded", canary=seeded),
            _obs("canary_observed", canary=observed),
            _obs("baseline_compared", "baseline recorded"),
        ],
        canary=seeded,
    )
    assert result.status in {"suspected", "not_confirmed"}
    assert result.confidence < 0.8


def test_canary_observation_without_matching_seed_cannot_confirm():
    canary = new_canary()
    result = IndirectPromptInjectionAnalyzer().analyze(
        [
            _obs("chat_surface"),
            _obs("indirect_input_source"),
            _obs("canary_seeded", canary=new_canary()),
            _obs("canary_observed", canary=canary),
            _obs("baseline_compared"),
        ]
    )
    assert result.status != "confirmed"


def test_without_baseline_exact_match_is_only_strong_signal():
    canary = new_canary()
    observations = [
        _obs("chat_surface"),
        _obs("indirect_input_source"),
        _obs("canary_seeded", canary=canary),
        _obs("canary_observed", canary=canary),
    ]
    result = IndirectPromptInjectionAnalyzer().analyze(observations, canary=canary)
    assert result.status == "strong_signal"
    assert result.confidence == 0.80


def test_seed_without_observation_is_not_confirmation():
    canary = new_canary()
    result = IndirectPromptInjectionAnalyzer().analyze(
        [
            _obs("indirect_input_source"),
            _obs("canary_seeded", canary=canary),
        ],
        canary=canary,
    )
    assert result.status == "suspected"
    assert result.confidence == 0.45


def test_unknown_observations_do_not_create_finding():
    result = IndirectPromptInjectionAnalyzer().analyze(
        [_obs("chat_surface"), _obs("tool_inventory"), _obs("random_signal")]
    )
    assert result.status == "not_confirmed"
    assert result.finding_type is None
    assert result.confidence == 0.0

from ai_testing import (
    IndirectPromptInjectionAnalyzer,
    Observation,
    build_indirect_canary,
    build_test_queries,
    new_canary,
)


def _obs(kind: str, description: str = "evidence") -> Observation:
    return Observation(kind, description, evidence=(description,))


def test_canary_and_queries_are_deterministic_shapes():
    canary = new_canary()
    assert canary.startswith("PHOBOS-")
    assert canary in build_indirect_canary(canary)
    assert build_test_queries("umbrella")


def test_confirmed_influence_without_state_change():
    observations = [
        _obs("chat_surface"),
        _obs("tool_inventory"),
        _obs("tool_arguments"),
        _obs("indirect_input_source"),
        _obs("canary_seeded"),
        _obs("baseline_compared"),
        _obs("canary_observed"),
    ]
    result = IndirectPromptInjectionAnalyzer().analyze(observations)
    assert result.status == "confirmed"
    assert result.finding_type == "indirect_prompt_injection"
    assert result.confidence >= 0.9
    assert result.metadata["state_change_validated"] is False


def test_confirmed_state_changing_path_has_higher_confidence():
    observations = [
        _obs("chat_surface"),
        _obs("tool_inventory"),
        _obs("tool_arguments"),
        _obs("authenticated_tool_execution"),
        _obs("indirect_input_source"),
        _obs("canary_seeded"),
        _obs("baseline_compared"),
        _obs("canary_observed"),
        _obs("state_change_validated"),
    ]
    result = IndirectPromptInjectionAnalyzer().analyze(observations)
    assert result.status == "confirmed"
    assert result.confidence == 0.99
    assert result.metadata["state_change_validated"] is True


def test_seed_without_influence_is_not_confirmation():
    result = IndirectPromptInjectionAnalyzer().analyze(
        [_obs("indirect_input_source"), _obs("canary_seeded")]
    )
    assert result.status == "suspected"
    assert result.finding_type == "indirect_prompt_injection"
    assert result.confidence < 0.5

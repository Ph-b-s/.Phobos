"""Bounded orchestration for evidence-driven security assessment procedures.

The engine deliberately knows nothing about browsers, credentials, payloads, or
arbitrary HTTP. Execution adapters supply small, predeclared actions that emit
structured observations. The engine enforces procedure order, execution limits,
and an explicit opt-in for state-changing validation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Protocol

from ai_testing import (
    INDIRECT_PROMPT_INJECTION_PROCEDURE,
    AssessmentProcedure,
    AssessmentResult,
    AssessmentStep,
    IndirectPromptInjectionAnalyzer,
    Observation,
)

MAX_STEPS = 32
MAX_OBSERVATIONS = 512
MAX_ERRORS = 32


class AssessmentHandler(Protocol):
    """Callable execution adapter for one declared assessment step."""

    def __call__(self, context: "AssessmentContext") -> Iterable[Observation]: ...


@dataclass(frozen=True, slots=True)
class AssessmentContext:
    """Immutable run configuration visible to an execution adapter."""

    procedure: AssessmentProcedure
    canary: str | None = None
    allow_state_change: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StepExecution:
    """Outcome of one procedure-step dispatch."""

    step_id: str
    status: str
    observations_added: int = 0
    error: str | None = None


@dataclass(frozen=True, slots=True)
class AssessmentRun:
    """Complete bounded assessment execution result."""

    result: AssessmentResult
    observations: tuple[Observation, ...]
    steps: tuple[StepExecution, ...]
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result.to_dict(),
            "observations": [
                {
                    "kind": item.kind,
                    "description": item.description,
                    "source": item.source,
                    "evidence": list(item.evidence),
                    "metadata": item.metadata,
                }
                for item in self.observations
            ],
            "steps": [
                {
                    "step_id": item.step_id,
                    "status": item.status,
                    "observations_added": item.observations_added,
                    "error": item.error,
                }
                for item in self.steps
            ],
            "errors": list(self.errors),
        }


class AssessmentEngine:
    """Execute a declared procedure through bounded adapter callbacks."""

    def __init__(
        self,
        *,
        max_steps: int = MAX_STEPS,
        max_observations: int = MAX_OBSERVATIONS,
        stop_on_error: bool = True,
        analyzer: IndirectPromptInjectionAnalyzer | None = None,
    ) -> None:
        if not 1 <= max_steps <= MAX_STEPS:
            raise ValueError(f"max_steps must be between 1 and {MAX_STEPS}")
        if not 1 <= max_observations <= MAX_OBSERVATIONS:
            raise ValueError(f"max_observations must be between 1 and {MAX_OBSERVATIONS}")
        self.max_steps = max_steps
        self.max_observations = max_observations
        self.stop_on_error = stop_on_error
        self.analyzer = analyzer or IndirectPromptInjectionAnalyzer()

    def run(
        self,
        procedure: AssessmentProcedure,
        handlers: Mapping[str, AssessmentHandler],
        *,
        canary: str | None = None,
        allow_state_change: bool = False,
        metadata: Mapping[str, Any] | None = None,
    ) -> AssessmentRun:
        procedure.validate()
        if len(procedure.steps) > self.max_steps:
            raise ValueError("assessment procedure exceeds execution limit")

        context = AssessmentContext(
            procedure=procedure,
            canary=canary,
            allow_state_change=allow_state_change,
            metadata=dict(metadata or {}),
        )
        observations: list[Observation] = []
        executions: list[StepExecution] = []
        errors: list[str] = []

        for step in procedure.steps:
            if not step.active:
                executions.append(StepExecution(step.id, "inactive"))
                continue

            if step.id == "validate_impact" and not context.allow_state_change:
                message = "state-changing validation requires explicit allow_state_change=True"
                executions.append(StepExecution(step.id, "blocked", error=message))
                errors.append(message)
                continue

            handler = handlers.get(step.id)
            if handler is None:
                message = f"no handler registered for assessment step: {step.id}"
                executions.append(StepExecution(step.id, "missing", error=message))
                errors.append(message)
                if self.stop_on_error:
                    break
                continue

            try:
                emitted = handler(context)
                added = 0
                for observation in emitted:
                    if not isinstance(observation, Observation):
                        raise TypeError("assessment handlers must emit Observation instances")
                    if len(observations) >= self.max_observations:
                        raise RuntimeError("assessment observation limit exceeded")
                    observations.append(observation)
                    added += 1
                executions.append(StepExecution(step.id, "completed", added))
            except Exception as exc:
                message = f"{step.id}: {type(exc).__name__}: {exc}"
                if len(errors) < MAX_ERRORS:
                    errors.append(message)
                executions.append(StepExecution(step.id, "error", error=message))
                if self.stop_on_error:
                    break

        result = self.analyzer.analyze(observations, canary=canary)
        return AssessmentRun(
            result=result,
            observations=tuple(observations),
            steps=tuple(executions),
            errors=tuple(errors[:MAX_ERRORS]),
        )


def default_indirect_prompt_injection_engine() -> AssessmentEngine:
    """Return a hardened engine for the first supported AI-security procedure."""
    return AssessmentEngine()


def indirect_prompt_injection_procedure() -> AssessmentProcedure:
    """Return the canonical indirect prompt-injection procedure."""
    return INDIRECT_PROMPT_INJECTION_PROCEDURE

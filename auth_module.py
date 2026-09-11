"""Workflow-backed authenticated-session bootstrap for Phobos.

Authentication is intentionally configuration-driven. The module does not
invent selectors or credentials; callers provide an authorized workflow using
the existing bounded browser interaction and test-account services.
"""
from __future__ import annotations

from typing import Any, Mapping

from browser_interaction import BrowserInteractor
from knowledge_store import SecurityObservation
from models import Finding
from module_runner import ModuleResult
from security_modules import ModuleContext
from workflow_engine import WorkflowContext, WorkflowEngine, WorkflowStep

MAX_AUTH_STEPS = 24


def _workflow_engine(context: ModuleContext) -> WorkflowEngine:
    engine = context.workflow
    if engine is None:
        raise RuntimeError("web.auth requires WorkflowEngine capability")
    return engine


def _parse_steps(payload: Mapping[str, Any]) -> tuple[WorkflowStep, ...]:
    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("auth_workflow.steps must be a non-empty list")
    if len(raw_steps) > MAX_AUTH_STEPS:
        raise ValueError("auth workflow exceeds step limit")
    steps: list[WorkflowStep] = []
    for item in raw_steps:
        if not isinstance(item, Mapping):
            raise TypeError("each auth workflow step must be an object")
        steps.append(WorkflowStep(
            id=str(item.get("id", "")),
            action=str(item.get("action", "")),
            description=str(item.get("description", "")),
            depends_on=tuple(str(value) for value in item.get("depends_on", ()) if value),
            metadata=dict(item.get("metadata", {})) if isinstance(item.get("metadata", {}), Mapping) else {},
        ))
    return tuple(steps)


def run_web_auth(context: ModuleContext) -> ModuleResult:
    config = context.metadata.get("auth_workflow")
    if not isinstance(config, Mapping):
        raise RuntimeError("web.auth requires auth_workflow configuration")
    browser = context.browser
    if browser is None:
        raise RuntimeError("web.auth requires browser capability")
    accounts = context.accounts
    if accounts is None:
        raise RuntimeError("web.auth requires AccountManager capability")

    interactor = context.interactor or BrowserInteractor(browser)
    engine = _workflow_engine(context)
    workflow_context = WorkflowContext(
        target=context.target,
        browser=interactor,
        accounts=accounts,
        applications=tuple(context.applications),
    )
    steps = _parse_steps(config)
    result = engine.run(
        str(config.get("workflow_id", "authenticated-session-bootstrap")),
        steps,
        workflow_context,
    )

    observations = [SecurityObservation(
        id=f"web.auth:step:{index}",
        kind=f"web.auth.{event.event_type}",
        source="web.auth",
        description=event.detail or f"Authentication workflow step {event.step_id} completed",
        data={"step_id": event.step_id, "event_type": event.event_type, "url": event.url, "data": event.data},
        confidence=1.0 if event.event_type == "completed" else 0.85,
    ) for index, event in enumerate(result.events)]

    observations.append(SecurityObservation(
        id="web.auth:workflow",
        kind="web.auth.workflow_result",
        source="web.auth",
        description=f"Authentication workflow finished with state {result.state.value}",
        data={"workflow_id": result.workflow_id, "state": result.state.value,
              "completed_steps": list(result.completed_steps), "error": result.error},
        confidence=1.0 if result.state.value == "completed" else 0.75,
    ))

    findings: list[Finding] = []
    if result.state.value in {"failed", "blocked"}:
        findings.append(Finding(
            id="web.auth:workflow_failure",
            type="authentication_workflow_not_completed",
            confidence=0.82,
            evidence=("web.auth:workflow",),
            metadata={"severity": "informational", "state": result.state.value, "error": result.error},
        ))
    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

"""Workflow-backed authorization boundary testing.

The module compares two explicitly configured roles against the same protected
resources. It never invents credentials, selectors, object identifiers, or
privilege assumptions. A matching protected response is reported as a
potential authorization failure that needs contextual confirmation.
"""
from __future__ import annotations

from hashlib import sha256
from typing import Any, Mapping

from knowledge_store import SecurityObservation
from models import Finding
from module_runner import ModuleResult
from security_modules import ModuleContext
from workflow_engine import WorkflowContext, WorkflowEngine, WorkflowStep, WorkflowState

MAX_PROTECTED_URLS = 32
MAX_WORKFLOW_STEPS = 24


def _steps(raw: Any, label: str) -> tuple[WorkflowStep, ...]:
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{label} must be a non-empty list")
    if len(raw) > MAX_WORKFLOW_STEPS:
        raise ValueError(f"{label} exceeds the workflow step limit")
    result: list[WorkflowStep] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise TypeError(f"{label} contains a non-object step")
        result.append(WorkflowStep(
            id=str(item.get("id", "")),
            action=str(item.get("action", "")),
            description=str(item.get("description", "")),
            depends_on=tuple(str(dep) for dep in item.get("depends_on", ()) if dep),
            metadata=dict(item.get("metadata", {})) if isinstance(item.get("metadata", {}), Mapping) else {},
        ))
    return tuple(result)


def _digest(text: str) -> str:
    normalized = " ".join(text.split())
    return sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def _run_role(engine: WorkflowEngine, context: ModuleContext, workflow_id: str, steps: tuple[WorkflowStep, ...]):
    if context.interactor is None:
        raise RuntimeError("web.access_control requires browser interactor capability")
    if context.accounts is None:
        raise RuntimeError("web.access_control requires AccountManager capability")
    workflow_context = WorkflowContext(
        target=context.target,
        browser=context.interactor,
        accounts=context.accounts,
        applications=tuple(context.applications),
    )
    return engine.run(workflow_id, steps, workflow_context)


def run_web_access_control(context: ModuleContext) -> ModuleResult:
    config = context.metadata.get("access_control")
    if not isinstance(config, Mapping):
        raise RuntimeError("web.access_control requires access_control configuration")
    engine = context.workflow
    if engine is None:
        raise RuntimeError("web.access_control requires WorkflowEngine capability")

    protected = tuple(dict.fromkeys(
        str(url).strip() for url in config.get("protected_urls", ())
        if str(url).strip()
    ))[:MAX_PROTECTED_URLS]
    if not protected:
        raise ValueError("access_control.protected_urls must contain at least one URL")

    low = _run_role(engine, context, str(config.get("low_workflow_id", "low-privilege")), _steps(config.get("low_workflow"), "low_workflow"))
    high = _run_role(engine, context, str(config.get("high_workflow_id", "high-privilege")), _steps(config.get("high_workflow"), "high_workflow"))

    if low.state is not WorkflowState.COMPLETED or high.state is not WorkflowState.COMPLETED:
        raise RuntimeError(
            f"authorization workflows did not both complete: low={low.state.value}, high={high.state.value}"
        )

    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for index, url in enumerate(protected):
        low_open = context.interactor.open(url)
        low_snapshot = context.interactor.snapshot()
        low_digest = _digest(low_snapshot.text)
        low_result = {"url": low_snapshot.url, "text_digest": low_digest, "text_length": len(low_snapshot.text)}

        high_open = context.interactor.open(url)
        high_snapshot = context.interactor.snapshot()
        high_digest = _digest(high_snapshot.text)
        high_result = {"url": high_snapshot.url, "text_digest": high_digest, "text_length": len(high_snapshot.text)}

        same_content = low_digest == high_digest and len(low_snapshot.text) == len(high_snapshot.text)
        oid = f"web.access_control:comparison:{index}"
        observations.append(SecurityObservation(
            id=oid,
            kind="web.access_control.role_comparison",
            source="web.access_control",
            description=f"Low- and high-privilege workflows compared the same protected resource: {url.split('?', 1)[0]}",
            data={"low": low_result, "high": high_result, "same_response_signature": same_content},
            confidence=0.92,
        ))
        if same_content:
            findings.append(Finding(
                id=f"web.access_control:finding:{index}",
                type="potential_authorization_boundary_failure",
                confidence=0.74,
                evidence=(oid,),
                metadata={
                    "severity": "high",
                    "url": url.split("?", 1)[0],
                    "validation": "low- and high-privilege workflows received identical normalized response signatures",
                    "status": "needs_context_confirmation",
                },
            ))

    return ModuleResult(observations=tuple(observations), findings=tuple(findings))

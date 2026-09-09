"""Bounded state-machine workflows for multi-page, multi-application security testing."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Iterable, Mapping

from account_manager import AccountManager, TestAccount
from browser_interaction import BrowserInteractor, BrowserInteractionError
from cross_application import ApplicationCandidate

MAX_WORKFLOW_STEPS = 64
MAX_WORKFLOW_EVENTS = 256


class WorkflowState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class WorkflowError(RuntimeError):
    """Raised for workflow definition or execution failures."""


@dataclass(frozen=True, slots=True)
class WorkflowEvent:
    step_id: str
    event_type: str
    url: str
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    id: str
    action: str
    description: str
    depends_on: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id.strip() or not self.action.strip() or not self.description.strip():
            raise ValueError("workflow steps require id, action, and description")
        object.__setattr__(self, "depends_on", tuple(dict.fromkeys(item.strip() for item in self.depends_on if item.strip())))
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(slots=True)
class WorkflowContext:
    target: str
    browser: BrowserInteractor
    accounts: AccountManager
    applications: tuple[ApplicationCandidate, ...] = ()
    values: dict[str, Any] = field(default_factory=dict)
    events: list[WorkflowEvent] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class WorkflowResult:
    workflow_id: str
    state: WorkflowState
    completed_steps: tuple[str, ...]
    events: tuple[WorkflowEvent, ...]
    values: dict[str, Any]
    error: str | None = None


StepHandler = Callable[[WorkflowContext, WorkflowStep], Any]


class WorkflowEngine:
    """Execute declarative workflows against bounded Phobos interaction services."""

    def __init__(self, *, max_steps: int = MAX_WORKFLOW_STEPS, max_events: int = MAX_WORKFLOW_EVENTS) -> None:
        if not 1 <= max_steps <= MAX_WORKFLOW_STEPS:
            raise ValueError(f"max_steps must be between 1 and {MAX_WORKFLOW_STEPS}")
        if not 1 <= max_events <= MAX_WORKFLOW_EVENTS:
            raise ValueError(f"max_events must be between 1 and {MAX_WORKFLOW_EVENTS}")
        self.max_steps = max_steps
        self.max_events = max_events
        self._handlers: dict[str, StepHandler] = {}

    def register_action(self, action: str, handler: StepHandler) -> None:
        action = action.strip()
        if not action:
            raise ValueError("workflow action cannot be empty")
        if not callable(handler):
            raise TypeError("workflow action handler must be callable")
        if action in self._handlers:
            raise ValueError(f"workflow action already registered: {action}")
        self._handlers[action] = handler

    def run(self, workflow_id: str, steps: Iterable[WorkflowStep], context: WorkflowContext) -> WorkflowResult:
        workflow_id = workflow_id.strip()
        if not workflow_id:
            raise ValueError("workflow_id cannot be empty")
        ordered = tuple(steps)
        self._validate_steps(ordered)
        state = WorkflowState.RUNNING
        completed: list[str] = []
        events: list[WorkflowEvent] = []

        for step in ordered:
            missing = [dependency for dependency in step.depends_on if dependency not in completed]
            if missing:
                state = WorkflowState.BLOCKED
                error = f"workflow step {step.id} is missing dependencies: {', '.join(missing)}"
                return WorkflowResult(workflow_id, state, tuple(completed), tuple(events), dict(context.values), error)
            handler = self._handlers.get(step.action)
            if handler is None:
                state = WorkflowState.BLOCKED
                error = f"no workflow action registered: {step.action}"
                return WorkflowResult(workflow_id, state, tuple(completed), tuple(events), dict(context.values), error)
            try:
                value = handler(context, step)
                if value is not None:
                    context.values[step.id] = value
                event = WorkflowEvent(step.id, "completed", _safe_url(context.target), step.description)
                completed.append(step.id)
            except BrowserInteractionError as exc:
                state = WorkflowState.FAILED
                error = f"{step.id}: {exc}"
                event = WorkflowEvent(step.id, "failed", _safe_url(context.target), error)
                events.append(event)
                break
            except Exception as exc:
                state = WorkflowState.FAILED
                error = f"{step.id}: {type(exc).__name__}: {exc}"
                event = WorkflowEvent(step.id, "failed", _safe_url(context.target), error)
                events.append(event)
                break
            events.append(event)
            if len(events) >= self.max_events:
                state = WorkflowState.BLOCKED
                error = "workflow event limit exceeded"
                break
        else:
            state = WorkflowState.COMPLETED
            error = None
        context.events.extend(events[: self.max_events - len(context.events)])
        return WorkflowResult(workflow_id, state, tuple(completed), tuple(events[: self.max_events]), dict(context.values), error)

    @staticmethod
    def _validate_steps(steps: tuple[WorkflowStep, ...]) -> None:
        if not steps:
            raise WorkflowError("workflow must contain at least one step")
        if len(steps) > MAX_WORKFLOW_STEPS:
            raise WorkflowError("workflow exceeds step limit")
        ids = {step.id for step in steps}
        if len(ids) != len(steps):
            raise WorkflowError("workflow contains duplicate step ids")
        for step in steps:
            unknown = set(step.depends_on) - ids
            if unknown:
                raise WorkflowError(f"workflow step {step.id} depends on unknown steps: {', '.join(sorted(unknown))}")


def register_standard_actions(engine: WorkflowEngine) -> WorkflowEngine:
    engine.register_action("navigate", lambda context, step: context.browser.open(str(step.metadata["url"])))
    engine.register_action("fill", lambda context, step: context.browser.fill(str(step.metadata["selector"]), str(step.metadata["value"])))
    engine.register_action("click", lambda context, step: context.browser.click(str(step.metadata["selector"])))
    engine.register_action("snapshot", lambda context, step: context.browser.snapshot().to_dict())
    engine.register_action("create_account", _create_account)
    engine.register_action("mark_account_verified", _mark_account_verified)
    return engine


def _create_account(context: WorkflowContext, step: WorkflowStep) -> dict[str, Any]:
    domain = str(step.metadata.get("email_domain", "invalid.test"))
    role = str(step.metadata.get("role", "user"))
    account = context.accounts.create(email_domain=domain, role=role, label=str(step.metadata.get("label", "test")))
    return {"account_id": account.id, "credentials": account.to_dict()["credentials"]}


def _mark_account_verified(context: WorkflowContext, step: WorkflowStep) -> dict[str, Any]:
    account_id = str(step.metadata["account_id"])
    context.accounts.set_state(account_id, __import__("account_manager").AccountState.VERIFIED)
    return {"account_id": account_id, "state": "verified"}


def _safe_url(url: str) -> str:
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

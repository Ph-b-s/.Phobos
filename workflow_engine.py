"""Bounded state-machine workflows for multi-page, multi-application security testing."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from account_manager import AccountManager, AccountState
from browser_interaction import BrowserInteractor, BrowserInteractionError
from cross_application import ApplicationCandidate, discover_related_applications

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
        completed: list[str] = []
        events: list[WorkflowEvent] = []

        for step in ordered:
            missing = [dependency for dependency in step.depends_on if dependency not in completed]
            if missing:
                return self._finish(workflow_id, WorkflowState.BLOCKED, completed, events, context,
                                    f"workflow step {step.id} is missing dependencies: {', '.join(missing)}")
            handler = self._handlers.get(step.action)
            if handler is None:
                return self._finish(workflow_id, WorkflowState.BLOCKED, completed, events, context,
                                    f"no workflow action registered: {step.action}")
            try:
                value = handler(context, step)
                if value is not None:
                    context.values[step.id] = _redact_value(value)
                completed.append(step.id)
                events.append(WorkflowEvent(step.id, "completed", _safe_url(context.target), step.description))
            except BrowserInteractionError as exc:
                error = f"{step.id}: {exc}"
                events.append(WorkflowEvent(step.id, "failed", _safe_url(context.target), error))
                return self._finish(workflow_id, WorkflowState.FAILED, completed, events, context, error)
            except Exception as exc:
                error = f"{step.id}: {type(exc).__name__}: {exc}"
                events.append(WorkflowEvent(step.id, "failed", _safe_url(context.target), error))
                return self._finish(workflow_id, WorkflowState.FAILED, completed, events, context, error)
            if len(events) >= self.max_events:
                return self._finish(workflow_id, WorkflowState.BLOCKED, completed, events, context,
                                    "workflow event limit exceeded")
        return self._finish(workflow_id, WorkflowState.COMPLETED, completed, events, context, None)

    @staticmethod
    def _validate_steps(steps: tuple[WorkflowStep, ...]) -> None:
        if not steps:
            raise WorkflowError("workflow must contain at least one step")
        if len(steps) > MAX_WORKFLOW_STEPS:
            raise WorkflowError("workflow exceeds step limit")
        ids = {step.id for step in steps}
        if len(ids) != len(steps):
            raise WorkflowError("workflow contains duplicate step ids")
        for index, step in enumerate(steps):
            unknown = set(step.depends_on) - ids
            if unknown:
                raise WorkflowError(f"workflow step {step.id} depends on unknown steps: {', '.join(sorted(unknown))}")
            if step.id in step.depends_on:
                raise WorkflowError(f"workflow step {step.id} cannot depend on itself")
            prior = {candidate.id for candidate in steps[:index]}
            if not set(step.depends_on).issubset(prior):
                raise WorkflowError(f"workflow dependencies must reference earlier steps: {step.id}")

    def _finish(self, workflow_id: str, state: WorkflowState, completed: list[str], events: list[WorkflowEvent],
                context: WorkflowContext, error: str | None) -> WorkflowResult:
        bounded = tuple(events[: self.max_events])
        remaining = max(0, self.max_events - len(context.events))
        context.events.extend(bounded[:remaining])
        return WorkflowResult(workflow_id, state, tuple(completed), bounded, dict(context.values), error)


def register_standard_actions(engine: WorkflowEngine) -> WorkflowEngine:
    engine.register_action("navigate", lambda context, step: context.browser.open(str(step.metadata["url"])))
    engine.register_action("fill", lambda context, step: context.browser.fill(str(step.metadata["selector"]), str(step.metadata["value"])))
    engine.register_action("fill_account_field", _fill_account_field)
    engine.register_action("click", lambda context, step: context.browser.click(str(step.metadata["selector"])))
    engine.register_action("snapshot", lambda context, step: context.browser.snapshot_dict())
    engine.register_action("discover_supporting_applications", _discover_supporting_applications)
    engine.register_action("create_account", _create_account)
    engine.register_action("mark_account_verified", _mark_account_verified)
    return engine


def _create_account(context: WorkflowContext, step: WorkflowStep) -> dict[str, Any]:
    account = context.accounts.create(
        email_domain=str(step.metadata.get("email_domain", "invalid.test")),
        role=str(step.metadata.get("role", "user")),
        label=str(step.metadata.get("label", "test")),
    )
    context.values[f"account:{account.id}"] = account.id
    return {"account_id": account.id, "credentials": account.to_dict()["credentials"]}


def _fill_account_field(context: WorkflowContext, step: WorkflowStep) -> dict[str, str]:
    account_id = str(step.metadata["account_id"])
    field = str(step.metadata["field"]).strip().lower()
    selectors = {"email": "email", "username": "username", "password": "password"}
    if field not in selectors:
        raise WorkflowError("account field must be email, username, or password")
    account = context.accounts.get(account_id)
    value = getattr(account.credentials, field)
    context.browser.fill(str(step.metadata["selector"]), value)
    return {"field": field, "selector": str(step.metadata["selector"]), "value": "<redacted>"}


def _discover_supporting_applications(context: WorkflowContext, step: WorkflowStep) -> dict[str, Any]:
    snapshot = context.browser.snapshot()
    found = discover_related_applications(context.target, links=snapshot.links,
                                          pages=({"url": snapshot.url, "text": snapshot.text},))
    context.applications = tuple(dict.fromkeys((*context.applications, *found)))
    return {"applications": [item.to_dict() for item in found]}


def _mark_account_verified(context: WorkflowContext, step: WorkflowStep) -> dict[str, Any]:
    account_id = str(step.metadata["account_id"])
    context.accounts.set_state(account_id, AccountState.VERIFIED)
    return {"account_id": account_id, "state": AccountState.VERIFIED.value}


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): ("<redacted>" if str(key).casefold() in {"password", "token", "secret"} else _redact_value(item))
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(item) for item in value]
    return value


def _safe_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

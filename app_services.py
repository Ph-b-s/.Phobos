"""Unified service composition for the Phobos desktop application.

The desktop shell and future integrations consume these services instead of
constructing scanner components independently. This keeps browser, identity,
workflow, cross-application discovery, AI, and module execution behind one
application boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from account_manager import AccountManager
from browser_adapter import BrowserLimits, BrowserSession, PlaywrightBrowserSession
from browser_interaction import BrowserInteractor
from cross_application import ApplicationCandidate, discover_related_applications
from request_manager import RequestManager
from scanner import ScanPlan, ScanResult, execute_plan
from scope import ScopeValidator
from workflow_engine import WorkflowEngine, register_standard_actions


@dataclass(slots=True)
class PhobosServices:
    """Runtime capabilities belonging to one desktop scan session."""

    target: str
    scope: ScopeValidator
    requests: RequestManager
    accounts: AccountManager
    workflows: WorkflowEngine
    browser: BrowserSession | None = None
    browser_interactor: BrowserInteractor | None = None
    applications: tuple[ApplicationCandidate, ...] = ()

    def discover_supporting_apps(self, links: list[str] | tuple[str, ...] = (), *, pages: list[dict[str, Any]] | tuple[dict[str, Any], ...] = ()) -> tuple[ApplicationCandidate, ...]:
        candidates = discover_related_applications(self.target, tuple(links), tuple(pages))
        self.applications = candidates
        return candidates

    def close(self) -> None:
        if self.browser is not None:
            self.browser.close()
            self.browser = None
            self.browser_interactor = None


def create_services(
    target: str,
    scopes: tuple[str, ...] | list[str],
    *,
    timeout: float = 10.0,
    max_redirects: int = 5,
    max_response_bytes: int = 2_000_000,
    user_agent: str = "Phobos/0.7.0",
    allow_private_targets: bool = False,
    browser: bool = True,
    browser_name: str = "chromium",
    browser_max_requests: int = 2_000,
) -> PhobosServices:
    scope = ScopeValidator(tuple(scopes), allow_private_targets=allow_private_targets)
    scope.validate(target)
    requests = RequestManager(
        scope,
        timeout=timeout,
        max_redirects=max_redirects,
        user_agent=user_agent,
        max_response_bytes=max_response_bytes,
    )
    accounts = AccountManager()
    workflows = register_standard_actions(WorkflowEngine())
    session: BrowserSession | None = None
    interactor: BrowserInteractor | None = None
    if browser:
        session = PlaywrightBrowserSession(
            scope,
            limits=BrowserLimits(max_requests=browser_max_requests, navigation_timeout_ms=int(timeout * 1000)),
            browser_name=browser_name,
            user_agent=user_agent,
        )
        interactor = BrowserInteractor(session)
    return PhobosServices(target, scope, requests, accounts, workflows, session, interactor)


def execute_scan(
    services: PhobosServices,
    assets: tuple[Any, ...],
    plan: ScanPlan,
    *,
    knowledge: Any | None = None,
    graph: Any | None = None,
    metadata: dict[str, Any] | None = None,
) -> ScanResult:
    """Execute a plan using the exact services owned by the desktop session."""
    capabilities = {
        "browser": services.browser,
        "interactor": services.browser_interactor,
        "accounts": services.accounts,
        "workflow": services.workflows,
        "applications": services.applications,
    }
    return execute_plan(
        services.target,
        assets,
        plan,
        knowledge=knowledge,
        graph=graph,
        metadata=metadata,
        capabilities=capabilities,
    )

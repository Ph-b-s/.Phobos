"""Core orchestration for AI-assisted web security scanning."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from models import Asset, Finding
from security_modules import ModuleContext, module_index


@dataclass(frozen=True, slots=True)
class ModuleSelection:
    """A security module selected for the current scan and why it is relevant."""

    module_id: str
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ScanPlan:
    """Ordered security-module plan produced by defaults or the AI planner."""

    selections: tuple[ModuleSelection, ...]
    source: str = "default"


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Normalized result of a scanner run."""

    target: str
    assets: tuple[Asset, ...]
    findings: tuple[Finding, ...]
    modules_run: tuple[str, ...]
    errors: tuple[str, ...] = ()


def default_module_selection(*, include_nmap: bool = False) -> ScanPlan:
    """Return the broad baseline security-test plan.

    Discovery builds the application context first. Security modules then test
    the discovered web surface. AI-specific procedures are part of that same
    testing layer. Nmap is simply an optional final web/security check that can
    add service-level evidence; it is not a separate discovery pipeline.
    """
    selected = [
        ModuleSelection("web.headers", "baseline web hardening"),
        ModuleSelection("web.cookies", "session security baseline"),
        ModuleSelection("web.exposure", "common exposure checks"),
        ModuleSelection("web.methods", "review discovered HTTP methods"),
        ModuleSelection("web.params", "prioritize discovered input surfaces"),
        ModuleSelection("web.config", "common configuration exposure"),
        ModuleSelection("ai.surface", "map and classify the site's AI functionality"),
        ModuleSelection("ai.prompt_injection", "test identified AI input boundaries"),
        ModuleSelection("ai.data_disclosure", "test model-mediated data exposure"),
        ModuleSelection("ai.tool_abuse", "test AI-controlled tool boundaries"),
        ModuleSelection("ai.excessive_agency", "test unintended AI-mediated actions"),
    ]
    if include_nmap:
        selected.append(ModuleSelection("web.nmap", "optional service-level security check"))
    return ScanPlan(tuple(selected), source="default")


def validate_plan(plan: ScanPlan) -> ScanPlan:
    """Reject unknown modules and duplicates before execution."""
    catalog = module_index()
    seen: set[str] = set()
    validated: list[ModuleSelection] = []
    for selection in plan.selections:
        if selection.module_id not in catalog:
            raise ValueError(f"unknown security module: {selection.module_id}")
        if selection.module_id in seen:
            continue
        seen.add(selection.module_id)
        validated.append(selection)
    return ScanPlan(tuple(validated), source=plan.source)


def execute_plan(
    target: str,
    assets: tuple[Asset, ...],
    plan: ScanPlan,
    *,
    runners: dict[str, Any] | None = None,
) -> ScanResult:
    """Run registered deterministic security modules and normalize output.

    Low-level HTTP/browser/network execution is injected through runners. The
    planner therefore decides *what* should be tested while modules decide
    *how* their declared security procedure is executed.
    """
    plan = validate_plan(plan)
    context = ModuleContext(target=target, assets=assets)
    runner_map = runners or {}
    findings: list[Finding] = []
    errors: list[str] = []
    modules_run: list[str] = []

    for selection in plan.selections:
        runner = runner_map.get(selection.module_id)
        if runner is None:
            continue
        try:
            result = tuple(runner(context))
            findings.extend(item for item in result if isinstance(item, Finding))
            modules_run.append(selection.module_id)
        except Exception as exc:
            errors.append(f"{selection.module_id}: {type(exc).__name__}: {exc}")

    return ScanResult(target, assets, tuple(findings), tuple(modules_run), tuple(errors))

"""Core orchestration for AI-assisted web security scanning."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from models import Asset, Finding
from security_modules import ModuleContext, ModuleSpec, module_index


@dataclass(frozen=True, slots=True)
class ModuleSelection:
    """A module selected for the current scan and why it is relevant."""

    module_id: str
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ScanPlan:
    """Deterministic execution plan produced from defaults or the AI planner."""

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
    """Return the initial broad, safe baseline plan.

    Reconnaissance is always performed separately. These modules represent
    security checks that can be layered on top of the discovered surface.
    Nmap is only added when explicitly requested.
    """
    selected = [
        ModuleSelection("web.headers", "baseline web hardening"),
        ModuleSelection("web.cookies", "session security baseline"),
        ModuleSelection("web.exposure", "common exposure checks"),
        ModuleSelection("web.methods", "review discovered HTTP methods"),
        ModuleSelection("web.params", "prioritize discovered input surfaces"),
        ModuleSelection("web.config", "common configuration exposure"),
        ModuleSelection("ai.surface", "confirm and classify the AI boundary"),
    ]
    if include_nmap:
        selected.append(ModuleSelection("network.nmap", "optional host/service context"))
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
    """Run registered deterministic modules and normalize their output.

    The actual HTTP/browser implementation is deliberately injected through
    runners. This keeps the planner independent from low-level execution and
    makes each security module testable in isolation.
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

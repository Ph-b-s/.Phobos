"""Core orchestration for AI-assisted web security scanning."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from models import Asset, Finding
from security_modules import ModuleContext, ModuleDomain, ModuleStage, module_index


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
    """Return the baseline plan in the intended Phobos execution order.

    Web and AI vulnerability modules form the main assessment. Nmap is an
    optional Web-domain security module and, when selected, is always appended
    as a supplemental test after the main Web/AI assessment.
    """
    selected = [
        ModuleSelection("web.headers", "baseline web hardening"),
        ModuleSelection("web.cookies", "session security baseline"),
        ModuleSelection("web.exposure", "common exposure checks"),
        ModuleSelection("web.methods", "review discovered HTTP methods"),
        ModuleSelection("web.params", "prioritize discovered input surfaces"),
        ModuleSelection("web.config", "common configuration exposure"),
        ModuleSelection("ai.prompt_injection", "test identified AI input boundaries"),
        ModuleSelection("ai.data_disclosure", "test model-mediated data exposure"),
        ModuleSelection("ai.tool_abuse", "test AI-controlled tool boundaries"),
        ModuleSelection("ai.excessive_agency", "test unintended AI-mediated actions"),
    ]
    if include_nmap:
        selected.append(ModuleSelection("web.nmap", "supplemental web-facing service vulnerability check"))
    return ScanPlan(tuple(selected), source="default")


def validate_plan(plan: ScanPlan) -> ScanPlan:
    """Reject unknown modules, duplicates, and invalid stage ordering."""
    catalog = module_index()
    seen: set[str] = set()
    validated: list[ModuleSelection] = []
    seen_supplemental = False

    for selection in plan.selections:
        spec = catalog.get(selection.module_id)
        if spec is None:
            raise ValueError(f"unknown security module: {selection.module_id}")
        if selection.module_id in seen:
            continue
        if spec.stage is ModuleStage.SUPPLEMENTAL:
            seen_supplemental = True
        elif seen_supplemental:
            raise ValueError(
                f"security module {selection.module_id} cannot run after a supplemental module"
            )
        seen.add(selection.module_id)
        validated.append(selection)

    return ScanPlan(tuple(validated), source=plan.source)


def module_domains(plan: ScanPlan) -> tuple[str, ...]:
    """Return the unique target areas represented by a plan."""
    catalog = module_index()
    domains: list[str] = []
    for selection in plan.selections:
        domain = catalog[selection.module_id].domain.value
        if domain not in domains:
            domains.append(domain)
    return tuple(domains)


def execute_plan(
    target: str,
    assets: tuple[Asset, ...],
    plan: ScanPlan,
    *,
    runners: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> ScanResult:
    """Run registered deterministic security modules and normalize output.

    Low-level HTTP/browser/network execution is injected through runners. The
    planner therefore decides *what* should be tested while modules decide
    *how* their declared security procedure is executed.
    """
    plan = validate_plan(plan)
    context = ModuleContext(target=target, assets=assets, metadata=dict(metadata or {}))
    runner_map = runners or {}
    catalog = module_index()
    findings: list[Finding] = []
    errors: list[str] = []
    modules_run: list[str] = []

    for selection in plan.selections:
        spec = catalog[selection.module_id]
        if runner_map.get(selection.module_id) is None:
            continue
        runner = runner_map[selection.module_id]
        try:
            result = tuple(runner(context))
            findings.extend(item for item in result if isinstance(item, Finding))
            modules_run.append(spec.id)
        except Exception as exc:
            errors.append(f"{spec.id}: {type(exc).__name__}: {exc}")

    return ScanResult(target, assets, tuple(findings), tuple(modules_run), tuple(errors))

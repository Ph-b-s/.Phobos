"""Core orchestration for AI-assisted web security scanning."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from graph import Graph
from knowledge_store import KnowledgeStore
from models import Asset, Finding
from module_runner import ModuleRegistry, ModuleRun, ModuleRunner, default_module_registry
from security_modules import ModuleStage, module_index


@dataclass(frozen=True, slots=True)
class ModuleSelection:
    module_id: str
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ScanPlan:
    selections: tuple[ModuleSelection, ...]
    source: str = "default"


@dataclass(frozen=True, slots=True)
class ScanResult:
    target: str
    assets: tuple[Asset, ...]
    findings: tuple[Finding, ...]
    modules_run: tuple[str, ...]
    errors: tuple[str, ...] = ()
    knowledge: KnowledgeStore | None = None
    module_run: ModuleRun | None = None


def default_module_selection(*, include_nmap: bool = False) -> ScanPlan:
    selected = [
        ModuleSelection("web.headers", "baseline web hardening"),
        ModuleSelection("web.cookies", "session security baseline"),
        ModuleSelection("web.exposure", "common exposure checks"),
        ModuleSelection("web.methods", "review discovered HTTP methods"),
        ModuleSelection("web.config", "common configuration exposure"),
        ModuleSelection("ai.prompt_injection", "test identified AI input boundaries"),
        ModuleSelection("ai.data_disclosure", "test model-mediated data exposure"),
        ModuleSelection("ai.tool_abuse", "test AI-controlled tool boundaries"),
        ModuleSelection("ai.excessive_agency", "test unintended AI-mediated actions"),
        ModuleSelection("cross_layer.attack_path", "correlate Web and AI evidence"),
    ]
    if include_nmap:
        selected.append(ModuleSelection("web.nmap", "supplemental web-facing service vulnerability check"))
    return ScanPlan(tuple(selected), source="default")


def merge_module_selections(base: ScanPlan, additions: Iterable[ModuleSelection], *, source: str | None = None) -> ScanPlan:
    catalog = module_index()
    combined = list(base.selections)
    seen = {item.module_id for item in combined}
    for selection in additions:
        if selection.module_id not in catalog:
            raise ValueError(f"unknown security module: {selection.module_id}")
        if selection.module_id not in seen:
            combined.append(selection)
            seen.add(selection.module_id)
    stage_order = {ModuleStage.WEB_AI: 0, ModuleStage.FOLLOW_UP: 1, ModuleStage.SUPPLEMENTAL: 2}
    combined.sort(key=lambda item: (stage_order[catalog[item.module_id].stage], item.module_id))
    return ScanPlan(tuple(combined), source=source or base.source)


def validate_plan(plan: ScanPlan) -> ScanPlan:
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
            raise ValueError(f"security module {selection.module_id} cannot run after a supplemental module")
        seen.add(selection.module_id)
        validated.append(selection)
    return ScanPlan(tuple(validated), source=plan.source)


def module_domains(plan: ScanPlan) -> tuple[str, ...]:
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
    runners: dict[str, Any] | ModuleRegistry | None = None,
    metadata: dict[str, Any] | None = None,
    knowledge: KnowledgeStore | None = None,
    graph: Graph | None = None,
) -> ScanResult:
    """Execute a plan through the production module runner."""
    plan = validate_plan(plan)
    if isinstance(runners, ModuleRegistry):
        registry = runners
    elif runners is None:
        registry = default_module_registry()
    else:
        registry = default_module_registry()
        for module_id, handler in runners.items():
            registry.replace(module_id, handler)

    module_run = ModuleRunner(registry).run(
        target,
        (selection.module_id for selection in plan.selections),
        knowledge=knowledge,
        graph=graph,
        context_metadata={
            "plan_source": plan.source,
            "module_reasons": {item.module_id: item.reason for item in plan.selections},
            **(metadata or {}),
        },
        assets=assets,
    )
    return ScanResult(
        target=target,
        assets=module_run.knowledge.assets,
        findings=module_run.findings,
        modules_run=tuple(item.module_id for item in module_run.executions if item.status == "completed"),
        errors=module_run.errors,
        knowledge=module_run.knowledge,
        module_run=module_run,
    )

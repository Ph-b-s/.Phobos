"""Core orchestration for AI-assisted web security scanning."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from knowledge_store import KnowledgeStore
from models import Asset, Finding
from security_modules import ModuleContext, ModuleStage, module_index


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
        if selection.module_id not in seen:
            combined.append(selection)
            seen.add(selection.module_id)
    stage_order = {ModuleStage.WEB_AI: 0, ModuleStage.FOLLOW_UP: 1, ModuleStage.SUPPLEMENTAL: 2}
    combined.sort(key=lambda item: stage_order[catalog[item.module_id].stage])
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
    runners: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    knowledge: KnowledgeStore | None = None,
) -> ScanResult:
    """Execute modules against one shared mutable security knowledge state."""
    plan = validate_plan(plan)
    store = knowledge or KnowledgeStore()
    store.add_assets(assets)
    runner_map = runners or {}
    catalog = module_index()
    modules_run: list[str] = []
    errors: list[str] = []

    for selection in plan.selections:
        spec = catalog[selection.module_id]
        runner = runner_map.get(selection.module_id)
        if runner is None:
            continue
        context = ModuleContext(
            target=target,
            assets=tuple(store.assets),
            knowledge=store,
            metadata=dict(metadata or {}),
        )
        try:
            result = tuple(runner(context))
            for item in result:
                if isinstance(item, Finding):
                    store.add_finding(item)
            modules_run.append(spec.id)
        except Exception as exc:
            errors.append(f"{spec.id}: {type(exc).__name__}: {exc}")

    return ScanResult(target, tuple(store.assets), store.findings, tuple(modules_run), tuple(errors), store)

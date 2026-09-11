"""Core orchestration for bounded AI-assisted web security scanning."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

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


def default_module_selection(*, include_nmap: bool = False, include_indirect_ai: bool = False) -> ScanPlan:
    """Return the safe default set of currently executable baseline modules."""
    selected = [
        ModuleSelection("web.headers", "baseline web hardening"), ModuleSelection("web.cookies", "session security baseline"),
        ModuleSelection("web.exposure", "common exposure checks"), ModuleSelection("web.methods", "review discovered HTTP methods"),
        ModuleSelection("web.config", "common configuration exposure"), ModuleSelection("web.cors", "CORS policy baseline"),
        ModuleSelection("web.info_disclosure", "scan bounded responses for sensitive data patterns"), ModuleSelection("web.api", "baseline discovered API behavior"),
        ModuleSelection("web.openapi", "identify structured API specifications"), ModuleSelection("web.open_redirect", "identify redirect-like input surfaces"),
        ModuleSelection("web.source_maps", "identify JavaScript source-map references"), ModuleSelection("web.sensitive_inputs", "inventory sensitive-looking input names"),
        ModuleSelection("web.xss", "probe reflected HTML injection with a harmless canary"), ModuleSelection("web.sqli", "probe for non-destructive SQL error signals"),
        ModuleSelection("web.nosqli", "probe query parameters for bounded NoSQL operator differentials"), ModuleSelection("web.csrf", "assess discovered state-changing forms for CSRF protection signals"),
        ModuleSelection("web.client_javascript", "inspect discovered JavaScript for risky source/sink combinations"), ModuleSelection("web.jwt", "inspect discovered JWT-like tokens for unsafe algorithm and claim signals"),
        ModuleSelection("web.graphql", "assess discovered GraphQL endpoints with bounded read-only introspection"), ModuleSelection("web.ssti", "probe arithmetic-only template expressions for evaluation signals"),
        ModuleSelection("web.path_traversal", "probe GET parameters with a nonexistent traversal marker"), ModuleSelection("web.file_upload", "passively assess discovered upload validation signals"),
        ModuleSelection("web.websocket", "discover WebSocket endpoints without connecting"), ModuleSelection("web.ssrf", "identify likely server-side request sinks"),
        ModuleSelection("web.command_injection", "identify likely command-execution sinks"), ModuleSelection("web.xxe", "identify likely XML-processing surfaces"),
        ModuleSelection("web.deserialization", "identify likely serialization/deserialization surfaces"), ModuleSelection("web.business_logic", "identify high-value workflow candidates"),
        ModuleSelection("web.request_smuggling", "inspect HTTP framing and proxy indicators without ambiguous payloads"), ModuleSelection("web.cache", "inspect cache policy and untrusted-input reflection signals"),
        ModuleSelection("web.host_header", "inspect Host-header trust behavior without changing state"),
        ModuleSelection("ai.rag", "identify retrieval and grounding surfaces"), ModuleSelection("ai.vector", "identify vector and embedding surfaces"),
        ModuleSelection("ai.data_poisoning", "identify untrusted AI context sources"), ModuleSelection("ai.tool_abuse", "identify model-controlled tool surfaces"),
        ModuleSelection("ai.unbounded_consumption", "inspect AI resource-consumption controls"), ModuleSelection("ai.multi_agent", "identify agent handoff boundaries"),
        ModuleSelection("ai.memory", "identify persistent AI memory surfaces"), ModuleSelection("ai.identity", "identify AI identity and privilege boundaries"), ModuleSelection("ai.trust_boundary", "connect AI and Web surface identifiers"),
        ModuleSelection("cross_layer.web_to_ai", "correlate Web inputs with AI surfaces"), ModuleSelection("cross_layer.ai_to_web", "correlate AI surfaces with downstream Web capabilities"),
        ModuleSelection("cross_layer.auth_boundary", "review Web/AI authorization boundaries"), ModuleSelection("cross_layer.data_flow", "trace cross-layer data movement"),
        ModuleSelection("cross_layer.control_flow", "trace AI-mediated control flow"), ModuleSelection("cross_layer.capability_escalation", "review capability expansion"),
        ModuleSelection("cross_layer.attack_path", "rank cross-layer attack paths"),
    ]
    if include_indirect_ai:
        selected.append(ModuleSelection("ai.indirect_prompt_injection", "run configured indirect-injection assessment"))
    if include_nmap:
        selected.append(ModuleSelection("web.nmap", "supplemental web-facing service vulnerability check"))
    return validate_plan(ScanPlan(tuple(selected), source="default"))


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


def execute_plan(target: str, assets: tuple[Asset, ...], plan: ScanPlan, *, runners: dict[str, Any] | ModuleRegistry | None = None,
                 metadata: dict[str, Any] | None = None, knowledge: KnowledgeStore | None = None, graph: Graph | None = None,
                 capabilities: Mapping[str, Any] | None = None) -> ScanResult:
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
        target, (selection.module_id for selection in plan.selections), knowledge=knowledge, graph=graph,
        context_metadata={"plan_source": plan.source, "module_reasons": {item.module_id: item.reason for item in plan.selections}, **(metadata or {})},
        assets=assets, capabilities=capabilities,
    )
    return ScanResult(target, module_run.knowledge.assets, module_run.findings,
                      tuple(item.module_id for item in module_run.executions if item.status == "completed"),
                      module_run.errors, module_run.knowledge, module_run)


def build_planner_context(
    target: str,
    assets: tuple[Asset, ...],
    knowledge: KnowledgeStore,
    plan: ScanPlan,
    *,
    max_findings: int = 32,
) -> dict[str, Any]:
    """Return the compact structured context used by the planner."""
    return {
        "target": target,
        "assets": [item.to_dict() for item in assets[:128]],
        "findings": [item.to_dict() for item in knowledge.findings[:max_findings]],
        "observations": [item.to_dict() for item in knowledge.observations[:128]],
        "planned_modules": [item.module_id for item in plan.selections],
    }

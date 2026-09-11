"""Registry-driven, bounded execution for Phobos security modules."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from cross_layer import analyze_cross_layer
from graph import Graph
from knowledge_store import KnowledgeStore, SecurityObservation
from models import Finding
from security_modules import ModuleContext, ModuleSpec, ModuleStage, SecurityModule, module_index

MAX_MODULES_PER_RUN = 64
MAX_RESULT_ITEMS_PER_MODULE = 256
MAX_ERRORS_PER_RUN = 64
MAX_FOLLOW_UPS_PER_RUN = 256


@dataclass(frozen=True, slots=True)
class ModuleResult:
    observations: tuple[SecurityObservation, ...] = ()
    findings: tuple[Finding, ...] = ()
    follow_ups: tuple[dict[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if len(self.observations) + len(self.findings) > MAX_RESULT_ITEMS_PER_MODULE:
            raise ValueError("module result exceeds item limit")
        object.__setattr__(self, "observations", tuple(self.observations))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "follow_ups", tuple(dict(item) for item in self.follow_ups))


@dataclass(frozen=True, slots=True)
class ModuleExecution:
    module_id: str
    status: str
    observations_added: int = 0
    findings_added: int = 0
    follow_ups_added: int = 0
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ModuleRun:
    executions: tuple[ModuleExecution, ...]
    findings: tuple[Finding, ...]
    observations: tuple[SecurityObservation, ...]
    follow_ups: tuple[dict[str, Any], ...]
    knowledge: KnowledgeStore
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "executions": [{"module_id": item.module_id, "status": item.status,
                            "observations_added": item.observations_added,
                            "findings_added": item.findings_added,
                            "follow_ups_added": item.follow_ups_added,
                            "error": item.error} for item in self.executions],
            "findings": [item.to_dict() for item in self.findings],
            "observations": [item.to_dict() for item in self.observations],
            "follow_ups": list(self.follow_ups),
            "errors": list(self.errors),
        }


ModuleFactory = Callable[[ModuleSpec], SecurityModule]
ModuleHandler = Callable[[ModuleContext], ModuleResult | Iterable[SecurityObservation | Finding]]


class ModuleRegistry:
    """Explicit registry of executable module implementations."""

    def __init__(self) -> None:
        self._handlers: dict[str, ModuleHandler] = {}

    def register(self, module_id: str, handler: ModuleHandler) -> None:
        module_id = module_id.strip()
        if module_id not in module_index():
            raise ValueError(f"cannot register unknown security module: {module_id}")
        if not callable(handler):
            raise TypeError("module handler must be callable")
        if module_id in self._handlers:
            raise ValueError(f"security module already registered: {module_id}")
        self._handlers[module_id] = handler

    def replace(self, module_id: str, handler: ModuleHandler) -> None:
        module_id = module_id.strip()
        if module_id not in module_index():
            raise ValueError(f"cannot register unknown security module: {module_id}")
        if not callable(handler):
            raise TypeError("module handler must be callable")
        self._handlers[module_id] = handler

    def get(self, module_id: str) -> ModuleHandler | None:
        return self._handlers.get(module_id)

    def ids(self) -> frozenset[str]:
        return frozenset(self._handlers)


def default_module_registry() -> ModuleRegistry:
    registry = ModuleRegistry()
    for module_id in (
        "cross_layer.web_to_ai", "cross_layer.ai_to_web", "cross_layer.auth_boundary",
        "cross_layer.data_flow", "cross_layer.control_flow", "cross_layer.capability_escalation",
        "cross_layer.attack_path",
    ):
        registry.register(module_id, _cross_layer_handler)

    from module_adapters import run_indirect_prompt_injection_module, run_nmap_module
    from standard_modules import (
        run_web_config,
        run_web_cookies,
        run_web_cors,
        run_web_exposure,
        run_web_headers,
        run_web_methods,
    )
    from advanced_web_modules import (
        run_web_api,
        run_web_info_disclosure,
        run_web_sqli,
        run_web_xss,
    )

    registry.register("web.headers", run_web_headers)
    registry.register("web.cookies", run_web_cookies)
    registry.register("web.exposure", run_web_exposure)
    registry.register("web.methods", run_web_methods)
    registry.register("web.config", run_web_config)
    registry.register("web.cors", run_web_cors)
    registry.register("web.info_disclosure", run_web_info_disclosure)
    registry.register("web.api", run_web_api)
    registry.register("web.xss", run_web_xss)
    registry.register("web.sqli", run_web_sqli)
    registry.register("web.nmap", run_nmap_module)
    registry.register("ai.indirect_prompt_injection", run_indirect_prompt_injection_module)
    return registry


@dataclass(frozen=True, slots=True)
class ModuleRunner:
    registry: ModuleRegistry
    max_modules: int = MAX_MODULES_PER_RUN
    max_follow_ups: int = MAX_FOLLOW_UPS_PER_RUN
    stop_on_error: bool = False

    def __post_init__(self) -> None:
        if not 1 <= self.max_modules <= MAX_MODULES_PER_RUN:
            raise ValueError(f"max_modules must be between 1 and {MAX_MODULES_PER_RUN}")
        if not 1 <= self.max_follow_ups <= MAX_FOLLOW_UPS_PER_RUN:
            raise ValueError(f"max_follow_ups must be between 1 and {MAX_FOLLOW_UPS_PER_RUN}")

    def run(self, target: str, module_ids: Iterable[str], *, knowledge: KnowledgeStore | None = None,
            graph: Graph | None = None, context_metadata: Mapping[str, Any] | None = None,
            assets: tuple[Any, ...] = (), capabilities: Mapping[str, Any] | None = None) -> ModuleRun:
        store = knowledge or KnowledgeStore()
        if assets:
            store.add_assets(assets)
        ids = tuple(dict.fromkeys(item.strip() for item in module_ids if item and item.strip()))
        if len(ids) > self.max_modules:
            raise ValueError(f"module run exceeds limit of {self.max_modules} modules")
        _validate_stage_order(ids)
        catalog = module_index()
        executions: list[ModuleExecution] = []
        errors: list[str] = []
        all_follow_ups: list[dict[str, Any]] = []
        caps = dict(capabilities or {})

        for module_id in ids:
            spec = catalog.get(module_id)
            if spec is None:
                message = f"unknown security module: {module_id}"
                executions.append(ModuleExecution(module_id, "invalid", error=message))
                errors.append(message)
                if self.stop_on_error:
                    break
                continue
            if not spec.active:
                executions.append(ModuleExecution(module_id, "inactive"))
                continue
            handler = self.registry.get(module_id)
            if handler is None:
                executions.append(ModuleExecution(module_id, "unimplemented"))
                continue

            context = ModuleContext(
                target=target,
                assets=tuple(store.assets),
                knowledge=store,
                graph=graph,
                browser=caps.get("browser"),
                interactor=caps.get("interactor"),
                accounts=caps.get("accounts"),
                workflow=caps.get("workflow"),
                applications=tuple(caps.get("applications", ())),
                metadata={
                    **dict(context_metadata or {}),
                    **dict(caps.get("metadata", {})),
                    "module_id": module_id,
                    "module_domain": spec.domain.value,
                    "module_stage": spec.stage.value,
                },
            )
            try:
                before_observations = {item.id for item in store.observations}
                before_findings = {item.id for item in store.findings}
                result = _normalize_result(handler(context), module_id)
                for observation in result.observations:
                    store.add_observation(observation)
                for finding in result.findings:
                    store.add_finding(finding)
                available = self.max_follow_ups - len(all_follow_ups)
                if len(result.follow_ups) > available:
                    raise RuntimeError("module follow-up limit exceeded")
                all_follow_ups.extend(result.follow_ups)
                executions.append(ModuleExecution(
                    module_id,
                    "completed",
                    sum(item.id not in before_observations for item in result.observations),
                    sum(item.id not in before_findings for item in result.findings),
                    len(result.follow_ups),
                ))
            except Exception as exc:
                message = f"{module_id}: {type(exc).__name__}: {exc}"
                if len(errors) < MAX_ERRORS_PER_RUN:
                    errors.append(message)
                executions.append(ModuleExecution(module_id, "error", error=message))
                if self.stop_on_error:
                    break

        return ModuleRun(tuple(executions), store.findings, store.observations,
                         tuple(all_follow_ups), store, tuple(errors[:MAX_ERRORS_PER_RUN]))


def _cross_layer_handler(context: ModuleContext) -> ModuleResult:
    if context.graph is None:
        return ModuleResult()
    analysis = analyze_cross_layer(context.graph, context.store())
    module_id = str(context.metadata.get("module_id", ""))
    selected = tuple(item for item in analysis.follow_ups if item["module_id"] == module_id)
    observations = tuple(
        SecurityObservation(
            id=f"{module_id}:{item['correlation_id']}", kind=f"cross_layer.{item['correlation_type']}",
            source=module_id, description=item["reason"], asset_ids=tuple(item["asset_ids"]),
            data={"correlation_id": item["correlation_id"], "priority": item["priority"]},
            confidence=float(item["priority"]),
        ) for item in selected[:MAX_RESULT_ITEMS_PER_MODULE]
    )
    follow_ups = analysis.follow_ups[:MAX_FOLLOW_UPS_PER_RUN] if module_id == "cross_layer.attack_path" else ()
    return ModuleResult(observations=observations, follow_ups=follow_ups)


def _validate_stage_order(module_ids: tuple[str, ...]) -> None:
    catalog = module_index()
    order = {ModuleStage.WEB_AI: 0, ModuleStage.FOLLOW_UP: 1, ModuleStage.SUPPLEMENTAL: 2}
    last_stage = -1
    for module_id in module_ids:
        spec = catalog.get(module_id)
        if spec is None:
            continue
        stage = order[spec.stage]
        if stage < last_stage:
            raise ValueError("module plan violates execution-stage ordering")
        last_stage = stage


def _normalize_result(value: ModuleResult | Iterable[SecurityObservation | Finding], module_id: str) -> ModuleResult:
    if isinstance(value, ModuleResult):
        return value
    if isinstance(value, (str, bytes, bytearray)):
        raise TypeError(f"module {module_id} returned a non-structured result")
    observations: list[SecurityObservation] = []
    findings: list[Finding] = []
    for item in value:
        if isinstance(item, SecurityObservation):
            observations.append(item)
        elif isinstance(item, Finding):
            findings.append(item)
        else:
            raise TypeError(f"module {module_id} returned unsupported result: {type(item).__name__}")
    return ModuleResult(tuple(observations), tuple(findings))


def executable_module_ids(registry: ModuleRegistry | None = None) -> frozenset[str]:
    return registry.ids() if registry is not None else frozenset()

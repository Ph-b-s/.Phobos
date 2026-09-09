"""Registry-driven, bounded execution for Phobos security modules.

The runner is the execution boundary between planning/correlation and concrete
security capabilities. Modules never choose arbitrary targets or transports;
they receive a shared ModuleContext and return structured results.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from knowledge_store import KnowledgeStore, SecurityObservation
from models import Finding
from security_modules import ModuleContext, ModuleSpec, SecurityModule, module_index

MAX_MODULES_PER_RUN = 64
MAX_RESULT_ITEMS_PER_MODULE = 256
MAX_ERRORS_PER_RUN = 64


@dataclass(frozen=True, slots=True)
class ModuleResult:
    """Structured output from one security module execution."""

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
    """Auditable outcome for a single module dispatch."""

    module_id: str
    status: str
    observations_added: int = 0
    findings_added: int = 0
    follow_ups_added: int = 0
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ModuleRun:
    """Complete bounded module-run result."""

    executions: tuple[ModuleExecution, ...]
    findings: tuple[Finding, ...]
    observations: tuple[SecurityObservation, ...]
    follow_ups: tuple[dict[str, Any], ...]
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "executions": [
                {
                    "module_id": item.module_id,
                    "status": item.status,
                    "observations_added": item.observations_added,
                    "findings_added": item.findings_added,
                    "follow_ups_added": item.follow_ups_added,
                    "error": item.error,
                }
                for item in self.executions
            ],
            "findings": [item.to_dict() for item in self.findings],
            "observations": [item.to_dict() for item in self.observations],
            "follow_ups": list(self.follow_ups),
            "errors": list(self.errors),
        }


ModuleFactory = Callable[[ModuleSpec], SecurityModule]
ModuleHandler = Callable[[ModuleContext], ModuleResult | Iterable[SecurityObservation | Finding]]


class ModuleRegistry:
    """Explicit registry of executable module implementations.

    Registration is intentionally separate from the vulnerability catalog:
    catalog entries describe capabilities; the registry proves that an actual
    implementation is available.
    """

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

    def contains(self, module_id: str) -> bool:
        return module_id in self._handlers


@dataclass(frozen=True, slots=True)
class ModuleRunner:
    """Execute a validated module plan against one shared knowledge store."""

    registry: ModuleRegistry
    max_modules: int = MAX_MODULES_PER_RUN
    stop_on_error: bool = False

    def __post_init__(self) -> None:
        if not 1 <= self.max_modules <= MAX_MODULES_PER_RUN:
            raise ValueError(f"max_modules must be between 1 and {MAX_MODULES_PER_RUN}")

    def run(
        self,
        target: str,
        module_ids: Iterable[str],
        *,
        knowledge: KnowledgeStore | None = None,
        context_metadata: Mapping[str, Any] | None = None,
        assets: tuple[Any, ...] = (),
    ) -> ModuleRun:
        store = knowledge or KnowledgeStore()
        if assets:
            store.add_assets(assets)

        ids = tuple(dict.fromkeys(item.strip() for item in module_ids if item and item.strip()))
        if len(ids) > self.max_modules:
            raise ValueError(f"module run exceeds limit of {self.max_modules} modules")

        catalog = module_index()
        executions: list[ModuleExecution] = []
        errors: list[str] = []
        findings_before = set(store.findings)
        observations_before = set(store.observations)
        all_follow_ups: list[dict[str, Any]] = []

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
                message = f"security module is not implemented: {module_id}"
                executions.append(ModuleExecution(module_id, "unimplemented", error=message))
                errors.append(message)
                if self.stop_on_error:
                    break
                continue

            context = ModuleContext(
                target=target,
                assets=tuple(store.assets),
                knowledge=store,
                metadata={
                    **dict(context_metadata or {}),
                    "module_id": module_id,
                    "module_domain": spec.domain.value,
                    "module_stage": spec.stage.value,
                },
            )
            try:
                raw = handler(context)
                result = _normalize_result(raw, module_id)
                for observation in result.observations:
                    store.add_observation(observation)
                for finding in result.findings:
                    store.add_finding(finding)
                all_follow_ups.extend(result.follow_ups)

                observations_added = sum(1 for item in result.observations if item.id not in observations_before)
                findings_added = sum(1 for item in result.findings if item.id not in findings_before)
                executions.append(
                    ModuleExecution(
                        module_id,
                        "completed",
                        observations_added,
                        findings_added,
                        len(result.follow_ups),
                    )
                )
            except Exception as exc:
                message = f"{module_id}: {type(exc).__name__}: {exc}"
                if len(errors) < MAX_ERRORS_PER_RUN:
                    errors.append(message)
                executions.append(ModuleExecution(module_id, "error", error=message))
                if self.stop_on_error:
                    break

        return ModuleRun(
            executions=tuple(executions),
            findings=store.findings,
            observations=store.observations,
            follow_ups=tuple(all_follow_ups),
            errors=tuple(errors[:MAX_ERRORS_PER_RUN]),
        )


def _normalize_result(
    value: ModuleResult | Iterable[SecurityObservation | Finding],
    module_id: str,
) -> ModuleResult:
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
    """Return actual implementations, not merely catalog entries."""
    return registry.ids() if registry is not None else frozenset()

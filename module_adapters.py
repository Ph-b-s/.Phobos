"""Execution adapters for the first production security modules."""
from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlsplit

from ai_testing import Observation, build_indirect_canary, build_test_queries, new_canary, validate_canary
from assessment_engine import AssessmentEngine, default_indirect_prompt_injection_engine, indirect_prompt_injection_procedure
from knowledge_store import SecurityObservation
from models import Finding
from module_runner import ModuleResult
from nmap_runner import NmapError, run_top_ports_scan
from security_modules import ModuleContext


class ModuleAdapterError(RuntimeError):
    """Raised when a module cannot be executed from the supplied capabilities."""


def _scope_from_context(context: ModuleContext) -> Any:
    scope = context.metadata.get("scope")
    if scope is None:
        raise ModuleAdapterError("web.nmap requires a ScopeValidator in module metadata")
    return scope


def run_nmap_module(context: ModuleContext) -> ModuleResult:
    """Run the bounded Nmap runner and normalize its services into observations."""
    scope = _scope_from_context(context)
    result = run_top_ports_scan(context.target, scope)
    host = urlsplit(context.target if "://" in context.target else f"https://{context.target}").hostname or context.target
    observations = tuple(
        SecurityObservation(
            id=f"web.nmap:{host}:{port.protocol}:{port.port}",
            kind="nmap.open_port",
            source="web.nmap",
            description=(f"Nmap observed open {port.protocol.upper()} port {port.port}"
                         + (f" ({port.service})" if port.service else "")),
            data={"host": host, "port": port.port, "protocol": port.protocol, "state": port.state,
                  "service": port.service, "product": port.product, "version": port.version, "reason": port.reason},
            confidence=1.0,
        )
        for port in result.ports
    )
    return ModuleResult(observations=observations)


class IndirectPromptInjectionAdapter:
    """Bounded browser/HTTP adapter for the canonical indirect-injection procedure."""

    REQUIRED = ("source_url", "source_selector", "source_submit_selector", "chat_url",
                "chat_input_selector", "chat_submit_selector", "product_name")

    def __init__(self, context: ModuleContext) -> None:
        self.context = context
        self.browser = context.require("browser")
        self.requests = context.metadata.get("request_manager")
        if self.requests is None:
            raise ModuleAdapterError("indirect prompt injection requires request_manager in module metadata")
        config = context.metadata.get("indirect_prompt_injection")
        if not isinstance(config, Mapping):
            raise ModuleAdapterError("indirect_prompt_injection configuration is missing")
        missing = [key for key in self.REQUIRED if not str(config.get(key, "")).strip()]
        if missing:
            raise ModuleAdapterError(f"indirect prompt injection configuration missing: {', '.join(missing)}")
        self.config = dict(config)
        self.canary = validate_canary(str(config.get("canary") or new_canary()))

    def handlers(self) -> dict[str, Any]:
        return {"discover_chat": self.discover_chat, "map_ai_api": self.map_ai_api,
                "map_tool_arguments": self.map_tool_arguments, "establish_auth_boundary": self.establish_auth_boundary,
                "discover_indirect_input": self.discover_indirect_input, "seed_canary": self.seed_canary,
                "prove_influence": self.prove_influence, "validate_impact": self.validate_impact}

    def _open_chat(self) -> None:
        self.browser.goto(str(self.config["chat_url"]))

    def _submit_chat(self, query: str) -> str:
        self.browser.goto(str(self.config["chat_url"]))
        self.browser.fill(str(self.config["chat_input_selector"]), query)
        self.browser.click(str(self.config["chat_submit_selector"]))
        return self.browser.text()[:20_000]

    def discover_chat(self):
        self._open_chat()
        snapshot = self.browser.snapshot()
        return (Observation("chat_surface", f"LLM interaction surface discovered at {snapshot.url}",
                             "browser_adapter", metadata={"url": snapshot.url, "title": snapshot.title}),)

    def map_ai_api(self):
        return (Observation("tool_inventory", "Browser network activity captured while opening the configured LLM surface.",
                             "browser_adapter", metadata={"network_observations": len(self.browser.network_observations())}),)

    def map_tool_arguments(self):
        return (Observation("tool_arguments", "Configured AI interaction selectors provide the bounded tool/input contract.",
                             "indirect_prompt_injection_adapter",
                             metadata={"chat_input_selector": str(self.config["chat_input_selector"])}),)

    def establish_auth_boundary(self):
        response = self.requests.get(str(self.config["chat_url"]))
        return (Observation("authenticated_tool_execution",
                             f"Configured AI surface responded with HTTP {response.status} in the assessment session.",
                             "request_manager", metadata={"status": response.status}),)

    def discover_indirect_input(self):
        response = self.requests.get(str(self.config["source_url"]))
        return (Observation("indirect_input_source",
                             f"Configured indirect input source is reachable with HTTP {response.status}.",
                             "request_manager", metadata={"url": str(self.config["source_url"]), "status": response.status}),)

    def seed_canary(self):
        allowed = bool(self.config.get("allow_state_change", self.context.metadata.get("allow_state_change", False)))
        if not allowed:
            raise ModuleAdapterError("canary seeding requires explicit allow_state_change=True")
        marker = build_indirect_canary(self.canary)
        self.browser.goto(str(self.config["source_url"]))
        self.browser.fill(str(self.config["source_selector"]), marker)
        self.browser.click(str(self.config["source_submit_selector"]))
        return (Observation("canary_seeded", "A unique Phobos canary was placed in the configured indirect input source.",
                             "browser_adapter", evidence=(marker,),
                             metadata={"canary": self.canary, "source_url": str(self.config["source_url"])}),)

    def prove_influence(self):
        queries = build_test_queries(str(self.config["product_name"]))
        baseline = self._submit_chat(queries[0])
        induced = self._submit_chat(queries[1])
        observations = [Observation("baseline_compared", "Clean and induced LLM interactions were executed for comparison.",
                                     "browser_adapter", metadata={"baseline_length": len(baseline), "induced_length": len(induced)})]
        if self.canary in induced:
            observations.append(Observation("canary_observed", "The exact seeded canary reappeared in the LLM response.",
                                             "browser_adapter", evidence=(self.canary,), metadata={"canary": self.canary}))
        return tuple(observations)

    def validate_impact(self):
        if not bool(self.config.get("impact_validation_selector")):
            raise ModuleAdapterError("impact validation is not configured")
        return (Observation("state_change_validated", "Configured impact-validation control is available for an explicitly authorized follow-up.",
                             "indirect_prompt_injection_adapter", metadata={"canary": self.canary, "validated": False}),)


def run_indirect_prompt_injection_module(context: ModuleContext) -> ModuleResult:
    """Execute the canonical indirect-prompt-injection procedure."""
    adapter = IndirectPromptInjectionAdapter(context)
    engine: AssessmentEngine = AssessmentEngine(stop_on_error=False)
    run = engine.run(indirect_prompt_injection_procedure(), adapter.handlers(), canary=adapter.canary,
                     allow_state_change=bool(context.metadata.get("allow_state_change", False)),
                     metadata={"module_id": "ai.indirect_prompt_injection"})

    observations = [SecurityObservation(
        id=f"ai.indirect_prompt_injection:{index}:{item.kind}",
        kind=f"ai.indirect_prompt_injection.{item.kind}", source="ai.indirect_prompt_injection",
        description=item.description, data={"evidence": list(item.evidence), **item.metadata},
        confidence=run.result.confidence if item.kind == "canary_observed" else 1.0,
    ) for index, item in enumerate(run.observations)]
    observations.extend(SecurityObservation(
        id=f"ai.indirect_prompt_injection:error:{index}", kind="ai.indirect_prompt_injection.assessment_error",
        source="ai.indirect_prompt_injection", description=error, data={}, confidence=1.0)
        for index, error in enumerate(run.errors))

    findings: tuple[Finding, ...] = ()
    if run.result.finding_type is not None:
        findings = (Finding(id="ai.indirect_prompt_injection", type=run.result.finding_type,
                            confidence=run.result.confidence, evidence=run.result.evidence,
                            metadata=run.result.metadata),)
    return ModuleResult(observations=tuple(observations), findings=findings)

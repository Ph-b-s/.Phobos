"""Security-module contracts and the Phobos vulnerability catalog."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from graph import Graph
from knowledge_store import KnowledgeStore
from models import Asset, Finding


class ModuleDomain(StrEnum):
    WEB = "web"
    AI = "ai"
    CROSS_LAYER = "cross_layer"


class ModuleStage(StrEnum):
    WEB_AI = "web_ai"
    FOLLOW_UP = "follow_up"
    SUPPLEMENTAL = "supplemental"


@dataclass(frozen=True, slots=True)
class ModuleContext:
    target: str
    assets: tuple[Asset, ...] = ()
    knowledge: KnowledgeStore | None = None
    graph: Graph | None = None
    browser: Any | None = None
    interactor: Any | None = None
    accounts: Any | None = None
    workflow: Any | None = None
    applications: tuple[Any, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def store(self) -> KnowledgeStore:
        if self.knowledge is None:
            raise RuntimeError("module context has no shared knowledge store")
        return self.knowledge

    def require(self, capability: str) -> Any:
        value = getattr(self, capability, None)
        if value is None:
            raise RuntimeError(f"module requires unavailable capability: {capability}")
        return value


class SecurityModule(Protocol):
    id: str
    name: str
    description: str

    def can_run(self, context: ModuleContext) -> bool: ...
    def run(self, context: ModuleContext) -> Any: ...


@dataclass(frozen=True, slots=True)
class ModuleSpec:
    id: str
    name: str
    description: str
    domain: ModuleDomain
    stage: ModuleStage = ModuleStage.WEB_AI
    active: bool = False
    implemented: bool = False
    tool: str | None = None

    @property
    def category(self) -> str:
        return self.domain.value


MODULE_CATALOG: tuple[ModuleSpec, ...] = (
    ModuleSpec("web.headers", "Security headers", "Check response security headers and policy gaps.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.cookies", "Cookie security", "Check Secure, HttpOnly, SameSite, scope, and session-cookie behavior.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.exposure", "Common exposure", "Check for common exposed files, debug surfaces, and sensitive endpoints.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.methods", "HTTP methods", "Test unusual or dangerous HTTP method exposure.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.auth", "Authentication", "Execute an authorized browser workflow to establish and observe an authenticated session.", ModuleDomain.WEB, active=True, implemented=True, tool="playwright"),
    ModuleSpec("web.access_control", "Access control", "Test authorization boundaries, IDOR, privilege escalation, and object access.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.injection", "Generic injection", "Select and coordinate injection procedures for discovered inputs.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.xss", "Cross-site scripting", "Test reflected, stored, and DOM XSS surfaces.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.sqli", "SQL injection", "Test database-backed inputs for SQL injection conditions.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.nosqli", "NoSQL injection", "Test document-database inputs for NoSQL injection conditions.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.ssrf", "Server-side request forgery", "Test server-side request features and trust-boundary crossings.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.csrf", "Cross-site request forgery", "Test state-changing actions for CSRF weaknesses.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.command_injection", "Command injection", "Test input paths that may reach operating-system command execution.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.path_traversal", "Path traversal", "Test file/path parameters for traversal outside intended directories.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.file_upload", "File upload", "Test upload validation, processing, storage, and execution boundaries.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.xxe", "XXE", "Test XML processing for external-entity injection conditions.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.ssti", "Server-side template injection", "Test template expression surfaces for server-side evaluation.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.deserialization", "Deserialization", "Test serialized-object inputs for unsafe deserialization behavior.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.cors", "CORS", "Test cross-origin policy and credential exposure.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.cache", "Web cache attacks", "Test cache poisoning, deception, and keying behavior.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.request_smuggling", "Request smuggling", "Test front-end/back-end HTTP parsing inconsistencies.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.host_header", "Host header attacks", "Test host-header handling and trust assumptions.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.jwt", "JWT security", "Test token parsing, signing, claims, and trust behavior.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.graphql", "GraphQL security", "Test GraphQL authorization, introspection, batching, and injection surfaces.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.websocket", "WebSocket security", "Test WebSocket authentication, authorization, and message handling.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.race_conditions", "Race conditions", "Test concurrent state transitions for timing-sensitive flaws.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.business_logic", "Business logic", "Test workflows for abuse, state confusion, and invariant violations.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.info_disclosure", "Information disclosure", "Check responses and interfaces for unintended sensitive data exposure.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.config", "Configuration security", "Check deployment and application configuration weaknesses.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.browser_runtime", "Browser runtime", "Use a real browser to execute JavaScript, observe rendered DOM, and capture runtime requests.", ModuleDomain.WEB, active=True, tool="playwright"),
    ModuleSpec("web.client_javascript", "Client-side JavaScript", "Inspect and test browser-side JavaScript routes, sinks, and application behavior.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.api", "API security", "Test discovered HTTP APIs, including authorization, input validation, and state transitions.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.nmap", "Nmap security module", "Optional Nmap-backed service and web-facing vulnerability checks after web/AI testing.", ModuleDomain.WEB, stage=ModuleStage.SUPPLEMENTAL, active=True, implemented=True, tool="nmap"),
    ModuleSpec("ai.prompt_injection", "Prompt injection", "Test direct prompt-injection paths into model instructions.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.indirect_prompt_injection", "Indirect prompt injection", "Test untrusted external content that can influence model instructions.", ModuleDomain.AI, active=True, implemented=True),
    ModuleSpec("ai.system_prompt", "System prompt leakage", "Test whether protected system instructions can be extracted or manipulated.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.data_disclosure", "AI data disclosure", "Test model-mediated disclosure of secrets or protected application data.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.output_handling", "Unsafe AI output handling", "Test whether model output becomes an unsafe downstream input.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.tool_abuse", "AI tool abuse", "Test model-controlled tools for unauthorized or unsafe actions.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.excessive_agency", "AI excessive agency", "Test whether AI functionality can exercise more authority than intended.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.rag", "RAG security", "Test retrieval, document trust, authorization, and grounding boundaries.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.vector", "Vector/embedding security", "Test embedding and vector-store trust and isolation weaknesses.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.data_poisoning", "AI data poisoning", "Test whether attacker-controlled data can corrupt model context or behavior.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.unbounded_consumption", "Unbounded consumption", "Test model-driven resource and cost exhaustion paths.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.multi_agent", "Multi-agent security", "Test trust and authorization boundaries between cooperating agents.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.goal_hijacking", "Goal hijacking", "Test whether untrusted inputs can redirect an agent's intended objective.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.context_manipulation", "Context manipulation", "Test memory and contextual state for attacker-controlled influence.", ModuleDomain.AI, active=True),
    ModuleSpec("cross_layer.web_to_ai", "Web to AI flow", "Correlate attacker-controlled Web inputs with downstream AI context or decisions.", ModuleDomain.CROSS_LAYER, stage=ModuleStage.FOLLOW_UP, active=True, implemented=True),
    ModuleSpec("cross_layer.ai_to_web", "AI to Web flow", "Correlate AI output or decisions with downstream Web/backend sinks.", ModuleDomain.CROSS_LAYER, stage=ModuleStage.FOLLOW_UP, active=True, implemented=True),
    ModuleSpec("cross_layer.auth_boundary", "Web/AI auth boundary", "Test whether user authorization is preserved when AI functionality performs actions.", ModuleDomain.CROSS_LAYER, stage=ModuleStage.FOLLOW_UP, active=True, implemented=True),
    ModuleSpec("cross_layer.data_flow", "Web/AI data-flow abuse", "Trace sensitive data across Web and AI contexts for unintended exposure or influence.", ModuleDomain.CROSS_LAYER, stage=ModuleStage.FOLLOW_UP, active=True, implemented=True),
    ModuleSpec("cross_layer.control_flow", "Web/AI control-flow abuse", "Detect AI-mediated changes to an application's intended execution path.", ModuleDomain.CROSS_LAYER, stage=ModuleStage.FOLLOW_UP, active=True, implemented=True),
    ModuleSpec("cross_layer.capability_escalation", "Capability escalation", "Detect cases where AI access expands attacker-controlled or user-level capability.", ModuleDomain.CROSS_LAYER, stage=ModuleStage.FOLLOW_UP, active=True, implemented=True),
    ModuleSpec("cross_layer.attack_path", "Cross-layer attack paths", "Correlate Web and AI evidence into bounded multi-step attack paths for follow-up testing.", ModuleDomain.CROSS_LAYER, stage=ModuleStage.FOLLOW_UP, active=True, implemented=True),
)


def module_specs() -> tuple[ModuleSpec, ...]:
    return MODULE_CATALOG


def module_index() -> dict[str, ModuleSpec]:
    return {item.id: item for item in MODULE_CATALOG}


def executable_module_ids(registry: Any | None = None) -> frozenset[str]:
    return registry.ids() if registry is not None else frozenset()

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
    ModuleSpec("web.access_control", "Access control", "Compare explicitly configured low/high privilege workflows against the same protected resources.", ModuleDomain.WEB, active=True, implemented=True, tool="playwright"),
    ModuleSpec("web.injection", "Generic injection", "Select and coordinate injection procedures for discovered inputs.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.xss", "Cross-site scripting", "Test reflected, stored, and DOM XSS surfaces.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.sqli", "SQL injection", "Test database-backed inputs for SQL injection conditions.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.nosqli", "NoSQL injection", "Test query parameters for bounded NoSQL operator differentials.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.ssrf", "Server-side request forgery", "Identify likely server-side request sinks from discovered input surfaces; active SSRF validation remains gated.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.csrf", "Cross-site request forgery", "Assess discovered state-changing forms for anti-CSRF protection signals.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.command_injection", "Command injection", "Identify likely command-execution sinks from discovered input surfaces; active execution remains gated.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.path_traversal", "Path traversal", "Test file/path parameters for traversal outside intended directories with a harmless marker.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.file_upload", "File upload", "Passively assess discovered upload validation signals without uploading files.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.xxe", "XXE", "Identify likely XML-processing surfaces; active entity testing remains gated.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.ssti", "Server-side template injection", "Test arithmetic-only template expressions for server-side evaluation signals.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.deserialization", "Deserialization", "Identify likely serialization/deserialization surfaces; active payload testing remains gated.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.cors", "CORS", "Test cross-origin policy and credential exposure.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.cache", "Web cache attacks", "Inspect cache policy and untrusted-input reflection signals without poisoning the cache.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.request_smuggling", "Request smuggling", "Inspect HTTP framing and proxy indicators without sending ambiguous parsing payloads.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.host_header", "Host header attacks", "Inspect whether an untrusted Host header influences redirects or response content.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.jwt", "JWT security", "Inspect discovered JWT-like tokens for unsafe algorithm signals without retaining token material.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.graphql", "GraphQL security", "Assess discovered GraphQL endpoints with bounded read-only introspection.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.websocket", "WebSocket security", "Discover WebSocket endpoints without connecting or sending messages.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.race_conditions", "Race conditions", "Test concurrent state transitions for timing-sensitive flaws.", ModuleDomain.WEB, active=True),
    ModuleSpec("web.business_logic", "Business logic", "Identify high-value workflow candidates without automatically changing application state.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.info_disclosure", "Information disclosure", "Check responses and interfaces for unintended sensitive data exposure.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.config", "Configuration security", "Check deployment and application configuration weaknesses.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.browser_runtime", "Browser runtime", "Use a real browser to execute JavaScript, observe rendered DOM, and capture runtime requests.", ModuleDomain.WEB, active=True, tool="playwright"),
    ModuleSpec("web.client_javascript", "Client-side JavaScript", "Inspect client-side JavaScript for attacker-controlled DOM sources and dangerous sinks.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.api", "API security", "Test discovered HTTP APIs, including authorization, input validation, and state transitions.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.openapi", "OpenAPI/Swagger", "Identify structured API specifications for deeper bounded API validation.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.open_redirect", "Open redirect", "Identify redirect-like parameters without sending external redirect probes.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.source_maps", "Source-map exposure", "Identify JavaScript source-map references that may expose development sources.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.sensitive_inputs", "Sensitive input inventory", "Identify sensitive-looking input names without retaining submitted values.", ModuleDomain.WEB, active=True, implemented=True),
    ModuleSpec("web.nmap", "Nmap security module", "Optional Nmap-backed service and web-facing vulnerability checks after web/AI testing.", ModuleDomain.WEB, stage=ModuleStage.SUPPLEMENTAL, active=True, implemented=True, tool="nmap"),
    ModuleSpec("ai.prompt_injection", "Prompt injection", "Execute a configured benign direct-injection canary against an AI surface.", ModuleDomain.AI, active=True, implemented=True, tool="playwright"),
    ModuleSpec("ai.indirect_prompt_injection", "Indirect prompt injection", "Test untrusted external content that can influence model instructions.", ModuleDomain.AI, active=True, implemented=True),
    ModuleSpec("ai.system_prompt", "System prompt leakage", "Test a configured protected system marker for unintended disclosure.", ModuleDomain.AI, active=True, implemented=True, tool="playwright"),
    ModuleSpec("ai.data_disclosure", "AI data disclosure", "Test a configured protected data marker for model-mediated disclosure.", ModuleDomain.AI, active=True, implemented=True, tool="playwright"),
    ModuleSpec("ai.output_handling", "Unsafe AI output handling", "Test whether model output becomes an unsafe downstream input.", ModuleDomain.AI, active=True, implemented=True, tool="playwright"),
    ModuleSpec("ai.tool_abuse", "AI tool abuse", "Identify model-controlled tool/action surfaces for authorization validation.", ModuleDomain.AI, active=True, implemented=True),
    ModuleSpec("ai.excessive_agency", "AI excessive agency", "Validate configured AI capability boundaries without executing prohibited actions.", ModuleDomain.AI, active=True),
    ModuleSpec("ai.rag", "RAG security", "Identify retrieval and grounding surfaces for authorization and trust validation.", ModuleDomain.AI, active=True, implemented=True),
    ModuleSpec("ai.vector", "Vector/embedding security", "Identify vector and embedding surfaces for isolation validation.", ModuleDomain.AI, active=True, implemented=True),
    ModuleSpec("ai.data_poisoning", "AI data poisoning", "Identify untrusted content sources that may feed AI context.", ModuleDomain.AI, active=True, implemented=True),
    ModuleSpec("ai.unbounded_consumption", "Unbounded consumption", "Inspect AI-capable surfaces for explicit resource controls.", ModuleDomain.AI, active=True, implemented=True),
    ModuleSpec("ai.multi_agent", "Multi-agent security", "Identify agent handoffs and delegated trust boundaries.", ModuleDomain.AI, active=True, implemented=True),
    ModuleSpec("ai.memory", "AI memory security", "Identify persistent AI memory and conversation-context surfaces for isolation validation.", ModuleDomain.AI, active=True, implemented=True),
    ModuleSpec("ai.identity", "AI identity boundary", "Identify user, tenant, role, and privilege context carried into AI flows.", ModuleDomain.AI, active=True, implemented=True),
    ModuleSpec("ai.goal_hijacking", "Goal hijacking", "Test whether untrusted inputs can redirect an agent's intended objective.", ModuleDomain.AI, active=True, implemented=True, tool="playwright"),
    ModuleSpec("ai.context_manipulation", "Context manipulation", "Test memory and contextual state for attacker-controlled influence.", ModuleDomain.AI, active=True, implemented=True, tool="playwright"),
    ModuleSpec("ai.trust_boundary", "AI/Web trust boundary", "Connect shared identifiers across AI and Web assets into bounded authorization follow-ups.", ModuleDomain.AI, active=True, implemented=True),
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

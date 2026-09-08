"""Security-module contracts and the initial passive web checks.

Phobos is a general web-security scanner for applications that expose AI
functionality. Individual security capabilities live behind a small common
module contract so the AI planner can reason about which checks to run without
owning low-level execution.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from models import Asset, Finding


@dataclass(frozen=True, slots=True)
class ModuleContext:
    """Shared read-only context supplied to security modules."""

    target: str
    assets: tuple[Asset, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


class SecurityModule(Protocol):
    """Minimal interface implemented by every Phobos security module."""

    id: str
    name: str
    description: str

    def can_run(self, context: ModuleContext) -> bool: ...
    def run(self, context: ModuleContext) -> tuple[Finding, ...]: ...


@dataclass(frozen=True, slots=True)
class ModuleSpec:
    id: str
    name: str
    description: str
    category: str
    active: bool = False


@dataclass(frozen=True, slots=True)
class PassiveSecurityModule:
    """Small deterministic module used by the scanner without active probing."""

    id: str
    name: str
    description: str
    category: str
    runner: Any

    def can_run(self, context: ModuleContext) -> bool:
        return True

    def run(self, context: ModuleContext) -> tuple[Finding, ...]:
        findings = self.runner(context)
        return tuple(findings)


MODULE_CATALOG: tuple[ModuleSpec, ...] = (
    ModuleSpec("web.headers", "Security headers", "Inspect response security headers and policy gaps.", "web"),
    ModuleSpec("web.cookies", "Cookie security", "Inspect cookie attributes such as Secure, HttpOnly, and SameSite.", "web"),
    ModuleSpec("web.exposure", "Common exposure checks", "Look for common publicly exposed files and endpoints.", "web"),
    ModuleSpec("web.methods", "HTTP method review", "Identify unusual or risky HTTP method exposure for discovered endpoints.", "web", active=True),
    ModuleSpec("web.params", "Parameter analysis", "Prioritize discovered parameters for deeper validation.", "web"),
    ModuleSpec("web.auth", "Authentication checks", "Assess authentication boundaries and session behavior.", "web", active=True),
    ModuleSpec("web.access_control", "Access control checks", "Test whether security-sensitive resources cross authorization boundaries.", "web", active=True),
    ModuleSpec("web.injection", "Injection checks", "Run appropriate input-validation procedures against discovered parameters.", "web", active=True),
    ModuleSpec("web.xss", "Cross-site scripting", "Assess reflected, stored, and DOM-related XSS surfaces.", "web", active=True),
    ModuleSpec("web.sqli", "SQL injection", "Assess database-backed parameters for SQL injection conditions.", "web", active=True),
    ModuleSpec("web.ssrf", "SSRF", "Assess server-side request features and trust-boundary crossings.", "web", active=True),
    ModuleSpec("web.uploads", "File upload security", "Assess upload handling and unsafe file-processing behavior.", "web", active=True),
    ModuleSpec("web.config", "Configuration exposure", "Inspect deployment and application configuration weaknesses.", "web"),
    ModuleSpec("ai.surface", "AI surface mapping", "Identify AI interfaces, providers, agents, and AI-oriented inputs.", "ai"),
    ModuleSpec("ai.prompt_injection", "Prompt injection", "Assess direct and indirect prompt-injection paths.", "ai", active=True),
    ModuleSpec("ai.data_disclosure", "AI data disclosure", "Assess model-mediated sensitive information disclosure.", "ai", active=True),
    ModuleSpec("ai.tool_abuse", "AI tool abuse", "Assess model-controlled tool and action boundaries.", "ai", active=True),
    ModuleSpec("ai.excessive_agency", "AI excessive agency", "Assess whether AI functionality can perform unintended privileged actions.", "ai", active=True),
    ModuleSpec("network.nmap", "Nmap", "Optional host/service discovery for supporting target context.", "network"),
)


def module_specs() -> tuple[ModuleSpec, ...]:
    """Return the immutable catalog exposed to the orchestration layer."""
    return MODULE_CATALOG


def module_index() -> dict[str, ModuleSpec]:
    """Return module definitions indexed by stable module ID."""
    return {item.id: item for item in MODULE_CATALOG}

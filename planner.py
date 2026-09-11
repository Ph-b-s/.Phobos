"""Bounded AI-assisted scan planning with deterministic guardrails."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable

from ai import AIError, LocalMistralClient
from security_modules import module_index

MAX_ITERATIONS = 5
MAX_NEW_MODULES_PER_ITERATION = 8


@dataclass(frozen=True, slots=True)
class PlannerDecision:
    action: str
    modules: tuple[str, ...]
    reason: str
    iteration: int

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "modules": list(self.modules), "reason": self.reason, "iteration": self.iteration}


class ScanPlanner:
    """Use the local model only for bounded module selection."""

    def __init__(self, client: LocalMistralClient, *, max_iterations: int = MAX_ITERATIONS):
        if not 1 <= max_iterations <= MAX_ITERATIONS:
            raise ValueError(f"max_iterations must be between 1 and {MAX_ITERATIONS}")
        self.client = client
        self.max_iterations = max_iterations

    def next_decision(
        self,
        *,
        target: str,
        iteration: int,
        completed_modules: Iterable[str],
        knowledge: dict[str, Any],
        graph_analysis: dict[str, Any] | None = None,
        eligible_modules: Iterable[str] | None = None,
    ) -> PlannerDecision:
        if iteration > self.max_iterations:
            return PlannerDecision("refuse", (), "planner iteration limit reached", iteration)
        completed = {item for item in completed_modules}
        allowed = set(eligible_modules or (item.id for item in module_index().values()))
        executable = {
            item.id: item
            for item in module_index().values()
            if item.implemented and item.active and item.id not in completed and item.id in allowed
        }
        context = {
            "target": target,
            "iteration": iteration,
            "completed_modules": sorted(completed),
            "available_executable_modules": sorted(executable),
            "knowledge": knowledge,
            "graph_analysis": graph_analysis or {},
        }
        try:
            decision = self.client.plan(json.dumps(context, ensure_ascii=False))
        except AIError as exc:
            return PlannerDecision("refuse", (), f"AI planning unavailable: {exc}", iteration)
        modules = tuple(item for item in decision.get("modules", ()) if item in executable)
        modules = modules[:MAX_NEW_MODULES_PER_ITERATION]
        if not modules:
            return PlannerDecision("refuse", (), decision.get("reason", "no new executable module selected"), iteration)
        return PlannerDecision("plan_scan", modules, decision.get("reason", ""), iteration)

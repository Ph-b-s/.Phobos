"""Deterministic scan summarization.

The summarizer does not invent risk. It aggregates evidence already produced by
Phobos and keeps severity and confidence separate.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from cross_layer import CrossLayerAnalysis
from models import Finding
from scanner import ScanResult


@dataclass(frozen=True, slots=True)
class ScanSummary:
    target: str
    pages: int
    endpoints: int
    inputs: int
    ai_surfaces: int
    modules_completed: int
    modules_failed: int
    findings: int
    severity_counts: dict[str, int]
    confidence_counts: dict[str, int]
    attack_paths: int
    correlations: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "pages": self.pages,
            "endpoints": self.endpoints,
            "inputs": self.inputs,
            "ai_surfaces": self.ai_surfaces,
            "modules_completed": self.modules_completed,
            "modules_failed": self.modules_failed,
            "findings": self.findings,
            "severity_counts": dict(self.severity_counts),
            "confidence_counts": dict(self.confidence_counts),
            "attack_paths": self.attack_paths,
            "correlations": self.correlations,
        }


def _confidence_band(value: float) -> str:
    if value >= 0.90:
        return "high"
    if value >= 0.70:
        return "medium"
    return "low"


def summarize_scan(scan: ScanResult, *, analysis: CrossLayerAnalysis) -> ScanSummary:
    assets = scan.assets
    severity = Counter(str(item.metadata.get("severity", "unspecified")) for item in scan.findings)
    confidence = Counter(_confidence_band(item.confidence) for item in scan.findings)
    return ScanSummary(
        target=scan.target,
        pages=sum(1 for item in assets if item.type.value == "page"),
        endpoints=sum(1 for item in assets if item.type.value == "endpoint"),
        inputs=sum(1 for item in assets if item.type.value == "input"),
        ai_surfaces=sum(1 for item in assets if item.type.value == "ai_agent"),
        modules_completed=len(scan.modules_run),
        modules_failed=len(scan.errors),
        findings=len(scan.findings),
        severity_counts=dict(sorted(severity.items())),
        confidence_counts=dict(sorted(confidence.items())),
        attack_paths=len(analysis.attack_paths),
        correlations=len(analysis.correlations),
    )


def finding_title(finding: Finding) -> str:
    return finding.type.replace("_", " ").strip().title()

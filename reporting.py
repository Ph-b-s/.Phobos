"""Human-readable Markdown reporting for completed Phobos assessments."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from cross_layer import CrossLayerAnalysis
from scanner import ScanResult
from summarizer import ScanSummary, finding_title


def _md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def render_markdown(scan: ScanResult, summary: ScanSummary, analysis: CrossLayerAnalysis) -> str:
    lines = [
        "# Phobos Security Assessment",
        "",
        f"**Target:** `{_md(scan.target)}`",
        "",
        "## Executive summary",
        "",
        f"Phobos discovered **{summary.pages} pages**, **{summary.endpoints} endpoints**, and **{summary.inputs} inputs**. "
        f"The run completed **{summary.modules_completed} modules** and recorded **{summary.findings} findings**.",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| AI surfaces | {summary.ai_surfaces} |",
        f"| Attack paths | {summary.attack_paths} |",
        f"| Correlations | {summary.correlations} |",
        f"| Module errors | {summary.modules_failed} |",
        "",
        "## Findings",
        "",
    ]
    if not scan.findings:
        lines.append("No findings were recorded.")
    else:
        lines.extend([
            "| Finding | Severity | Confidence | Evidence |",
            "|---|---|---:|---:|",
        ])
        for finding in scan.findings:
            severity = str(finding.metadata.get("severity", "unspecified"))
            lines.append(
                f"| {_md(finding_title(finding))} | {_md(severity)} | {finding.confidence:.2f} | {len(finding.evidence)} |"
            )
        lines.append("")
        for finding in scan.findings:
            lines.extend([
                f"### {finding_title(finding)}",
                "",
                f"- Type: `{_md(finding.type)}`",
                f"- Confidence: `{finding.confidence:.2f}`",
                f"- Evidence references: `{len(finding.evidence)}`",
            ])
            if finding.metadata:
                lines.append(f"- Metadata: `{_md(finding.metadata)}`")
            lines.append("")

    lines.extend(["## Cross-layer attack paths", ""])
    if not analysis.attack_paths:
        lines.append("No cross-layer attack paths were correlated.")
    else:
        for path in analysis.attack_paths:
            lines.extend([
                f"### `{_md(path.id)}` — {_md(path.pattern)}",
                "",
                f"Confidence: **{path.confidence:.2f}**",
                "",
                _md(path.rationale),
                "",
                "```text",
                " → ".join(path.nodes),
                "```",
                "",
            ])

    lines.extend([
        "## Validation and limitations",
        "",
        "Phobos separates severity from confidence. Correlation is not confirmation.",
        "State-changing validation is disabled unless both explicit safety gates are supplied.",
        "",
        "## Reproduction artifacts",
        "",
        "The `.phobos/` directory contains structured scan, graph, knowledge, module-run, finding, and report artifacts.",
        "",
    ])
    return "\n".join(lines)


def write_markdown(path: Path | str, content: str) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(destination)
    return destination

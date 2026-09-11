"""Phobos command-line entry point."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from account_manager import AccountManager
from ai import AIConfig, AIError, LocalMistralClient
from browser_adapter import BrowserAdapterError, BrowserLimits, PlaywrightBrowserSession
from browser_interaction import BrowserInteractor
from config import DEFAULT_USER_AGENT, PHOBOS_VERSION, ScanConfig
from crawler import ReconCrawler
from cross_application import discover_related_applications, merge_applications_into_graph
from cross_layer import analyze_cross_layer
from evidence import EvidenceStore
from graph import Graph
from knowledge_store import KnowledgeStore, SecurityObservation
from models import Asset, AssetType
from planner import ScanPlanner
from reporting import render_markdown, write_markdown
from request_manager import RequestManager
from scanner import ModuleSelection, ScanPlan, build_planner_context, default_module_selection, execute_plan, merge_module_selections, validate_plan
from security_modules import module_index
from scope import ScopeValidator
from workflow_engine import WorkflowEngine, register_standard_actions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phobos", description="Phobos — AI-assisted security scanner for AI-enabled web applications.")
    parser.add_argument("--version", action="version", version=f"Phobos {PHOBOS_VERSION}")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="discover and assess a scoped application")
    scan.add_argument("target")
    scan.add_argument("--scope", action="append", dest="scopes", metavar="DOMAIN")
    scan.add_argument("--output", default=".phobos")
    scan.add_argument("--timeout", type=float, default=10.0)
    scan.add_argument("--max-pages", type=int, default=100)
    scan.add_argument("--max-discovered-urls", type=int, default=5_000)
    scan.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    scan.add_argument("--allow-private-targets", action="store_true")
    scan.add_argument("--browser", action="store_true", help="enable Playwright dynamic reconnaissance")
    scan.add_argument("--browser-name", choices=("chromium", "firefox", "webkit"), default="chromium")
    scan.add_argument("--browser-max-requests", type=int, default=2_000)
    scan.add_argument("--nmap", action="store_true", help="enable optional Nmap module")
    scan.add_argument("--module", action="append", dest="modules", metavar="MODULE_ID")
    scan.add_argument("--no-default-modules", action="store_true")
    scan.add_argument("--ai", action="store_true", help="enable iterative local-Mistral planning")
    scan.add_argument("--max-iterations", type=int, default=3)
    scan.add_argument("--indirect-config", metavar="PATH", help="JSON config for the controlled indirect-injection procedure")
    scan.add_argument("--allow-state-change", action="store_true", help="allow explicitly configured state-changing validation")
    scan.add_argument("--confirm-high-risk", action="store_true", help="second human-approval gate for state-changing validation")
    scan.add_argument("--no-report", action="store_true", help="skip Markdown report generation")
    agent = sub.add_parser("ai", help="ask the local Mistral security planner for a module plan")
    agent.add_argument("request", nargs="+")
    agent.add_argument("--target", required=True)
    agent.add_argument("--scope", action="append", dest="scopes", metavar="DOMAIN")
    agent.add_argument("--allow-private-targets", action="store_true")
    modules = sub.add_parser("modules", help="list the vulnerability-module catalog")
    modules.add_argument("--json", action="store_true")
    doctor = sub.add_parser("doctor", help="check the local Phobos environment")
    doctor.add_argument("--quiet", action="store_true")
    return parser


def _target_url(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("target must not be empty")
    return value if "://" in value else f"https://{value}"


def _load_indirect_config(path: str | None) -> dict[str, object] | None:
    if not path:
        return None
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("indirect-config must contain a JSON object")
    return payload


def run_modules(args: argparse.Namespace) -> int:
    rows = [{"id": item.id, "name": item.name, "domain": item.domain.value, "stage": item.stage.value,
             "active": item.active, "implemented": item.implemented, "tool": item.tool, "description": item.description}
            for item in module_index().values()]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print("[PHOBOS] Vulnerability module catalog")
    for row in rows:
        state = "implemented" if row["implemented"] else "planned"
        tool = f", tool={row['tool']}" if row["tool"] else ""
        print(f"- {row['id']}: {row['name']} [{row['domain']}/{row['stage']}, {state}{tool}] — {row['description']}")
    return 0


def _runtime_available(config: AIConfig) -> bool:
    from urllib.error import URLError
    from urllib.request import Request, urlopen
    try:
        with urlopen(Request(config.base_url.rsplit("/api/", 1)[0] + "/api/version", method="GET"), timeout=2.0):
            return True
    except (OSError, URLError):
        return False


def run_doctor(args: argparse.Namespace) -> int:
    checks: list[tuple[str, bool, str]] = [("Python >= 3.11", sys.version_info >= (3, 11), ".".join(map(str, sys.version_info[:3])))]
    try:
        config = AIConfig.from_env()
        runtime = _runtime_available(config)
        checks.extend([("AI backend", True, "local Mistral"), ("AI endpoint", True, config.base_url),
                       ("AI model", True, config.model), ("AI runtime", runtime,
                        "running" if runtime else "not running; Phobos can start it when needed")])
    except AIError as exc:
        checks.append(("AI configuration", False, str(exc)))
    ok = all(result for _, result, _ in checks)
    if not args.quiet:
        print("[PHOBOS] Environment diagnostics")
        for label, passed, detail in checks:
            print(f"{'✓' if passed else '✗'} {label}: {detail}")
        print("\n✓ Environment looks ready." if ok else "\n✗ Environment is not ready.")
    return 0 if ok else 1


def _seed_recon_observations(store: KnowledgeStore, assets: tuple[Asset, ...], recon) -> None:
    store.add_assets(assets)
    for asset in assets:
        if asset.type in {AssetType.ENDPOINT, AssetType.API, AssetType.FORM, AssetType.INPUT, AssetType.JAVASCRIPT, AssetType.PAGE}:
            store.add_observation(SecurityObservation(
                id=f"recon.web:{asset.id}", kind=f"recon.web.{asset.type.value}", source="recon.web",
                description=f"Web reconnaissance discovered {asset.type.value}: {asset.name}", asset_ids=(asset.id,),
                data={"url": asset.url, "confidence": asset.confidence}, confidence=asset.confidence))
    for asset in recon.ai_surfaces:
        store.add_observation(SecurityObservation(
            id=f"recon.ai:{asset.id}", kind="recon.ai_surface", source="recon.ai",
            description=f"Passive reconnaissance identified a likely AI surface: {asset.name}", asset_ids=(asset.id,),
            data={"url": asset.url, "confidence": asset.confidence}, confidence=asset.confidence))


def _initial_plan(args: argparse.Namespace, indirect_config: dict[str, object] | None) -> ScanPlan:
    if args.no_default_modules:
        plan = ScanPlan((), source="cli")
    elif args.ai:
        plan = ScanPlan(tuple(ModuleSelection(module_id, reason) for module_id, reason in (
            ("web.headers", "baseline web hardening"), ("web.cookies", "session security baseline"),
            ("web.exposure", "common exposure checks"), ("web.methods", "review discovered HTTP methods"),
            ("web.config", "common configuration exposure"), ("web.cors", "CORS policy baseline"))), source="ai-seeded")
    else:
        plan = default_module_selection(include_nmap=args.nmap, include_indirect_ai=indirect_config is not None)
    explicit = [ModuleSelection(item, "explicit CLI selection") for item in (args.modules or ())]
    return validate_plan(merge_module_selections(plan, explicit, source=plan.source))


def run_scan(args: argparse.Namespace) -> int:
    target = _target_url(args.target)
    config = ScanConfig.from_cli(target, tuple(args.scopes or ()), args.output, timeout=args.timeout,
                                 max_pages=args.max_pages, max_discovered_urls=args.max_discovered_urls,
                                 user_agent=args.user_agent, allow_private_targets=args.allow_private_targets)
    scope = ScopeValidator(config.normalized_scopes, allow_private_targets=config.allow_private_targets)
    manager = RequestManager(scope, timeout=config.timeout, max_redirects=config.max_redirects,
                             user_agent=config.user_agent, max_response_bytes=config.max_response_bytes)
    output = EvidenceStore(config.output_dir)
    output.initialize()
    graph = Graph()
    website = Asset("website_001", AssetType.WEBSITE, config.target, config.target, metadata={"scopes": list(scope.allowed_domains)})
    graph.add_node(id=website.id, type=website.type.value, label=website.name, attributes=website.metadata)
    browser: PlaywrightBrowserSession | None = None
    indirect_config = _load_indirect_config(args.indirect_config)
    allow_state_change = bool(args.allow_state_change and args.confirm_high_risk)
    if args.allow_state_change and not args.confirm_high_risk:
        print("[PHOBOS] State-changing validation requested without --confirm-high-risk; validation remains disabled.")

    print("[PHOBOS] Starting scan")
    print(f"  Target: {config.target}")
    print(f"  Scope:  {', '.join(scope.allowed_domains)}")
    print(f"  Web runtime: {'browser/JavaScript' if args.browser else 'static HTTP'}")
    if args.ai:
        print(f"  AI planning: enabled ({args.max_iterations} iterations max)")

    try:
        if args.browser:
            browser = PlaywrightBrowserSession(scope, limits=BrowserLimits(
                max_requests=args.browser_max_requests, navigation_timeout_ms=int(config.timeout * 1000)),
                browser_name=args.browser_name, user_agent=config.user_agent)
        recon = ReconCrawler(manager, max_pages=config.max_pages, max_discovered_urls=config.max_discovered_urls,
                             browser=browser).crawl(config.target, graph=graph)
        assets = (website, *recon.assets)
        related = discover_related_applications(
            config.target, links=tuple(dict.fromkeys(asset.url for asset in assets if asset.url)),
            pages=tuple({"url": page.url, "text": page.name} for page in recon.pages[:100]), same_registrable_domain=False)
        supporting_assets = merge_applications_into_graph(graph, website.id, related)
        if supporting_assets:
            assets = (*assets, *supporting_assets)

        knowledge = KnowledgeStore()
        _seed_recon_observations(knowledge, assets, recon)
        capabilities = {
            "browser": browser,
            "interactor": BrowserInteractor(browser) if browser is not None else None,
            "accounts": AccountManager(),
            "workflow": register_standard_actions(WorkflowEngine()),
            "applications": related,
            "metadata": {"scope": scope, "request_manager": manager,
                         "indirect_prompt_injection": indirect_config or {}, "allow_state_change": allow_state_change},
        }
        eligible_ai_modules = {item.id for item in module_index().values() if item.active and item.implemented}
        if not args.nmap:
            eligible_ai_modules.discard("web.nmap")
        if indirect_config is None:
            eligible_ai_modules.discard("ai.indirect_prompt_injection")

        plan = _initial_plan(args, indirect_config)
        completed: set[str] = set()
        final_scan = None
        planner = ScanPlanner(LocalMistralClient(AIConfig.from_env()), max_iterations=args.max_iterations) if args.ai else None
        wave = plan
        for iteration in range(1, args.max_iterations + 1):
            pending = tuple(item for item in wave.selections if item.module_id not in completed)
            if not pending:
                if planner is None:
                    break
                analysis = analyze_cross_layer(graph, knowledge)
                decision = planner.next_decision(
                    target=config.target, iteration=iteration, completed_modules=completed,
                    knowledge=json.loads(build_planner_context(config.target, knowledge, completed_modules=completed,
                                                               iteration=iteration, eligible_modules=eligible_ai_modules)),
                    graph_analysis=analysis.to_dict(), eligible_modules=eligible_ai_modules)
                if not decision.modules:
                    break
                wave = ScanPlan(tuple(ModuleSelection(mid, decision.reason) for mid in decision.modules), source="ai")
                pending = wave.selections
            final_scan = execute_plan(config.target, assets, ScanPlan(pending, source=wave.source), knowledge=knowledge,
                                      graph=graph, metadata={"browser_enabled": args.browser, "iteration": iteration,
                                      "allow_state_change": allow_state_change}, capabilities=capabilities)
            completed.update(final_scan.modules_run)
            print(f"[PHOBOS] Iteration {iteration}: {len(final_scan.modules_run)} modules completed")
            if planner is None or iteration >= args.max_iterations:
                break
            analysis = analyze_cross_layer(graph, knowledge)
            planner_context = json.loads(build_planner_context(config.target, knowledge, completed_modules=completed,
                                                                iteration=iteration + 1, eligible_modules=eligible_ai_modules))
            decision = planner.next_decision(target=config.target, iteration=iteration + 1, completed_modules=completed,
                                            knowledge=planner_context, graph_analysis=analysis.to_dict(), eligible_modules=eligible_ai_modules)
            if not decision.modules:
                break
            print(f"[PHOBOS AI] {decision.reason}")
            wave = ScanPlan(tuple(ModuleSelection(mid, decision.reason) for mid in decision.modules), source="ai")
        if final_scan is None:
            final_scan = execute_plan(config.target, assets, plan, knowledge=knowledge, graph=graph, capabilities=capabilities)
        analysis = analyze_cross_layer(graph, final_scan.knowledge)
    except (BrowserAdapterError, AIError, ValueError, RuntimeError, TypeError, OSError) as exc:
        output.write_json("scan.json", {"schema_version": "1.0", "target": config.target, "status": "failed", "error": str(exc)})
        output.write_json("graph.json", graph.to_dict())
        print(f"✗ Scan stopped: {exc}", file=sys.stderr)
        return 2
    finally:
        if browser is not None:
            browser.close()

    from summarizer import summarize_scan
    summary = summarize_scan(final_scan, analysis=analysis)
    output.write_json("scan.json", {"schema_version": "1.0", "target": config.target, "scopes": list(scope.allowed_domains),
        "status": "assessment_complete", "summary": summary.to_dict(),
        "plan": {"source": plan.source, "modules": [item.module_id for item in plan.selections]}})
    output.write_json("assets.json", [item.to_dict() for item in final_scan.assets])
    output.write_json("graph.json", graph.to_dict())
    output.write_json("cross_layer.json", analysis.to_dict())
    output.write_json("module_run.json", final_scan.module_run.to_dict() if final_scan.module_run else {})
    output.write_json("knowledge.json", final_scan.knowledge.to_dict() if final_scan.knowledge else {})
    output.write_json("findings.json", [item.to_dict() for item in final_scan.findings])
    output.write_json("cross_applications.json", [item.to_dict() for item in related])
    output.write_json("browser_observations.json", [{"kind": getattr(item, "kind", ""), "description": getattr(item, "description", ""),
        "source": getattr(item, "source", ""), "metadata": getattr(item, "metadata", {})} for item in recon.browser_observations])
    if not args.no_report:
        write_markdown(config.output_dir / "report.md", render_markdown(final_scan, summary, analysis))

    print(f"✓ {summary.pages} pages discovered")
    print(f"✓ {summary.endpoints} endpoints discovered")
    print(f"✓ {summary.inputs} inputs discovered")
    print(f"✓ {summary.ai_surfaces} AI signals discovered")
    print(f"✓ {summary.attack_paths} cross-layer attack paths correlated")
    print(f"✓ {summary.modules_completed} modules completed")
    print(f"✓ {summary.findings} findings recorded")
    print(f"\nResults saved to {config.output_dir}")
    return 0


def run_ai(args: argparse.Namespace) -> int:
    target = _target_url(args.target)
    parsed = urlparse(target)
    scopes = tuple(args.scopes or (parsed.hostname or "",))
    scope = ScopeValidator(scopes, allow_private_targets=args.allow_private_targets)
    try:
        validated = scope.validate(target)
        request = " ".join(args.request).strip()
        decision = LocalMistralClient(AIConfig.from_env()).plan(f"Target: {validated}\nRequest: {request}")
        print(json.dumps(decision, indent=2))
        return 0
    except (AIError, ValueError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan": return run_scan(args)
    if args.command == "ai": return run_ai(args)
    if args.command == "modules": return run_modules(args)
    if args.command == "doctor": return run_doctor(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

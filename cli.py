"""Phobos command-line entry point."""
from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import urlparse

from ai import AIConfig, AIError, VeniceClient
from browser_adapter import BrowserAdapterError, BrowserLimits, PlaywrightBrowserSession
from config import DEFAULT_USER_AGENT, PHOBOS_VERSION, ScanConfig
from crawler import ReconCrawler
from evidence import EvidenceStore
from graph import Graph
from models import Asset, AssetType
from request_manager import RequestError, RequestManager
from scanner import ModuleSelection, ScanPlan, default_module_selection, merge_module_selections, validate_plan
from security_modules import module_index
from scope import ScopeValidator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phobos",
        description="Phobos — AI-assisted web security scanner for AI-enabled applications.",
    )
    parser.add_argument("--version", action="version", version=f"Phobos {PHOBOS_VERSION}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="discover and assess a scoped AI-enabled web application")
    scan.add_argument("target", help="absolute HTTP(S) target URL")
    scan.add_argument("--scope", action="append", dest="scopes", metavar="DOMAIN")
    scan.add_argument("--output", default=".phobos")
    scan.add_argument("--timeout", type=float, default=10.0)
    scan.add_argument("--max-pages", type=int, default=100)
    scan.add_argument("--max-discovered-urls", type=int, default=5_000)
    scan.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    scan.add_argument("--allow-private-targets", action="store_true")
    scan.add_argument("--browser", action="store_true", help="enable Playwright for JavaScript execution and dynamic Web reconnaissance")
    scan.add_argument("--browser-name", choices=("chromium", "firefox", "webkit"), default="chromium")
    scan.add_argument("--browser-max-requests", type=int, default=2_000)
    scan.add_argument("--nmap", action="store_true", help="enable the optional Nmap web-security module after the main assessment")
    scan.add_argument("--module", action="append", dest="modules", metavar="MODULE_ID", help="add a security module (repeatable)")
    scan.add_argument("--no-default-modules", action="store_true", help="disable the default baseline module plan")
    scan.add_argument("--ai", action="store_true", help="use the Phobos AI planner to prioritize additional modules")

    agent = sub.add_parser("ai", help="ask the Phobos AI planner for a security-module plan")
    agent.add_argument("request", nargs="+", help="security-planning request")
    agent.add_argument("--target", required=True, help="explicit HTTP(S) target")
    agent.add_argument("--scope", action="append", dest="scopes", metavar="DOMAIN")
    agent.add_argument("--allow-private-targets", action="store_true")

    modules = sub.add_parser("modules", help="list the Phobos vulnerability-module catalog")
    modules.add_argument("--json", action="store_true")

    doctor = sub.add_parser("doctor", help="check the local Phobos environment")
    doctor.add_argument("--quiet", action="store_true", help="only return the diagnostic exit code")
    return parser


def _target_url(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("target must not be empty")
    return value if "://" in value else f"https://{value}"


def run_modules(args: argparse.Namespace) -> int:
    rows = [
        {
            "id": item.id,
            "name": item.name,
            "domain": item.domain.value,
            "stage": item.stage.value,
            "active": item.active,
            "implemented": item.implemented,
            "tool": item.tool,
            "description": item.description,
        }
        for item in module_index().values()
    ]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print("[PHOBOS] Vulnerability module catalog")
    for row in rows:
        state = "implemented" if row["implemented"] else "planned"
        tool = f", tool={row['tool']}" if row["tool"] else ""
        print(f"- {row['id']}: {row['name']} [{row['domain']}/{row['stage']}, {state}{tool}] — {row['description']}")
    return 0


def run_doctor(args: argparse.Namespace) -> int:
    checks: list[tuple[str, bool, str]] = []
    checks.append(("Python >= 3.11", sys.version_info >= (3, 11), _python_version()))
    api_key_set = bool(os.environ.get("VENICE_API_KEY", "").strip())
    checks.append(("VENICE_API_KEY set", api_key_set, "set" if api_key_set else "missing"))
    try:
        config = AIConfig.from_env()
        checks.append(("AI endpoint uses HTTPS", True, config.base_url))
        checks.append(("AI model configured", True, config.model))
    except AIError as exc:
        checks.append(("AI configuration", False, str(exc)))
    ok = all(result for _, result, _ in checks)
    if not args.quiet:
        print("[PHOBOS] Environment diagnostics")
        for label, passed, detail in checks:
            print(f"{'✓' if passed else '✗'} {label}: {detail}")
        print("\n✓ Environment looks ready." if ok else "\n✗ Environment is not ready.")
    return 0 if ok else 1


def _python_version() -> str:
    return ".".join(str(part) for part in sys.version_info[:3])


def _build_plan(args: argparse.Namespace, context: str) -> ScanPlan:
    plan = ScanPlan((), source="cli") if args.no_default_modules else default_module_selection(include_nmap=args.nmap)
    additions = [ModuleSelection(module_id, "explicit CLI selection") for module_id in (args.modules or ())]

    if args.ai:
        decision = VeniceClient(AIConfig.from_env()).plan(context)
        print(f"[PHOBOS AI] {decision['reason']}")
        additions.extend(ModuleSelection(module_id, "selected by Phobos AI") for module_id in decision["modules"])
        return validate_plan(merge_module_selections(plan, additions, source="ai"))

    return validate_plan(merge_module_selections(plan, additions, source=plan.source))


def run_scan(args: argparse.Namespace) -> int:
    config = ScanConfig.from_cli(_target_url(args.target), tuple(args.scopes or ()), args.output, timeout=args.timeout, max_pages=args.max_pages, max_discovered_urls=args.max_discovered_urls, user_agent=args.user_agent, allow_private_targets=args.allow_private_targets)
    scope = ScopeValidator(config.normalized_scopes, allow_private_targets=config.allow_private_targets)
    manager = RequestManager(scope, timeout=config.timeout, max_redirects=config.max_redirects, user_agent=config.user_agent, max_response_bytes=config.max_response_bytes)
    store = EvidenceStore(config.output_dir)
    graph = Graph()
    website = Asset("website_001", AssetType.WEBSITE, config.target, config.target, metadata={"scopes": list(scope.allowed_domains)})
    graph.add_node(id=website.id, type=website.type.value, label=website.name, attributes=website.metadata)
    browser: PlaywrightBrowserSession | None = None

    print("[PHOBOS] Starting scan")
    print(f"  Target: {config.target}")
    print(f"  Scope:  {', '.join(scope.allowed_domains)}")
    print(f"  Web runtime: {'browser/JavaScript' if args.browser else 'static HTTP'}")

    try:
        if args.browser:
            browser = PlaywrightBrowserSession(
                scope,
                limits=BrowserLimits(max_requests=args.browser_max_requests, navigation_timeout_ms=int(config.timeout * 1000)),
                browser_name=args.browser_name,
                user_agent=config.user_agent,
            )
        recon = ReconCrawler(
            manager,
            max_pages=config.max_pages,
            max_discovered_urls=config.max_discovered_urls,
            browser=browser,
        ).crawl(config.target, graph=graph)
        for page in recon.pages:
            graph.add_edge(source=website.id, target=page.id, relationship="hosts")
        assets = (website, *recon.assets)
        context = json.dumps({"target": config.target, "assets": [asset.to_dict() for asset in assets[:500]]}, ensure_ascii=False)
        plan = _build_plan(args, context)
    except (RequestError, AIError, BrowserAdapterError, ValueError) as exc:
        store.write_json("scan.json", {"schema_version": "1.0", "target": config.target, "status": "failed", "error": str(exc)})
        store.write_json("graph.json", graph.to_dict())
        print(f"✗ Scan stopped: {exc}", file=sys.stderr)
        return 2
    finally:
        if browser is not None:
            browser.close()

    store.write_json("scan.json", {
        "schema_version": "1.0",
        "target": config.target,
        "scopes": list(scope.allowed_domains),
        "status": "recon_complete",
        "summary": {
            "pages": len(recon.pages),
            "forms": len(recon.forms),
            "inputs": len(recon.inputs),
            "endpoints": len(recon.endpoints),
            "javascript_files": len(recon.javascript),
            "ai_surfaces": len(recon.ai_surfaces),
            "browser_observations": len(recon.browser_observations),
            "errors": len(recon.errors),
        },
        "plan": {
            "source": plan.source,
            "modules": [item.module_id for item in plan.selections],
        },
    })
    store.write_json("assets.json", [asset.to_dict() for asset in assets])
    store.write_json("graph.json", graph.to_dict())
    store.write_json("browser_observations.json", [
        {
            "kind": getattr(item, "kind", ""),
            "description": getattr(item, "description", ""),
            "source": getattr(item, "source", ""),
            "metadata": getattr(item, "metadata", {}),
        }
        for item in recon.browser_observations
    ])
    store.write_json("findings.json", [])

    print(f"✓ {len(recon.pages)} pages discovered")
    print(f"✓ {len(recon.endpoints)} endpoints discovered")
    print(f"✓ {len(recon.inputs)} inputs discovered")
    print(f"✓ {len(recon.javascript)} JavaScript assets discovered")
    print(f"✓ {len(recon.ai_surfaces)} AI signals discovered")
    if args.browser:
        print(f"✓ {len(recon.browser_observations)} browser observations captured")
    print("\nPlanned security coverage:")
    for item in plan.selections:
        print(f"  • {item.module_id} — {item.reason}")
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
        decision = VeniceClient(AIConfig.from_env()).plan(f"Target: {validated}\nRequest: {request}")
        print(json.dumps(decision, indent=2))
        return 0
    except (AIError, ValueError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "ai":
        return run_ai(args)
    if args.command == "modules":
        return run_modules(args)
    if args.command == "doctor":
        return run_doctor(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
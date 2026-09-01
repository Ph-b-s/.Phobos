"""Phobos command-line entry point."""
from __future__ import annotations

import argparse
import os
import sys
from urllib.parse import urlparse

from ai import AIConfig, AIError, VeniceClient
from config import ScanConfig
from crawler import ReconCrawler
from evidence import EvidenceStore
from graph import Graph
from models import Asset, AssetType
from request_manager import RequestError, RequestManager
from scope import ScopeValidator

PHOBOS_VERSION = "0.2.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phobos",
        description="Phobos — scoped web and AI security reconnaissance.",
    )
    parser.add_argument("--version", action="version", version=f"Phobos {PHOBOS_VERSION}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run scoped passive web reconnaissance")
    scan.add_argument("target", help="absolute HTTP(S) target URL")
    scan.add_argument("--scope", action="append", dest="scopes", metavar="DOMAIN")
    scan.add_argument("--output", default=".phobos")
    scan.add_argument("--timeout", type=float, default=10.0)
    scan.add_argument("--max-pages", type=int, default=100)
    scan.add_argument("--max-discovered-urls", type=int, default=5_000)
    scan.add_argument("--user-agent", default="Phobos/0.2")
    scan.add_argument("--allow-private-targets", action="store_true")

    agent = sub.add_parser(
        "ai",
        help="use Venice Uncensored to select a predefined web-security reconnaissance action",
    )
    agent.add_argument("request", nargs="+", help="natural-language security request")
    agent.add_argument("--target", required=True, help="explicit HTTP(S) target; the AI cannot change it")
    agent.add_argument("--scope", action="append", dest="scopes", metavar="DOMAIN")
    agent.add_argument("--output", default=".phobos")
    agent.add_argument("--timeout", type=float, default=10.0)
    agent.add_argument("--max-pages", type=int, default=100)
    agent.add_argument("--max-discovered-urls", type=int, default=5_000)
    agent.add_argument("--user-agent", default="Phobos/0.2")
    agent.add_argument("--dry-run", action="store_true", help="plan only; do not send web requests")
    agent.add_argument("--allow-private-targets", action="store_true")

    doctor = sub.add_parser("doctor", help="check the local Phobos environment")
    doctor.add_argument("--quiet", action="store_true", help="only return the diagnostic exit code")

    return parser


def _target_url(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("target must not be empty")
    return value if "://" in value else f"https://{value}"


def run_doctor(args: argparse.Namespace) -> int:
    checks: list[tuple[str, bool, str]] = []
    checks.append(("Python >= 3.11", sys.version_info >= (3, 11), _python_version()))
    api_key_set = bool(os.environ.get("VENICE_API_KEY", "").strip())
    checks.append(("VENICE_API_KEY set", api_key_set, "set" if api_key_set else "missing"))
    try:
        config = AIConfig.from_env()
        checks.append(("Venice endpoint uses HTTPS", True, config.base_url))
        checks.append(("AI model configured", True, config.model))
    except AIError as exc:
        checks.append(("Venice configuration", False, str(exc)))

    ok = all(result for _, result, _ in checks)
    if not args.quiet:
        print("[PHOBOS] Environment diagnostics")
        for label, passed, detail in checks:
            mark = "✓" if passed else "✗"
            print(f"{mark} {label}: {detail}")
        print("\n✓ Environment looks ready." if ok else "\n✗ Environment is not ready.")
    return 0 if ok else 1


def _python_version() -> str:
    return ".".join(str(part) for part in sys.version_info[:3])


def run_scan(args: argparse.Namespace, *, focus: str | None = None, plan_reason: str | None = None) -> int:
    config = ScanConfig.from_cli(
        args.target,
        tuple(args.scopes or ()),
        args.output,
        timeout=args.timeout,
        max_pages=args.max_pages,
        max_discovered_urls=args.max_discovered_urls,
        user_agent=args.user_agent,
        allow_private_targets=args.allow_private_targets,
    )
    scope = ScopeValidator(config.normalized_scopes, allow_private_targets=config.allow_private_targets)
    manager = RequestManager(
        scope,
        timeout=config.timeout,
        max_redirects=config.max_redirects,
        user_agent=config.user_agent,
        max_response_bytes=config.max_response_bytes,
    )
    store = EvidenceStore(config.output_dir)
    graph = Graph()
    website = Asset(
        id="website_001",
        type=AssetType.WEBSITE,
        name=config.target,
        url=config.target,
        metadata={"scopes": list(scope.allowed_domains)},
    )
    graph.add_node(id=website.id, type=website.type.value, label=website.name, attributes=website.metadata)

    print("[PHOBOS] Starting reconnaissance...")
    print(f"  Target: {config.target}")
    print(f"  Scope:  {', '.join(scope.allowed_domains)}")
    if focus:
        print(f"  Focus:  {focus}")
    if plan_reason:
        print(f"  Plan:   {plan_reason}")
    print()

    try:
        result = ReconCrawler(
            manager,
            max_pages=config.max_pages,
            max_discovered_urls=config.max_discovered_urls,
        ).crawl(config.target, graph=graph)
    except RequestError as exc:
        store.write_json(
            "scan.json",
            {
                "schema_version": "1.0",
                "target": config.target,
                "scopes": list(scope.allowed_domains),
                "status": "failed",
                "focus": focus,
                "error": str(exc),
            },
        )
        store.write_json("graph.json", graph.to_dict())
        store.write_json("assets.json", [website.to_dict()])
        store.write_json("findings.json", [])
        print(f"✗ Scan stopped: {exc}", file=sys.stderr)
        return 2

    for page in result.pages:
        graph.add_edge(source=website.id, target=page.id, relationship="hosts")
    assets = [website, *result.assets]
    store.write_json(
        "scan.json",
        {
            "schema_version": "1.0",
            "target": config.target,
            "scopes": list(scope.allowed_domains),
            "status": "complete",
            "focus": focus,
            "summary": {
                "pages": len(result.pages),
                "forms": len(result.forms),
                "inputs": len(result.inputs),
                "endpoints": len(result.endpoints),
                "javascript_files": len(result.javascript),
                "ai_surfaces": len(result.ai_surfaces),
                "errors": len(result.errors),
            },
            "crawler": {
                "max_pages": config.max_pages,
                "max_discovered_urls": config.max_discovered_urls,
            },
            "security": {"allow_private_targets": config.allow_private_targets},
            "ai_plan": {"reason": plan_reason} if plan_reason else None,
        },
    )
    store.write_json("assets.json", [asset.to_dict() for asset in assets])
    store.write_json("graph.json", graph.to_dict())
    store.write_json("findings.json", [])

    print(f"✓ {len(result.pages)} pages discovered")
    print(f"✓ {len(result.forms)} forms discovered")
    print(f"✓ {len(result.inputs)} input parameters discovered")
    print(f"✓ {len(result.endpoints)} endpoints discovered")
    print(f"✓ {len(result.javascript)} JavaScript references discovered")
    print(f"✓ {len(result.ai_surfaces)} likely AI surfaces discovered")
    if result.errors:
        print(f"! {len(result.errors)} recoverable errors")
    print(
        f"\nBuilding execution graph...\n\n✓ {len(graph.nodes)} nodes created\n✓ {len(graph.edges)} relationships created\n\n"
        f"Scan complete.\nResults saved to {config.output_dir}"
    )
    return 0


def run_ai(args: argparse.Namespace) -> int:
    request_text = " ".join(args.request).strip()
    target = _target_url(args.target)
    parsed = urlparse(target)
    scopes = tuple(args.scopes or (parsed.hostname or "",))
    scope = ScopeValidator(scopes, allow_private_targets=args.allow_private_targets)

    try:
        validated_target = scope.validate(target)
        print("[PHOBOS AI] Sending request to Venice Uncensored...")
        decision = VeniceClient(AIConfig.from_env()).decide(request_text)
        print(f"  Action: {decision['action']}")
        print(f"  Reason: {decision['reason']}")

        if decision["action"] == "refuse":
            print("No supported action was requested.")
            return 0
        if decision["action"] not in {"web_recon", "ai_surface_discovery"}:
            print("✗ Unsupported AI action", file=sys.stderr)
            return 2
        if args.dry_run:
            print("\n[DRY RUN] No web requests will be made.")
            print(f"  Target: {validated_target}")
            print(f"  Planned action: {decision['action']}")
            return 0

        args.target = validated_target
        if decision["action"] == "ai_surface_discovery":
            print("\n[PHOBOS AI] Running reconnaissance with AI-surface discovery focus...")
        return run_scan(args, focus=decision["action"], plan_reason=decision["reason"])
    except (AIError, RequestError, ValueError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "ai":
        return run_ai(args)
    if args.command == "doctor":
        return run_doctor(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

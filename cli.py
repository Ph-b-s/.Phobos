"""Phobos command-line entry point."""
from __future__ import annotations

import argparse
import sys

from ai import AIConfig, AIError, VeniceClient
from config import ScanConfig
from crawler import ReconCrawler
from evidence import EvidenceStore
from graph import Graph
from models import Asset, AssetType
from nmap_runner import NmapError, run_top_ports_scan
from request_manager import RequestError, RequestManager
from scope import ScopeValidator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phobos",
        description="Phobos — scoped AI security reconnaissance and attack-surface mapping.",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run a scoped web reconnaissance scan")
    scan.add_argument("target", help="absolute http(s) target URL")
    scan.add_argument("--scope", action="append", dest="scopes", metavar="DOMAIN")
    scan.add_argument("--output", default=".phobos")
    scan.add_argument("--timeout", type=float, default=10.0)
    scan.add_argument("--max-pages", type=int, default=100)
    scan.add_argument("--user-agent", default="Phobos/0.1")
    scan.add_argument("--allow-private-targets", action="store_true")

    agent = sub.add_parser("ai", help="ask Venice Uncensored to select Phobos's safe nmap action")
    agent.add_argument("request", nargs="+", help="natural-language request")
    agent.add_argument("--target", required=True, help="hostname or IP to scan; never chosen by the AI")
    agent.add_argument("--scope", action="append", dest="scopes", metavar="DOMAIN")
    agent.add_argument("--timeout", type=float, default=60.0, help="maximum nmap runtime in seconds")
    agent.add_argument("--dry-run", action="store_true", help="ask the AI and show the fixed Nmap command without executing it")
    agent.add_argument("--allow-private-targets", action="store_true")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    config = ScanConfig.from_cli(
        args.target,
        tuple(args.scopes or ()),
        args.output,
        timeout=args.timeout,
        max_pages=args.max_pages,
        allow_private_targets=args.allow_private_targets,
    )
    scope = ScopeValidator(config.normalized_scopes, allow_private_targets=config.allow_private_targets)
    manager = RequestManager(
        scope,
        timeout=config.timeout,
        max_redirects=config.max_redirects,
        user_agent=args.user_agent,
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
    print(f"  Scope:  {', '.join(scope.allowed_domains)}\n")
    try:
        result = ReconCrawler(manager, max_pages=config.max_pages).crawl(config.target, graph=graph)
    except RequestError as exc:
        store.write_json(
            "scan.json",
            {
                "schema_version": "1.0",
                "target": config.target,
                "scopes": list(scope.allowed_domains),
                "status": "failed",
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
            "summary": {
                "pages": len(result.pages),
                "forms": len(result.forms),
                "inputs": len(result.inputs),
                "endpoints": len(result.endpoints),
                "javascript_files": len(result.javascript),
                "errors": len(result.errors),
            },
            "crawler": {"max_pages": config.max_pages},
            "security": {"allow_private_targets": config.allow_private_targets},
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
    if result.errors:
        print(f"! {len(result.errors)} recoverable errors")
    print(
        f"\nBuilding execution graph...\n\n✓ {len(graph.nodes)} nodes created\n✓ {len(graph.edges)} relationships created\n\n"
        f"Scan complete.\nResults saved to {config.output_dir}"
    )
    return 0


def run_ai(args: argparse.Namespace) -> int:
    request_text = " ".join(args.request).strip()
    scopes = tuple(args.scopes or (args.target,))
    scope = ScopeValidator(scopes, allow_private_targets=args.allow_private_targets)

    try:
        target = args.target
        validated_target = scope.validate(target if "://" in target else f"https://{target}")
        print("[PHOBOS AI] Sending request to Venice Uncensored...")
        decision = VeniceClient(AIConfig.from_env()).decide(request_text)
        print(f"  Action: {decision['action']}")
        print(f"  Reason: {decision['reason']}")
        if decision["action"] == "refuse":
            print("No supported action was requested.")
            return 0
        if decision["action"] != "nmap_top_ports":
            print("✗ Unsupported AI action", file=sys.stderr)
            return 2

        print(f"\n[PHOBOS] Prepared scoped nmap reconnaissance against {validated_target}...")
        if args.dry_run:
            print("[DRY RUN] Nmap will NOT be executed.")
            result = run_top_ports_scan(target, scope, timeout=args.timeout, execute=False)
            print(f"\n$ {' '.join(result.command)}")
            return 0

        result = run_top_ports_scan(target, scope, timeout=args.timeout)
        print(f"\n$ {' '.join(result.command)}")
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        if result.returncode != 0:
            print(f"✗ nmap exited with status {result.returncode}", file=sys.stderr)
            return result.returncode if 1 <= result.returncode <= 125 else 2
        print("✓ nmap completed successfully")
        return 0
    except (AIError, NmapError, ValueError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "ai":
        return run_ai(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""Phobos command-line entry point."""

from __future__ import annotations

import argparse
import sys

from phobos.core.config import ScanConfig
from phobos.core.models import Asset, AssetType
from phobos.core.request_manager import RequestManager, RequestError
from phobos.core.scope import ScopeValidator
from phobos.graph.graph import Graph
from phobos.recon.crawler import ReconCrawler
from phobos.storage.evidence import EvidenceStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phobos",
        description="Phobos — scoped reconnaissance and attack-surface mapping for authorized security testing.",
    )
    subcommands = parser.add_subparsers(dest="command")

    scan = subcommands.add_parser("scan", help="run a scoped reconnaissance scan")
    scan.add_argument("target", help="absolute http(s) target URL")
    scan.add_argument(
        "--scope",
        action="append",
        dest="scopes",
        metavar="DOMAIN",
        help="allowed hostname/domain; may be supplied more than once",
    )
    scan.add_argument("--output", default=".phobos", help="scan output directory")
    scan.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    scan.add_argument("--max-pages", type=int, default=100, help="maximum pages to crawl")
    scan.add_argument("--user-agent", default="Phobos/0.1", help="HTTP User-Agent")
    return parser


def run_scan(args: argparse.Namespace) -> int:
    config = ScanConfig.from_cli(
        target=args.target,
        scopes=tuple(args.scopes or ()),
        output_dir=args.output,
    )
    scope = ScopeValidator(config.normalized_scopes)
    request_manager = RequestManager(
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
    graph.add_node(
        id=website.id,
        type=website.type.value,
        label=website.name,
        attributes=website.metadata,
    )

    print("[PHOBOS] Starting reconnaissance...")
    print(f"  Target: {config.target}")
    print(f"  Scope:  {', '.join(scope.allowed_domains)}")
    print()

    try:
        result = ReconCrawler(request_manager, max_pages=args.max_pages).crawl(config.target, graph=graph)
    except RequestError as exc:
        store.write_json(
            "scan.json",
            {
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
                "api_endpoints": 0,
                "javascript_files": len(result.javascript),
                "errors": len(result.errors),
            },
            "crawler": {"max_pages": args.max_pages},
        },
    )
    store.write_json("assets.json", [asset.to_dict() for asset in assets])
    store.write_json("graph.json", graph.to_dict())
    store.write_json("findings.json", [])

    print(f"✓ {len(result.pages)} pages discovered")
    print(f"✓ {len(result.forms)} forms discovered")
    print(f"✓ {len(result.inputs)} input parameters discovered")
    print("✓ 0 API endpoints discovered")
    print(f"✓ {len(result.javascript)} JavaScript files analyzed")
    if result.errors:
        print(f"! {len(result.errors)} recoverable errors")
    print()
    print("Building execution graph...")
    print()
    print(f"✓ {len(graph.nodes)} nodes created")
    print(f"✓ {len(graph.edges)} relationships created")
    print()
    print("Scan complete.")
    print(f"Results saved to {config.output_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        try:
            return run_scan(args)
        except ValueError as exc:
            parser.error(str(exc))
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

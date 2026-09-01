"""Phobos command-line entry point."""

from __future__ import annotations

import argparse
import sys

from phobos.core.config import ScanConfig
from phobos.core.request_manager import RequestError, RequestManager
from phobos.core.models import Asset, AssetType
from phobos.core.scope import ScopeValidator
from phobos.graph.graph import Graph
from phobos.storage.evidence import EvidenceStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phobos",
        description="Phobos — authorized AI security reconnaissance framework",
    )
    subcommands = parser.add_subparsers(dest="command")

    scan = subcommands.add_parser("scan", help="start a scoped reconnaissance scan")
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
    graph.add_node(id=website.id, type=website.type.value, label=website.name, attributes=website.metadata)

    print("[PHOBOS] Starting reconnaissance...")
    print(f"  Target: {config.target}")
    print(f"  Scope:  {', '.join(scope.allowed_domains)}")

    try:
        response = request_manager.get(config.target)
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

    page = Asset(
        id="page_001",
        type=AssetType.PAGE,
        name=response.url,
        url=response.url,
        metadata={"status_code": response.status, "content_type": response.headers.get("content-type", "")},
    )
    graph.add_node(id=page.id, type=page.type.value, label=page.name, attributes=page.metadata)
    graph.add_edge(source=website.id, target=page.id, relationship="hosts")

    store.write_json(
        "scan.json",
        {
            "target": config.target,
            "scopes": list(scope.allowed_domains),
            "status": "complete",
            "http": {"url": response.url, "status": response.status},
            "summary": {"pages": 1, "forms": 0, "inputs": 0, "api_endpoints": 0, "javascript_files": 0},
        },
    )
    store.write_json("graph.json", graph.to_dict())
    store.write_json("assets.json", [website.to_dict(), page.to_dict()])
    store.write_json("findings.json", [])

    print("✓ 1 page discovered")
    print("✓ 0 forms discovered")
    print("✓ 0 input parameters discovered")
    print("✓ 0 API endpoints discovered")
    print("✓ 0 JavaScript files analyzed")
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

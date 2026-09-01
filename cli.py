"""Phobos command-line entry point."""
from __future__ import annotations
import argparse
import sys
from config import ScanConfig
from models import Asset, AssetType
from request_manager import RequestError, RequestManager
from scope import ScopeValidator
from graph import Graph
from crawler import ReconCrawler
from evidence import EvidenceStore

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phobos", description="Phobos — scoped AI security reconnaissance and attack-surface mapping.")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="run a scoped reconnaissance scan")
    scan.add_argument("target", help="absolute http(s) target URL")
    scan.add_argument("--scope", action="append", dest="scopes", metavar="DOMAIN")
    scan.add_argument("--output", default=".phobos")
    scan.add_argument("--timeout", type=float, default=10.0)
    scan.add_argument("--max-pages", type=int, default=100)
    scan.add_argument("--user-agent", default="Phobos/0.1")
    scan.add_argument("--allow-private-targets", action="store_true")
    return parser

def run_scan(args: argparse.Namespace) -> int:
    config = ScanConfig.from_cli(args.target, tuple(args.scopes or ()), args.output, timeout=args.timeout, max_pages=args.max_pages, allow_private_targets=args.allow_private_targets)
    scope = ScopeValidator(config.normalized_scopes, allow_private_targets=config.allow_private_targets)
    manager = RequestManager(scope, timeout=config.timeout, max_redirects=config.max_redirects, user_agent=args.user_agent, max_response_bytes=config.max_response_bytes)
    store = EvidenceStore(config.output_dir)
    graph = Graph()
    website = Asset(id="website_001", type=AssetType.WEBSITE, name=config.target, url=config.target, metadata={"scopes": list(scope.allowed_domains)})
    graph.add_node(id=website.id, type=website.type.value, label=website.name, attributes=website.metadata)
    print("[PHOBOS] Starting reconnaissance...")
    print(f"  Target: {config.target}")
    print(f"  Scope:  {', '.join(scope.allowed_domains)}\n")
    try:
        result = ReconCrawler(manager, max_pages=config.max_pages).crawl(config.target, graph=graph)
    except RequestError as exc:
        store.write_json("scan.json", {"schema_version": "1.0", "target": config.target, "scopes": list(scope.allowed_domains), "status": "failed", "error": str(exc)})
        store.write_json("graph.json", graph.to_dict())
        store.write_json("assets.json", [website.to_dict()])
        store.write_json("findings.json", [])
        print(f"✗ Scan stopped: {exc}", file=sys.stderr)
        return 2
    for page in result.pages:
        graph.add_edge(source=website.id, target=page.id, relationship="hosts")
    assets = [website, *result.assets]
    store.write_json("scan.json", {"schema_version": "1.0", "target": config.target, "scopes": list(scope.allowed_domains), "status": "complete", "summary": {"pages": len(result.pages), "forms": len(result.forms), "inputs": len(result.inputs), "endpoints": len(result.endpoints), "javascript_files": len(result.javascript), "errors": len(result.errors)}, "crawler": {"max_pages": config.max_pages}, "security": {"allow_private_targets": config.allow_private_targets}})
    store.write_json("assets.json", [asset.to_dict() for asset in assets])
    store.write_json("graph.json", graph.to_dict())
    store.write_json("findings.json", [])
    print(f"✓ {len(result.pages)} pages discovered")
    print(f"✓ {len(result.forms)} forms discovered")
    print(f"✓ {len(result.inputs)} input parameters discovered")
    print(f"✓ {len(result.endpoints)} endpoints discovered")
    print(f"✓ {len(result.javascript)} JavaScript references discovered")
    if result.errors: print(f"! {len(result.errors)} recoverable errors")
    print(f"\nBuilding execution graph...\n\n✓ {len(graph.nodes)} nodes created\n✓ {len(graph.edges)} relationships created\n\nScan complete.\nResults saved to {config.output_dir}")
    return 0

def main(argv: list[str] | None = None) -> int:
    parser = build_parser(); args = parser.parse_args(argv)
    if args.command == "scan":
        try: return run_scan(args)
        except ValueError as exc: parser.error(str(exc))
    parser.print_help(); return 0

if __name__ == "__main__": raise SystemExit(main())

from pathlib import Path

import pytest

from cli import build_parser
from config import ScanConfig
from evidence import EvidenceStore
from graph import Graph
from scope import ScopeError, ScopeValidator


def test_scope_boundaries():
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    assert scope.is_in_scope("https://example.com/")
    assert scope.is_in_scope("https://app.example.com/")
    assert not scope.is_in_scope("https://evil-example.com/")
    assert not scope.is_in_scope("https://example.com.evil.test/")
    assert not scope.is_in_scope("https://example.com@evil.test/")


def test_scope_normalizes_fragments_and_host_case():
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    assert scope.validate("https://Example.COM/a#x") == "https://example.com/a"


def test_scope_rejects_unresolvable_public_host(monkeypatch: pytest.MonkeyPatch):
    scope = ScopeValidator(("example.com",))

    def fail_resolution(*args, **kwargs):
        raise OSError("DNS failure")

    monkeypatch.setattr("scope.socket.getaddrinfo", fail_resolution)
    with pytest.raises(ScopeError, match="could not resolve destination safely"):
        scope.validate("https://example.com/")


def test_scope_rejects_invalid_scope_entry():
    with pytest.raises(ValueError, match="scope entries"):
        ScopeValidator(("https://example.com",))


def test_scope_rejects_literal_private_ip_by_default():
    scope = ScopeValidator(("192.168.56.10",))
    assert not scope.is_in_scope("https://192.168.56.10/")


def test_graph_requires_nodes():
    graph = Graph()
    graph.add_node(id="a", type="input")
    graph.add_node(id="b", type="ai_agent")
    graph.add_edge(source="a", target="b", relationship="influences")
    assert len(graph.nodes) == 2 and len(graph.edges) == 1


def test_graph_rejects_conflicting_duplicate_edge():
    graph = Graph()
    graph.add_node(id="a", type="page")
    graph.add_node(id="b", type="endpoint")
    graph.add_edge(source="a", target="b", relationship="links_to", attributes={"confidence": 0.8})
    with pytest.raises(ValueError, match="edge already exists"):
        graph.add_edge(source="a", target="b", relationship="links_to", attributes={"confidence": 0.4})


def test_config():
    config = ScanConfig.from_cli("https://example.com/path")
    assert config.normalized_scopes == ("example.com",)
    assert config.output_dir == Path(".phobos")
    assert config.max_discovered_urls >= config.max_pages


def test_config_rejects_unsafe_limits():
    with pytest.raises(ValueError, match="max_discovered_urls"):
        ScanConfig.from_cli("https://example.com", max_pages=10, max_discovered_urls=9)


def test_evidence_blocks_traversal(tmp_path):
    store = EvidenceStore(tmp_path / "scan")
    with pytest.raises(ValueError):
        store.write_json("../escape.json", {})


def test_cli_parser():
    args = build_parser().parse_args(
        [
            "scan",
            "https://example.com",
            "--scope",
            "example.com",
            "--max-pages",
            "25",
            "--max-discovered-urls",
            "100",
        ]
    )
    assert args.command == "scan"
    assert args.max_pages == 25
    assert args.max_discovered_urls == 100


def test_cli_ai_dry_run_parser():
    args = build_parser().parse_args(
        ["ai", "--target", "example.com", "--scope", "example.com", "--dry-run", "map", "the", "web"]
    )
    assert args.command == "ai" and args.dry_run is True


def test_cli_doctor_parser():
    args = build_parser().parse_args(["doctor", "--quiet"])
    assert args.command == "doctor" and args.quiet is True

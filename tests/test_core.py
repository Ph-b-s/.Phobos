from pathlib import Path

import pytest

from phobos.cli.main import build_parser
from phobos.core.config import ScanConfig
from phobos.core.request_manager import RequestError, RequestManager
from phobos.core.scope import ScopeValidator
from phobos.graph.graph import Graph
from phobos.storage.evidence import EvidenceStore


def test_scope_allows_exact_domain_and_subdomains() -> None:
    scope = ScopeValidator(("example.com",))
    assert scope.is_in_scope("https://example.com/")
    assert scope.is_in_scope("https://app.example.com/login")
    assert not scope.is_in_scope("https://example.com.evil.test/")
    assert not scope.is_in_scope("https://evil-example.com/")


def test_scope_rejects_unsupported_urls() -> None:
    scope = ScopeValidator(("example.com",))
    assert not scope.is_in_scope("ftp://example.com/file")
    assert not scope.is_in_scope("https://user:pass@example.com/")


def test_request_manager_blocks_before_network(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = ScopeValidator(("example.com",))
    manager = RequestManager(scope)

    called = False

    def fail(*args: object, **kwargs: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("network should not be reached")

    monkeypatch.setattr(manager._opener, "open", fail)
    with pytest.raises(RequestError, match="out-of-scope"):
        manager.get("https://evil.test/")
    assert not called


def test_graph_requires_nodes_before_edges() -> None:
    graph = Graph()
    graph.add_node(id="input_001", type="web_input", label="comment")
    graph.add_node(id="agent_001", type="ai_agent", label="Agent")
    graph.add_edge(source="input_001", target="agent_001", relationship="influences")

    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert graph.to_dict()["edges"][0]["relationship"] == "influences"


def test_config_defaults_to_target_hostname() -> None:
    config = ScanConfig.from_cli("https://example.com/path")
    assert config.normalized_scopes == ("example.com",)
    assert config.output_dir == Path(".phobos")


def test_evidence_store_writes_json(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / ".phobos")
    destination = store.write_json("scan.json", {"status": "complete"})
    assert destination.exists()
    assert destination.read_text(encoding="utf-8").strip().startswith("{")


def test_cli_scan_parser() -> None:
    args = build_parser().parse_args(
        ["scan", "https://example.com", "--scope", "example.com", "--output", "results"]
    )
    assert args.command == "scan"
    assert args.target == "https://example.com"
    assert args.scopes == ["example.com"]
    assert args.output == "results"

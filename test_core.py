from pathlib import Path
import pytest
from cli import build_parser
from config import ScanConfig
from evidence import EvidenceStore
from graph import Graph
from scope import ScopeError, ScopeValidator

def test_scope_boundaries():
    s=ScopeValidator(("example.com",),allow_private_targets=True)
    assert s.is_in_scope("https://example.com/")
    assert s.is_in_scope("https://app.example.com/")
    assert not s.is_in_scope("https://evil-example.com/")
    assert not s.is_in_scope("https://example.com.evil.test/")
    assert not s.is_in_scope("https://example.com@evil.test/")

def test_scope_normalizes_fragments():
    s=ScopeValidator(("example.com",),allow_private_targets=True)
    assert s.validate("https://example.com/a#x")=="https://example.com/a"

def test_graph_requires_nodes():
    g=Graph(); g.add_node(id='a',type='input'); g.add_node(id='b',type='ai_agent'); g.add_edge(source='a',target='b',relationship='influences')
    assert len(g.nodes)==2 and len(g.edges)==1

def test_config():
    c=ScanConfig.from_cli('https://example.com/path')
    assert c.normalized_scopes==('example.com',) and c.output_dir==Path('.phobos')

def test_evidence_blocks_traversal(tmp_path):
    s=EvidenceStore(tmp_path/'scan')
    with pytest.raises(ValueError): s.write_json('../escape.json',{})

def test_cli_parser():
    a=build_parser().parse_args(['scan','https://example.com','--scope','example.com','--max-pages','25'])
    assert a.command=='scan' and a.max_pages==25

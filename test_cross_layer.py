from cross_layer import correlate_attack_paths
from graph import Graph


def test_correlates_web_ai_web_attack_path():
    graph = Graph()
    graph.add_node(id="input-1", type="input", label="comment")
    graph.add_node(id="ai-1", type="ai_agent", label="support agent")
    graph.add_node(id="tool-1", type="tool", label="internal API tool")
    graph.add_node(id="endpoint-1", type="endpoint", label="/admin/export")
    graph.add_edge(source="input-1", target="ai-1", relationship="influences")
    graph.add_edge(source="ai-1", target="tool-1", relationship="controls")
    graph.add_edge(source="tool-1", target="endpoint-1", relationship="invokes")

    paths = correlate_attack_paths(graph)
    assert paths
    assert any(path.pattern == "web_to_ai_to_web" for path in paths)


def test_ignores_web_only_paths():
    graph = Graph()
    graph.add_node(id="page-1", type="page")
    graph.add_node(id="endpoint-1", type="endpoint")
    graph.add_edge(source="page-1", target="endpoint-1", relationship="links_to")

    assert correlate_attack_paths(graph) == ()

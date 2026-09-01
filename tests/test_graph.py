from phobos.graph.graph import Graph


def test_graph_deduplicates_edges():
    graph = Graph()
    graph.add_node(id="a", type="input", label="comment")
    graph.add_node(id="b", type="ai_agent", label="agent")
    graph.add_edge(source="a", target="b", relationship="influences")
    graph.add_edge(source="a", target="b", relationship="influences")

    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert graph.to_dict()["edges"][0]["relationship"] == "influences"

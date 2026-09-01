"""Small deterministic in-memory directed graph."""
from collections.abc import Iterable
from typing import Any
from nodes import GraphEdge, GraphNode

class Graph:
    def __init__(self): self._nodes={}; self._edges={}
    @property
    def nodes(self): return tuple(self._nodes.values())
    @property
    def edges(self): return tuple(self._edges.values())
    def add_node(self, *, id: str, type: str, label: str='', attributes: dict[str,Any]|None=None):
        if not id.strip(): raise ValueError('node id cannot be empty')
        node=GraphNode(id,type,label,attributes or {}); old=self._nodes.get(id)
        if old and old!=node: raise ValueError(f'node already exists with different data: {id}')
        self._nodes[id]=node; return node
    def add_edge(self, *, source: str, target: str, relationship: str, attributes: dict[str,Any]|None=None):
        if source not in self._nodes or target not in self._nodes: raise KeyError('both source and target nodes must exist')
        if not relationship.strip(): raise ValueError('edge relationship cannot be empty')
        edge=GraphEdge(source,target,relationship,attributes or {}); self._edges[(source,target,relationship)]=edge; return edge
    def extend_nodes(self,nodes: Iterable[GraphNode]):
        for n in nodes: self.add_node(id=n.id,type=n.type,label=n.label,attributes=n.attributes)
    def to_dict(self): return {'nodes':[n.to_dict() for n in self.nodes],'edges':[e.to_dict() for e in self.edges]}
    def __len__(self): return len(self._nodes)

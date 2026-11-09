from typing import List, Dict, Any
from pydantic import BaseModel, Field


class AttackNode(BaseModel):
    node_id: str
    phase: str
    description: str
    vulnerability_id: str
    severity: str


class AttackEdge(BaseModel):
    source_id: str
    target_id: str
    transition_mechanism: str


class AttackGraph(BaseModel):
    """Member 2: Attack Chain Graph linking discrete vulnerabilities into exploit paths."""
    chain_title: str
    severity: str
    nodes: List[AttackNode] = Field(default_factory=list)
    edges: List[AttackEdge] = Field(default_factory=list)

    def add_step(self, node: AttackNode, incoming_from_id: str = None, mechanism: str = None):
        self.nodes.append(node)
        if incoming_from_id:
            self.edges.append(AttackEdge(
                source_id=incoming_from_id,
                target_id=node.node_id,
                transition_mechanism=mechanism or "Enables next stage exploit"
            ))


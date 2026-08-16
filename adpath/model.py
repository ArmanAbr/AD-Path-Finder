from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict


EDGE_INFO: dict[str, dict] = {
    "MemberOf":            {"cost": 0, "desc": "is a member of (inherits the group's rights)"},
    "AdminTo":             {"cost": 1, "desc": "is local admin on the target computer"},
    "HasSession":          {"cost": 1, "desc": "has a logon session on (creds harvestable)"},
    "Owns":                {"cost": 1, "desc": "owns the object (can rewrite its DACL)"},
    "GenericAll":          {"cost": 1, "desc": "full control over the object"},
    "GenericWrite":        {"cost": 1, "desc": "can write any (non-protected) attribute"},
    "WriteDacl":           {"cost": 1, "desc": "can rewrite the object's DACL, then grant self control"},
    "WriteOwner":          {"cost": 1, "desc": "can set object owner to self, then WriteDacl"},
    "ForceChangePassword": {"cost": 1, "desc": "can reset the target user's password"},
    "AddMember":           {"cost": 1, "desc": "can add members to the target group"},
    "AllExtendedRights":   {"cost": 1, "desc": "holds all extended rights (incl. password reset)"},
    "AddKeyCredentialLink":{"cost": 1, "desc": "can add a shadow credential (msDS-KeyCredentialLink)"},
    "DCSync":              {"cost": 1, "desc": "can replicate directory secrets (dump all hashes)"},
    "CanRDP":              {"cost": 1, "desc": "can RDP to the target computer"},
    "CanPSRemote":         {"cost": 1, "desc": "can WinRM/PSRemote to the target computer"},
}

TRAVERSABLE_EDGES = set(EDGE_INFO)

NODE_TYPES = {"User", "Group", "Computer", "Domain", "OU", "GPO"}


@dataclass
class Node:
    id: str
    type: str
    name: str
    props: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.name} ({self.type})"


@dataclass
class Edge:
    src: str
    dst: str
    type: str

    @property
    def cost(self) -> int:
        return EDGE_INFO.get(self.type, {}).get("cost", 1)


class Graph:
    def __init__(self, domain: str = "") -> None:
        self.domain = domain
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adj: dict[str, list[Edge]] = {}

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node
        self._adj.setdefault(node.id, [])

    def add_edge(self, edge: Edge) -> None:
        if edge.type not in EDGE_INFO:
            raise ValueError(f"Unknown edge type: {edge.type}")
        self.edges.append(edge)
        self._adj.setdefault(edge.src, []).append(edge)
        self._adj.setdefault(edge.dst, [])

    def out_edges(self, node_id: str) -> list[Edge]:
        return self._adj.get(node_id, [])

    def find_by_name(self, name: str) -> Node | None:
        name_l = name.lower()
        for n in self.nodes.values():
            if n.name.lower() == name_l:
                return n
        for n in self.nodes.values():
            if n.name.lower().split("@", 1)[0] == name_l:
                return n
        return None

    def resolve(self, ident: str) -> Node | None:
        return self.nodes.get(ident) or self.find_by_name(ident)

    def to_json(self, path: str) -> None:
        data = {
            "domain": self.domain,
            "nodes": [asdict(n) for n in self.nodes.values()],
            "edges": [asdict(e) for e in self.edges],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    @classmethod
    def from_json(cls, path: str) -> "Graph":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        g = cls(domain=data.get("domain", ""))
        for n in data.get("nodes", []):
            g.add_node(Node(id=n["id"], type=n["type"], name=n["name"], props=n.get("props", {})))
        for e in data.get("edges", []):
            g.add_edge(Edge(src=e["src"], dst=e["dst"], type=e["type"]))
        return g

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for n in self.nodes.values():
            counts[n.type] = counts.get(n.type, 0) + 1
        counts["edges"] = len(self.edges)
        return counts

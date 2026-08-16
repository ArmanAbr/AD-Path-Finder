from __future__ import annotations

import heapq
from dataclasses import dataclass

from .model import Edge, Graph, Node

HIGH_VALUE_RID_SUFFIXES = ("-512", "-519", "-518", "-516", "-500")
HIGH_VALUE_SIDS = {
    "S-1-5-32-544",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-551",
}


@dataclass
class Path:
    nodes: list[Node]
    edges: list[Edge]

    @property
    def abuse_cost(self) -> int:
        return sum(e.cost for e in self.edges)

    @property
    def hops(self) -> int:
        return len(self.edges)


def is_high_value(node: Node) -> bool:
    if node.props.get("high_value"):
        return True
    if node.id in HIGH_VALUE_SIDS:
        return True
    return any(node.id.endswith(suffix) for suffix in HIGH_VALUE_RID_SUFFIXES)


def high_value_targets(g: Graph) -> list[Node]:
    return [n for n in g.nodes.values() if is_high_value(n)]


def shortest_path(g: Graph, src_id: str, dst_ids: set[str]) -> Path | None:
    if src_id not in g.nodes:
        return None
    pq: list[tuple[int, int, str]] = [(0, 0, src_id)]
    best: dict[str, tuple[int, int]] = {src_id: (0, 0)}
    prev: dict[str, tuple[str, Edge]] = {}

    reached: str | None = None
    while pq:
        cost, hops, nid = heapq.heappop(pq)
        if nid in dst_ids and nid != src_id:
            reached = nid
            break
        if (cost, hops) > best.get(nid, (cost, hops)):
            continue
        for e in g.out_edges(nid):
            ncost, nhops = cost + e.cost, hops + 1
            if (ncost, nhops) < best.get(e.dst, (10**9, 10**9)):
                best[e.dst] = (ncost, nhops)
                prev[e.dst] = (nid, e)
                heapq.heappush(pq, (ncost, nhops, e.dst))

    if reached is None:
        return None

    node_ids = [reached]
    edges: list[Edge] = []
    cur = reached
    while cur in prev:
        pnode, pedge = prev[cur]
        edges.append(pedge)
        node_ids.append(pnode)
        cur = pnode
    node_ids.reverse()
    edges.reverse()
    return Path(nodes=[g.nodes[i] for i in node_ids], edges=edges)


def paths_to_domain_admin(g: Graph, sources: list[Node] | None = None) -> list[tuple[Node, Path]]:
    targets = {n.id for n in high_value_targets(g)}
    if not targets:
        return []
    if sources is None:
        sources = [
            n for n in g.nodes.values()
            if n.type == "User" and n.props.get("enabled", True)
        ]
    results: list[tuple[Node, Path]] = []
    for s in sources:
        if s.id in targets:
            continue
        p = shortest_path(g, s.id, targets)
        if p:
            results.append((s, p))
    results.sort(key=lambda t: (t[1].abuse_cost, t[1].hops))
    return results


def who_can_reach(g: Graph, target: Node) -> list[tuple[Node, Path]]:
    out: list[tuple[Node, Path]] = []
    for n in g.nodes.values():
        if n.id == target.id:
            continue
        p = shortest_path(g, n.id, {target.id})
        if p:
            out.append((n, p))
    out.sort(key=lambda t: (t[1].abuse_cost, t[1].hops))
    return out


def quick_wins(g: Graph) -> dict[str, list[Node]]:
    wins: dict[str, list[Node]] = {
        "kerberoastable": [],
        "asrep_roastable": [],
        "unconstrained_delegation": [],
        "dcsync_capable": [],
        "admincount_users": [],
    }
    for n in g.nodes.values():
        p = n.props
        if p.get("kerberoastable"):
            wins["kerberoastable"].append(n)
        if p.get("asrep_roastable"):
            wins["asrep_roastable"].append(n)
        if p.get("unconstrained_delegation"):
            wins["unconstrained_delegation"].append(n)
        if n.type == "User" and p.get("adminCount"):
            wins["admincount_users"].append(n)
    for e in g.edges:
        if e.type == "DCSync":
            src = g.nodes.get(e.src)
            if src and src not in wins["dcsync_capable"]:
                wins["dcsync_capable"].append(src)
    return wins

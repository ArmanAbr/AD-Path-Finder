from __future__ import annotations

from .analyzer import Path, high_value_targets, is_high_value
from .model import EDGE_INFO, Graph


def format_path(path: Path, explain: bool = False) -> str:
    parts = [path.nodes[0].label]
    for node, edge in zip(path.nodes[1:], path.edges):
        parts.append(f"\n    --[{edge.type}]--> {node.label}")
        if explain:
            parts.append(f"\n        > {EDGE_INFO.get(edge.type, {}).get('desc', '')}")
    return "".join(parts)


def print_paths_to_da(results, limit: int = 20, explain: bool = False) -> None:
    if not results:
        print("[-] No attack paths to any high-value target were found.")
        return
    print(f"[+] {len(results)} principal(s) can reach a high-value target. "
          f"Showing the {min(limit, len(results))} shortest:\n")
    for i, (src, path) in enumerate(results[:limit], 1):
        print(f"--- Path #{i}  (abuse steps: {path.abuse_cost}, hops: {path.hops}) ---")
        print(f"  {format_path(path, explain=explain)}\n")


def print_high_value(g: Graph) -> None:
    hv = high_value_targets(g)
    print(f"[*] High-value targets ({len(hv)}):")
    for n in hv:
        print(f"    - {n.label}")
    print()


def print_quick_wins(wins: dict) -> None:
    labels = {
        "kerberoastable": "Kerberoastable users (SPN set)",
        "asrep_roastable": "AS-REP roastable users (no pre-auth)",
        "unconstrained_delegation": "Unconstrained delegation",
        "dcsync_capable": "Can DCSync (dump all hashes)",
        "admincount_users": "Protected (adminCount=1) users",
    }
    print("[*] Quick wins:")
    any_win = False
    for key, label in labels.items():
        items = wins.get(key, [])
        if items:
            any_win = True
            print(f"    {label}: {len(items)}")
            for n in items:
                print(f"        - {n.name}")
    if not any_win:
        print("    (none found)")
    print()


def export_dot(g: Graph, path: str, only_edges_in=None) -> None:
    def esc(s: str) -> str:
        return s.replace('"', '\\"')

    lines = ["digraph AD {", '  rankdir=LR;', '  node [style=filled, fontname="Segoe UI"];']
    drawn_nodes = set()

    def node_line(nid: str) -> str:
        n = g.nodes[nid]
        if is_high_value(n):
            color = "#ff6b6b"
        elif n.type == "Group":
            color = "#ffd166"
        elif n.type == "Computer":
            color = "#4dabf7"
        elif n.type == "Domain":
            color = "#b197fc"
        else:
            color = "#c3fae8"
        shape = "box" if n.type in ("Computer", "Domain") else "ellipse"
        return f'  "{esc(nid)}" [label="{esc(n.name)}\\n({n.type})", fillcolor="{color}", shape={shape}];'

    for e in g.edges:
        if only_edges_in is not None and (e.src, e.dst, e.type) not in only_edges_in:
            continue
        for nid in (e.src, e.dst):
            if nid not in drawn_nodes and nid in g.nodes:
                lines.append(node_line(nid))
                drawn_nodes.add(nid)
        style = "bold" if e.cost == 0 else "solid"
        lines.append(f'  "{esc(e.src)}" -> "{esc(e.dst)}" [label="{e.type}", style={style}];')

    lines.append("}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"[+] Graphviz written to {path}  (render: dot -Tpng {path} -o graph.png)")

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from adpath.analyzer import (
    high_value_targets,
    paths_to_domain_admin,
    quick_wins,
    shortest_path,
    who_can_reach,
)
from adpath.model import Graph
from adpath import report

BANNER = r"""
   _   ___    ___      _   _    ___ _         _
  /_\ |   \  | _ \__ _| |_| |_ / __(_)_ _  __| |___ _ _
 / _ \| |) | |  _/ _` |  _| ' \ (__| | ' \/ _` / -_) '_|
/_/ \_\___/  |_| \__,_|\__|_||_\___|_|_||_\__,_\___|_|
        map the road to Domain Admin
"""

EPILOG = r"""
examples:
  py adpath_finder.py collect -d LAB.LOCAL --dc 10.10.10.5 -u lowpriv -p 'Password1' -o loot.json
  py adpath_finder.py collect -d LAB.LOCAL --dc 10.10.10.5 -u lowpriv --hash <ntlm> -o loot.json
  py adpath_finder.py analyze -i loot.json --paths --explain
  py adpath_finder.py analyze -i loot.json --high-value
  py adpath_finder.py analyze -i loot.json --quick-wins
  py adpath_finder.py analyze -i loot.json --from alice
  py adpath_finder.py analyze -i loot.json --target "Domain Admins"
  py adpath_finder.py analyze -i loot.json --paths --dot paths.dot

Only run against Active Directory you own or are authorized to test.
"""


def cmd_collect(args: argparse.Namespace) -> int:
    try:
        from adpath.collector import collect
    except ImportError:
        print("[!] Live collection needs ldap3 (and impacket): pip install ldap3 impacket")
        return 2
    print(f"[*] Connecting to {args.dc} as {args.domain}\\{args.user} ...")
    g = collect(
        dc_host=args.dc, domain=args.domain, username=args.user,
        password=args.password or "", nt_hash=args.hash or "",
        use_ssl=args.ssl, port=args.port,
    )
    print(f"[+] Collected: {g.stats()}")
    g.to_json(args.output)
    print(f"[+] Saved graph to {args.output}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    g = Graph.from_json(args.input)
    print(f"[*] Loaded {args.input}: domain={g.domain or '?'}  {g.stats()}\n")

    did_something = False

    if args.high_value:
        report.print_high_value(g)
        did_something = True

    if args.quick_wins:
        report.print_quick_wins(quick_wins(g))
        did_something = True

    if args.from_principal:
        src = g.resolve(args.from_principal)
        if not src:
            print(f"[!] No node matches {args.from_principal!r}")
            return 1
        targets = {n.id for n in high_value_targets(g)}
        p = shortest_path(g, src.id, targets)
        if p:
            print(f"[+] Shortest path from {src.label} to Domain Admin "
                  f"(abuse steps: {p.abuse_cost}, hops: {p.hops}):\n")
            print("  " + report.format_path(p, explain=args.explain) + "\n")
        else:
            print(f"[-] No path from {src.label} to any high-value target.")
        did_something = True

    if args.target:
        tgt = g.resolve(args.target)
        if not tgt:
            print(f"[!] No node matches {args.target!r}")
            return 1
        results = who_can_reach(g, tgt)
        if results:
            print(f"[+] {len(results)} principal(s) can reach {tgt.label}. "
                  f"Showing up to {args.limit}:\n")
            for i, (src, p) in enumerate(results[:args.limit], 1):
                print(f"--- #{i}  (abuse steps: {p.abuse_cost}, hops: {p.hops}) ---")
                print("  " + report.format_path(p, explain=args.explain) + "\n")
        else:
            print(f"[-] No principal can reach {tgt.label}.")
        did_something = True

    if args.paths:
        results = paths_to_domain_admin(g)
        report.print_paths_to_da(results, limit=args.limit, explain=args.explain)
        if args.dot and results:
            edges_in = set()
            for _src, p in results[:args.limit]:
                for e in p.edges:
                    edges_in.add((e.src, e.dst, e.type))
            report.export_dot(g, args.dot, only_edges_in=edges_in)
        did_something = True

    if args.dot and not args.paths:
        report.export_dot(g, args.dot)
        did_something = True

    if not did_something:
        print("[!] Nothing to do. Try --paths, --high-value, --quick-wins, "
              "--from NAME, or --target NAME.")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    print(BANNER)
    p = argparse.ArgumentParser(
        description="Collect Active Directory and find attack paths to Domain Admin.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="collect from a live DC into JSON")
    c.add_argument("-d", "--domain", required=True, help="domain, e.g. LAB.LOCAL")
    c.add_argument("--dc", required=True, help="domain controller host/IP")
    c.add_argument("-u", "--user", required=True, help="username")
    c.add_argument("-p", "--password", help="password")
    c.add_argument("--hash", help="NTLM hash (pass-the-hash)")
    c.add_argument("--ssl", action="store_true", help="use LDAPS")
    c.add_argument("--port", type=int, help="LDAP port (default 389, or 636 with --ssl)")
    c.add_argument("-o", "--output", default="loot.json", help="output JSON (default loot.json)")
    c.set_defaults(func=cmd_collect)

    a = sub.add_parser("analyze", help="analyse a collected JSON graph")
    a.add_argument("-i", "--input", required=True, help="collected JSON graph")
    a.add_argument("--paths", action="store_true", help="shortest paths from all users to Domain Admin")
    a.add_argument("--from", dest="from_principal", metavar="NAME", help="paths from a specific principal")
    a.add_argument("--target", metavar="NAME", help="who can reach this node")
    a.add_argument("--high-value", action="store_true", help="list high-value targets")
    a.add_argument("--quick-wins", action="store_true", help="kerberoast/asrep/deleg/dcsync")
    a.add_argument("--explain", action="store_true", help="annotate each edge with how it's abused")
    a.add_argument("--dot", metavar="FILE", help="export Graphviz DOT (of shown paths, or whole graph)")
    a.add_argument("--limit", type=int, default=20, help="max paths to show (default 20)")
    a.set_defaults(func=cmd_analyze)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

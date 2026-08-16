# AD-Path-Finder

A small BloodHound-style tool for Active Directory. It pulls users, groups, computers
and their ACLs over LDAP, turns them into a graph, and finds the shortest attack paths
from any user to Domain Admin. It also lists the usual quick wins: Kerberoastable and
AS-REP roastable accounts, unconstrained delegation and DCSync rights.

I wrote it to understand what BloodHound is actually doing under the hood: how raw AD
permissions turn into attack edges, and how a path search turns a pile of ACLs into
"reset bob's password, then you're DA".

## Features

- Parses `nTSecurityDescriptor` DACLs and maps access masks and extended-right GUIDs
  (`GenericAll`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AddMember`,
  `AddKeyCredentialLink`, DCSync) to graph edges
- Weighted Dijkstra search that prefers paths with the fewest abuse steps
  (group membership hops cost nothing)
- Collection and analysis are separate: collect once from a DC into JSON, then
  analyze offline as many times as you want
- Graphviz export of the found paths or the whole graph
- 18 unit tests that run without AD or any third-party packages

## How it works

```
collect (live DC)  -->  loot.json  -->  analyze (offline)
  ldap3 + impacket        graph         Dijkstra + reports
```

```
adpath_finder.py        CLI with collect and analyze subcommands
adpath/model.py         Node / Edge / Graph and JSON load/save
adpath/acl.py           access mask + GUID to edge mapping, DACL parsing
adpath/collector.py     LDAP collection (ldap3, impacket)
adpath/analyzer.py      pathfinding, high-value targets, quick wins
adpath/report.py        text output and Graphviz DOT export
labs/sample_domain.json small fake domain for offline testing
tests/test_units.py     unit tests
```

## Edges

`MemberOf` (cost 0), `AdminTo`, `HasSession`, `Owns`, `GenericAll`, `GenericWrite`,
`WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AddMember`, `AllExtendedRights`,
`AddKeyCredentialLink`, `DCSync`, `CanRDP`, `CanPSRemote` (cost 1 each).

Because membership is free and every abusable right costs 1, the shortest path is the
one where you have to abuse the fewest things.

## Setup

Analysis only uses the Python standard library. You only need the packages in
`requirements.txt` for live collection:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Running it offline

```powershell
py adpath_finder.py analyze -i labs\sample_domain.json --paths --quick-wins --explain
```

Example path from the sample domain:

```
alice --[MemberOf]--> HelpDesk --[ForceChangePassword]--> bob
      --[MemberOf]--> ITStaff  --[GenericAll]--> ServerAdmins
      --[MemberOf]--> Domain Admins
```

To get a picture (needs Graphviz `dot` on PATH):

```powershell
py adpath_finder.py analyze -i labs\sample_domain.json --paths --dot paths.dot
dot -Tpng paths.dot -o paths.png
```

## Collecting from a lab DC

With a password:

```powershell
py adpath_finder.py collect -d LAB.LOCAL --dc 10.10.10.5 -u lowpriv -p 'Password1' -o loot.json
```

Or with an NT hash:

```powershell
py adpath_finder.py collect -d LAB.LOCAL --dc 10.10.10.5 -u lowpriv --hash <ntlm> -o loot.json
```

Then:

```powershell
py adpath_finder.py analyze -i loot.json --paths --explain
```

## Options

| Flag | Meaning |
|------|---------|
| `--paths` | shortest path from every user to a high-value target |
| `--from NAME` | shortest path from one principal to Domain Admin |
| `--target NAME` | everyone who can reach a given node |
| `--high-value` | list high-value targets |
| `--quick-wins` | kerberoast / AS-REP / delegation / DCSync / adminCount |
| `--explain` | show how each edge is abused |
| `--dot FILE` | export Graphviz (shown paths, or the whole graph) |
| `--limit N` | max paths to show (default 20) |

## Lab setup

To try it against real data, promote a Windows Server VM to a DC
(`Install-ADDSForest`), create a few users and groups, and add some bad ACLs on purpose.

Let HelpDesk reset bob's password:

```powershell
dsacls "CN=bob,CN=Users,DC=lab,DC=local" /G "LAB\HelpDesk:CA;Reset Password"
```

Give ITStaff full control over ServerAdmins:

```powershell
dsacls "CN=ServerAdmins,CN=Users,DC=lab,DC=local" /G "LAB\ITStaff:GA"
```

Then collect as a low-privileged user and the path shows up.

## Tests

```powershell
py -m unittest discover -s tests -v
```

## Disclaimer

Only use this against environments you own or are authorized to test.

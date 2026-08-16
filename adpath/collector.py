from __future__ import annotations

from .acl import parse_security_descriptor
from .model import Edge, Graph, Node

UAC_ACCOUNTDISABLE        = 0x00000002
UAC_TRUSTED_FOR_DELEG     = 0x00080000
UAC_DONT_REQ_PREAUTH      = 0x00400000

_ATTRS = [
    "objectSid", "sAMAccountName", "distinguishedName", "objectClass",
    "memberOf", "member", "primaryGroupID", "adminCount",
    "userAccountControl", "servicePrincipalName", "nTSecurityDescriptor",
]


def collect(
    dc_host: str,
    domain: str,
    username: str,
    password: str = "",
    nt_hash: str = "",
    use_ssl: bool = False,
    port: int | None = None,
) -> Graph:
    from ldap3 import Server, Connection, NTLM, ALL, SUBTREE
    from ldap3.protocol.microsoft import security_descriptor_control

    server = Server(dc_host, port=port, use_ssl=use_ssl, get_info=ALL)
    user = f"{domain}\\{username}"
    auth = password if password else f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}"
    conn = Connection(server, user=user, password=auth, authentication=NTLM, auto_bind=True)

    base_dn = server.info.other["defaultNamingContext"][0]
    g = Graph(domain=domain.upper())

    sd_control = security_descriptor_control(sdflags=0x04)

    ldap_filter = "(|(objectClass=user)(objectClass=group)(objectClass=computer))"
    conn.extend.standard.paged_search(
        base_dn, ldap_filter, search_scope=SUBTREE,
        attributes=_ATTRS, controls=sd_control, paged_size=500,
        generator=False,
    )

    sid_by_dn: dict[str, str] = {}
    raw_entries = []

    for entry in conn.entries:
        a = entry.entry_attributes_as_dict
        sid = _first(a.get("objectSid"))
        dn = _first(a.get("distinguishedName"))
        if not sid or not dn:
            continue
        sid_by_dn[dn.lower()] = sid
        raw_entries.append(a)

        ntype = _node_type(a.get("objectClass", []))
        sam = _first(a.get("sAMAccountName")) or dn
        name = f"{sam}@{domain.upper()}"
        props = _flags(a)
        g.add_node(Node(id=sid, type=ntype, name=name, props=props))

    for a in raw_entries:
        sid = _first(a.get("objectSid"))
        for grp_dn in a.get("memberOf", []) or []:
            grp_sid = sid_by_dn.get(grp_dn.lower())
            if grp_sid:
                g.add_edge(Edge(src=sid, dst=grp_sid, type="MemberOf"))

        sd = a.get("nTSecurityDescriptor")
        raw = sd[0] if isinstance(sd, list) and sd else sd
        if isinstance(raw, (bytes, bytearray)):
            try:
                for trustee_sid, edge_types in parse_security_descriptor(bytes(raw)):
                    if trustee_sid not in g.nodes:
                        continue
                    for et in edge_types:
                        g.add_edge(Edge(src=trustee_sid, dst=sid, type=et))
            except RuntimeError:
                pass

    conn.unbind()
    return g


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _node_type(object_classes: list[str]) -> str:
    oc = {c.lower() for c in object_classes}
    if "computer" in oc:
        return "Computer"
    if "group" in oc:
        return "Group"
    return "User"


def _flags(a: dict) -> dict:
    uac = int(_first(a.get("userAccountControl")) or 0)
    spns = a.get("servicePrincipalName") or []
    sam = (_first(a.get("sAMAccountName")) or "").lower()
    classes = {c.lower() for c in a.get("objectClass", [])}
    is_user = "user" in classes and "computer" not in classes
    return {
        "enabled": not (uac & UAC_ACCOUNTDISABLE),
        "adminCount": int(_first(a.get("adminCount")) or 0),
        "kerberoastable": bool(spns) and is_user and sam != "krbtgt",
        "asrep_roastable": bool(uac & UAC_DONT_REQ_PREAUTH) and is_user,
        "unconstrained_delegation": bool(uac & UAC_TRUSTED_FOR_DELEG),
    }

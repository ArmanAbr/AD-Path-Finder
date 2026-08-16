from __future__ import annotations

DS_CREATE_CHILD   = 0x00000001
DS_SELF           = 0x00000008
DS_READ_PROP      = 0x00000010
DS_WRITE_PROP     = 0x00000020
DS_CONTROL_ACCESS = 0x00000100
WRITE_DACL        = 0x00040000
WRITE_OWNER       = 0x00080000
GENERIC_ALL       = 0x10000000
GENERIC_WRITE     = 0x40000000

GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_REPL_GET_CHANGES      = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_REPL_GET_CHANGES_ALL  = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_MEMBER_ATTR           = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_KEY_CREDENTIAL_LINK   = "5b47d60f-6090-40b2-9f37-2a4de88f3063"

ACCESS_ALLOWED_ACE_TYPE        = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
ACE_OBJECT_TYPE_PRESENT        = 0x01
INHERIT_ONLY_ACE               = 0x08


def map_ace(mask: int, object_type_guid: str | None) -> list[str]:
    guid = (object_type_guid or "").lower().strip("{}")
    edges: list[str] = []

    if mask & GENERIC_ALL:
        edges.append("GenericAll")
        return edges
    if mask & WRITE_DACL:
        edges.append("WriteDacl")
    if mask & WRITE_OWNER:
        edges.append("WriteOwner")

    if mask & GENERIC_WRITE:
        edges.append("GenericWrite")
    if mask & DS_WRITE_PROP:
        if not guid:
            edges.append("GenericWrite")
        elif guid == GUID_MEMBER_ATTR:
            edges.append("AddMember")
        elif guid == GUID_KEY_CREDENTIAL_LINK:
            edges.append("AddKeyCredentialLink")
    if mask & DS_SELF and guid == GUID_MEMBER_ATTR:
        edges.append("AddMember")

    if mask & DS_CONTROL_ACCESS:
        if not guid:
            edges.append("AllExtendedRights")
        elif guid == GUID_FORCE_CHANGE_PASSWORD:
            edges.append("ForceChangePassword")
        elif guid in (GUID_REPL_GET_CHANGES, GUID_REPL_GET_CHANGES_ALL):
            edges.append("DCSync")

    seen: set[str] = set()
    return [e for e in edges if not (e in seen or seen.add(e))]


IGNORED_TRUSTEE_SIDS = {
    "S-1-1-0",
    "S-1-5-10",
    "S-1-3-0",
    "S-1-5-18",
    "S-1-5-9",
}


def parse_security_descriptor(sd_bytes: bytes) -> list[tuple[str, list[str]]]:
    try:
        from impacket.ldap import ldaptypes
        from impacket.uuid import bin_to_string
    except ImportError as exc:
        raise RuntimeError(
            "impacket is required to parse security descriptors "
            "(pip install impacket)."
        ) from exc

    out: list[tuple[str, list[str]]] = []
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    except Exception:
        return out
    if sd["Dacl"] is None:
        return out

    for ace in sd["Dacl"].aces:
        ace_type = ace["AceType"]
        if ace_type not in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE):
            continue
        if ace["AceFlags"] & INHERIT_ONLY_ACE:
            continue
        body = ace["Ace"]
        sid = body["Sid"].formatCanonical()
        if sid in IGNORED_TRUSTEE_SIDS:
            continue
        mask = int(body["Mask"]["Mask"])

        object_type_guid = None
        if ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE and body["Flags"] & ACE_OBJECT_TYPE_PRESENT:
            object_type_guid = bin_to_string(body["ObjectType"]).lower()

        edges = map_ace(mask, object_type_guid)
        if edges:
            out.append((sid, edges))
    return out

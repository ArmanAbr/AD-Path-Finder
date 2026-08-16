import os
import tempfile
import unittest

from adpath import acl
from adpath.analyzer import (
    high_value_targets,
    is_high_value,
    paths_to_domain_admin,
    quick_wins,
    shortest_path,
)
from adpath.model import Edge, Graph, Node

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "labs", "sample_domain.json")
BASE = "S-1-5-21-1111111111-2222222222-3333333333"


class TestAclMapping(unittest.TestCase):
    def test_generic_all_wins(self):
        self.assertEqual(acl.map_ace(acl.GENERIC_ALL, None), ["GenericAll"])

    def test_generic_all_subsumes_others(self):
        mask = acl.GENERIC_ALL | acl.WRITE_DACL
        self.assertEqual(acl.map_ace(mask, None), ["GenericAll"])

    def test_write_dacl_and_owner(self):
        mask = acl.WRITE_DACL | acl.WRITE_OWNER
        edges = acl.map_ace(mask, None)
        self.assertIn("WriteDacl", edges)
        self.assertIn("WriteOwner", edges)

    def test_force_change_password(self):
        edges = acl.map_ace(acl.DS_CONTROL_ACCESS, acl.GUID_FORCE_CHANGE_PASSWORD)
        self.assertEqual(edges, ["ForceChangePassword"])

    def test_all_extended_rights_when_no_guid(self):
        edges = acl.map_ace(acl.DS_CONTROL_ACCESS, None)
        self.assertEqual(edges, ["AllExtendedRights"])

    def test_dcsync_replication_guid(self):
        edges = acl.map_ace(acl.DS_CONTROL_ACCESS, acl.GUID_REPL_GET_CHANGES_ALL)
        self.assertEqual(edges, ["DCSync"])

    def test_add_member_via_write_prop_member(self):
        edges = acl.map_ace(acl.DS_WRITE_PROP, acl.GUID_MEMBER_ATTR)
        self.assertEqual(edges, ["AddMember"])

    def test_write_any_property_is_generic_write(self):
        edges = acl.map_ace(acl.DS_WRITE_PROP, None)
        self.assertEqual(edges, ["GenericWrite"])

    def test_key_credential_link(self):
        edges = acl.map_ace(acl.DS_WRITE_PROP, acl.GUID_KEY_CREDENTIAL_LINK)
        self.assertEqual(edges, ["AddKeyCredentialLink"])

    def test_uninteresting_mask_yields_nothing(self):
        self.assertEqual(acl.map_ace(acl.DS_READ_PROP, None), [])


class TestGraphModel(unittest.TestCase):
    def test_roundtrip_json(self):
        g = Graph.from_json(SAMPLE)
        self.assertEqual(g.domain, "LAB.LOCAL")
        self.assertIn(f"{BASE}-512", g.nodes)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            path = tf.name
        g.to_json(path)
        g2 = Graph.from_json(path)
        self.assertEqual(g.stats(), g2.stats())
        os.unlink(path)

    def test_unknown_edge_rejected(self):
        g = Graph()
        g.add_node(Node("a", "User", "a"))
        g.add_node(Node("b", "User", "b"))
        with self.assertRaises(ValueError):
            g.add_edge(Edge("a", "b", "NotARealEdge"))


class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.g = Graph.from_json(SAMPLE)

    def test_high_value_is_domain_admins(self):
        hv = {n.id for n in high_value_targets(self.g)}
        self.assertIn(f"{BASE}-512", hv)
        self.assertTrue(is_high_value(self.g.nodes[f"{BASE}-512"]))
        self.assertFalse(is_high_value(self.g.nodes[f"{BASE}-1105"]))

    def test_alice_reaches_da_with_two_abuse_steps(self):
        p = shortest_path(self.g, f"{BASE}-1105", {f"{BASE}-512"})
        self.assertIsNotNone(p)
        self.assertEqual(p.abuse_cost, 2)
        self.assertEqual(p.hops, 5)
        self.assertEqual([e.type for e in p.edges],
                         ["MemberOf", "ForceChangePassword", "MemberOf", "GenericAll", "MemberOf"])

    def test_bob_has_cheaper_path_than_alice(self):
        results = dict((src.name, path) for src, path in paths_to_domain_admin(self.g))
        self.assertLess(results["bob@LAB.LOCAL"].abuse_cost,
                        results["alice@LAB.LOCAL"].abuse_cost)

    def test_frank_reaches_da_via_session(self):
        p = shortest_path(self.g, f"{BASE}-1110", {f"{BASE}-512"})
        self.assertIsNotNone(p)
        self.assertEqual([e.type for e in p.edges], ["AdminTo", "HasSession", "MemberOf"])

    def test_isolated_user_has_no_path(self):
        p = shortest_path(self.g, f"{BASE}-1107", {f"{BASE}-512"})
        self.assertIsNone(p)

    def test_quick_wins(self):
        w = quick_wins(self.g)
        self.assertEqual([n.name for n in w["kerberoastable"]], ["carol@LAB.LOCAL"])
        self.assertEqual([n.name for n in w["asrep_roastable"]], ["dave@LAB.LOCAL"])
        self.assertEqual([n.name for n in w["unconstrained_delegation"]], ["WS01$@LAB.LOCAL"])
        self.assertIn(f"{BASE}-512", {n.id for n in w["dcsync_capable"]})


if __name__ == "__main__":
    unittest.main()

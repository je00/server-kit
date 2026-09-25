"""Saved-policy topology remains conservative, bounded, and credential-free."""

import copy
import json
import unittest
from unittest.mock import patch

from dashboard.topology import build_topology


def node(name, kind="awg", **values):
    return {"name": name, "kind": kind, "address": "10.20.0.10" if name == "desk" else "10.20.0.11",
            "state": "已启用", "access_mode": "unrestricted" if kind == "awg" else "restricted",
            "permissions": [], **values}


def rule(target="desk", ip="10.20.0.10", network="tcp", ports=None):
    return {"target": target, "ip": ip, "network": network, "ports": [22] if ports is None else ports}


def relation(model, identifier):
    return next(item for item in model["relations"] if item["node"]["id"] == identifier)


class TopologyModelTests(unittest.TestCase):
    def test_empty_and_malformed_overviews_are_json_safe(self):
        for value in (None, [], "bad", {}, {"nodes": None}, {"nodes": [None, 4, {}, node("../../bad"), node("bad", kind="other"), node("bad", kind=[])]}):
            with self.subTest(value=value):
                model = build_topology(value)
                self.assertEqual(model["selected"]["id"], "hub")
                self.assertEqual(model["selected_id"], "hub")
                self.assertEqual(model["relations"], [])
                self.assertEqual(model["summary"]["nodes"], 0)
                json.dumps(model)

    def test_selection_prefers_explicit_then_protected_then_first_then_hub(self):
        overview = {"nodes": [node("phone", "vless"), node("desk", protected=True)]}
        self.assertEqual(build_topology(overview)["selected"]["id"], "awg:desk")
        self.assertEqual(build_topology(overview, "vless:phone")["selected"]["id"], "vless:phone")
        self.assertEqual(build_topology(overview, "hub")["selected"]["id"], "hub")
        self.assertEqual(build_topology(overview, ["bad"])["selected"]["id"], "awg:desk")
        overview["nodes"][1]["protected"] = False
        self.assertEqual(build_topology(overview, "missing")["selected"]["id"], "vless:phone")

    def test_source_only_policy_does_not_require_destination_permission(self):
        overview = {"nodes": [node("desk"), node("phone", access_mode="restricted")]}
        edge = relation(build_topology(overview), "awg:phone")
        self.assertEqual(edge["forward"]["status"], "allowed")
        self.assertEqual(edge["reverse"]["status"], "denied")
        self.assertEqual(edge["relation"], "outbound")

    def test_unrestricted_ignores_saved_rules_and_two_directions_can_be_full(self):
        model = build_topology({"nodes": [node("desk", permissions=[None]), node("phone")]})
        edge = relation(model, "awg:phone")
        self.assertEqual(edge["relation"], "mutual")
        self.assertEqual(edge["forward"]["scopes"], ["全部协议 · 全部端口"])
        self.assertFalse(edge["forward"]["warnings"])

    def test_awg_named_target_uses_current_address_and_union_compresses_ports(self):
        permissions = [rule("phone", "192.0.2.1", ports=[1, 22, 8000, 8001, 65535]),
                       rule("phone", "192.0.2.2", ports=[8002, 8003]),
                       rule("phone", network="udp", ports=[53])]
        model = build_topology({"nodes": [node("desk", access_mode="restricted", permissions=permissions), node("phone")]})
        edge = relation(model, "awg:phone")
        self.assertEqual(edge["forward"]["status"], "partial")
        self.assertEqual(edge["forward"]["scopes"], ["TCP · 1, 22, 8000-8003, 65535", "UDP · 53"])
        self.assertEqual(edge["relation"], "mutual")
        self.assertIn("范围限制", edge["label"])

    def test_full_rule_supersedes_partial_scopes(self):
        permissions = [rule("phone", ports=[22]), rule("phone", network="all", ports=[])]
        edge = relation(build_topology({"nodes": [node("desk", access_mode="restricted", permissions=permissions), node("phone")]}), "awg:phone")
        self.assertEqual(edge["forward"]["status"], "allowed")
        self.assertEqual(edge["forward"]["scopes"], ["全部协议 · 全部端口"])

    def test_awg_all_cidr_is_checked_and_unknown_hub_is_not_guessed(self):
        overview = {"nodes": [node("desk", access_mode="restricted", permissions=[rule("all", "10.20.0.0/24")]), node("phone")]}
        model = build_topology(overview)
        self.assertEqual(relation(model, "awg:phone")["forward"]["status"], "partial")
        hub = relation(model, "hub")
        self.assertEqual(hub["forward"]["status"], "unknown")
        self.assertIn("中心节点", hub["forward"]["summary"])
        overview["nodes"][1]["address"] = "10.21.0.11"
        self.assertEqual(relation(build_topology(overview), "awg:phone")["forward"]["status"], "denied")

    def test_vless_all_uses_unavailable_current_cidr_not_saved_cidr(self):
        for saved_cidr in ("10.20.0.0/24", "192.0.2.0/24"):
            with self.subTest(cidr=saved_cidr):
                model = build_topology({"nodes": [node("phone", "vless", permissions=[rule("all", saved_cidr, "all", [])]), node("desk")]})
                result = relation(model, "awg:desk")["forward"]
                self.assertEqual(result["status"], "unknown")
                self.assertIn("实际网段", result["summary"])
                self.assertEqual(result["scopes"], ["全部协议 · 全部端口"])
                self.assertEqual(relation(model, "hub")["forward"]["status"], "unknown")

    def test_vless_explicit_rule_can_confirm_scope_alongside_unknown_all(self):
        model = build_topology({"nodes": [node("phone", "vless", permissions=[rule("all", "10.20.0.0/24", "all", []), rule("desk")]), node("desk")]})
        result = relation(model, "awg:desk")["forward"]
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["scopes"], ["TCP · 22"])
        self.assertTrue(result["warnings"])

    def test_awg_explicit_vps_is_configured_but_vless_vps_requires_hub_ip(self):
        for kind, expected in (("awg", "partial"), ("vless", "unknown")):
            model = build_topology({"nodes": [node("desk", kind, access_mode="restricted", permissions=[rule("vps", "10.20.0.1")])]})
            self.assertEqual(relation(model, "hub")["forward"]["status"], expected)
        model = build_topology({"nodes": [node("desk")]}, "hub")
        self.assertEqual(relation(model, "awg:desk")["forward"]["status"], "unknown")
        self.assertEqual(model["selected"]["address"], "")

    def test_vless_never_becomes_an_inbound_target(self):
        model = build_topology({"nodes": [node("desk"), node("phone", "vless"), node("tablet", "vless")]}, "vless:phone")
        self.assertEqual(relation(model, "awg:desk")["reverse"]["status"], "not_applicable")
        self.assertEqual(relation(model, "vless:tablet")["relation"], "not_applicable")

    def test_vless_stale_name_does_not_authorize_wrong_ip_but_ip_still_routes(self):
        overview = {"nodes": [node("phone", "vless", permissions=[rule("desk", "10.20.0.99", "all", [])]), node("desk"), node("new", address="10.20.0.99")]}
        model = build_topology(overview)
        stale = relation(model, "awg:desk")["forward"]
        self.assertEqual(stale["status"], "denied")
        self.assertTrue(stale["warnings"])
        actual = relation(model, "awg:new")["forward"]
        self.assertEqual(actual["status"], "allowed")
        self.assertTrue(actual["warnings"])

    def test_dangling_awg_target_is_ignored_but_vless_saved_ip_is_used(self):
        for kind, expected in (("awg", "denied"), ("vless", "partial")):
            model = build_topology({"nodes": [node("phone", kind, access_mode="restricted", permissions=[rule("gone")]), node("desk")]})
            result = relation(model, "awg:desk")["forward"]
            self.assertEqual(result["status"], expected)
            self.assertTrue(result["warnings"])

    def test_disabled_and_pending_nodes_preserve_scope_without_claiming_access(self):
        for state, expected in (("已禁用", "inactive"), ("等待首次握手", "unknown"), ("unexpected", "unknown")):
            for disabled_source in (False, True):
                with self.subTest(state=state, source=disabled_source):
                    nodes = [node("desk"), node("phone")]
                    nodes[0 if disabled_source else 1]["state"] = state
                    model = build_topology({"nodes": nodes})
                    edge = relation(model, "awg:phone")
                    self.assertEqual(edge["forward"]["status"], expected)
                    self.assertEqual(edge["reverse"]["status"], expected)
                    self.assertEqual(edge["forward"]["scopes"], ["全部协议 · 全部端口"])
                    self.assertTrue(all(item["online_label"] == "未检测" for item in model["nodes"]))

    def test_invalid_policy_fields_are_unknown_and_never_imply_allow(self):
        malformed = [None, {}, rule(ports=[True]), rule(ports=[0]), rule(ports=[65536]), rule(ports=["22"]),
                     rule(ports=[]), rule(ip="invalid"), rule(network="icmp"), rule(network=[]), rule(target="<script>")]
        for permission in malformed:
            with self.subTest(permission=permission):
                model = build_topology({"nodes": [node("desk", access_mode="restricted", permissions=[permission]), node("phone")]})
                self.assertEqual(relation(model, "awg:phone")["forward"]["status"], "unknown")
        for values in ({"access_mode": None}, {"access_mode": "restricted", "permissions": None}):
            model = build_topology({"nodes": [node("desk", **values), node("phone")]})
            self.assertEqual(relation(model, "awg:phone")["forward"]["status"], "unknown")

    def test_invalid_addresses_and_duplicate_ids_do_not_fabricate_nodes(self):
        model = build_topology({"nodes": [node("desk"), node("desk", address="192.0.2.5"), node("phone", address="private-not-an-ip")]})
        self.assertEqual(model["summary"]["nodes"], 2)
        self.assertTrue(model["warnings"])
        self.assertEqual(relation(model, "awg:phone")["forward"]["status"], "unknown")
        for address in (None, 10, True, [], "not-an-address"):
            with self.subTest(address=address):
                model = build_topology({"nodes": [node("desk", address=address), node("phone")]})
                self.assertEqual(relation(model, "awg:phone")["forward"]["status"], "unknown")
                self.assertEqual(relation(model, "awg:phone")["reverse"]["status"], "unknown")
                self.assertEqual(relation(model, "hub")["forward"]["status"], "unknown")

    def test_projection_excludes_credentials_and_does_not_mutate_input(self):
        secret = "do-not-project-this-credential"
        overview = {"nodes": [node("desk", protected=True, private_key=secret, uuid=secret,
                                  domains=[secret], exit_names=[secret], kind_label=secret,
                                  public_key_fingerprint=secret, detail=secret)],
                    "pending_access": True, "pending_vless": True, "unknown": secret}
        original = copy.deepcopy(overview)
        model = build_topology(overview)
        encoded = json.dumps(model)
        self.assertNotIn(secret, encoded)
        self.assertEqual(overview, original)
        self.assertEqual(len(model["warnings"]), 2)
        self.assertEqual(set(model["nodes"][1]), {"id", "name", "kind", "kind_label", "address", "state", "availability", "protected", "online_label"})

    def test_only_selected_node_relations_are_computed(self):
        import dashboard.topology as topology
        nodes = [node(f"node-{i}") for i in range(200)]
        with patch.object(topology, "_access", wraps=topology._access) as calculate:
            model = build_topology({"nodes": nodes})
        self.assertEqual(len(model["relations"]), 200)
        self.assertEqual(calculate.call_count, 400)
        self.assertEqual(model["summary"], {"nodes": 200, "awg": 200, "vless": 0, "enabled": 200, "disabled": 0, "pending": 0})

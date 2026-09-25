"""Synthetic VLESS topology regression; projects through the real backend only."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "web"))

from dashboard.topology import build_topology  # noqa: E402


ALL_SCOPE = ["全部协议 · 全部端口"]
PARTIAL_SCOPES = ["TCP · 22, 9080", "UDP · 53, 123"]
PHONE_ALL = "vless:phone-all"
PHONE_PORTS = "vless:phone-ports"
SECRET_SENTINEL = "synthetic-topology-private-credential-never-render"
OBSERVED_AT = "2026-09-25T15:00:00+00:00"


def permission(target, address, protocol="all", ports=()):
    return {"target": target, "ip": address, "network": protocol, "ports": list(ports)}


def overview_fixture():
    """Match overview's public data shape without reading any host configuration."""
    names = ("admin-desktop", "office-laptop", "nas-primary", "nas-backup", "lab-server", "media-server", "travel-laptop")
    nodes = [
        {"name": name, "kind": "awg", "address": f"10.77.0.{index + 10}", "state": "已启用",
         "protected": index == 0, "access_mode": "unrestricted" if index == 0 else "restricted",
         "permissions": [] if index == 0 else [permission("vps", "10.77.0.1", "tcp", (22, 9080))]}
        for index, name in enumerate(names)
    ]
    nodes.extend([
        {"name": "phone-all", "kind": "vless", "state": "已启用", "permissions": [
            # The renderer replaces this stale saved CIDR with the context fact.
            permission("all", "192.0.2.0/24"), permission("vps", "10.77.0.1", "tcp", (22, 9080))]},
        {"name": "phone-ports", "kind": "vless", "state": "已启用", "permissions": [
            permission("vps", "10.77.0.1", "tcp", (22, 9080)),
            permission("vps", "10.77.0.1", "udp", (53, 123))]},
        {"name": "phone-nas", "kind": "vless", "state": "已启用", "permissions": [
            permission("nas-primary", "10.77.0.12", "tcp", (443, 445))]},
        {"name": "phone-disabled", "kind": "vless", "state": "已禁用", "permissions": [
            permission("all", "192.0.2.0/24")]},
    ])
    # Deliberately include synthetic credential-like raw fields to prove that
    # this context and the projector do not send such fields to the diagram.
    for node in nodes:
        node["private_key"] = SECRET_SENTINEL
        node["share_uri"] = "vless://" + SECRET_SENTINEL
    return {"schema_version": 1, "nodes": nodes, "pending_access": False, "pending_vless": False,
            "topology_context": {"hub_address": "10.77.0.1", "vless_networks": {"phone-all": "10.77.0.0/24"}}}


def projected_models():
    raw = overview_fixture()

    def project(overview, selected_id):
        # The production view adds observed_at after the pure projection too.
        return {**build_topology(overview, selected_id), "observed_at": OBSERVED_AT}

    ids = ["hub", *(f"{node['kind']}:{node['name']}" for node in raw["nodes"])]
    models = {identifier: project(raw, identifier) for identifier in ids}
    missing = copy.deepcopy(raw)
    missing.pop("topology_context")
    return {"generated_by": "dashboard.topology.build_topology", "models": models,
            "missing_context": project(missing, PHONE_ALL), "initial_selected": PHONE_ALL}


class TopologyPermissionsFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = projected_models()
        cls.all_model = cls.packet["models"][PHONE_ALL]
        cls.port_model = cls.packet["models"][PHONE_PORTS]

    def test_realistic_inventory_has_seven_awg_four_vless_and_hub(self):
        self.assertEqual(len(self.all_model["nodes"]), 12)
        self.assertEqual(self.all_model["summary"]["awg"], 7)
        self.assertEqual(self.all_model["summary"]["vless"], 4)

    def test_all_phone_projects_eight_full_scope_directions(self):
        links = [link for link in self.all_model["links"] if link["source"] == PHONE_ALL]
        self.assertEqual(len(links), 8)
        self.assertEqual({link["target"] for link in links}, {node["id"] for node in self.all_model["nodes"] if node["kind"] in {"hub", "awg"}})
        self.assertTrue(all(link["status"] == "allowed" and link["scopes"] == ALL_SCOPE for link in links))

    def test_all_network_includes_known_hub_and_subsumes_specific_hub_ports(self):
        hub = next(relation for relation in self.all_model["relations"] if relation["node"]["id"] == "hub")
        self.assertEqual(hub["forward"]["status"], "allowed")
        self.assertEqual(hub["forward"]["scopes"], ALL_SCOPE)

    def test_phone_cannot_be_an_inbound_network_target(self):
        self.assertTrue(all(relation["reverse"]["status"] == "not_applicable" for relation in self.all_model["relations"]))
        self.assertFalse(any(link["target"] == PHONE_ALL for link in self.all_model["links"]))

    def test_known_hub_tcp_udp_ranges_remain_partial(self):
        links = [link for link in self.port_model["links"] if link["source"] == PHONE_PORTS]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["target"], "hub")
        self.assertEqual(links[0]["status"], "partial")
        self.assertEqual(links[0]["scopes"], PARTIAL_SCOPES)

    def test_missing_facts_do_not_convert_saved_cidr_into_confirmed_access(self):
        model = self.packet["missing_context"]
        self.assertFalse(any(link["source"] == PHONE_ALL for link in model["links"]))
        self.assertTrue(all(relation["forward"]["status"] == "unknown" for relation in model["relations"] if relation["node"]["kind"] in {"hub", "awg"}))

    def test_disabled_vless_and_credentials_do_not_leak_into_confirmed_links(self):
        self.assertFalse(any(link["source"] == "vless:phone-disabled" for link in self.all_model["links"]))
        serialized = json.dumps(self.packet, ensure_ascii=False)
        self.assertNotIn(SECRET_SENTINEL, serialized)
        self.assertNotIn("vless://", serialized)


if __name__ == "__main__":
    if "--json" in sys.argv:
        print(json.dumps(projected_models(), ensure_ascii=False))
    else:
        unittest.main()

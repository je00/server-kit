#!/usr/bin/env python3
"""验证普通 AWG 节点默认互通，并仅在显式受限后生成拦截规则。"""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

from lib.awg_access import PolicyError, change, commit, forget, render_nft


class AwgAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.active = self.root / "awg-access.json"
        self.pending = self.root / "awg-access.pending.json"
        self.peers = self.root / "peers.tsv"
        self.output = self.root / "rules.nft"
        self.peers.write_text(
            "desk\t10.20.0.10\nphone\t10.20.0.11\n",
            encoding="utf-8",
        )

    def common(self, **values: object) -> argparse.Namespace:
        return argparse.Namespace(
            active=self.active,
            pending=self.pending,
            peers=self.peers,
            server_ip="10.20.0.1",
            network_cidr="10.20.0.0/24",
            **values,
        )

    def render(self, policy: dict) -> str:
        self.active.write_text(json.dumps(policy), encoding="utf-8")
        render_nft(self.common(
            policy=self.active,
            iface="awg0",
            public_ports="52114,1848,8443",
            output=self.output,
        ))
        return self.output.read_text(encoding="utf-8")

    def test_missing_policy_keeps_all_nodes_and_ports_unrestricted(self) -> None:
        rendered = self.render({"version": 1, "clients": {}})
        self.assertIn('iifname "awg0" oifname "awg0" counter accept', rendered)
        self.assertNotIn("限制 desk", rendered)
        self.assertNotIn("限制 phone", rendered)

    def test_restricted_node_allows_saved_ports_then_drops_other_access(self) -> None:
        rendered = self.render({"version": 1, "clients": {
            "desk": {"mode": "restricted", "allow": [
                {"target": "phone", "ip": "10.20.0.99", "ports": [22, 443], "network": "tcp"},
                {"target": "vps", "ip": "192.0.2.1", "ports": [9080], "network": "tcp"},
            ]},
        }})
        self.assertIn("ip saddr 10.20.0.10 ip daddr 10.20.0.11 tcp dport { 22, 443 }", rendered)
        self.assertIn("ip saddr 10.20.0.10 ip daddr 10.20.0.1 tcp dport { 9080 }", rendered)
        self.assertIn('ip saddr 10.20.0.10 counter drop comment "server-kit 限制 desk 横向访问"', rendered)
        self.assertIn('ip daddr 10.20.0.1 counter drop comment "server-kit 限制 desk 访问 VPS"', rendered)
        self.assertLess(
            rendered.index("ct state established,related counter accept"),
            rendered.index('comment "server-kit 限制 desk 访问 VPS"'),
        )

    def test_unrestricted_mode_ignores_saved_allow_list(self) -> None:
        rendered = self.render({"version": 1, "clients": {
            "desk": {"mode": "unrestricted", "allow": [
                {"target": "phone", "ip": "10.20.0.11", "ports": [22], "network": "tcp"},
            ]},
        }})
        self.assertNotIn("desk -> phone", rendered)
        self.assertNotIn("限制 desk", rendered)

    def test_policy_changes_are_pending_until_commit(self) -> None:
        change(self.common(operation="allow", client="desk", arguments=["phone", "22,443", "tcp"]))
        self.assertFalse(self.active.exists())
        pending = json.loads(self.pending.read_text(encoding="utf-8"))
        self.assertEqual(pending["clients"]["desk"]["mode"], "unrestricted")
        change(self.common(operation="mode", client="desk", arguments=["restricted"]))
        commit(self.common())
        active = json.loads(self.active.read_text(encoding="utf-8"))
        self.assertEqual(active["clients"]["desk"]["mode"], "restricted")
        self.assertFalse(self.pending.exists())

    def test_all_nodes_can_use_specific_ports(self) -> None:
        change(self.common(operation="allow", client="desk", arguments=["all", "22,443", "tcp"]))
        change(self.common(operation="mode", client="desk", arguments=["restricted"]))
        commit(self.common())
        active = json.loads(self.active.read_text(encoding="utf-8"))
        self.assertEqual(active["clients"]["desk"]["mode"], "restricted")
        self.assertEqual(active["clients"]["desk"]["allow"], [{
            "target": "all", "ip": "10.20.0.0/24", "ports": [22, 443],
            "network": "tcp",
        }])
        rendered = self.render(active)
        self.assertEqual(rendered.count("ip daddr 10.20.0.0/24 tcp dport { 22, 443 }"), 2)

    def test_same_target_rules_append_and_can_be_deleted_exactly(self) -> None:
        change(self.common(operation="allow", client="desk", arguments=["phone", "22", "tcp"]))
        change(self.common(operation="allow", client="desk", arguments=["phone", "53", "udp"]))
        change(self.common(operation="deny", client="desk", arguments=["phone", "22", "tcp"]))
        commit(self.common())
        active = json.loads(self.active.read_text(encoding="utf-8"))
        self.assertEqual(active["clients"]["desk"]["allow"], [{
            "target": "phone", "ip": "10.20.0.11", "ports": [53],
            "network": "udp",
        }])

    def test_specific_node_can_use_all_ports(self) -> None:
        change(self.common(operation="allow", client="desk", arguments=["phone"]))
        change(self.common(operation="mode", client="desk", arguments=["restricted"]))
        commit(self.common())
        rendered = self.render(json.loads(self.active.read_text(encoding="utf-8")))
        self.assertIn("ip daddr 10.20.0.11 counter accept", rendered)
        self.assertNotIn("desk -> phone\" tcp dport", rendered)

    def test_self_target_is_rejected(self) -> None:
        with self.assertRaisesRegex(PolicyError, "自身"):
            change(self.common(operation="allow", client="desk", arguments=["desk", "22", "tcp"]))

    def test_forget_makes_reused_name_default_to_unrestricted(self) -> None:
        self.active.write_text(json.dumps({"version": 1, "clients": {
            "desk": {"mode": "restricted", "allow": []},
            "phone": {"mode": "restricted", "allow": [{
                "target": "desk", "ip": "10.20.0.10", "ports": [22],
                "network": "tcp",
            }]},
        }}), encoding="utf-8")
        forget(self.common(client="desk"))
        commit(self.common())
        active = json.loads(self.active.read_text(encoding="utf-8"))
        self.assertNotIn("desk", active["clients"])
        self.assertEqual(active["clients"]["phone"]["allow"], [])


if __name__ == "__main__":
    unittest.main()

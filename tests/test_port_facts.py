#!/usr/bin/env python3
"""验证端口事实 module 的采集、投影和安全边界。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lib.server_kit_port_facts import (
    PortFacts,
    PortFactsError,
    PortFactSources,
    compact_ports,
)


class MemoryObservationAdapter:
    """测试使用的主机观察 adapter。"""

    def __init__(self, sockets: list[dict[str, object]]) -> None:
        self._sockets = sockets

    def sockets(self) -> list[dict[str, object]]:
        return list(self._sockets)

    def unit_states(self, units):
        return {unit: {"enabled": True, "active": True} for unit in units}


class PortFactsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.sources = PortFactSources(
            security=root / "security.json",
            awg=root / "awg.conf",
            mosh=root / "mosh.conf",
            management=root / "management.conf",
            xray=root / "xray.json",
            file_service=root / "file.json",
            clash_service=root / "clash.json",
        )
        self.sources.security.write_text(json.dumps({"ssh": {
            "public_address": "203.0.113.10", "public_port": 62222,
            "public_bind_address": "0.0.0.0",
            "amneziawg_address": "10.20.0.1", "amneziawg_port": 22,
        }}), encoding="utf-8")
        self.sources.awg.write_text(
            "AWG_IFACE=awg0\nAWG_SERVER_IP=10.20.0.1\n"
            "AWG_SUBNET_CIDR=10.20.0.0/24\nAWG_PRIMARY_PORT=443\n"
            "AWG_BACKUP_PORT1=1848\nAWG_BACKUP_PORT2=\n",
            encoding="utf-8",
        )
        self.sources.mosh.write_text(
            "MOSH_ENABLED=yes\nMOSH_BIND_IP=10.20.0.1\nMOSH_INTERFACE=awg0\n"
            "MOSH_SUBNET_CIDR=10.20.0.0/24\nMOSH_PORT_START=60001\nMOSH_PORT_END=60010\n",
            encoding="utf-8",
        )
        self.sources.management.write_text(
            "MANAGEMENT_ENABLED=yes\nMANAGEMENT_AWG_IP=10.20.0.1\nMANAGEMENT_PORT=9080\n",
            encoding="utf-8",
        )
        self.sources.xray.write_text(json.dumps({"inbounds": [{
            "listen": "0.0.0.0", "port": 443, "protocol": "vless",
            "streamSettings": {"network": "tcp", "realitySettings": {"target": "www.cloudflare.com:443"}},
        }]}), encoding="utf-8")
        self.sources.clash_service.write_text(json.dumps({"port": 52541}), encoding="utf-8")

    def collect(self) -> PortFacts:
        sockets = [
            {"protocol": "tcp", "address": "0.0.0.0", "port": 62222, "process": "sshd"},
            {"protocol": "tcp", "address": "10.20.0.1", "port": 22, "process": "sshd"},
            {"protocol": "tcp", "address": "0.0.0.0", "port": 443, "process": "xray"},
            {"protocol": "tcp", "address": "0.0.0.0", "port": 52541, "process": "python3"},
            {"protocol": "udp", "address": "0.0.0.0", "port": 443, "process": "awg"},
            {"protocol": "tcp", "address": "10.20.0.1", "port": 9080, "process": "gunicorn"},
            {"protocol": "tcp", "address": "0.0.0.0", "port": 14525, "process": "other"},
        ]
        return PortFacts.collect(self.sources, MemoryObservationAdapter(sockets))

    def test_collects_once_and_projects_consistent_service_and_firewall_views(self) -> None:
        facts = self.collect()
        self.assertEqual(facts.service_summaries()["server-kit-mosh"], "UDP 60001-60010 · AWG 内网 · 按需")
        rows = facts.firewall_rows()
        self.assertIn(("内网入口", "AWG", "UDP", "60001-60010"), rows)
        self.assertEqual(facts.unmanaged[0]["port"], 14525)

    def test_optional_second_backup_is_not_required(self) -> None:
        facts = self.collect()
        self.assertNotIn("amneziawg-backup2", {item["id"] for item in facts.listeners})
        rules = facts.render_nft(
            "eth0", "203.0.113.10", "awg0", "10.20.0.1", "10.20.0.0/24"
        )
        self.assertIn("1848", rules)
        self.assertNotIn("8443", rules)

    def test_public_rules_follow_interface_and_ports_without_pinning_public_ipv4(self) -> None:
        rules = self.collect().render_nft(
            "eth0", "203.0.113.10", "awg0", "10.20.0.1", "10.20.0.0/24"
        )
        self.assertIn('meta nfproto ipv4 iifname "eth0" tcp dport @public_tcp_ports', rules)
        self.assertIn('meta nfproto ipv4 iifname "eth0" udp dport @public_udp_ports', rules)
        self.assertNotIn('meta nfproto ipv6 iifname "eth0"', rules)
        self.assertNotIn("ip daddr 203.0.113.10", rules)

    def test_shadowsocks_xray_inbound_manages_tcp_and_udp(self) -> None:
        self.sources.xray.write_text(json.dumps({"inbounds": [{
            "tag": "server-kit-relay",
            "listen": "0.0.0.0",
            "port": 2083,
            "protocol": "shadowsocks",
            "settings": {"network": "tcp,udp"},
        }]}), encoding="utf-8")
        sockets = [
            {"protocol": "tcp", "address": "0.0.0.0", "port": 2083, "process": "xray"},
            {"protocol": "udp", "address": "0.0.0.0", "port": 2083, "process": "xray"},
        ]
        facts = PortFacts.collect(self.sources, MemoryObservationAdapter(sockets))
        relay = {item["id"]: item for item in facts.listeners if item["port"] == 2083}
        self.assertEqual(set(relay), {"xray-0-tcp", "xray-0-udp"})
        self.assertTrue(all(item["listening"] for item in relay.values()))
        sets = facts.firewall_sets()
        self.assertIn(2083, sets[("public", "TCP")])
        self.assertIn(2083, sets[("public", "UDP")])

    def test_legacy_document_is_normalized_but_unknown_schema_is_rejected(self) -> None:
        legacy = PortFacts({
            "policy": {"unmanaged_firewall_action": "deny_by_default"},
            "listeners": [{
                "protocol": "tcp", "port": 22, "exposure": "amneziawg",
                "enabled": True, "service_active": True, "listening": True,
            }],
            "observed_unmanaged": [],
        })
        self.assertEqual(legacy.document["schema_version"], 1)
        with self.assertRaises(PortFactsError):
            PortFacts({"schema_version": 9})

    def test_port_range_compaction_is_stable(self) -> None:
        self.assertEqual(compact_ports({60003, 60001, 60002, 62222}), "60001-60003/62222")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""验证专用服务清单只返回管理页面需要的脱敏字段。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lib.server_kit_inventory import InventoryPaths, RuntimeFacts, build_inventory


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.paths = InventoryPaths(
            vless=root / "vless.json",
            clash=root / "clash.json",
            file=root / "file.json",
            mosh=root / "mosh.conf",
            awg=root / "awg.conf",
            awg_peers=root / "peers.tsv",
            management=root / "management.conf",
            ports=root / "ports.json",
            firewall_active=root / "firewall.nft",
            firewall_candidate=root / "firewall-candidate.nft",
            firewall_transaction=root / "firewall-transaction.json",
            ssh_auth=root / "ssh-auth.conf",
        )

    def write_json(self, path: Path, value: object) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_vless_inventory_hides_uuid_and_only_counts_access_rules(self) -> None:
        self.write_json(
            self.paths.vless,
            {
                "version": 1,
                "clients": {
                    "home-iphone": {
                        "email": "server-kit-vless:home-iphone",
                        "uuid": "secret-vless-uuid",
                        "enabled": True,
                        "allow": [{"cidr": "10.20.0.0/24"}, {"port": 22}],
                    }
                },
            },
        )
        inventory = build_inventory("vless", self.paths, mosh_sessions=0)
        encoded = json.dumps(inventory)
        self.assertNotIn("secret-vless-uuid", encoded)
        self.assertEqual(
            inventory["items"],
            [{"name": "home-iphone", "state": "已启用", "detail": "2 条访问授权"}],
        )

    def test_vless_inventory_compacts_continuous_permission_ports(self) -> None:
        self.write_json(self.paths.vless, {"clients": {"phone": {
            "enabled": True,
            "allow": [{"target": "vps", "network": "udp", "ports": list(range(60001, 60011))}],
        }}})
        inventory = build_inventory("vless", self.paths, mosh_sessions=0)
        self.assertEqual(inventory["items"][0]["detail"], "vps · UDP 60001-60010")

    def test_legacy_single_file_config_is_still_listed(self) -> None:
        self.write_json(
            self.paths.file,
            {"download_name": "shared_file.yaml", "file_size": 1536, "token": "secret"},
        )
        inventory = build_inventory("file", self.paths, mosh_sessions=0)
        self.assertEqual(inventory["facts"]["文件数量"], "1")
        self.assertEqual(inventory["items"][0]["name"], "shared_file.yaml")
        self.assertNotIn("secret", json.dumps(inventory))

    def test_clash_inventory_hides_tokens_paths_and_full_hashes(self) -> None:
        self.write_json(
            self.paths.clash,
            {
                "port": 52541,
                "server_address": "203.0.113.10",
                "downloads": [
                    {
                        "download_name": "home.yaml",
                        "peer_name": "home-desk",
                        "node_kind": "awg",
                        "file_size": 2048,
                        "sha256": "a" * 64,
                        "token": "secret-download-token",
                        "payload_path": "/secret/payload.yaml",
                    }
                ],
            },
        )
        inventory = build_inventory("clash", self.paths, mosh_sessions=0)
        encoded = json.dumps(inventory)
        self.assertNotIn("secret-download-token", encoded)
        self.assertNotIn("/secret/payload.yaml", encoded)
        self.assertNotIn("a" * 64, encoded)
        self.assertEqual(inventory["items"][0]["name"], "home-desk")
        self.assertEqual(inventory["items"][0]["resource_id"], "home-desk")
        self.assertEqual(inventory["items"][0]["detail"], "home.yaml · AmneziaWG · 2.0 KiB")

    def test_mosh_inventory_exposes_only_operational_facts(self) -> None:
        self.paths.mosh.write_text(
            "MOSH_ENABLED=yes\nMOSH_PORT_START=60001\nMOSH_PORT_END=60010\n",
            encoding="utf-8",
        )
        mosh = build_inventory("mosh", self.paths, mosh_sessions=3)
        self.assertEqual(mosh["facts"]["活动会话"], "3")
        self.assertEqual(mosh["facts"]["UDP 范围"], "60001-60010")

    def test_missing_file_service_returns_empty_safe_inventory(self) -> None:
        inventory = build_inventory("file", self.paths, mosh_sessions=0)
        self.assertEqual(inventory["items"], [])
        self.assertEqual(inventory["facts"], {"配置状态": "未配置"})

    def test_firewall_inventory_shows_effective_policy_without_source_paths(self) -> None:
        self.write_json(
            self.paths.ports,
            {
                "policy": {"unmanaged_firewall_action": "deny_by_default"},
                "observed_unmanaged": [
                    {"exposure": "loopback"},
                    {"exposure": "public"},
                ],
            },
        )
        self.paths.firewall_active.write_text(
            """table inet server_kit_filter {
  set public_tcp_ports {
    type inet_service
    elements = { 443, 52541, 62222 }
  }
  set public_udp_ports {
    type inet_service
    elements = { 443, 1848, 8443 }
  }
  set awg_tcp_ports {
    type inet_service
    elements = { 22, 9080 }
  }
  set awg_udp_ports {
    type inet_service
    elements = { 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010 }
  }
  chain input {
    type filter hook input priority 10; policy drop;
  }
}
""",
            encoding="utf-8",
        )
        inventory = build_inventory("firewall", self.paths, mosh_sessions=0)
        self.assertEqual(inventory["facts"]["方案"], "nftables 独立 inet 规则表")
        self.assertEqual(inventory["facts"]["当前状态"], "已生效")
        self.assertEqual(inventory["facts"]["未托管外部监听"], "1")
        self.assertIn(
            {"name": "内网入口", "state": "60001-60010", "detail": "AWG 内网 · UDP"},
            inventory["items"],
        )
        self.assertNotIn(str(self.paths.firewall_active), json.dumps(inventory))

    def test_awg_management_ssh_and_certificate_have_safe_details(self) -> None:
        self.paths.awg.write_text(
            "AWG_IFACE=awg0\nAWG_SUBNET_CIDR=10.20.0.0/24\nAWG_SERVER_IP=10.20.0.1\n"
            "AWG_PRIMARY_PORT=443\nAWG_BACKUP_PORT1=8443\nAWG_BACKUP_PORT2=1848\nAWG_MTU=1280\n"
            "AWG_H1=secret-obfuscation-value\n",
            encoding="utf-8",
        )
        self.paths.awg_peers.write_text("home-desk\t10.20.0.101\n", encoding="utf-8")
        self.paths.management.write_text(
            "MANAGEMENT_AWG_IP=10.20.0.1\nMANAGEMENT_PORT=9080\nMANAGEMENT_ADMIN_PEER=home-desk\n",
            encoding="utf-8",
        )
        self.write_json(
            self.paths.ports,
            {
                "listeners": [
                    {
                        "service": "ssh.service",
                        "protocol": "tcp",
                        "port": 22,
                        "exposure": "amneziawg",
                        "bind_addresses": ["10.20.0.1"],
                        "purpose": "AmneziaWG 内网 SSH",
                        "listening": True,
                    }
                ]
            },
        )
        self.paths.ssh_auth.write_text(
            "PubkeyAuthentication yes\nPasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n"
            "AuthenticationMethods publickey\n",
            encoding="utf-8",
        )
        runtime = RuntimeFacts(
            cert_timer_state="active",
            cert_next_run="Fri 2026-08-07 12:31:08 UTC",
            cert_last_run="Fri 2026-08-07 00:49:10 UTC",
        )
        awg = build_inventory("amneziawg", self.paths, 0, runtime)
        management = build_inventory("management", self.paths, 0, runtime)
        ssh = build_inventory("ssh", self.paths, 0, runtime)
        cert = build_inventory("cert-renew", self.paths, 0, runtime)
        self.assertEqual(awg["items"][0]["name"], "home-desk")
        self.assertNotIn("secret-obfuscation-value", json.dumps(awg))
        self.assertEqual(management["facts"]["访问范围"], "仅 AWG 内网")
        self.assertEqual(ssh["facts"]["登录认证"], "仅 SSH 公钥")
        self.assertEqual(ssh["items"][0]["state"], "监听中")
        self.assertEqual(cert["facts"]["定时器"], "已启用")

    def test_all_registered_services_have_nonempty_fact_summary(self) -> None:
        runtime = RuntimeFacts(cert_timer_state="active")
        service_ids = (
            "amneziawg", "management", "vless", "clash", "file",
            "mosh", "cert-renew", "firewall", "ssh",
        )
        for service_id in service_ids:
            with self.subTest(service_id=service_id):
                inventory = build_inventory(service_id, self.paths, 0, runtime)
                self.assertTrue(inventory["facts"])


if __name__ == "__main__":
    unittest.main()

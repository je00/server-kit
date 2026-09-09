#!/usr/bin/env python3
"""验证安全事务模型只返回结构化事实和准确回滚窗口。"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from lib.server_kit_transactions import TransactionPaths, build_transaction_snapshot


class TransactionSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.paths = TransactionPaths(
            root / "ssh-auth.conf", root / "ssh-auth-transaction.json",
            root / "active.nft", root / "candidate.nft", root / "firewall-transaction.json",
            root / "ports.json", root / "security.json", root / "ssh-transaction.json",
        )

    def test_ssh_auth_pending_state_has_countdown_and_no_backup_path(self) -> None:
        self.paths.ssh_auth_config.write_text("PasswordAuthentication yes\n", encoding="utf-8")
        self.paths.ssh_auth_transaction.write_text(json.dumps({
            "created_at": "2026-08-07T12:00:00+00:00", "backup_path": "/secret/path"
        }), encoding="utf-8")
        result = build_transaction_snapshot(
            "ssh_auth", self.paths, True, datetime(2026, 8, 7, 12, 2, tzinfo=timezone.utc)
        )
        self.assertEqual(result["state"], "pending")
        self.assertEqual(result["remaining_seconds"], 180)
        self.assertNotIn("secret", json.dumps(result))

    def test_firewall_preview_compares_only_managed_port_sets(self) -> None:
        self.paths.firewall_active.write_text("set public_tcp_ports {\n elements = { 443, 62222 }\n }\nset awg_udp_ports {\n elements = { 60001, 60002, 60003 }\n }\n", encoding="utf-8")
        self.paths.firewall_candidate.write_text("set public_tcp_ports {\n elements = { 443, 52541, 62222 }\n }\nset awg_udp_ports {\n elements = { 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010 }\n }\n", encoding="utf-8")
        result = build_transaction_snapshot("firewall", self.paths, False)
        public_tcp = result["changes"][0]
        self.assertEqual(public_tcp["current"], "443/62222")
        self.assertEqual(public_tcp["target"], "443/52541/62222")
        self.assertTrue(public_tcp["changed"])
        awg_udp = result["changes"][3]
        self.assertEqual(awg_udp["current"], "60001-60003")
        self.assertEqual(awg_udp["target"], "60001-60010")
        self.assertFalse(result["writes_enabled"])
        self.assertTrue(result["ready"])

    def test_unmanaged_external_listener_blocks_firewall_apply(self) -> None:
        self.paths.firewall_candidate.write_text("table inet server_kit_filter {}\n", encoding="utf-8")
        self.paths.ports.write_text(json.dumps({"observed_unmanaged": [
            {"protocol": "tcp", "address": "0.0.0.0", "port": 14525, "process": "docker-proxy", "exposure": "public"},
            {"protocol": "tcp", "address": "127.0.0.1", "port": 25, "process": "mail", "exposure": "loopback"},
        ]}), encoding="utf-8")
        result = build_transaction_snapshot("firewall", self.paths, True)
        self.assertFalse(result["ready"])
        self.assertEqual(result["blockers"], ["TCP 0.0.0.0:14525 · docker-proxy · 未托管监听"])

    def test_ssh_listener_preview_keeps_awg_22_and_validates_public_port(self) -> None:
        self.paths.ssh_security.write_text(json.dumps({
            "ssh": {
                "public_address": "203.0.113.9", "public_port": 62000,
                "amneziawg_address": "10.20.0.1",
            }
        }), encoding="utf-8")
        result = build_transaction_snapshot(
            "ssh_listener", self.paths, True,
            public_ip="203.0.113.10", public_port="62222",
        )
        self.assertTrue(result["ready"])
        self.assertEqual(result["changes"][1]["target"], "62222")
        self.assertEqual(result["changes"][2]["current"], "22")
        blocked = build_transaction_snapshot(
            "ssh_listener", self.paths, True,
            public_ip="203.0.113.10", public_port="50800",
        )
        self.assertFalse(blocked["ready"])
        self.assertIn("临时端口", blocked["blockers"][0])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""验证统一节点视图只返回脱敏状态，并正确识别待同步差异。"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path
from unittest.mock import patch

from lib.server_kit_network import NetworkPaths, build_overview, clean_permissions


class NetworkOverviewTests(unittest.TestCase):
    def test_topology_context_uses_explicit_paths_without_reading_default_host_files(self) -> None:
        context = {"hub_address": "10.77.0.1", "vless_networks": {"phone": "10.77.0.0/24"}}
        with patch("lib.server_kit_network.collect_topology_context", return_value=context) as collect:
            result = build_overview(self.paths, False)
        self.assertEqual(result["topology_context"], context)
        collect.assert_called_once_with(None, None, json.loads(self.paths.vless_active.read_text())["clients"])

    def test_cli_accepts_old_arguments_and_explicit_read_only_fact_paths(self) -> None:
        root = Path(self.temporary.name)
        state = root / "awg-state.conf"
        state.write_text("AWG_SERVER_IP='10.77.0.1'\nAWG_SUBNET_CIDR='10.88.0.0/24'\n")
        xray = root / "xray.json"
        xray.write_text("{}")
        base = [sys.executable, str(Path(__file__).resolve().parents[1] / "lib/server_kit_network.py"),
                *(str(getattr(self.paths, field.name)) for field in fields(self.paths)[:13]), "0"]
        before = {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()}
        for extra, hub in (([], ""), ([str(state), str(xray)], "10.77.0.1")):
            with self.subTest(extra=extra):
                result = subprocess.run(base + extra, text=True, capture_output=True, check=True, timeout=10)
                value = json.loads(result.stdout)
                self.assertEqual(value["topology_context"], {"hub_address": hub, "vless_networks": {}})
                self.assertFalse(value["writes_enabled"])
        self.assertEqual(before, {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()})

    def test_port_ranges_are_displayed_compactly_without_changing_stored_ports(self) -> None:
        ports = [22, *range(8000, 8011)]
        permission = clean_permissions([{"target": "vps", "ip": "10.20.0.1", "network": "tcp", "ports": ports}])[0]
        self.assertEqual(permission["ports"], ports)
        self.assertEqual(permission["ports_label"], "22, 8000-8010")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.paths = NetworkPaths(
            root / "active.tsv", root / "disabled.tsv",
            root / "credentials.tsv",
            root / "enrollments.json",
            root / "awg-access.json", root / "awg-access.pending.json",
            root / "vless.json",
            root / "vless.pending.json", root / "clash.json", root / "publications.json",
            root / "node-domains.json",
            root / "clash-inputs.json",
            root / "management.conf",
        )
        self.paths.clash_inputs.write_text(json.dumps({
            "version": 4, "airports": [], "default_exit_id": "111111111111",
            "awg_exit_selections": {}, "exits": [{
                "id": "111111111111", "name": "默认出口", "proxy": {
                    "name": "EXIT.111111111111", "type": "socks5",
                    "server": "exit.test", "port": 1080, "dialer-proxy": "MID",
                },
            }],
        }), encoding="utf-8")
        self.paths.publication_state.write_text(
            '{"version":1,"disabled":[],"clean_mode":["iphone"]}\n', encoding="utf-8"
        )
        self.paths.management.write_text(
            "MANAGEMENT_ADMIN_PEER=desk\nMANAGEMENT_PORT=9080\n", encoding="utf-8"
        )
        self.paths.node_domains.write_text(
            '{"version":1,"nodes":{"desk":["nas.internal.example"]},'
            '"addresses":{"192.168.0.103":["git.example.com"]}}\n', encoding="utf-8"
        )
        self.paths.awg_active.write_text("desk\t10.20.0.10\n", encoding="utf-8")
        self.paths.awg_disabled.write_text("old-phone\t10.20.0.11\n", encoding="utf-8")
        self.paths.awg_credentials.write_text(
            "desk\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t"
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\tclient\n",
            encoding="utf-8",
        )
        self.paths.awg_enrollments.write_text('{"schema_version":1,"items":{}}\n', encoding="utf-8")
        self.paths.vless_active.write_text(json.dumps({"clients": {
            "iphone": {"uuid": "secret-uuid", "enabled": True, "legacy_stash": True, "allow": [
                {"target": "desk", "ip": "10.20.0.10", "ports": [22, 443], "network": "tcp"}
            ]},
            "ipad": {"uuid": "another-secret", "enabled": False, "allow": []},
        }}), encoding="utf-8")
        self.paths.clash.write_text(json.dumps({
            "mode": "clash", "server_address": "example", "port": 443,
            "downloads": [
                {"peer_name": "desk", "node_kind": "awg", "token": "secret-token"},
                {"peer_name": "ipad", "node_kind": "vless", "token": "stale-token"},
            ],
        }), encoding="utf-8")

    def test_overview_marks_enabled_and_disabled_publication_differences(self) -> None:
        result = build_overview(self.paths, True)
        states = {item["name"]: item["publication_state"] for item in result["nodes"]}
        self.assertEqual(states["desk"], "已发布")
        self.assertEqual(states["iphone"], "待同步")
        self.assertEqual(states["ipad"], "待同步移除")
        self.assertTrue(result["sync_available"])
        self.assertEqual(result["summary"]["stale"], 2)
        desk = next(item for item in result["nodes"] if item["name"] == "desk")
        iphone = next(item for item in result["nodes"] if item["name"] == "iphone")
        self.assertTrue(desk["protected"])
        self.assertEqual(desk["custody"], "client")
        self.assertEqual(iphone["custody"], "")
        self.assertTrue(iphone["legacy_stash"])
        self.assertFalse(desk["legacy_stash"])
        self.assertTrue(iphone["clean_mode"])
        self.assertFalse(desk["clean_mode"])
        self.assertNotIn("custody_label", desk)
        self.assertNotIn("custody_label", iphone)
        self.assertRegex(desk["public_key_fingerprint"], r"^[0-9a-f]{16}$")
        self.assertEqual(desk["access_mode"], "unrestricted")
        self.assertEqual(desk["domains"], ["nas.internal.example"])
        self.assertEqual(desk["exit_ids"], ["111111111111"])
        self.assertEqual(desk["exit_names"], ["默认出口"])
        self.assertEqual(iphone["exit_ids"], ["111111111111"])
        self.assertEqual(iphone["exit_names"], ["默认出口"])
        self.assertEqual(result["exit_options"][0]["default"], True)
        self.assertEqual(result["host_records"], [{
            "address": "192.168.0.103", "domains": ["git.example.com"],
        }])
        self.assertEqual(desk["permissions"][0], {
            "target": "all", "target_label": "全部节点", "ip": "",
            "ports": [], "ports_label": "全部端口", "network": "all",
            "network_label": "全部协议",
        })
        self.assertEqual(result["management_port"], 9080)
        self.assertFalse(result["pending_access"])
        self.assertEqual(iphone["permissions"][0]["ports_label"], "22, 443")
        self.assertEqual(result["targets"][0], {
            "name": "all", "label": "全部节点",
        })
        self.assertIn({"name": "desk", "label": "desk · 10.20.0.10"}, result["targets"])

    def test_awg_access_policy_is_visible_but_defaults_to_unrestricted(self) -> None:
        self.paths.awg_access.write_text(json.dumps({"version": 1, "clients": {
            "desk": {"mode": "restricted", "allow": [{
                "target": "vps", "ip": "10.20.0.1", "ports": [22, 9080],
                "network": "tcp",
            }]},
        }}), encoding="utf-8")
        self.paths.awg_access_pending.write_text("{}\n", encoding="utf-8")
        result = build_overview(self.paths, True)
        desk = next(item for item in result["nodes"] if item["name"] == "desk")
        self.assertEqual(desk["access_mode"], "restricted")
        self.assertEqual(desk["permissions"][0]["target"], "vps")
        self.assertTrue(result["pending_access"])

    def test_overview_never_exposes_tokens_or_client_ids(self) -> None:
        encoded = json.dumps(build_overview(self.paths, True), ensure_ascii=False)
        self.assertNotIn("secret-token", encoded)
        self.assertNotIn("secret-uuid", encoded)
        self.assertNotIn("another-secret", encoded)
        self.assertNotIn("BBBBBBBBBBBBBBBB", encoded)

    def test_disabled_publication_does_not_disable_node(self) -> None:
        self.paths.publication_state.write_text(
            '{"version":1,"disabled":["iphone"]}\n', encoding="utf-8"
        )
        self.paths.clash.write_text(json.dumps({
            "mode": "clash", "server_address": "example", "port": 443,
            "downloads": [
                {"peer_name": "desk", "node_kind": "awg", "token": "secret-token"},
            ],
        }), encoding="utf-8")
        result = build_overview(self.paths, True)
        iphone = next(item for item in result["nodes"] if item["name"] == "iphone")
        control = next(item for item in result["subscription_items"] if item["name"] == "iphone")
        self.assertEqual(iphone["state"], "已启用")
        self.assertEqual(control["state"], "发布已停用")
        self.assertFalse(control["published"])
        self.assertEqual(result["summary"]["stale"], 0)

    def test_orphan_publication_is_counted_once(self) -> None:
        self.paths.clash.write_text(json.dumps({
            "mode": "clash", "server_address": "example", "port": 443,
            "downloads": [
                {"peer_name": "desk", "node_kind": "awg", "token": "secret-token"},
                {"peer_name": "removed", "node_kind": "awg", "token": "stale-token"},
            ],
        }), encoding="utf-8")
        result = build_overview(self.paths, True)
        self.assertEqual(result["summary"]["stale"], 2)

    def test_pending_first_handshake_is_visible_without_key_material(self) -> None:
        self.paths.awg_enrollments.write_text(json.dumps({
            "schema_version": 1,
            "items": {"desk": {
                "public_key": "A" * 43 + "=", "created_epoch": 1_800_000_000,
                "expires_epoch": 1_800_000_300,
            }},
        }), encoding="utf-8")
        result = build_overview(self.paths, True)
        desk = next(item for item in result["nodes"] if item["name"] == "desk")
        self.assertEqual(desk["state"], "等待首次握手")
        self.assertEqual(result["summary"]["pending_enrollment"], 1)
        self.assertNotIn("A" * 43 + "=", json.dumps(result))

if __name__ == "__main__":
    unittest.main()

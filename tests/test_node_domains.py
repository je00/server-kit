#!/usr/bin/env python3
"""验证订阅强制解析记录的校验与原子持久化。"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from lib.server_kit_node_domains import (
    NodeDomainError, load_address_state, load_state, set_address_domains, set_domains,
)


class NodeDomainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "node-domains.json"
        self.active = self.root / "peers.tsv"
        self.disabled = self.root / "peers.disabled.tsv"
        self.active.write_text(
            "home-nas\t10.20.0.103\nhome-desk\t10.20.0.101\n", encoding="utf-8"
        )
        self.disabled.write_text("", encoding="utf-8")

    def test_set_normalizes_domains_and_empty_list_clears_mapping(self) -> None:
        result = set_domains(
            self.config, self.active, self.disabled, "home-nas",
            ["NAS.INTERNAL.EXAMPLE.", "git.example.com", "git.example.com"],
        )
        self.assertEqual(result["address"], "10.20.0.103")
        self.assertEqual(result["domains"], ["nas.internal.example", "git.example.com"])
        if os.name != "nt":
            self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(load_state(self.config)["home-nas"], result["domains"])
        set_domains(self.config, self.active, self.disabled, "home-nas", [])
        self.assertEqual(load_state(self.config), {})

    def test_rejects_unknown_node_invalid_domain_and_duplicate_owner(self) -> None:
        with self.assertRaisesRegex(NodeDomainError, "现有"):
            set_domains(self.config, self.active, self.disabled, "missing", ["a.example.com"])
        with self.assertRaisesRegex(NodeDomainError, "完整域名"):
            set_domains(self.config, self.active, self.disabled, "home-nas", ["localhost"])
        wildcard = set_domains(
            self.config, self.active, self.disabled, "home-nas",
            ["*.INTERNAL.EXAMPLE."], ["gateway-demo.example.net"],
        )
        self.assertEqual(wildcard["domains"], ["*.internal.example"])
        with self.assertRaisesRegex(NodeDomainError, "覆盖 VPS 域名"):
            set_domains(
                self.config, self.active, self.disabled, "home-nas",
                ["*.managed.example.com"], ["gateway-demo.managed.example.com"],
            )
        set_domains(self.config, self.active, self.disabled, "home-nas", ["nas.internal.example"])
        with self.assertRaisesRegex(NodeDomainError, "home-nas"):
            set_domains(self.config, self.active, self.disabled, "home-desk", ["nas.internal.example"])

    def test_rejects_corrupt_or_ambiguous_state(self) -> None:
        self.config.write_text(json.dumps({
            "version": 1,
            "nodes": {
                "home-nas": ["git.example.com"],
                "home-desk": ["git.example.com"],
            },
        }), encoding="utf-8")
        with self.assertRaisesRegex(NodeDomainError, "多个节点"):
            load_state(self.config)

    def test_arbitrary_ip_mapping_is_persisted_and_kept_when_nodes_change(self) -> None:
        result = set_address_domains(
            self.config, "2001:0db8::103",
            ["GIT.EXAMPLE.COM.", "*.INTERNAL.EXAMPLE."],
        )
        self.assertEqual(result["address"], "2001:db8::103")
        self.assertEqual(load_address_state(self.config), {
            "2001:db8::103": ["git.example.com", "*.internal.example"],
        })
        set_domains(self.config, self.active, self.disabled, "home-nas", ["nas.example.com"])
        self.assertIn("2001:db8::103", load_address_state(self.config))
        set_address_domains(self.config, "2001:db8::103", [])
        self.assertEqual(load_address_state(self.config), {})
        self.assertEqual(load_state(self.config)["home-nas"], ["nas.example.com"])

    def test_arbitrary_ip_mapping_rejects_invalid_ip_and_duplicate_domain(self) -> None:
        with self.assertRaisesRegex(NodeDomainError, "目标 IP"):
            set_address_domains(self.config, "not-an-ip", ["git.example.com"])
        set_domains(self.config, self.active, self.disabled, "home-nas", ["git.example.com"])
        with self.assertRaisesRegex(NodeDomainError, "home-nas"):
            set_address_domains(self.config, "192.168.0.103", ["git.example.com"])


if __name__ == "__main__":
    unittest.main()

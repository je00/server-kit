#!/usr/bin/env python3
"""验证 VLESS 客户端隔离策略的生成结果。"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_DIR / "lib" / "vless_access.py"
SPEC = importlib.util.spec_from_file_location("vless_access", MODULE_PATH)
assert SPEC and SPEC.loader
vless_access = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vless_access)


class VlessAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.peer_db = self.root / "peers.tsv"
        self.awg_state = self.root / "manager.conf"
        self.peer_db.write_text("home-desk\t10.20.0.101\napie-p15v\t10.20.0.201\n", encoding="utf-8")
        self.awg_state.write_text("AWG_SERVER_IP=10.20.0.1\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_resolve_target(self) -> None:
        self.assertEqual(
            vless_access.resolve_target("all", self.peer_db, self.awg_state),
            ("all", "10.20.0.0/24"),
        )
        self.assertEqual(
            vless_access.resolve_target("vps", self.peer_db, self.awg_state),
            ("vps", "10.20.0.1"),
        )
        self.assertEqual(
            vless_access.resolve_target("apie-p15v", self.peer_db, self.awg_state),
            ("apie-p15v", "10.20.0.201"),
        )
        with self.assertRaises(vless_access.PolicyError):
            vless_access.resolve_target("missing", self.peer_db, self.awg_state)

    def test_allow_target_reports_protocol_and_ports(self) -> None:
        active = self.root / "active.json"
        pending = self.root / "pending.json"
        active.write_text(json.dumps({
            "version": 1,
            "clients": {"home-iphone": {"uuid": "11111111-1111-4111-8111-111111111111", "enabled": True, "allow": []}},
        }), encoding="utf-8")
        args = argparse.Namespace(
            name="home-iphone", target="vps", ports="22,443", network="tcp",
            active=active, pending=pending, peer_db=self.peer_db, awg_state=self.awg_state,
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            vless_access.allow_target(args)
        self.assertIn("TCP 22,443", output.getvalue())

    def test_permissions_append_and_exact_delete_preserves_other_rules(self) -> None:
        active = self.root / "active.json"
        pending = self.root / "pending.json"
        active.write_text(json.dumps({
            "version": 1,
            "clients": {"home-iphone": {
                "uuid": "11111111-1111-4111-8111-111111111111",
                "enabled": True,
                "allow": [{
                    "target": "home-desk", "ip": "10.20.0.101",
                    "ports": [22], "network": "tcp",
                }],
            }},
        }), encoding="utf-8")
        vless_access.allow_target(argparse.Namespace(
            name="home-iphone", target="home-desk", ports="53", network="udp",
            active=active, pending=pending, peer_db=self.peer_db, awg_state=self.awg_state,
        ))
        policy = json.loads(pending.read_text(encoding="utf-8"))
        self.assertEqual(len(policy["clients"]["home-iphone"]["allow"]), 2)

        vless_access.deny_target(argparse.Namespace(
            name="home-iphone", target="home-desk", ports="22", network="tcp",
            active=active, pending=pending,
        ))
        remaining = json.loads(pending.read_text(encoding="utf-8"))["clients"]["home-iphone"]["allow"]
        self.assertEqual(remaining, [{
            "target": "home-desk", "ip": "10.20.0.101",
            "ports": [53], "network": "udp",
        }])

    def test_range_round_trip_render_and_delete(self) -> None:
        active, pending = self.root / "active.json", self.root / "pending.json"
        active.write_text(json.dumps({"version": 1, "clients": {"phone": {
            "uuid": "11111111-1111-4111-8111-111111111111", "enabled": True,
            "email": "server-kit-vless:phone", "allow": [],
        }}}))
        args = argparse.Namespace(name="phone", target="vps", ports="22,60001-60003,60003-60005", network="udp",
                                  active=active, pending=pending, peer_db=self.peer_db, awg_state=self.awg_state)
        with contextlib.redirect_stdout(io.StringIO()):
            vless_access.allow_target(args)
        policy = json.loads(pending.read_text())
        self.assertEqual(policy["clients"]["phone"]["allow"][0]["ports"], [22, *range(60001, 60006)])
        config = {"inbounds": [{"tag": "vless-public", "protocol": "vless", "settings": {"clients": []}}],
                  "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
                  "routing": {"rules": []}}
        rendered = vless_access.render_config(config, policy, "vless-public", "10.20.0.0/24")
        rule = rendered["routing"]["rules"][0]
        self.assertEqual(rule["port"], "22,60001-60005")
        self.assertEqual(rule["network"], "udp")
        args.ports = "60001-60005,22"
        with self.assertRaises(vless_access.PolicyError):
            vless_access.allow_target(args)
        with contextlib.redirect_stdout(io.StringIO()):
            vless_access.deny_target(args)
        self.assertEqual(json.loads(pending.read_text())["clients"]["phone"]["allow"], [])

    def test_legacy_stash_compatibility_is_per_client_policy(self) -> None:
        active = self.root / "active.json"
        pending = self.root / "pending.json"
        active.write_text(json.dumps({
            "version": 1,
            "clients": {
                "home-iphone6": {
                    "uuid": "11111111-1111-4111-8111-111111111111",
                    "email": "server-kit-vless:home-iphone6",
                    "enabled": True,
                    "allow": [],
                },
                "home-iphone": {
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "email": "server-kit-vless:home-iphone",
                    "enabled": True,
                    "allow": [],
                },
            },
        }), encoding="utf-8")
        args = argparse.Namespace(
            command="client-compat-enable", name="home-iphone6",
            active=active, pending=pending,
        )

        vless_access.client_set_compatibility(args)

        policy = json.loads(pending.read_text(encoding="utf-8"))
        self.assertTrue(policy["clients"]["home-iphone6"]["legacy_stash"])
        self.assertNotIn("legacy_stash", policy["clients"]["home-iphone"])
        lines = vless_access.policy_lines(policy)
        self.assertIn("  订阅语法：旧版 Stash 兼容", lines)

    def test_allow_all_renders_one_full_awg_network_rule(self) -> None:
        config = {
            "inbounds": [{
                "tag": "vless-public", "protocol": "vless",
                "settings": {"clients": []},
            }],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {"rules": []},
        }
        policy = {
            "version": 1,
            "clients": {
                "home-iphone": {
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "email": "server-kit-vless:home-iphone",
                    "enabled": True,
                    "allow": [{
                        "target": "all", "ip": "10.20.0.0/24",
                        "ports": [], "network": "all",
                    }],
                },
            },
        }

        rendered = vless_access.render_config(
            config, policy, "vless-public", "10.20.0.0/24"
        )
        rule = rendered["routing"]["rules"][0]
        self.assertEqual(rule["ip"], ["10.20.0.0/24"])
        self.assertNotIn("network", rule)
        self.assertNotIn("port", rule)
        self.assertEqual(rule["outboundTag"], "server-kit-vless-home-iphone")

    def test_target_and_port_ranges_are_independent(self) -> None:
        config = {
            "inbounds": [{
                "tag": "vless-public", "protocol": "vless",
                "settings": {"clients": []},
            }],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {"rules": []},
        }
        policy = {
            "version": 1,
            "clients": {
                "home-iphone": {
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "email": "server-kit-vless:home-iphone",
                    "enabled": True,
                    "allow": [
                        {"target": "all", "ip": "10.20.0.0/24", "ports": [22], "network": "tcp"},
                        {"target": "apie-p15v", "ip": "10.20.0.201", "ports": [], "network": "all"},
                    ],
                },
            },
        }

        rules = vless_access.render_config(
            config, policy, "vless-public", "10.20.0.0/24"
        )["routing"]["rules"]
        all_nodes = next(rule for rule in rules if rule.get("ip") == ["10.20.0.0/24"] and rule.get("outboundTag") != "block")
        self.assertEqual(all_nodes["network"], "tcp")
        self.assertEqual(all_nodes["port"], "22")
        one_node = next(rule for rule in rules if rule.get("ip") == ["10.20.0.201/32"])
        self.assertNotIn("network", one_node)
        self.assertNotIn("port", one_node)

    def test_render_preserves_unmanaged_client_and_enforces_allowlist(self) -> None:
        config = {
            "inbounds": [
                {
                    "tag": "vless-public",
                    "protocol": "vless",
                    "settings": {"clients": [{
                        "id": "11111111-1111-4111-8111-111111111111",
                        "email": "existing-user",
                        "flow": "xtls-rprx-vision",
                    }]},
                },
                {
                    "tag": "vless-public-rescue",
                    "protocol": "vless",
                    "settings": {"clients": []},
                },
            ],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {"rules": [{
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "block",
            }]},
        }
        policy = {
            "version": 1,
            "clients": {
                "home-iphone": {
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "email": "server-kit-vless:home-iphone",
                    "enabled": True,
                    "allow": [
                        {"target": "vps", "ip": "10.20.0.1", "ports": [22], "network": "tcp"},
                        {"target": "apie-p15v", "ip": "10.20.0.201", "ports": [22, 443], "network": "tcp"},
                    ],
                }
            },
        }

        rendered = vless_access.render_config(config, policy, "vless-public", "10.20.0.0/24")
        inbound_clients = rendered["inbounds"][0]["settings"]["clients"]
        self.assertEqual([item["email"] for item in inbound_clients], [
            "existing-user",
            "server-kit-vless:home-iphone",
        ])
        self.assertEqual(inbound_clients[1]["flow"], "xtls-rprx-vision")
        self.assertEqual(
            rendered["inbounds"][1]["settings"]["clients"], inbound_clients
        )

        managed_outbound = next(
            item for item in rendered["outbounds"]
            if item.get("tag") == "server-kit-vless-home-iphone"
        )
        self.assertEqual(managed_outbound["settings"], {"domainStrategy": "UseIP"})

        rules = rendered["routing"]["rules"]
        self.assertEqual(rules[0]["user"], ["server-kit-vless:home-iphone"])
        self.assertEqual(rules[0]["outboundTag"], "server-kit-vless-home-iphone")
        self.assertEqual(rules[0]["ip"], ["10.20.0.201/32"])
        self.assertEqual(rules[0]["port"], "22,443")
        self.assertEqual(rules[1]["ip"], ["10.20.0.1/32"])
        self.assertEqual(rules[1]["port"], "22")
        self.assertEqual(rules[2], {
            "type": "field",
            "user": ["server-kit-vless:home-iphone"],
            "ip": ["10.20.0.0/24"],
            "outboundTag": "block",
        })
        self.assertEqual(rules[3], {
            "type": "field",
            "user": ["server-kit-vless:home-iphone"],
            "outboundTag": "server-kit-vless-home-iphone",
        })
        self.assertEqual(rules[4]["ip"], ["geoip:private"])

    def test_render_uses_server_side_dns_for_internal_node_domains(self) -> None:
        config = {
            "dns": {
                "hosts": {
                    "public.example.com": "203.0.113.10",
                    "stale.internal.example": "10.20.0.99",
                },
                "servers": ["localhost"],
            },
            "inbounds": [{
                "tag": "vless-public", "protocol": "vless",
                "settings": {"clients": []},
            }],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {"rules": []},
        }
        policy = {
            "version": 1,
            "clients": {
                "home-iphone": {
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "email": "server-kit-vless:home-iphone",
                    "enabled": True,
                    "allow": [{
                        "target": "home-nas", "ip": "10.20.0.103",
                        "ports": [443], "network": "tcp",
                    }],
                },
            },
        }

        rendered = vless_access.render_config(
            config, policy, "vless-public", "10.20.0.0/24",
            {"nas.internal.example": "10.20.0.103", "git.example.com": "10.20.0.103"},
        )

        self.assertEqual(rendered["dns"]["hosts"], {
            "public.example.com": "203.0.113.10",
            "nas.internal.example": "10.20.0.103",
            "git.example.com": "10.20.0.103",
        })
        self.assertEqual(rendered["dns"]["servers"], ["localhost"])
        self.assertEqual(rendered["routing"]["domainStrategy"], "IPIfNonMatch")

    def test_load_internal_domain_hosts_converts_allowed_wildcards(self) -> None:
        domains = self.root / "node-domains.json"
        domains.write_text(json.dumps({
            "version": 1,
            "nodes": {
                "home-desk": ["*.internal.example", "git.example.com"],
                "removed-node": ["removed.example.com"],
            },
            "addresses": {
                "192.168.0.103": ["nas.example.com"],
            },
        }), encoding="utf-8")

        self.assertEqual(
            vless_access.load_internal_domain_hosts(domains, self.peer_db),
            {
                "domain:internal.example": "10.20.0.101",
                "git.example.com": "10.20.0.101",
                "nas.example.com": "192.168.0.103",
            },
        )

    def test_revoked_vps_permission_is_blocked_before_client_fallback(self) -> None:
        config = {
            "inbounds": [{
                "tag": "vless-public",
                "protocol": "vless",
                "settings": {"clients": []},
            }],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {"rules": []},
        }
        policy = {
            "version": 1,
            "clients": {
                "home-iphone": {
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "email": "server-kit-vless:home-iphone",
                    "enabled": True,
                    "allow": [{
                        "target": "apie-p15v",
                        "ip": "10.20.0.201",
                        "ports": [22],
                        "network": "tcp",
                    }],
                }
            },
        }

        rendered = vless_access.render_config(
            config, policy, "vless-public", "10.20.0.0/24"
        )
        rules = rendered["routing"]["rules"]
        self.assertFalse(any(
            rule.get("ip") == ["10.20.0.1/32"] and rule.get("outboundTag") != "block"
            for rule in rules
        ))
        self.assertEqual(rules[1]["ip"], ["10.20.0.0/24"])
        self.assertEqual(rules[1]["outboundTag"], "block")
        self.assertNotIn("ip", rules[2])

    def test_render_replaces_stale_managed_entries(self) -> None:
        config = {
            "inbounds": [{
                "tag": "vless-public",
                "protocol": "vless",
                "settings": {"clients": [{
                    "id": "33333333-3333-4333-8333-333333333333",
                    "email": "server-kit-vless:old-client",
                }]},
            }],
            "outbounds": [{
                "tag": "server-kit-vless-old-client",
                "protocol": "freedom",
            }],
            "routing": {"rules": [{
                "type": "field",
                "user": ["server-kit-vless:old-client"],
                "outboundTag": "server-kit-vless-old-client",
            }]},
        }
        rendered = vless_access.render_config(config, vless_access.empty_policy(), "vless-public", "10.20.0.0/24")
        self.assertEqual(rendered["inbounds"][0]["settings"]["clients"], [])
        self.assertEqual(rendered["outbounds"], [])
        self.assertEqual(rendered["routing"]["rules"], [])


if __name__ == "__main__":
    unittest.main()

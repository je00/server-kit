#!/usr/bin/env python3
"""验证服务端中转配置、Xray 投影和订阅节点。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lib.server_kit_relay import (
    BLOCK_OUTBOUND_TAG,
    INBOUND_TAG,
    OUTBOUND_TAG,
    RelayError,
    VLESS_EMAIL_PREFIX,
    disable_shadowsocks,
    configure_dns,
    enable_vless,
    initialize,
    relay_client_uuid,
    render_xray,
    render_exit_dns_workers,
    subscription_node,
    vless_subscription_nodes,
)
from lib.vless_access import render_config as render_vless_access


class ServerRelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "server-relay.json"
        self.inputs = self.root / "clash-inputs.json"
        self.xray = self.root / "xray.json"
        self.inputs.write_text(json.dumps({
            "version": 4,
            "airports": [],
            "default_exit_id": "111111111111",
            "awg_exit_selections": {
                "home-desk": ["111111111111", "222222222222"],
                "home-phone": ["222222222222"],
            },
            "exits": [{"id": "111111111111", "name": "Primary", "proxy": {
                "name": "EXIT.Primary",
                "type": "socks5",
                "server": "192.0.2.30",
                "port": 45001,
                "username": "relay-user",
                "password": "relay-pass",
                "dialer-proxy": "MID",
            }}, {"id": "222222222222", "name": "Backup", "proxy": {
                "name": "EXIT.Backup", "type": "socks5", "server": "192.0.2.31",
                "port": 45002, "dialer-proxy": "MID",
            }}],
        }), encoding="utf-8")
        self.xray.write_text(json.dumps({
            "inbounds": [{"tag": "vless-public", "port": 443, "protocol": "vless"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]},
        }), encoding="utf-8")

    def test_initializes_secret_without_overwriting_existing_port(self) -> None:
        value = initialize(self.config, 2083)
        self.assertGreaterEqual(len(value["password"]), 24)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(initialize(self.config, 2083)["password"], value["password"])
        with self.assertRaises(RelayError):
            initialize(self.config, 2087)

    def enable_consistent_dns(self, ids=None) -> None:
        initialize(self.config, 2083)
        enable_vless(self.config)
        inputs = json.loads(self.inputs.read_text())
        for index, item in enumerate(inputs["exits"]):
            item["proxy"]["server"] = "gateway.example.com"
            item["proxy"]["port"] = 45001 + index
        self.inputs.write_text(json.dumps(inputs))
        configure_dns(self.config, self.inputs, ids or ["111111111111", "222222222222"])

    def test_consistent_dns_isolates_exit_transport_and_cache_without_bootstrap_cycle(self) -> None:
        self.enable_consistent_dns()
        workers = render_exit_dns_workers(self.config, self.inputs)
        self.assertEqual(set(workers), {"111111111111", "222222222222"})
        local_ports = set()
        for index, worker in enumerate(workers.values()):
            inbound = worker["inbounds"][0]
            self.assertEqual(inbound["listen"], "127.0.0.1")
            self.assertEqual(inbound["settings"]["auth"], "password")
            self.assertFalse(inbound["sniffing"]["enabled"])
            local_ports.add(inbound["port"])
            dns = worker["dns"]
            self.assertEqual(dns["queryStrategy"], "UseIPv4")
            self.assertNotIn("localhost", dns["servers"])
            self.assertTrue(all(server["address"].startswith(("https://1.0.0.1/", "https://8.8.8.8/")) for server in dns["servers"]))
            self.assertTrue(all(server["domains"] == ["regexp:.*"] for server in dns["servers"]))
            self.assertTrue(dns["enableParallelQuery"])
            outbounds = {item["tag"]: item for item in worker["outbounds"]}
            raw = outbounds["dns-transport"]
            data = outbounds["resolved-exit"]
            self.assertEqual(raw["targetStrategy"], "AsIs")
            self.assertEqual(data["targetStrategy"], "ForceIPv4")
            self.assertEqual(raw["settings"], data["settings"])
            self.assertEqual(raw["settings"]["servers"][0]["port"], 45001 + index)
            self.assertEqual(raw["streamSettings"]["sockopt"], {"domainStrategy": "AsIs"})
            self.assertNotIn("proxySettings", raw)
            self.assertEqual(worker["outbounds"][0]["protocol"], "blackhole")
            routing = worker["routing"]
            self.assertEqual(routing["domainStrategy"], "IPOnDemand")
            self.assertEqual(routing["rules"][0]["outboundTag"], "dns-transport")
            self.assertEqual(routing["rules"][0]["inboundTag"], [dns["tag"]])
            self.assertEqual(routing["rules"][0]["port"], "443")
            self.assertEqual(routing["rules"][1]["outboundTag"], "block")
            self.assertEqual(routing["rules"][2]["ip"], ["geoip:private"])
        self.assertEqual(len(local_ports), 2)

    def test_dns_mode_updates_only_selected_main_exit_and_keeps_private_dns(self) -> None:
        self.enable_consistent_dns(["111111111111"])
        peers = self.root / "peers.tsv"
        peers.write_text("")
        policy = self.root / "access.json"
        policy.write_text(json.dumps({"clients": {"client": {"enabled": True}}}))
        base = json.loads(self.xray.read_text())
        base["dns"] = {"hosts": {"git.example.com": "10.20.0.103"}, "servers": ["localhost"]}
        self.xray.write_text(json.dumps(base))
        config = render_xray(self.config, self.inputs, self.xray, peers, policy)
        self.assertEqual(config["dns"], base["dns"])
        primary = next(o for o in config["outbounds"] if o.get("tag") == f"{OUTBOUND_TAG}-111111111111")
        backup = next(o for o in config["outbounds"] if o.get("tag") == f"{OUTBOUND_TAG}-222222222222")
        self.assertEqual(primary["settings"]["servers"][0]["address"], "127.0.0.1")
        self.assertEqual(backup["settings"]["servers"][0]["address"], "gateway.example.com")
        worker = render_exit_dns_workers(self.config, self.inputs)["111111111111"]
        self.assertEqual(primary["settings"]["servers"][0]["port"], worker["inbounds"][0]["port"])
        self.assertEqual(primary["settings"]["servers"][0]["users"][0]["pass"], worker["inbounds"][0]["settings"]["accounts"][0]["pass"])
        self.xray.write_text(json.dumps(config))
        self.assertEqual(config, render_xray(self.config, self.inputs, self.xray, peers, policy))
        configure_dns(self.config, self.inputs, [])
        self.assertEqual(render_exit_dns_workers(self.config, self.inputs), {})
        restored = render_xray(self.config, self.inputs, self.xray, peers, policy)
        primary = next(o for o in restored["outbounds"] if o.get("tag") == f"{OUTBOUND_TAG}-111111111111")
        self.assertEqual(primary["settings"]["servers"][0]["address"], "gateway.example.com")

    def test_dns_mode_rejects_unknown_ids_and_local_upstream_without_changing_fact(self) -> None:
        self.enable_consistent_dns()
        before = self.config.read_bytes()
        with self.assertRaises(RelayError):
            configure_dns(self.config, self.inputs, ["ffffffffffff"])
        self.assertEqual(before, self.config.read_bytes())
        inputs = json.loads(self.inputs.read_text())
        inputs["exits"][0]["proxy"]["server"] = "127.0.0.1"
        self.inputs.write_text(json.dumps(inputs))
        with self.assertRaises(RelayError):
            configure_dns(self.config, self.inputs, ["111111111111"])
        self.assertEqual(before, self.config.read_bytes())

    def test_deleted_exit_removes_worker_without_affecting_remaining_exit(self) -> None:
        self.enable_consistent_dns()
        before = render_exit_dns_workers(self.config, self.inputs)
        inputs = json.loads(self.inputs.read_text())
        inputs["exits"].pop()
        self.inputs.write_text(json.dumps(inputs))
        after = render_exit_dns_workers(self.config, self.inputs)
        self.assertEqual(after, {"111111111111": before["111111111111"]})

    def test_renders_managed_inbound_outbound_and_first_routing_rule(self) -> None:
        initialize(self.config, 2083)
        rendered = render_xray(self.config, self.inputs, self.xray)
        inbound = next(item for item in rendered["inbounds"] if item["tag"] == INBOUND_TAG)
        self.assertEqual(inbound["protocol"], "shadowsocks")
        self.assertEqual(inbound["settings"]["network"], "tcp,udp")
        self.assertEqual(inbound["settings"]["method"], "chacha20-poly1305")
        outbound = next(item for item in rendered["outbounds"] if item["tag"] == f"{OUTBOUND_TAG}-111111111111")
        server = outbound["settings"]["servers"][0]
        self.assertEqual((server["address"], server["port"]), ("192.0.2.30", 45001))
        self.assertEqual(server["users"][0]["user"], "relay-user")
        self.assertEqual(rendered["routing"]["rules"][0], {
            "type": "field", "inboundTag": [INBOUND_TAG], "ip": ["geoip:private"],
            "outboundTag": BLOCK_OUTBOUND_TAG,
        })
        self.assertEqual(rendered["routing"]["rules"][1], {
            "type": "field", "inboundTag": [INBOUND_TAG], "outboundTag": f"{OUTBOUND_TAG}-111111111111",
        })
        self.assertEqual(len([item for item in render_xray(self.config, self.inputs, self.xray)["inbounds"] if item.get("tag") == INBOUND_TAG]), 1)

    def test_subscription_uses_legacy_stash_cipher_and_hostname_server(self) -> None:
        initialize(self.config, 2083)
        node = subscription_node(self.config, "vpn.example.com")
        assert node is not None
        self.assertEqual(node["type"], "ss")
        self.assertEqual(node["cipher"], "chacha20-ietf-poly1305")
        self.assertTrue(node["udp"])
        self.assertEqual(node["server"], "vpn.example.com")

    def test_disabling_shadowsocks_removes_inbound_and_subscription_node(self) -> None:
        initialize(self.config, 2083)
        disable_shadowsocks(self.config)
        rendered = render_xray(self.config, self.inputs, self.xray)
        self.assertNotIn(INBOUND_TAG, {item.get("tag") for item in rendered["inbounds"]})
        self.assertIsNone(subscription_node(self.config, "198.51.100.10"))

    def test_rejects_non_socks_exit(self) -> None:
        initialize(self.config, 2083)
        self.inputs.write_text('{"exit_proxy":{"type":"vless"}}', encoding="utf-8")
        with self.assertRaises(RelayError):
            render_xray(self.config, self.inputs, self.xray)

    def test_vless_relay_uses_stable_per_subscription_identities_on_all_public_inbounds(self) -> None:
        initialize(self.config, 2083)
        relay = enable_vless(self.config)
        self.assertEqual(relay_client_uuid(relay, "home-phone"), relay_client_uuid(relay, "home-phone"))
        self.assertNotEqual(relay_client_uuid(relay, "home-phone"), relay_client_uuid(relay, "home-desk"))
        self.xray.write_text(json.dumps({
            "inbounds": [
                {"tag": "vless-public", "port": 443, "protocol": "vless", "settings": {
                    "clients": [{"id": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision"}],
                }},
                {"tag": "vless-public-rescue", "port": 2053, "protocol": "vless", "settings": {"clients": []}},
            ],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": []},
        }), encoding="utf-8")
        peers = self.root / "peers.tsv"
        peers.write_text("home-desk\t10.20.0.101\n", encoding="utf-8")
        policy = self.root / "vless-access.json"
        policy.write_text(json.dumps({"version": 1, "clients": {
            "home-phone": {"enabled": True}, "disabled": {"enabled": False},
        }}), encoding="utf-8")
        rendered = render_xray(self.config, self.inputs, self.xray, peers, policy)
        expected_emails = {
            f"{VLESS_EMAIL_PREFIX}home-desk:111111111111",
            f"{VLESS_EMAIL_PREFIX}home-desk:222222222222",
            f"{VLESS_EMAIL_PREFIX}home-phone:222222222222",
        }
        for inbound in (item for item in rendered["inbounds"] if item.get("protocol") == "vless"):
            emails = {item.get("email") for item in inbound["settings"]["clients"]}
            self.assertTrue(expected_emails <= emails)
        self.assertEqual(rendered["routing"]["rules"][0]["ip"], ["geoip:private"])
        self.assertEqual(set(rendered["routing"]["rules"][0]["user"]), expected_emails)
        route_tags = {
            rule.get("outboundTag") for rule in rendered["routing"]["rules"]
            if any(str(user).startswith(VLESS_EMAIL_PREFIX) for user in rule.get("user", []))
            and "ip" not in rule
        }
        self.assertEqual(route_tags, {
            f"{OUTBOUND_TAG}-111111111111", f"{OUTBOUND_TAG}-222222222222",
        })
        access_rendered = render_vless_access(
            rendered,
            {"version": 1, "clients": {
                "home-phone": {
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "email": "server-kit-vless:home-phone",
                    "enabled": True,
                    "allow": [],
                },
            }},
            "vless-public",
            "10.20.0.0/24",
        )
        retained_emails = {
            item.get("email")
            for item in access_rendered["inbounds"][0]["settings"]["clients"]
        }
        self.assertTrue(expected_emails <= retained_emails)
        routed_users = {
            user for rule in access_rendered["routing"]["rules"]
            if str(rule.get("outboundTag", "")).startswith(f"{OUTBOUND_TAG}-")
            for user in rule.get("user", [])
        }
        self.assertEqual(routed_users, expected_emails)

        nodes = vless_subscription_nodes(self.config, "home-phone", {
            "name": "template", "type": "vless", "server": "198.51.100.10", "port": 443,
        }, [{"id": "111111111111", "name": "Primary"}, {"id": "222222222222", "name": "Backup"}])
        self.assertEqual([item["name"] for item in nodes], [
            "SERVER.RELAY.VLESS.Primary", "SERVER.RELAY.VLESS.Backup",
        ])
        self.assertNotEqual(nodes[0]["uuid"], nodes[1]["uuid"])


if __name__ == "__main__":
    unittest.main()

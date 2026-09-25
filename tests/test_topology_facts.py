"""Conservative proofs of saved topology facts, without probes or credentials."""

from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.server_kit_topology_facts import collect_topology_context, valid_topology_context
from lib.vless_access import render_config


def client(name="phone", *, enabled=True, permissions=None, identifier=None):
    return {
        "uuid": identifier or "11111111-1111-4111-8111-111111111111",
        "email": f"server-kit-vless:{name}", "enabled": enabled,
        "allow": permissions if permissions is not None else [
            {"target": "all", "ip": "192.0.2.0/24", "network": "tcp", "ports": [22, 8000, 8001]},
        ],
    }


def rendered(clients, cidr="10.20.0.0/24"):
    return render_config({
        "inbounds": [{"tag": "vless-public", "protocol": "vless", "settings": {"clients": []}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
        "routing": {"rules": []},
    }, {"version": 1, "clients": copy.deepcopy(clients)}, "vless-public", cidr)


class TopologyFactsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "manager.conf"
        self.xray = self.root / "config.json"
        self.clients = {"phone": client()}
        self.config = rendered(self.clients)
        self.state.write_text("AWG_SERVER_IP=10.20.0.1\nAWG_SUBNET_CIDR=203.0.113.0/24\n")

    def tearDown(self):
        self.temporary.cleanup()

    def collect(self, config=None, clients=None):
        self.xray.write_text(json.dumps(config if config is not None else self.config))
        result = collect_topology_context(self.state, self.xray, self.clients if clients is None else clients)
        self.assertTrue(valid_topology_context(result))
        return result

    def test_effective_network_comes_from_actual_rules_not_saved_ip_or_manager_subnet(self):
        self.assertEqual(self.collect(), {"hub_address": "10.20.0.1", "vless_networks": {"phone": "10.20.0.0/24"}})
        self.assertEqual(self.clients["phone"]["allow"][0]["ip"], "192.0.2.0/24")

    def test_hub_missing_never_uses_a_default(self):
        self.assertEqual(collect_topology_context(None, None, {}), {"hub_address": "", "vless_networks": {}})
        for text in ("", "AWG_SUBNET_CIDR=10.20.0.0/24\n", "# AWG_SERVER_IP=10.20.0.1\n"):
            with self.subTest(text=text):
                self.state.write_text(text)
                self.assertEqual(self.collect()["hub_address"], "")

    def test_hub_accepts_only_explicit_consistent_safe_assignments(self):
        examples = (
            (" AWG_SERVER_IP='10.20.0.1' # comment\n", "10.20.0.1"),
            ('SERVER_ADDRESS="10.20.0.1/24"\n', "10.20.0.1"),
            ("export SERVER_ADDRESS=2001:db8::1/64\nAWG_SERVER_IP=2001:db8::1\n", "2001:db8::1"),
            ("AWG_SERVER_IP=10.20.0.1\nAWG_SERVER_IP=10.20.0.1\n", "10.20.0.1"),
        )
        for text, address in examples:
            with self.subTest(text=text):
                self.state.write_text(text)
                self.assertEqual(self.collect()["hub_address"], address)

    def test_hub_invalid_conflicting_or_executable_values_are_unknown(self):
        cases = (
            "AWG_SERVER_IP=10.20.0.1\nSERVER_ADDRESS=10.21.0.1\n",
            "AWG_SERVER_IP=10.20.0.1\nAWG_SERVER_IP=bad\n",
            "AWG_SERVER_IP=\n", "AWG_SERVER_IP='10.20.0.1\n",
            "AWG_SERVER_IP=999.20.0.1\n", "SERVER_ADDRESS=10.20.0.1/99\n",
            "AWG_SERVER_IP=fe80::1%awg0\n", "AWG_SERVER_IP=10.20.0.1 extra\n",
            "AWG_SERVER_IP=$(touch should-not-exist)\n", "AWG_SERVER_IP=`echo 10.20.0.1`\n",
            "AWG_SERVER_IP=10.20.0.1; touch should-not-exist\n",
            "AWG_SERVER_IP = 10.20.0.1;\n", "AWG_SERVER_IP+=10.20.0.1\n",
        )
        for text in cases:
            with self.subTest(text=text):
                self.state.write_text(text)
                self.assertEqual(self.collect()["hub_address"], "")
        self.assertFalse((self.root / "should-not-exist").exists())

    def test_missing_unreadable_or_bad_encoding_inputs_fail_closed(self):
        missing = self.root / "absent"
        for path in (None, missing, self.root):
            with self.subTest(path=path):
                self.assertEqual(collect_topology_context(path, path, self.clients), {"hub_address": "", "vless_networks": {}})
        self.state.write_bytes(b"AWG_SERVER_IP=\xff")
        self.xray.write_bytes(b"\xff")
        self.assertEqual(collect_topology_context(self.state, self.xray, self.clients), {"hub_address": "", "vless_networks": {}})

    def test_bad_json_duplicate_fields_and_non_json_constants_are_unknown(self):
        for text in ("bad", "[]", "null", '{"routing":{},"routing":{}}', '{"secret":NaN}'):
            with self.subTest(text=text):
                self.xray.write_text(text)
                self.assertEqual(collect_topology_context(self.state, self.xray, self.clients)["vless_networks"], {})

    def test_oversized_and_deeply_nested_input_is_bounded_and_optional(self):
        self.xray.write_text(" " * (4 * 1024 * 1024 + 1))
        self.assertEqual(collect_topology_context(self.state, self.xray, self.clients)["vless_networks"], {})
        self.xray.write_text("[" * 2000 + "]" * 2000)
        self.assertEqual(collect_topology_context(self.state, self.xray, self.clients)["vless_networks"], {})
        self.state.write_text("AWG_SERVER_IP=10.20.0.1\n" + "#" * (64 * 1024))
        self.assertEqual(self.collect()["hub_address"], "")

    def test_optional_renderer_failure_is_silent_and_does_not_break_overview(self):
        self.xray.write_text(json.dumps(self.config))
        output = io.StringIO()
        with patch("lib.server_kit_topology_facts.render_config", side_effect=RuntimeError("private-input")), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(collect_topology_context(self.state, self.xray, self.clients),
                             {"hub_address": "10.20.0.1", "vless_networks": {}})
        self.assertEqual(output.getvalue(), "")

    def test_missing_or_malformed_xray_sections_are_unknown(self):
        cases = [{}, {"routing": []}, {"routing": {"domainStrategy": "IPIfNonMatch", "rules": [None]}}]
        for field in ("inbounds", "outbounds"):
            for value in (None, {}, [None], []):
                config = copy.deepcopy(self.config)
                config[field] = value
                cases.append(config)
        for config in cases:
            with self.subTest(config=config):
                self.assertEqual(self.collect(config)["vless_networks"], {})

    def test_routing_domain_strategy_must_match_renderer(self):
        for strategy in (None, "AsIs", "IPOnDemand"):
            config = copy.deepcopy(self.config)
            config["routing"]["domainStrategy"] = strategy
            self.assertEqual(self.collect(config)["vless_networks"], {})

    def test_actual_all_guard_and_policy_protocol_ports_must_match(self):
        changes = (
            (0, "ip", ["192.0.2.0/24"]), (0, "network", "udp"), (0, "port", "22"),
            (0, "outboundTag", "direct"), (1, "ip", ["10.21.0.0/24"]),
            (2, "outboundTag", "direct"),
        )
        for index, field, value in changes:
            with self.subTest(index=index, field=field):
                config = copy.deepcopy(self.config)
                config["routing"]["rules"][index][field] = value
                self.assertEqual(self.collect(config)["vless_networks"], {})

    def test_partial_and_full_all_permissions_use_authoritative_rendering(self):
        permissions = [
            {"target": "all", "ip": "192.0.2.0/24", "network": "tcp,udp", "ports": [53]},
            {"target": "nas", "ip": "10.20.0.9", "network": "tcp", "ports": [445]},
            {"target": "vps", "ip": "10.20.0.1", "network": "all", "ports": []},
        ]
        for all_permission in ({"target": "all", "ip": "192.0.2.0/24", "network": "all", "ports": []}, permissions[0]):
            clients = {"phone": client(permissions=[all_permission, *permissions[1:]])}
            self.assertEqual(self.collect(rendered(clients), clients)["vless_networks"], {"phone": "10.20.0.0/24"})

    def test_extra_routing_conditions_or_rules_are_never_treated_as_confirmation(self):
        for field, value in (("domain", ["private.invalid"]), ("inboundTag", ["vless-public"]),
                             ("source", ["10.20.0.5"]), ("protocol", ["http"]), ("attrs", "anything")):
            for index in (0, 1, 2):
                with self.subTest(field=field, index=index):
                    config = copy.deepcopy(self.config)
                    config["routing"]["rules"][index][field] = value
                    self.assertEqual(self.collect(config)["vless_networks"], {})
        config = copy.deepcopy(self.config)
        config["routing"]["rules"].append(copy.deepcopy(config["routing"]["rules"][0]))
        self.assertEqual(self.collect(config)["vless_networks"], {})

    def test_guard_fallback_missing_duplicated_or_reordered_are_unknown(self):
        base = self.config["routing"]["rules"]
        permutations = (base[:2], base[1:], [base[0], base[2]],
                        [base[1], base[0], base[2]], [base[2], base[0], base[1]],
                        [base[0], base[1], base[1], base[2]])
        for rules in permutations:
            with self.subTest(rules=rules):
                config = copy.deepcopy(self.config)
                config["routing"]["rules"] = copy.deepcopy(rules)
                self.assertEqual(self.collect(config)["vless_networks"], {})

    def test_global_shadow_before_fallback_is_unknown_but_retained_later_rule_is_safe(self):
        global_rule = {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}
        for index in (0, 1, 2):
            config = copy.deepcopy(self.config)
            config["routing"]["rules"].insert(index, global_rule)
            self.assertEqual(self.collect(config)["vless_networks"], {})
        config = copy.deepcopy(self.config)
        config["routing"]["rules"].append(global_rule)
        self.assertEqual(self.collect(config)["vless_networks"], {"phone": "10.20.0.0/24"})

    def test_only_explicitly_other_users_can_be_skipped_before_client_rules(self):
        for users in ([], None, "other", [None], [""], ["other", "server-kit-vless:phone"]):
            config = copy.deepcopy(self.config)
            config["routing"]["rules"].insert(0, {"type": "field", "user": users, "outboundTag": "block"})
            self.assertEqual(self.collect(config)["vless_networks"], {})
        config = copy.deepcopy(self.config)
        config["routing"]["rules"].insert(0, {"type": "field", "user": ["other"], "outboundTag": "block"})
        self.assertEqual(self.collect(config)["vless_networks"], {"phone": "10.20.0.0/24"})

    def test_managed_inbound_identity_is_required_and_consistent(self):
        for change in ({"id": "22222222-2222-4222-8222-222222222222"}, {"email": "other"}, {"level": 1}, {"flow": []}):
            config = copy.deepcopy(self.config)
            config["inbounds"][0]["settings"]["clients"][0].update(change)
            self.assertEqual(self.collect(config)["vless_networks"], {})
        for protocol in ("trojan", None):
            config = copy.deepcopy(self.config)
            config["inbounds"][0]["protocol"] = protocol
            self.assertEqual(self.collect(config)["vless_networks"], {})
        config = copy.deepcopy(self.config)
        config["inbounds"][0]["settings"]["clients"] = []
        self.assertEqual(self.collect(config)["vless_networks"], {})

    def test_duplicate_identity_rejected_but_matching_vless_siblings_supported(self):
        config = copy.deepcopy(self.config)
        config["inbounds"][0]["settings"]["clients"] *= 2
        self.assertEqual(self.collect(config)["vless_networks"], {})
        config = copy.deepcopy(self.config)
        sibling = copy.deepcopy(config["inbounds"][0])
        sibling["tag"] = "vless-public-secondary"
        config["inbounds"].append(sibling)
        self.assertEqual(self.collect(config)["vless_networks"], {"phone": "10.20.0.0/24"})
        sibling["settings"]["clients"][0]["email"] = "other"
        self.assertEqual(self.collect(config)["vless_networks"], {})

    def test_equivalent_uuid_spelling_cannot_hide_conflicting_inbound_identity(self):
        clients = {"phone": client(identifier="abcdef01-1111-4111-8111-111111111111")}
        config = rendered(clients)
        sibling = copy.deepcopy(config["inbounds"][0])
        sibling["tag"] = "other-vless"
        sibling["settings"]["clients"][0] = {
            "id": clients["phone"]["uuid"].upper(), "email": "unrestricted-other",
        }
        config["inbounds"].append(sibling)
        self.assertEqual(self.collect(config, clients)["vless_networks"], {})
        clients["other"] = client("other", identifier=clients["phone"]["uuid"].upper())
        self.assertEqual(self.collect(rendered({"phone": clients["phone"]}), clients)["vless_networks"], {})

    def test_matching_flow_is_permitted_without_exposing_it(self):
        config = copy.deepcopy(self.config)
        config["inbounds"][0]["settings"]["clients"][0]["flow"] = "xtls-rprx-vision"
        self.assertEqual(self.collect(config)["vless_networks"], {"phone": "10.20.0.0/24"})

    def test_outbound_must_be_exact_client_freedom_and_block_must_be_blackhole(self):
        for index, changes in ((1, {"protocol": "freedom"}), (2, {"protocol": "socks"}),
                               (2, {"settings": {"domainStrategy": "AsIs"}}),
                               (2, {"proxySettings": {"tag": "exit-secret"}})):
            config = copy.deepcopy(self.config)
            config["outbounds"][index].update(changes)
            self.assertEqual(self.collect(config)["vless_networks"], {})
        for index in (1, 2):
            config = copy.deepcopy(self.config)
            config["outbounds"].append(copy.deepcopy(config["outbounds"][index]))
            self.assertEqual(self.collect(config)["vless_networks"], {})
        config = copy.deepcopy(self.config)
        config["outbounds"][1]["settings"] = {}
        self.assertEqual(self.collect(config)["vless_networks"], {"phone": "10.20.0.0/24"})

    def test_disabled_unmanaged_invalid_or_without_all_policy_is_omitted(self):
        for changes in ({"enabled": False}, {"enabled": 1}, {"enabled": "yes"}, {"email": "unmanaged"},
                        {"uuid": "bad"}, {"uuid": None}, {"allow": []}, {"allow": None},
                        {"allow": [{"target": "nas", "ip": "10.20.0.9", "network": "tcp", "ports": [445]}]}):
            clients = copy.deepcopy(self.clients)
            clients["phone"].update(changes)
            self.assertEqual(self.collect(clients=clients)["vless_networks"], {})
        for clients in ({"../phone": client("../phone")}, {"phone": None}, [], None):
            self.xray.write_text(json.dumps(self.config))
            self.assertEqual(collect_topology_context(self.state, self.xray, clients)["vless_networks"], {})

    def test_malformed_policy_fragments_do_not_raise_or_generate_facts(self):
        cases = [None, [], {}, {"target": "all"}]
        for changes in ({"network": []}, {"ports": [True]}, {"ports": [65536]}, {"ports": []},
                        {"target": "unsafe name"}, {"ip": "bad"}, {"unknown": "hidden"},
                        {"network": "all", "ports": [22]}):
            permission = copy.deepcopy(self.clients["phone"]["allow"][0])
            permission.update(changes)
            cases.append(permission)
        for permission in cases:
            clients = {"phone": client(permissions=[permission])}
            self.assertEqual(self.collect(clients=clients)["vless_networks"], {})

    def test_policy_changed_since_actual_render_is_unknown(self):
        clients = copy.deepcopy(self.clients)
        clients["phone"]["allow"][0]["ports"].append(443)
        self.assertEqual(self.collect(clients=clients)["vless_networks"], {})

    def test_network_proofs_are_per_client_and_can_differ(self):
        clients = {"phone": client(), "tablet": client("tablet", identifier="22222222-2222-4222-8222-222222222222")}
        first, second = rendered({"phone": clients["phone"]}), rendered({"tablet": clients["tablet"]}, "10.30.0.0/24")
        config = copy.deepcopy(first)
        config["inbounds"][0]["settings"]["clients"] += second["inbounds"][0]["settings"]["clients"]
        config["routing"]["rules"] += second["routing"]["rules"]
        config["outbounds"].append(second["outbounds"][-1])
        self.assertEqual(self.collect(config, clients)["vless_networks"], {"phone": "10.20.0.0/24", "tablet": "10.30.0.0/24"})
        config["routing"]["rules"][-3]["port"] = "80"
        self.assertEqual(self.collect(config, clients)["vless_networks"], {"phone": "10.20.0.0/24"})

    def test_duplicate_policy_identity_is_ambiguous(self):
        clients = {**self.clients, "tablet": client("tablet")}
        self.assertEqual(self.collect(clients=clients)["vless_networks"], {})

    def test_ipv6_canonical_network_is_supported_but_host_bits_and_scopes_are_not(self):
        config = rendered(self.clients, "2001:db8::/64")
        self.assertEqual(self.collect(config)["vless_networks"], {"phone": "2001:db8::/64"})
        for value in ("10.20.0.1/24", "10.20.0.0", "2001:DB8::/64", "fe80::%awg0/64", "geoip:private", None):
            config = copy.deepcopy(self.config)
            config["routing"]["rules"][1]["ip"] = [value]
            self.assertEqual(self.collect(config)["vless_networks"], {})

    def test_inputs_unchanged_and_no_probes_writes_logs_or_secrets(self):
        self.config["dns"] = {"hosts": {"private-domain.invalid": "10.20.0.5"}}
        self.config["outbounds"].append({"tag": "private-exit", "protocol": "socks", "settings": {"password": "secret-password"}})
        self.xray.write_text(json.dumps(self.config))
        before_files = [(path.read_bytes(), path.stat().st_mtime_ns) for path in (self.state, self.xray)]
        before_clients = copy.deepcopy(self.clients)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), \
                patch("subprocess.run", side_effect=AssertionError("No commands")), \
                patch("socket.socket", side_effect=AssertionError("No network")):
            facts = collect_topology_context(self.state, self.xray, self.clients)
        self.assertEqual(before_clients, self.clients)
        self.assertEqual(before_files, [(path.read_bytes(), path.stat().st_mtime_ns) for path in (self.state, self.xray)])
        self.assertEqual(output.getvalue(), "")
        encoded = json.dumps(facts)
        for secret in ("uuid", "email", self.clients["phone"]["uuid"], self.clients["phone"]["email"],
                       "private-domain", "private-exit", "secret-password", "outbound", "dns"):
            self.assertNotIn(secret, encoded)

    def test_context_validator_is_exact_and_rejects_noncanonical_or_secret_fields(self):
        valid = {"hub_address": "10.20.0.1", "vless_networks": {"phone": "10.20.0.0/24"}}
        self.assertTrue(valid_topology_context(valid))
        self.assertTrue(valid_topology_context({"hub_address": "", "vless_networks": {}}))
        invalid = [None, [], {}, {**valid, "email": "secret"},
                   {"hub_address": "10.20.0.1"}, {"hub_address": None, "vless_networks": {}},
                   {"hub_address": "10.20.0.1/24", "vless_networks": {}},
                   {"hub_address": "2001:DB8::1", "vless_networks": {}},
                   {"hub_address": "fe80::1%awg0", "vless_networks": {}},
                   {"hub_address": "", "vless_networks": []}]
        for name, network in (("unsafe name", "10.20.0.0/24"), ("../secret", "10.20.0.0/24"),
                              ("phone", "10.20.0.1/24"), ("phone", "10.20.0.0"), ("phone", ""),
                              ("phone", "geoip:private"), ("phone", "2001:DB8::/64"), (1, "10.20.0.0/24")):
            invalid.append({"hub_address": "", "vless_networks": {name: network}})
        for value in invalid:
            with self.subTest(value=value):
                self.assertIs(valid_topology_context(value), False)


if __name__ == "__main__":
    unittest.main()

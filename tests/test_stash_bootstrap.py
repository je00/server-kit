"""Exact-node DNS exceptions must not rewrite domestic policy or leak site DNS."""
import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lib.server_kit_proxy_resources import COUNTRY_CATALOG, normalized_config, overview, update
from lib.stash_bootstrap import (
    DIRECT_DOH, _not_builtin_filter, apply_stash_bootstrap, entry_domain,
    guard_provider_groups, inventory_from_provider, normalize_inventory,
)

URL = "https://provider.example.net/sub?token=private"
AIRPORT_ID = "111111111111"


def airport():
    return {"id": AIRPORT_ID, "name": "Example", "url": URL, "enabled": True,
            "countries": ["de"], "bootstrap_dns": inventory_from_provider({
                "proxies": [{"name": "DE 1", "server": "entry.example.net", "password": "secret"}],
            }, URL)}


class StashBootstrapTests(unittest.TestCase):
    def test_inventory_validation_does_not_require_yaml_in_web_runtime(self):
        result = subprocess.run([sys.executable, "-S", "-c",
            "from lib.stash_bootstrap import normalize_inventory; "
            "assert normalize_inventory(None, 'https://example.net') is None"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def config(self):
        return {
            "dns": {"follow-rule": True, "nameserver": ["https://8.8.8.8/dns-query#PROXY"],
                    "direct-nameserver": list(DIRECT_DOH), "nameserver-policy": {
                        "geosite:cn": list(DIRECT_DOH), "+.domestic.example.net": list(DIRECT_DOH),
                        "custom.example.net": "https://1.0.0.1/dns-query#PROXY",
                        "provider.example.net": ["https://1.1.1.1/dns-query#RELAY"],
                    }},
            "proxies": [{"name": "RELAY", "type": "vless", "server": "203.0.113.10",
                         "benchmark-url": "http://cp.cloudflare.com/generate_204"}],
            "proxy-providers": {f"airport-{AIRPORT_ID}": {"type": "http", "url": URL}},
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "proxies": ["DE"]},
                {"name": "DE", "type": "url-test", "use": [f"airport-{AIRPORT_ID}"], "filter": "(?i)德国|DE"},
            ],
            "hosts": {"nas.internal.example": "10.20.0.101"},
            "proxy-hosts": {"nas.internal.example": "10.20.0.101"},
            "rules": ["IP-CIDR,10.20.0.0/24,PRIVATE-phone,no-resolve",
                      "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve", "IP-CIDR,1.12.12.12/32,DIRECT,no-resolve",
                      "DOMAIN-SUFFIX,domestic.example.net,DIRECT", "MATCH,PROXY"],
        }

    def test_only_exact_entry_policy_added_domestic_and_lan_are_unchanged(self):
        config = self.config()
        before = copy.deepcopy(config)
        apply_stash_bootstrap(config, {"airports": [airport()]})
        added = config["dns"]["nameserver-policy"].pop("entry.example.net")
        self.assertEqual(added, list(DIRECT_DOH))
        self.assertEqual(config["dns"], before["dns"])
        for key in ("rules", "hosts", "proxy-hosts", "proxies", "proxy-providers"):
            self.assertEqual(config[key], before[key])
        self.assertEqual(config["proxy-groups"][0], before["proxy-groups"][0])
        self.assertNotIn("cp.cloudflare.com", config["dns"]["nameserver-policy"])

    def test_node_dns_route_does_not_depend_on_proxy(self):
        config = self.config()
        apply_stash_bootstrap(config, {"airports": [airport()]})
        for resolver in config["dns"]["nameserver-policy"]["entry.example.net"]:
            ip = resolver.split("/")[2]
            self.assertIn(f"IP-CIDR,{ip}/32,DIRECT,no-resolve", config["rules"])
        self.assertEqual(config["dns"]["nameserver"], ["https://8.8.8.8/dns-query#PROXY"])
        self.assertNotIn("DOMAIN,entry.example.net,DIRECT", config["rules"])

    def test_idempotent_projection(self):
        config = self.config()
        for group_filter in ("(?i)德国|DE", ""):
            with self.subTest(pattern=group_filter):
                config["proxy-groups"][1]["filter"] = group_filter
                apply_stash_bootstrap(config, {"airports": [airport()]})
                once = copy.deepcopy(config)
                apply_stash_bootstrap(config, {"airports": [airport()]})
                self.assertEqual(config, once)

    def test_country_and_all_groups_keep_reject_and_drop_empty_provider_direct(self):
        for country in COUNTRY_CATALOG:
            group = {"name": country["id"], "type": "url-test", "use": ["airport"], "filter": country["filter"]}
            guard_provider_groups({"proxy-groups": [group]})
            pattern = re.compile(group["filter"])
            self.assertEqual(group["proxies"], ["REJECT"])
            self.assertEqual(group["empty-fallback"], "REJECT")
            # Simulate the native provider's DIRECT placeholder after a cache failure.
            candidates = [name for name in group["proxies"] + ["DIRECT"] if pattern.search(name)]
            self.assertEqual(candidates, ["REJECT"])
            for name in ("DIRECT", "PASS", "GLOBAL"):
                self.assertIsNone(pattern.search(name), (country["id"], name))
        all_pattern = re.compile(_not_builtin_filter())
        for name in ("DE", "JP 1", "DIRECT-X", "DIRECTOR", "GLOBAL-HK", "PASS-US", "新加坡", "REJECT"):
            self.assertIsNotNone(all_pattern.search(name), name)
        self.assertNotIn("?!", all_pattern.pattern)

    def test_unsafe_custom_group_is_rejected(self):
        with self.assertRaises(ValueError):
            guard_provider_groups({"proxy-groups": [{"use": ["airport"], "filter": ".*"}]})

    def test_existing_exact_dns_exception_is_never_overwritten(self):
        config = self.config()
        config["dns"]["nameserver-policy"]["entry.example.net"] = "https://8.8.8.8/dns-query#PROXY"
        before = copy.deepcopy(config)
        with self.assertRaises(ValueError):
            apply_stash_bootstrap(config, {"airports": [airport()]})
        self.assertEqual(config, before)

    def test_benchmark_or_resource_hostname_cannot_be_added_to_direct_dns(self):
        for host in ("cp.cloudflare.com", "provider.example.net"):
            item = airport()
            item["bootstrap_dns"]["domains"] = [host]
            with self.assertRaises(ValueError):
                apply_stash_bootstrap(self.config(), {"airports": [item]})

    def test_disabled_removed_or_stale_provider_does_not_add_exceptions(self):
        for mode in ("disabled", "removed", "stale"):
            config, item = self.config(), airport()
            if mode == "disabled":
                item["enabled"] = False
            elif mode == "removed":
                config["proxy-providers"] = {}
            else:
                item["url"] += "-changed"
            apply_stash_bootstrap(config, {"airports": [item]})
            self.assertNotIn("entry.example.net", config["dns"]["nameserver-policy"])

    def test_template_subscription_mismatch_is_rejected(self):
        config = self.config()
        config["proxy-providers"][f"airport-{AIRPORT_ID}"]["url"] += "-changed"
        with self.assertRaises(ValueError):
            apply_stash_bootstrap(config, {"airports": [airport()]})

    def test_inventory_only_keeps_servers_not_sni_urls_names_or_credentials(self):
        value = inventory_from_provider({"proxies": [
            {"server": "ENTRY.example.net.", "name": "Website secret", "sni": "www.example.org", "password": "secret"},
            {"server": "entry.example.net"}, {"server": "203.0.113.10"}, {"server": "2001:db8::1"},
        ]}, URL)
        self.assertEqual(value["domains"], ["entry.example.net"])
        self.assertNotIn("secret", json.dumps(value))
        self.assertNotIn("token", json.dumps(value))
        self.assertEqual(value["url_sha256"], hashlib.sha256(URL.encode()).hexdigest())

    def test_bad_domains_cannot_expand_policy_scope(self):
        for value in (None, 3, "*.example.net", "+.example.net", "geosite:cn", "https://example.net/", "a\n.example.net", "localhost", "a..example.net"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                entry_domain(value)
        with self.assertRaises(ValueError):
            normalize_inventory({"url_sha256": hashlib.sha256(URL.encode()).hexdigest(), "domains": ["203.0.113.1"]}, URL)

    def test_catalog_preserves_inventory_but_invalidates_changed_url(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inputs.json"
            path.write_text(json.dumps({"version": 4, "airports": [airport()], "exits": []}))
            self.assertIn("bootstrap_dns", normalized_config(path)["airports"][0])
            self.assertNotIn("entry.example.net", json.dumps(overview(path)))
            payload = {"operation": "airport_update", "airport_id": AIRPORT_ID, "airport_name": "Renamed",
                       "airport_url": "", "airport_enabled": True, "countries": ["all"]}
            update(path, payload)
            self.assertIn("bootstrap_dns", normalized_config(path)["airports"][0])
            update(path, {**payload, "airport_url": URL + "-new"})
            self.assertNotIn("bootstrap_dns", normalized_config(path)["airports"][0])
            with self.assertRaises(Exception):
                update(path, {"operation": "airport_bootstrap_update", "airport_id": AIRPORT_ID,
                              "bootstrap_dns": airport()["bootstrap_dns"]})

    def test_offline_import_checks_subscription_and_redacts_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            item = airport()
            item.pop("bootstrap_dns")
            path = root / "inputs.json"
            path.write_text(json.dumps({"version": 4, "airports": [item], "exits": []}))
            client, cache = root / "client.yaml", root / "cache.yaml"
            client.write_text(json.dumps({"proxy-providers": {f"airport-{AIRPORT_ID}": {"url": URL}}}))
            cache.write_text("proxies:\n  - server: entry.example.net\n    password: secret\n")
            export = [sys.executable, "-m", "lib.stash_bootstrap", "export", "--airport-id", AIRPORT_ID,
                      "--client-config", str(client), "--provider-cache", str(cache)]
            exported = subprocess.run(export, capture_output=True, text=True, check=True).stdout
            self.assertNotIn("private", exported)
            self.assertNotIn("secret", exported)
            command = [sys.executable, "-m", "lib.stash_bootstrap", "import", "--config", str(path),
                       "--airport-id", AIRPORT_ID]
            result = subprocess.run(command, input=exported, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {"ok": True, "domain_count": 1})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(normalized_config(path)["airports"][0]["bootstrap_dns"]["domains"], ["entry.example.net"])
            before = path.read_bytes()
            client.write_text("invalid: [token=private")
            result = subprocess.run(export, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_bytes(), before)
            self.assertNotIn("private", result.stdout + result.stderr)
            stale = json.loads(exported)
            stale["url_sha256"] = "0" * 64
            result = subprocess.run(command, input=json.dumps(stale), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()

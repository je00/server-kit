#!/usr/bin/env python3
"""验证机场选择到 Mihomo 配置的唯一投影。"""

from __future__ import annotations

import unittest
from pathlib import Path

from ruamel.yaml import YAML

from lib.clash_airport_projection import apply_airport_projection, apply_clean_projection


class ClashAirportProjectionTests(unittest.TestCase):
    def config(self) -> dict:
        return YAML(typ="rt").load(Path("clash_skeleton.yaml").read_text(encoding="utf-8"))

    def test_only_enabled_airport_countries_are_added_to_proxy(self) -> None:
        config = self.config()
        catalog = {"airports": [
            {"id": "111111111111", "name": "主用", "url": "https://a.test/sub", "enabled": True, "countries": ["hk", "jp"]},
            {"id": "222222222222", "name": "停用", "url": "https://b.test/sub", "enabled": False, "countries": ["all"]},
        ]}
        names = apply_airport_projection(config, catalog)
        self.assertEqual(names, ["机场 · 主用 · 香港", "机场 · 主用 · 日本"])
        self.assertEqual(list(config["proxy-providers"]), ["airport-111111111111"])
        proxy = next(item for item in config["proxy-groups"] if item["name"] == "PROXY")
        self.assertEqual(config["proxy-groups"][0]["name"], "PROXY")
        self.assertEqual(proxy["proxies"][-2:], names)
        self.assertFalse(any(item.get("name") == "plane-tw" for item in config["proxy-groups"]))
        provider = config["proxy-providers"]["airport-111111111111"]
        self.assertEqual(provider["override"]["additional-prefix"], "[主用] ")
        self.assertEqual(
            provider["health-check"]["url"],
            "https://8.8.8.8/generate_204",
        )
        self.assertFalse(provider["health-check"]["lazy"])
        country_group = next(
            item for item in config["proxy-groups"]
            if item["name"] == "机场 · 主用 · 香港"
        )
        self.assertEqual(country_group["url"], "https://8.8.8.8/generate_204")
        self.assertFalse(country_group["lazy"])
        group_names = [item["name"] for item in config["proxy-groups"]]
        self.assertLess(group_names.index("MID"), group_names.index("机场 · 主用 · 香港"))

    def test_clean_projection_removes_airports_and_hides_mid_from_proxy(self) -> None:
        config = self.config()
        apply_airport_projection(config, {"airports": [{
            "id": "111111111111", "name": "主用", "url": "https://a.test/sub",
            "enabled": True, "countries": ["hk", "jp"],
        }]})
        apply_clean_projection(config)
        self.assertFalse(any(
            name == "airport" or name.startswith("airport-")
            for name in config["proxy-providers"]
        ))
        group_names = [item["name"] for item in config["proxy-groups"]]
        self.assertIn("MID", group_names)
        self.assertFalse(any(name.startswith("机场 · ") for name in group_names))
        proxy = next(item for item in config["proxy-groups"] if item["name"] == "PROXY")
        self.assertNotIn("MID", proxy["proxies"])
        self.assertEqual(proxy["proxies"], [])

    def test_skeleton_uses_ip_doh_and_eager_health_checks(self) -> None:
        config = self.config()
        dns = config["dns"]
        domestic_doh = [
            "https://223.5.5.5/dns-query",
            "https://1.12.12.12/dns-query",
        ]
        self.assertNotIn("default-nameserver", dns)
        self.assertEqual(dns["proxy-server-nameserver"], domestic_doh)
        self.assertEqual(dns["nameserver-policy"]["geosite:cn"], domestic_doh)
        self.assertEqual(dns["nameserver-policy"]["+.byd.auto"], domestic_doh)
        self.assertTrue(dns["follow-rule"])
        self.assertEqual(dns["enhanced-mode"], "fake-ip")

        provider = config["proxy-providers"]["airport"]
        self.assertEqual(
            provider["health-check"]["url"],
            "https://8.8.8.8/generate_204",
        )
        self.assertFalse(provider["health-check"]["lazy"])
        checked_groups = {
            group["name"]: group
            for group in config["proxy-groups"]
            if group.get("type") in {"fallback", "url-test"}
        }
        self.assertEqual(set(checked_groups), {"MID"})
        for group in checked_groups.values():
            self.assertEqual(group["url"], "https://8.8.8.8/generate_204")
            self.assertFalse(group["lazy"])

        self.assertNotIn(
            "UDP-FAILOVER",
            [group["name"] for group in config["proxy-groups"]],
        )
        udp_rule_index = config["rules"].index("NETWORK,udp,PROXY")
        self.assertEqual(config["rules"][udp_rule_index + 1], "NETWORK,udp,REJECT")
        self.assertNotIn("IP-CIDR,203.0.113.10/32,DIRECT,no-resolve", config["rules"])
        self.assertNotIn("IP-CIDR,198.51.100.20/32,DIRECT,no-resolve", config["rules"])

    def test_all_country_has_no_filter_and_empty_selection_keeps_valid_proxy(self) -> None:
        config = self.config()
        apply_airport_projection(config, {"airports": [
            {"id": "111111111111", "name": "全部", "url": "https://a.test/sub", "enabled": True, "countries": ["all"]},
        ]})
        group = next(item for item in config["proxy-groups"] if item["name"] == "机场 · 全部 · 全部地区")
        self.assertNotIn("filter", group)
        empty = self.config()
        names = apply_airport_projection(empty, {"airports": []})
        proxy = next(item for item in empty["proxy-groups"] if item["name"] == "PROXY")
        self.assertEqual(names, [])
        self.assertEqual(proxy["proxies"], ["chain.mid.proxy", "MID"])


if __name__ == "__main__":
    unittest.main()

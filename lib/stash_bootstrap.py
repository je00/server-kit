#!/usr/bin/env python3
"""Stash 3.4 bootstrap: exact entry domains only; no network fetching here."""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

DIRECT_DOH = ("https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query")
MAX_DOMAINS = 4096
MAX_PROVIDER_BYTES = 4 * 1024 * 1024


def entry_domain(value: object) -> str | None:
    """Normalize an exact hostname. IP entries need no DNS exception."""
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("节点入口域名格式无效。")
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("节点入口域名格式无效。") from None
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("节点入口必须是完整域名，不能使用通配符、URL 或规则表达式。")
    return domain


def normalize_inventory(value: object, url: str) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"url_sha256", "domains"}:
        raise ValueError("节点 DNS 清单格式无效。")
    digest = value["url_sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("节点 DNS 清单缺少订阅指纹。")
    # Changing the subscription invalidates its old exceptions automatically.
    if digest != hashlib.sha256(url.encode()).hexdigest():
        return None
    domains = value["domains"]
    if not isinstance(domains, list) or len(domains) > MAX_DOMAINS:
        raise ValueError("节点 DNS 清单数量无效。")
    clean = [entry_domain(item) for item in domains]
    if any(item is None for item in clean):
        raise ValueError("节点 DNS 清单只能包含域名。")
    return {"url_sha256": digest, "domains": sorted(set(clean))}


def inventory_from_provider(provider: object, url: str) -> dict:
    proxies = provider.get("proxies") if isinstance(provider, dict) else None
    if not isinstance(proxies, list) or not proxies or len(proxies) > MAX_DOMAINS:
        raise ValueError("节点缓存必须包含非空 proxies 列表。")
    domains = set()
    for node in proxies:
        if not isinstance(node, dict):
            raise ValueError("节点缓存格式无效。")
        domain = entry_domain(node.get("server"))
        if domain:
            domains.add(domain)
    return {"url_sha256": hashlib.sha256(url.encode()).hexdigest(), "domains": sorted(domains)}


def _not_builtin_filter() -> str:
    """RE2-compatible complement of DIRECT/PASS/GLOBAL (no lookahead)."""
    def branches(prefix: str, words: list[str]) -> list[str]:
        children = sorted({word[len(prefix)] for word in words if len(word) > len(prefix)})
        terms = [] if prefix in words else [re.escape(prefix)]
        if children:
            terms.append(re.escape(prefix) + "[^" + "".join(children) + "].*")
            for child in children:
                terms.extend(branches(prefix + child, [word for word in words if word.startswith(prefix + child)]))
        else:
            terms.append(re.escape(prefix) + ".+")
        return terms
    return "^(?:" + "|".join(branches("", ["DIRECT", "PASS", "GLOBAL"])) + ")$"


def guard_provider_groups(config: dict) -> None:
    for group in config.get("proxy-groups", []):
        if not isinstance(group, dict) or not group.get("use"):
            continue
        # Never insert PROXY (would recurse) or another exit (would change IP).
        group["proxies"] = ["REJECT"]
        group["empty-fallback"] = "REJECT"  # Mihomo; native Stash uses proxies above.
        pattern = group.get("filter", "")
        if not isinstance(pattern, str):
            raise ValueError("机场策略组过滤条件无效。")
        if not pattern:
            group["filter"] = _not_builtin_filter()
        elif pattern == _not_builtin_filter():
            continue
        else:
            # Generated country filters use a leading (?i), supported by RE2.
            flags = "(?i)" if pattern.startswith("(?i)") else ""
            body = pattern[len(flags):]
            if body.endswith("|^REJECT$"):
                body = body[:-len("|^REJECT$")]
                if body.startswith("(?:") and body.endswith(")"):
                    body = body[3:-1]
            try:
                if any(re.search(pattern, name) for name in ("DIRECT", "PASS", "GLOBAL")):
                    raise ValueError("机场过滤条件可能接受直连占位节点，拒绝发布。")
            except re.error:
                raise ValueError("机场策略组过滤条件无效。") from None
            group["filter"] = flags + "(?:" + body + ")|^REJECT$"


def apply_stash_bootstrap(config: dict, catalog: dict) -> None:
    """Project modern VLESS profiles; leave AWG and legacy profiles untouched."""
    providers = config.get("proxy-providers", {})
    dns = config.get("dns")
    rules = config.get("rules")
    if not isinstance(dns, dict) or not isinstance(rules, list) or not isinstance(providers, dict):
        raise ValueError("Stash DNS 或规则配置无效。")
    original = dns.get("nameserver-policy", {})
    if not isinstance(original, dict):
        raise ValueError("Stash DNS 策略必须是映射。")
    # Identify control-plane DNS so entry exceptions cannot overwrite it.
    # Existing domestic DNS and website routing are user policy, not ours to change.
    resources = {}
    for section_name, section in config.items():
        if not str(section_name).endswith("-providers") or not isinstance(section, dict):
            continue
        for provider in section.values():
            if isinstance(provider, dict) and provider.get("url"):
                host = urlsplit(provider["url"]).hostname
                if host and host in original:
                    resources[host] = original[host]

    domains = set()
    for airport in catalog.get("airports", []):
        if not airport.get("enabled") or f"airport-{airport['id']}" not in providers:
            continue
        inventory = normalize_inventory(airport.get("bootstrap_dns"), airport["url"])
        if inventory:
            if providers[f"airport-{airport['id']}"].get("url") != airport["url"]:
                raise ValueError("发布模板与节点 DNS 清单的订阅不一致。")
            domains.update(inventory["domains"])
    for node in config.get("proxies", []):
        if isinstance(node, dict) and node.get("server"):
            domain = entry_domain(node["server"])
            if domain:
                domains.add(domain)
    benchmarks = {
        urlsplit(str(item.get(key, ""))).hostname
        for section in (config.get("proxies", []), list(providers.values()), config.get("proxy-groups", []))
        for item in section if isinstance(item, dict)
        for key in ("benchmark-url", "url")
    }
    if domains.intersection(resources) or domains.intersection(benchmarks):
        raise ValueError("节点域名与订阅、规则或测速域名重叠，不能安全添加直连 DNS 例外。")

    policies = copy.deepcopy(original)
    for domain in sorted(domains):
        if domain in policies:
            # Do not overwrite an existing exact policy, even for a node.
            values = policies[domain]
            values = values if isinstance(values, list) else [values]
            if ({str(value).split("#", 1)[0] for value in values} != set(DIRECT_DOH)
                    or any("#" in str(value) and not str(value).endswith("#DIRECT") for value in values)):
                raise ValueError("节点域名已有不同的 DNS 策略，拒绝覆盖用户配置。")
        else:
            policies[domain] = list(DIRECT_DOH)
    dns["nameserver-policy"] = policies
    dns["follow-rule"] = True
    routes = [
        *(f"IP-CIDR,{urlsplit(value).hostname}/32,DIRECT,no-resolve" for value in DIRECT_DOH),
    ]
    for rule in reversed(routes):
        if rule not in rules:
            rules.insert(0, rule)
    guard_provider_groups(config)


def _read_yaml(path: Path) -> dict:
    try:
        from ruamel.yaml import YAML

        with path.open("rb") as handle:
            content = handle.read(MAX_PROVIDER_BYTES + 1)
        if len(content) > MAX_PROVIDER_BYTES:
            raise ValueError()
        value = YAML(typ="safe").load(content)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except Exception:
        # Parser messages can contain subscription tokens/passwords.
        raise ValueError("无法读取客户端配置或节点缓存。") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export", help="Extract domain-only metadata from a trusted client cache")
    export.add_argument("--airport-id", required=True)
    export.add_argument("--client-config", required=True, type=Path)
    export.add_argument("--provider-cache", required=True, type=Path)
    importer = commands.add_parser("import", help="Read metadata from stdin; never fetch a subscription")
    importer.add_argument("--config", required=True, type=Path)
    importer.add_argument("--airport-id", required=True)
    args = parser.parse_args()
    try:
        if args.command == "export":
            client = _read_yaml(args.client_config)
            provider = client.get("proxy-providers", {}).get(f"airport-{args.airport_id}", {})
            url = provider.get("url")
            if not isinstance(url, str) or urlsplit(url).scheme not in {"http", "https"}:
                raise ValueError()
            inventory = inventory_from_provider(_read_yaml(args.provider_cache), url)
            print(json.dumps(inventory))
            return 0
        try:
            from .server_kit_proxy_resources import normalized_config, update
        except ImportError:
            from server_kit_proxy_resources import normalized_config, update
        catalog = normalized_config(args.config)
        airport = next((item for item in catalog["airports"] if item["id"] == args.airport_id), None)
        if airport is None:
            raise ValueError("机场不存在。")
        content = sys.stdin.read(MAX_PROVIDER_BYTES + 1)
        if len(content) > MAX_PROVIDER_BYTES:
            raise ValueError()
        inventory = normalize_inventory(json.loads(content), airport["url"])
        if inventory is None:
            raise ValueError("客户端与服务端订阅不一致，拒绝导入。")
        update(args.config, {"operation": "airport_bootstrap_update", "airport_id": args.airport_id,
                             "bootstrap_dns": inventory})
        print(json.dumps({"ok": True, "domain_count": len(inventory["domains"])}))
        return 0
    except Exception:
        print("节点 DNS 清单处理失败；请检查文件、机场标识和订阅是否匹配。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

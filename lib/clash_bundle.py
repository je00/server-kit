#!/usr/bin/env python3
"""从同一 Clash 骨架生成 AWG 和受限 VLESS 的个性化订阅。"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import shlex
import urllib.parse
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.util import load_yaml_guess_indent

try:
    from .server_kit_public_endpoint import load as load_public_endpoint
except ImportError:
    from server_kit_public_endpoint import load as load_public_endpoint

try:
    from .server_kit_node_domains import (
        NodeDomainError, load_address_state, load_state as load_node_domain_state,
    )
except ImportError:  # 直接执行脚本时 lib 目录本身位于模块搜索路径
    from server_kit_node_domains import (
        NodeDomainError, load_address_state, load_state as load_node_domain_state,
    )

try:
    from .server_kit_relay import (
        RelayError, load_config as load_relay_config, subscription_node,
        vless_subscription_nodes,
    )
except ImportError:
    from server_kit_relay import (
        RelayError, load_config as load_relay_config, subscription_node,
        vless_subscription_nodes,
    )

try:
    from .clash_airport_projection import apply_clean_projection
    from .stash_bootstrap import apply_stash_bootstrap
    from .server_kit_publication_state import PublicationStateError, load as load_publication_state
    from .server_kit_proxy_resources import (
        ProxyResourceError, normalized_config as load_proxy_inputs, selected_exit_ids,
    )
except ImportError:
    from clash_airport_projection import apply_clean_projection
    from stash_bootstrap import apply_stash_bootstrap
    from server_kit_publication_state import PublicationStateError, load as load_publication_state
    from server_kit_proxy_resources import (
        ProxyResourceError, normalized_config as load_proxy_inputs, selected_exit_ids,
    )


NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
TOKEN_PATTERN = re.compile(r"^[0-9a-f]{64}$")
STASH_DISABLED_RULE_PROVIDERS = {
    "reject",
    "proxy",
    "direct",
    "gfw",
    "tld-not-cn",
}
STASH_BENCHMARK_URL = "http://cp.cloudflare.com/generate_204"
STASH_BENCHMARK_TIMEOUT = 5
DNS_PROXY_UPSTREAMS = (
    "https://8.8.8.8/dns-query#PROXY",
    # 1.1.1.1 is reserved for the dedicated relay probe; use its alternate
    # address here to keep the general resolver on a separate routing role.
    "https://1.0.0.1/dns-query#PROXY",
)
DOMESTIC_DNS_UPSTREAMS = ("223.5.5.5", "1.12.12.12")
BOOTSTRAP_DNS_UPSTREAMS = tuple(
    f"https://{address}/dns-query#DIRECT" for address in DOMESTIC_DNS_UPSTREAMS
)


def fail(message: str) -> None:
    raise SystemExit(message)


def load_json(path: Path, default: dict | None = None) -> dict:
    if not path.is_file():
        if default is not None:
            return copy.deepcopy(default)
        fail(f"文件不存在：{path}")
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError) as error:
        fail(f"无法读取 JSON {path}：{error}")
    if not isinstance(value, dict):
        fail(f"JSON 顶层必须是对象：{path}")
    return value


def load_assignments(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        try:
            parts = shlex.split(raw_value, posix=True)
        except ValueError:
            continue
        if len(parts) == 1:
            values[key] = parts[0]
    return values


def load_peer_db(path: Path) -> list[tuple[str, str]]:
    peers: list[tuple[str, str]] = []
    names: set[str] = set()
    addresses: set[str] = set()
    if not path.is_file():
        return peers
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw_line:
            continue
        fields = raw_line.split("\t")
        if len(fields) != 2:
            fail(f"节点清单 {path} 第 {line_number} 行格式无效")
        name, address = fields
        if not NAME_PATTERN.fullmatch(name):
            fail(f"节点名称无效：{name}")
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError as error:
            fail(f"节点 {name} 的 IP 无效：{error}")
        if name in names or address in addresses:
            fail(f"节点名称或 IP 重复：{name}")
        names.add(name)
        addresses.add(address)
        peers.append((name, address))
    return peers


def direct_rule(endpoint: str) -> str:
    try:
        address = ipaddress.ip_address(endpoint.strip("[]"))
    except ValueError:
        return f"DOMAIN,{endpoint},DIRECT"
    if address.version == 6:
        return f"IP-CIDR6,{address}/128,DIRECT,no-resolve"
    return f"IP-CIDR,{address}/32,DIRECT,no-resolve"


def normalize_endpoint_address(value: str) -> str:
    """接受数字 IP 或规范 FQDN，供代理启动端点使用。"""

    candidate = value.strip().rstrip(".")
    try:
        return str(ipaddress.ip_address(candidate.strip("[]")))
    except ValueError:
        pass
    try:
        candidate = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        fail("代理启动端点不是有效 IP 或域名")
    labels = candidate.split(".")
    label_pattern = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
    if (
        len(candidate) > 253
        or len(labels) < 2
        or any(not label_pattern.fullmatch(label) for label in labels)
    ):
        fail("代理启动端点不是有效 IP 或域名")
    return candidate


def add_route_exclusion(config: dict, value: str) -> None:
    tun = config.setdefault("tun", CommentedMap())
    if not isinstance(tun, dict):
        fail("基础 Clash 订阅的 tun 必须是映射")
    exclusions = tun.get("route-exclude-address")
    if exclusions is None:
        exclusions = CommentedSeq()
        tun["route-exclude-address"] = exclusions
    if not isinstance(exclusions, list):
        fail("tun.route-exclude-address 必须是列表")
    while value in exclusions:
        exclusions.remove(value)
    exclusions.insert(0, value)


def load_existing_tokens(path: Path) -> dict[str, str]:
    tokens: dict[str, str] = {}
    config = load_json(path, {"downloads": []})
    for item in config.get("downloads", []):
        if not isinstance(item, dict):
            continue
        name = item.get("peer_name", "")
        token = item.get("token", "")
        if NAME_PATTERN.fullmatch(name) and TOKEN_PATTERN.fullmatch(token):
            tokens[name] = token
    return tokens


def append_node(config: dict, node: dict) -> None:
    proxies = config.setdefault("proxies", CommentedSeq())
    if not isinstance(proxies, list):
        fail("基础 Clash 订阅的 proxies 必须是列表")
    proxies.append(CommentedMap(node))
    if "proxy-groups" in config and hasattr(config, "yaml_set_comment_before_after_key"):
        config.yaml_set_comment_before_after_key("proxy-groups", before="\n")


def apply_exit_projection(config: dict, catalog: dict, node_name: str, kind: str) -> list[str]:
    """只保留当前订阅身份允许看到的出口节点。"""

    exits = catalog.get("exits", [])
    if not isinstance(exits, list):
        fail("出口节点目录格式无效")
    exit_names = {
        item["id"]: item["proxy"]["name"]
        for item in exits
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and isinstance(item.get("proxy"), dict)
        and isinstance(item["proxy"].get("name"), str)
    }
    if len(exit_names) != len(exits):
        fail("出口节点目录包含无效发布名称")
    selected_ids = selected_exit_ids(catalog, node_name)
    selected_names = [exit_names[item] for item in selected_ids if item in exit_names]
    known_names = set(exit_names.values()) | {"chain.mid.proxy"}

    proxies = config.get("proxies")
    groups = config.get("proxy-groups")
    if not isinstance(proxies, list) or not isinstance(groups, list):
        fail("基础 Clash 订阅缺少出口节点或策略组")
    proxies[:] = [
        item for item in proxies
        if not (
            isinstance(item, dict)
            and item.get("name") in known_names
            and item.get("name") not in selected_names
        )
    ]
    proxy_group = next((
        item for item in groups
        if isinstance(item, dict) and item.get("name") == "PROXY"
    ), None)
    if not isinstance(proxy_group, dict) or not isinstance(proxy_group.get("proxies"), list):
        fail("基础 Clash 订阅缺少 PROXY 分组")
    proxy_group["proxies"][:] = [
        item for item in proxy_group["proxies"]
        if item not in known_names or item in selected_names
    ]
    return [item for item in selected_ids if item in exit_names]


def prepend_rules(config: dict, rules: list[str]) -> None:
    target = config.setdefault("rules", CommentedSeq())
    if not isinstance(target, list):
        fail("基础 Clash 订阅的 rules 必须是列表")
    for rule in rules:
        while rule in target:
            target.remove(rule)
    for rule in reversed(rules):
        target.insert(0, rule)


def apply_internal_hosts(config: dict, mappings: dict[str, str]) -> None:
    """把全局强制解析记录注入每个订阅，并确保 DNS 尊重 hosts。"""

    hosts = config.setdefault("hosts", CommentedMap())
    if not isinstance(hosts, dict):
        fail("基础 Clash 订阅的 hosts 必须是映射")
    for domain, address in mappings.items():
        hosts[domain] = address
    dns = config.setdefault("dns", CommentedMap())
    if not isinstance(dns, dict):
        fail("基础 Clash 订阅的 dns 必须是映射")
    dns["use-hosts"] = True


def add_fake_ip_filter(config: dict, hostname: str) -> None:
    """让隧道入口域名始终返回真实 IP，避免 VPN 切换时缓存 Fake-IP。"""

    dns = config.get("dns")
    if not isinstance(dns, dict):
        fail("基础 Clash 订阅缺少 dns 映射")
    filters = dns.setdefault("fake-ip-filter", CommentedSeq())
    if not isinstance(filters, list):
        fail("基础 Clash 订阅的 dns.fake-ip-filter 必须是列表")
    filters[:] = [item for item in filters if str(item).casefold() != hostname.casefold()]
    filters.insert(0, hostname)


def apply_vless_proxy_hosts(config: dict, mappings: dict[str, str]) -> None:
    """Stash 向 VLESS 转发域名时，在客户端把代理目标改写为内网 IP。"""

    proxy_hosts = config.setdefault("proxy-hosts", CommentedMap())
    if not isinstance(proxy_hosts, dict):
        fail("基础 Clash 订阅的 proxy-hosts 必须是映射")
    for domain, address in mappings.items():
        proxy_hosts[domain] = address


def _legacy_dns_value(value: object) -> object:
    """移除旧版 Stash 不认识的 DNS 出站片段。"""

    if isinstance(value, str):
        return value.split("#", 1)[0]
    if isinstance(value, list):
        return CommentedSeq(_legacy_dns_value(item) for item in value)
    return value


def add_server_relay(config: dict, node: dict) -> None:
    """把服务端中转加入节点清单和主选择组，但不改变现代订阅默认项。"""

    proxies = config.setdefault("proxies", CommentedSeq())
    groups = config.get("proxy-groups", [])
    if not isinstance(proxies, list) or not isinstance(groups, list):
        fail("基础 Clash 订阅的 proxies 和 proxy-groups 必须是列表")
    relay_name = node["name"]
    proxies[:] = [
        item for item in proxies
        if not isinstance(item, dict) or item.get("name") != relay_name
    ]
    proxies.append(CommentedMap(node))
    main_group = next(
        (item for item in groups if isinstance(item, dict) and item.get("name") == "PROXY"),
        None,
    )
    if main_group is None:
        fail("基础 Clash 订阅缺少 PROXY 策略组")
    members = main_group.get("proxies")
    if not isinstance(members, list):
        fail("PROXY 策略组的 proxies 必须是列表")
    while relay_name in members:
        members.remove(relay_name)
    # 保留现代订阅原来的默认项，只把中转放在其后作为可选救援节点。
    members.insert(1 if members else 0, relay_name)


def apply_stash_benchmark(config: dict) -> None:
    """Use Stash's native benchmark fields, including remotely refreshed nodes.

    Provider benchmark-url/benchmark-timeout have been supported since 2.6.5.
    Mihomo health-check.url is not a substitute for these fields in Stash.
    """

    proxies = config.get("proxies", [])
    if not isinstance(proxies, list):
        fail("基础 Clash 订阅的 proxies 必须是列表")
    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        proxy["benchmark-url"] = STASH_BENCHMARK_URL
        proxy["benchmark-timeout"] = STASH_BENCHMARK_TIMEOUT
    providers = config.get("proxy-providers", {})
    if not isinstance(providers, dict):
        fail("基础 Clash 订阅的 proxy-providers 必须是映射")
    for provider in providers.values():
        if isinstance(provider, dict):
            provider["benchmark-url"] = STASH_BENCHMARK_URL
            provider["benchmark-timeout"] = STASH_BENCHMARK_TIMEOUT


def resource_endpoints(config: dict) -> set[str]:
    """收集远程 Provider/规则资源 URL 的主机，供启动链路使用。"""

    endpoints: set[str] = set()
    for section_name, section in config.items():
        if not isinstance(section_name, str) or not section_name.endswith("-providers"):
            continue
        if not isinstance(section, dict):
            continue
        for provider in section.values():
            if not isinstance(provider, dict):
                continue
            url = provider.get("url")
            if not isinstance(url, str):
                continue
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            endpoints.add(parsed.hostname)
    return endpoints


def configure_resource_download_proxy(config: dict, proxy_name: str) -> None:
    """让现代 Mihomo 的远程 Provider/规则下载显式经过启动组。"""

    for section_name, section in config.items():
        if not isinstance(section_name, str) or not section_name.endswith("-providers"):
            continue
        if not isinstance(section, dict):
            continue
        for provider in section.values():
            if (
                isinstance(provider, dict)
                and provider.get("type") == "http"
                and isinstance(provider.get("url"), str)
            ):
                provider["proxy"] = proxy_name


def endpoint_rule(endpoint: str, target: str) -> str:
    try:
        address = ipaddress.ip_address(endpoint)
    except ValueError:
        return f"DOMAIN,{endpoint},{target}"
    family = "IP-CIDR6" if address.version == 6 else "IP-CIDR"
    return f"{family},{address}/{address.max_prefixlen},{target},no-resolve"


def configure_provider_empty_fallback(config: dict, relay_name: str) -> None:
    """Mihomo 的远程 Provider 为空时使用服务端中转，禁止退回 DIRECT。"""

    groups = config.get("proxy-groups", [])
    if not isinstance(groups, list):
        fail("基础 Clash 订阅的 proxy-groups 必须是列表")
    for group in groups:
        if isinstance(group, dict) and isinstance(group.get("use"), list):
            group["empty-fallback"] = relay_name


def relay_endpoint_names(relay_name: str) -> tuple[str, str]:
    names = (f"{relay_name}.443", f"{relay_name}.2053")
    if any(
        len(name) > 96
        or not name.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
        for name in names
    ):
        fail("服务端 VLESS 转发组名称过长，无法生成 443/2053 节点名称")
    return names


def apply_exit_dns_projection(
    config: dict,
    exit_records: list[dict],
    relay_nodes: list[dict],
    consistent_exit_ids: set[str],
) -> None:
    """把受保护出口绑定到同身份的服务端入口，避免客户端绕过出口 DNS。"""

    if not any(record["id"] in consistent_exit_ids for record in exit_records):
        return
    if len(exit_records) != len(relay_nodes):
        fail("出口一致 DNS 缺少匹配的 VLESS 服务端转发身份")
    proxies = config.get("proxies")
    if not isinstance(proxies, list):
        fail("基础 Clash 订阅的 proxies 必须是列表")
    endpoints = {
        item.get("name"): item for item in proxies if isinstance(item, dict)
    }
    replacements: dict[str, dict] = {}
    # vless_subscription_nodes 按出口记录的顺序生成对应身份。
    for record, relay in zip(exit_records, relay_nodes):
        if record["id"] not in consistent_exit_ids:
            continue
        exit_name = record["proxy"]["name"]
        # 纯净订阅已经删除 EXIT 节点，只保留服务端转发组。
        if exit_name not in endpoints:
            continue
        primary_name, _ = relay_endpoint_names(relay["name"])
        endpoint = endpoints.get(primary_name)
        if (
            not isinstance(endpoint, dict)
            or endpoint.get("type") != "vless"
            or endpoint.get("port") != 443
            or endpoint.get("uuid") != relay["uuid"]
            or endpoint.get("dialer-proxy") is not None
        ):
            fail(f"出口一致 DNS 缺少独立的 443 服务端入口：{exit_name}")
        replacement = copy.deepcopy(endpoint)
        replacement["name"] = exit_name
        replacements[exit_name] = replacement
    proxies[:] = [
        CommentedMap(replacements[item["name"]])
        if isinstance(item, dict) and item.get("name") in replacements else item
        for item in proxies
    ]


def move_proxy_group_first(config: dict) -> None:
    groups = config.get("proxy-groups", [])
    if not isinstance(groups, list):
        fail("基础 Clash 订阅的 proxy-groups 必须是列表")
    main_group = next(
        (item for item in groups if isinstance(item, dict) and item.get("name") == "PROXY"),
        None,
    )
    if main_group is None:
        fail("基础 Clash 订阅缺少 PROXY 策略组")
    groups.remove(main_group)
    groups.insert(0, main_group)


def add_server_relay_group(
    config: dict,
    relay_nodes: list[dict],
    server_address: str,
    relay_group_name: str = "SERVER.RELAY.VLESS",
) -> tuple[list[str], set[str]]:
    """为每个出口建立独立双入口组，并用首选出口承载 DNS 启动链。"""

    fixed_address = normalize_endpoint_address(server_address)

    proxies = config.setdefault("proxies", CommentedSeq())
    groups = config.get("proxy-groups", [])
    dns = config.get("dns")
    if not isinstance(proxies, list) or not isinstance(groups, list):
        fail("基础 Clash 订阅的 proxies 和 proxy-groups 必须是列表")
    if not isinstance(dns, dict):
        fail("基础 Clash 订阅的 dns 必须是映射")

    endpoint_templates = {
        item.get("name"): item
        for item in proxies
        if isinstance(item, dict)
        and item.get("name") in {"ENDPOINT.MID.443", "ENDPOINT.MID.2053"}
    }
    if set(endpoint_templates) != {"ENDPOINT.MID.443", "ENDPOINT.MID.2053"}:
        fail("SERVER.RELAY.VLESS 需要 443 和 2053 两个 MID VLESS 节点模板")
    if not relay_nodes:
        fail("SERVER.RELAY.VLESS 缺少可发布出口")
    endpoint_names: list[str] = []
    primary_names: list[str] = []
    group_names: list[str] = []
    for relay_node in relay_nodes:
        relay_uuid = relay_node.get("uuid")
        relay_name = relay_node.get("name")
        if not isinstance(relay_uuid, str) or not relay_uuid:
            fail("SERVER.RELAY.VLESS 的服务端转发身份缺少 UUID")
        if not isinstance(relay_name, str) or not relay_name:
            fail("SERVER.RELAY.VLESS 转发节点名称无效")
        primary_node, rescue_node = relay_endpoint_names(relay_name)
        group_names.append(relay_name)
        primary_names.append(primary_node)
        endpoint_names.extend((primary_node, rescue_node))
    node_names = set(endpoint_names)
    proxies[:] = [
        item for item in proxies
        if not isinstance(item, dict)
        or (
            item.get("name") not in node_names | {relay_group_name}
            and not str(item.get("name", "")).startswith(f"{relay_group_name}.")
        )
    ]
    for relay_node in relay_nodes:
        primary_node, rescue_node = relay_endpoint_names(str(relay_node["name"]))
        for template_name, node_name, port in (
            ("ENDPOINT.MID.443", primary_node, 443),
            ("ENDPOINT.MID.2053", rescue_node, 2053),
        ):
            node = copy.deepcopy(endpoint_templates[template_name])
            node["name"] = node_name
            node["server"] = fixed_address
            node["port"] = port
            node["uuid"] = relay_node["uuid"]
            node.pop("dialer-proxy", None)
            proxies.append(CommentedMap(node))

    groups[:] = [
        item for item in groups
        if not isinstance(item, dict)
        or (
            item.get("name") != relay_group_name
            and not str(item.get("name", "")).startswith(f"{relay_group_name}.")
        )
    ]
    relay_groups = CommentedSeq()
    for relay_name, primary_name in zip(group_names, primary_names):
        relay_groups.append(CommentedMap({
            "name": relay_name,
            "type": "fallback",
            "proxies": CommentedSeq([primary_name, f"{relay_name}.2053"]),
            "url": "https://8.8.8.8/generate_204",
            "interval": 300,
            "lazy": False,
        }))
    main_group = next(
        (item for item in groups if isinstance(item, dict) and item.get("name") == "PROXY"),
        None,
    )
    if main_group is None or not isinstance(main_group.get("proxies"), list):
        fail("基础 Clash 订阅缺少有效的 PROXY 策略组")
    main_group["proxies"][:] = [
        item for item in main_group["proxies"]
        if item != relay_group_name
        and not str(item).startswith(f"{relay_group_name}.")
    ]
    main_group["proxies"][:0] = group_names
    move_proxy_group_first(config)
    groups[1:1] = relay_groups

    bootstrap_group_name = group_names[0]
    relay_upstream = f"https://1.1.1.1/dns-query#{bootstrap_group_name}"
    domestic_doh = CommentedSeq(
        f"https://{address}/dns-query" for address in DOMESTIC_DNS_UPSTREAMS
    )
    # 代理节点尚未建立前，只能通过独立直连 DNS 找到入口域名。
    # IP 形式 DoH 不依赖其他域名，也不会把普通业务 DNS 改为直连。
    dns["proxy-server-nameserver"] = CommentedSeq(BOOTSTRAP_DNS_UPSTREAMS)
    dns["direct-nameserver"] = domestic_doh
    dns["nameserver"] = CommentedSeq(DNS_PROXY_UPSTREAMS)
    policies = dns.setdefault("nameserver-policy", CommentedMap())
    if not isinstance(policies, dict):
        fail("基础 Clash 订阅的 dns.nameserver-policy 必须是映射")
    policies[fixed_address] = CommentedSeq(BOOTSTRAP_DNS_UPSTREAMS)
    bootstrap_endpoints = resource_endpoints(config)
    configure_resource_download_proxy(config, bootstrap_group_name)
    for endpoint in sorted(bootstrap_endpoints):
        policies[endpoint] = CommentedSeq([relay_upstream])

    prepend_rules(config, [
        *(f"IP-CIDR,{address}/32,DIRECT,no-resolve" for address in DOMESTIC_DNS_UPSTREAMS),
        f"IP-CIDR,1.1.1.1/32,{bootstrap_group_name},no-resolve",
        *(endpoint_rule(endpoint, bootstrap_group_name) for endpoint in sorted(bootstrap_endpoints)),
        direct_rule(fixed_address),
    ])
    configure_provider_empty_fallback(config, primary_names[0])
    return group_names, node_names


def apply_legacy_stash_compat(
    config: dict,
    public_address: str,
    relay_name: str = "",
    preserved_vless_names: set[str] | None = None,
    vless_relay_group_names: list[str] | None = None,
) -> None:
    """把现代 Mihomo/Stash 配置降级为老 Stash 可反序列化的语法。

    老版本把 ``route-exclude-address`` 和 DNS policy 的若干字段声明为
    单个字符串；现代配置中的数组会触发 ``cannot unmarshal !!seq into
    string``。兼容投影仅用于被标记的 VLESS 订阅。
    """

    public_address = normalize_endpoint_address(public_address)

    # Stash 自己管理 iOS VPN 隧道，旧版本不接受 Mihomo 的 tun 数组字段。
    config.pop("tun", None)

    proxies = config.get("proxies", [])
    if not isinstance(proxies, list):
        fail("基础 Clash 订阅的 proxies 必须是列表")
    unsupported_names: set[str] = set()
    # 兼容订阅仍需保留 MID 的两个独立 VLESS 入口。旧版 Stash 不支持的是
    # 通过 dialer-proxy 把 SOCKS 节点套在 MID 上的链式写法，而不是 MID
    # fallback 组本身。
    mid_vless_names = {"ENDPOINT.MID.443", "ENDPOINT.MID.2053"}
    preserved_vless_names = (preserved_vless_names or set()) | mid_vless_names
    vless_relay_group_names = vless_relay_group_names or []
    for proxy in proxies:
        if (
            isinstance(proxy, dict)
            and proxy.get("type") == "vless"
            and (
                proxy.get("name") in mid_vless_names
                or str(proxy.get("name", "")).startswith("PRIVATE-")
            )
        ):
            proxy["server"] = public_address
        if isinstance(proxy, dict) and (
            (
                proxy.get("type") == "vless"
                and proxy.get("name") not in preserved_vless_names
            )
            or proxy.get("dialer-proxy") is not None
        ):
            name = proxy.get("name")
            if isinstance(name, str):
                unsupported_names.add(name)
    if relay_name or preserved_vless_names:
        proxies[:] = [
            proxy for proxy in proxies
            if not isinstance(proxy, dict) or proxy.get("name") not in unsupported_names
        ]

        groups = config.get("proxy-groups", [])
        if not isinstance(groups, list):
            fail("基础 Clash 订阅的 proxy-groups 必须是列表")
        for group in groups:
            if not isinstance(group, dict):
                continue
            empty_fallback = group.pop("empty-fallback", "")
            members = group.get("proxies")
            if (
                isinstance(group.get("use"), list)
                and isinstance(empty_fallback, str)
                and empty_fallback in preserved_vless_names
            ):
                if not isinstance(members, list):
                    members = CommentedSeq()
                    group["proxies"] = members
                if empty_fallback not in members:
                    # 旧 Stash 不支持 Mihomo empty-fallback；给 Provider 组
                    # 放入真实中转节点，避免空 Provider 被解释为 DIRECT。
                    members.append(empty_fallback)
            if not isinstance(members, list):
                continue
            members[:] = [
                member for member in members
                if member not in unsupported_names
            ]
            if group.get("name") == "PROXY":
                # 只提升原本就在 PROXY 中的服务端中转组；443/2053 实际
                # 节点需在兼容订阅中保留，但不能越过 fallback 组直接混入
                # 日常出口选择。
                relay_vless_names = sorted(
                    (preserved_vless_names - mid_vless_names) & set(members)
                )
                relay_group_names = [
                    name for name in vless_relay_group_names if name in members
                ]
                preferred = [
                    name for name in [*relay_group_names, relay_name, *relay_vless_names, "MID"]
                    if name
                ]
                members[:] = [member for member in members if member not in preferred]
                members[:0] = preferred
        rules = config.get("rules", [])
        if not isinstance(rules, list):
            fail("基础 Clash 订阅的 rules 必须是列表")
        rules[:] = [
            rule for rule in rules
            if not isinstance(rule, str)
            or not any(
                rule.endswith(f",{name}") or f",{name}," in rule
                for name in unsupported_names
            )
        ]
    prepend_rules(config, [direct_rule(public_address)])
    move_proxy_group_first(config)

    # 旧 Stash 不声明 Provider 下载代理；前置 DOMAIN 规则承担同一职责。
    for section_name, section in config.items():
        if not isinstance(section_name, str) or not section_name.endswith("-providers"):
            continue
        if isinstance(section, dict):
            for provider in section.values():
                if isinstance(provider, dict):
                    provider.pop("proxy", None)

    dns = config.get("dns")
    if dns is None:
        return
    if not isinstance(dns, dict):
        fail("基础 Clash 订阅的 dns 必须是映射")

    # 这些键是现代 Mihomo 的扩展；旧 Stash 通过 follow-rule 路由 IP 形式 DoH。
    dns.pop("respect-rules", None)
    dns.pop("direct-nameserver", None)
    dns.pop("direct-nameserver-follow-policy", None)
    if "nameserver" in dns:
        dns["nameserver"] = _legacy_dns_value(dns["nameserver"])

    proxy_nameservers = dns.get("proxy-server-nameserver")
    if isinstance(proxy_nameservers, list):
        if proxy_nameservers:
            dns["proxy-server-nameserver"] = _legacy_dns_value(proxy_nameservers[0])
        else:
            dns.pop("proxy-server-nameserver", None)
    elif proxy_nameservers is not None:
        dns["proxy-server-nameserver"] = _legacy_dns_value(proxy_nameservers)

    policies = dns.get("nameserver-policy")
    if isinstance(policies, dict):
        for key, value in list(policies.items()):
            if isinstance(value, list):
                if value:
                    policies[key] = _legacy_dns_value(value[0])
                else:
                    del policies[key]
            else:
                policies[key] = _legacy_dns_value(value)


def comment_yaml_line(line: str) -> str:
    """保留缩进和换行，把一行 YAML 内容改为注释。"""
    match = re.match(r"^(\s*)(.*?)(\r?\n)?$", line)
    if match is None:
        return line
    indent, content, ending = match.groups()
    if not content or content.lstrip().startswith("#"):
        return line
    return f"{indent}# {content}{ending or ''}"


def comment_stash_rules(text: str) -> str:
    """注释 Stash 停用的规则及规则集，完整保留骨架中的原始内容。"""
    lines = text.splitlines(keepends=True)
    section = ""
    provider_indent: int | None = None
    provider_disabled = False
    output: list[str] = []

    for line in lines:
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        active = bool(stripped.strip()) and not stripped.startswith("#")

        if active and indent == 0:
            key_match = re.match(r"^([^:#]+):", stripped)
            key = key_match.group(1).strip() if key_match else ""
            section = key if key in {"rule-providers", "rules"} else ""
            provider_indent = None
            provider_disabled = False
            output.append(line)
            continue

        if section == "rule-providers" and active:
            key_match = re.match(r"^(\s+)([A-Za-z0-9_.-]+):", line)
            if key_match:
                current_indent = len(key_match.group(1))
                if provider_indent is None:
                    provider_indent = current_indent
                if current_indent == provider_indent:
                    provider_disabled = (
                        key_match.group(2) in STASH_DISABLED_RULE_PROVIDERS
                    )
            if provider_disabled:
                line = comment_yaml_line(line)
        elif section == "rules" and active:
            rule_match = re.match(r"^\s*-\s*RULE-SET,([^,\s]+),", line)
            if rule_match and rule_match.group(1) in STASH_DISABLED_RULE_PROVIDERS:
                line = comment_yaml_line(line)

        output.append(line)

    return "".join(output)

def write_subscription(
    yaml: YAML,
    config: dict,
    path: Path,
    comment_disabled_rules: bool = False,
) -> bytes:
    stream = io.StringIO()
    yaml.dump(config, stream)
    text = stream.getvalue()
    if comment_disabled_rules:
        text = comment_stash_rules(text)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    return path.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--awg-peer-db", type=Path, required=True)
    parser.add_argument("--awg-state", type=Path, required=True)
    parser.add_argument("--public-endpoint", type=Path, default=Path("/etc/server-kit/public-endpoint.json"))
    parser.add_argument("--vless-policy", type=Path, required=True)
    parser.add_argument("--vless-summary", type=Path, required=True)
    parser.add_argument("--staging-dir", type=Path, required=True)
    parser.add_argument("--final-dir", type=Path, required=True)
    parser.add_argument("--existing-config", type=Path, required=True)
    parser.add_argument("--publication-state", type=Path, required=True)
    parser.add_argument("--proxy-inputs", type=Path, required=True)
    parser.add_argument("--node-domains", type=Path, required=True)
    parser.add_argument("--server-relay", type=Path, required=True)
    parser.add_argument("--output-config", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--server-address", required=True)
    parser.add_argument("--relay-address", default="")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()

    base_text = args.base.read_text(encoding="utf-8")
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.width = 4096
    _, indent, offset = load_yaml_guess_indent(base_text)
    if indent is not None:
        yaml.indent(mapping=max(indent - (offset or 0), 1), sequence=indent, offset=offset or 0)
    yaml.line_break = "\r\n" if "\r\n" in base_text else "\n"
    base = yaml.load(base_text)
    if not isinstance(base, dict):
        fail("基础 Clash 订阅必须是 YAML 映射")

    relay_address = normalize_endpoint_address(args.relay_address or args.server_address)

    try:
        relay_config = load_relay_config(args.server_relay, required=False)
        relay_node = subscription_node(args.server_relay, relay_address)
    except RelayError as error:
        fail(str(error))
    consistent_exit_ids = set((relay_config or {}).get("dns_consistent_exit_ids", []))
    if consistent_exit_ids and not (
        relay_config and relay_config["enabled"] and relay_config["vless_enabled"]
    ):
        fail("出口一致 DNS 需要启用 VLESS 服务端转发，拒绝发布绕过该模式的出口")
    if relay_node is not None:
        add_server_relay(base, relay_node)
        prepend_rules(base, [direct_rule(str(relay_node["server"]))])

    awg_state = load_assignments(args.awg_state)
    awg_network = awg_state.get("AWG_SUBNET_CIDR", "10.20.0.0/24")
    stable_endpoint = load_public_endpoint(args.public_endpoint, strict=True)
    awg_endpoint = stable_endpoint or awg_state.get("AWG_PUBLIC_IP", "")
    if stable_endpoint:
        add_fake_ip_filter(base, stable_endpoint)
        proxies = base.get("proxies", [])
        if not isinstance(proxies, list):
            fail("基础 Clash 订阅的 proxies 必须是列表")
        endpoint_nodes = [
            item for item in proxies
            if isinstance(item, dict)
            and item.get("name") in {"ENDPOINT.MID.443", "ENDPOINT.MID.2053"}
        ]
        if {item.get("name") for item in endpoint_nodes} != {
            "ENDPOINT.MID.443", "ENDPOINT.MID.2053"
        }:
            fail("基础 Clash 订阅必须包含 443 和 2053 两个 MID 节点")
        for endpoint_node in endpoint_nodes:
            endpoint_node["server"] = stable_endpoint
    ipaddress.ip_network(awg_network, strict=False)
    awg_peers = load_peer_db(args.awg_peer_db)
    if awg_peers and not awg_endpoint:
        fail(f"AWG 已有普通节点，但状态文件缺少 AWG_PUBLIC_IP：{args.awg_state}")
    if awg_endpoint and not stable_endpoint:
        try:
            ipaddress.ip_address(awg_endpoint)
        except ValueError as error:
            fail(f"AWG_PUBLIC_IP 不是有效 IP：{error}")
    awg_names = {name for name, _ in awg_peers}
    awg_addresses = dict(awg_peers)
    try:
        node_domains = load_node_domain_state(args.node_domains)
        address_domains = load_address_state(args.node_domains)
    except NodeDomainError as error:
        fail(str(error))
    host_mappings = {
        domain: awg_addresses[name]
        for name, domains in node_domains.items()
        if name in awg_addresses
        for domain in domains
    }
    host_mappings.update({
        domain: address
        for address, domains in address_domains.items()
        for domain in domains
    })
    vless_policy = load_json(args.vless_policy, {"version": 1, "clients": {}})
    vless_summary = load_json(args.vless_summary)
    vless_template = vless_summary.get("vless_template")
    if not isinstance(vless_template, dict):
        fail("VLESS 摘要缺少节点模板")

    def add_vless_server_relay(
        subscription: dict, name: str, selected_ids: list[str], *, legacy_stash: bool = False
    ) -> tuple[list[str], set[str]]:
        records_by_id = {
            item["id"]: item
            for item in proxy_inputs.get("exits", [])
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        selected_records = [records_by_id[item] for item in selected_ids if item in records_by_id]
        try:
            relay_nodes = vless_subscription_nodes(
                args.server_relay, name, vless_template, selected_records
            )
        except RelayError as error:
            fail(str(error))
        if not relay_nodes:
            return [], set()
        for relay in relay_nodes:
            endpoint = str(relay.get("server", ""))
            if not endpoint:
                fail("VLESS 服务端转发节点缺少 server")
        relay_group_names, endpoint_names = add_server_relay_group(
            subscription, relay_nodes, relay_address
        )
        if not legacy_stash:
            apply_exit_dns_projection(
                subscription, selected_records, relay_nodes, consistent_exit_ids
            )
        return relay_group_names, endpoint_names
    vless_clients = vless_policy.get("clients", {})
    if not isinstance(vless_clients, dict):
        fail("VLESS 权限文件中的 clients 必须是对象")
    all_names = set(awg_names)
    for name, client in vless_clients.items():
        if not NAME_PATTERN.fullmatch(name):
            fail(f"VLESS 客户端名称无效：{name}")
        if not isinstance(client, dict) or not client.get("enabled", True):
            continue
        if name in all_names:
            fail(f"普通节点与 VLESS 客户端重名：{name}")
        all_names.add(name)
    if not all_names:
        fail("当前没有可发布的普通节点或 VLESS 客户端")

    args.staging_dir.mkdir(parents=True, exist_ok=True)
    existing_tokens = load_existing_tokens(args.existing_config)
    try:
        publication_state = load_publication_state(args.publication_state)
    except PublicationStateError as error:
        fail(str(error))
    disabled_publications = set(publication_state["disabled"])
    clean_mode_nodes = set(publication_state["clean_mode"])
    try:
        proxy_inputs = load_proxy_inputs(args.proxy_inputs)
    except ProxyResourceError as error:
        fail(str(error))
    used_tokens: set[str] = set()
    downloads = []

    def publish(
        name: str,
        kind: str,
        subscription: dict,
        comment_disabled_rules: bool = False,
    ) -> None:
        download_name = f"clash-{name}.yaml"
        path = args.staging_dir / download_name
        content = write_subscription(
            yaml,
            subscription,
            path,
            comment_disabled_rules=comment_disabled_rules,
        )
        token = existing_tokens.get(name, "")
        while not TOKEN_PATTERN.fullmatch(token) or token in used_tokens:
            token = secrets.token_hex(32)
        used_tokens.add(token)
        downloads.append({
            "peer_name": name,
            "node_kind": kind,
            "token": token,
            "download_name": download_name,
            "payload_path": str(args.final_dir / download_name),
            "content_type": "text/yaml; charset=utf-8",
            "sha256": hashlib.sha256(content).hexdigest(),
            "file_size": len(content),
        })

    for name, _ in awg_peers:
        if name in disabled_publications:
            continue
        subscription = copy.deepcopy(base)
        selected_exit_ids_for_node = apply_exit_projection(
            subscription, proxy_inputs, name, "awg"
        )
        if name in clean_mode_nodes:
            apply_clean_projection(subscription)
        add_vless_server_relay(subscription, name, selected_exit_ids_for_node)
        apply_internal_hosts(subscription, host_mappings)
        add_route_exclusion(subscription, awg_network)
        rules = [f"IP-CIDR,{awg_network},DIRECT,no-resolve"]
        if awg_endpoint:
            try:
                endpoint_address = ipaddress.ip_address(awg_endpoint)
                add_route_exclusion(
                    subscription,
                    f"{endpoint_address}/{endpoint_address.max_prefixlen}",
                )
            except ValueError:
                pass
            rules.insert(0, direct_rule(awg_endpoint))
        prepend_rules(subscription, rules)
        publish(name, "amneziawg", subscription)

    for name in sorted(vless_clients):
        client = vless_clients[name]
        if not isinstance(client, dict) or not client.get("enabled", True):
            continue
        if name in disabled_publications:
            continue
        client_id = client.get("uuid", "")
        if not isinstance(client_id, str) or not client_id:
            fail(f"VLESS 客户端 {name} 缺少 UUID")
        legacy_stash = client.get("legacy_stash", False)
        if not isinstance(legacy_stash, bool):
            fail(f"VLESS 客户端 {name} 的 legacy_stash 必须是布尔值")
        subscription = copy.deepcopy(base)
        selected_exit_ids_for_node = apply_exit_projection(
            subscription, proxy_inputs, name, "vless"
        )
        if name in clean_mode_nodes:
            apply_clean_projection(subscription)
        vless_relay_group_names, preserved_relay_names = add_vless_server_relay(
            subscription, name, selected_exit_ids_for_node, legacy_stash=legacy_stash
        )
        apply_internal_hosts(subscription, host_mappings)
        apply_vless_proxy_hosts(subscription, host_mappings)
        node = copy.deepcopy(vless_template)
        node_name = f"PRIVATE-{name}"
        node["name"] = node_name
        node["uuid"] = client_id
        if stable_endpoint:
            node["server"] = stable_endpoint
        endpoint = str(node.get("server", ""))
        if not endpoint:
            fail(f"VLESS 客户端 {name} 的节点模板缺少 server")
        append_node(subscription, node)
        if endpoint:
            try:
                endpoint_address = ipaddress.ip_address(endpoint)
                add_route_exclusion(subscription, f"{endpoint_address}/{endpoint_address.max_prefixlen}")
            except ValueError:
                pass
        prepend_rules(subscription, [
            direct_rule(endpoint),
            f"IP-CIDR,{awg_network},{node_name},no-resolve",
        ])
        apply_stash_benchmark(subscription)
        if legacy_stash:
            apply_legacy_stash_compat(
                subscription,
                relay_address,
                str(relay_node["name"]) if relay_node is not None else "",
                preserved_relay_names,
                vless_relay_group_names,
            )
        else:
            try:
                apply_stash_bootstrap(subscription, proxy_inputs)
            except ValueError as error:
                fail(str(error))
        publish(name, "vless", subscription, comment_disabled_rules=True)

    service_config = {
        "mode": "clash",
        "port": args.port,
        "server_address": args.server_address,
        "downloads": downloads,
        "cert_path": args.cert,
        "key_path": args.key,
    }
    args.output_config.parent.mkdir(parents=True, exist_ok=True)
    with args.output_config.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(service_config, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(args.output_config, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

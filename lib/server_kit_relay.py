#!/usr/bin/env python3
"""管理 Clash/Stash 的服务端 Shadowsocks 与 VLESS 转发身份。"""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import tempfile
import uuid
from pathlib import Path

try:
    from .server_kit_proxy_resources import ProxyResourceError, exit_publish_token
except ImportError:
    from server_kit_proxy_resources import ProxyResourceError, exit_publish_token


SCHEMA_VERSION = 1
INBOUND_TAG = "server-kit-relay"
OUTBOUND_TAG = "server-kit-relay-exit"
BLOCK_OUTBOUND_TAG = "server-kit-relay-block"
DEFAULT_NODE_NAME = "SERVER.RELAY"
DEFAULT_METHOD = "chacha20-poly1305"
DEFAULT_CLIENT_CIPHER = "chacha20-ietf-poly1305"
VLESS_EMAIL_PREFIX = "server-kit-relay-vless:"
DEFAULT_VLESS_NODE_NAME = "SERVER.RELAY.VLESS"
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class RelayError(RuntimeError):
    """表示中转配置不完整或不安全。"""


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RelayError(f"文件不存在：{path}") from error
    except (OSError, ValueError) as error:
        raise RelayError(f"无法读取 JSON {path}：{error}") from error
    if not isinstance(value, dict):
        raise RelayError(f"JSON 顶层必须是对象：{path}")
    return value


def _atomic_write(path: Path, value: dict, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _valid_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise RelayError("服务端中转端口必须是 1–65535 的整数。")
    return value


def load_config(path: Path, *, required: bool = True) -> dict | None:
    if not path.is_file():
        if required:
            raise RelayError(f"服务端中转尚未配置：{path}")
        return None
    value = _load_json(path)
    if value.get("schema_version") != SCHEMA_VERSION:
        raise RelayError("服务端中转配置版本无效。")
    if not isinstance(value.get("enabled"), bool):
        raise RelayError("服务端中转 enabled 必须是布尔值。")
    shadowsocks_enabled = value.get("shadowsocks_enabled", True)
    if not isinstance(shadowsocks_enabled, bool):
        raise RelayError("Shadowsocks 服务端中转开关必须是布尔值。")
    listen = value.get("listen")
    try:
        listen = str(ipaddress.ip_address(listen))
    except (TypeError, ValueError) as error:
        raise RelayError("服务端中转监听地址必须是 IP。") from error
    method = value.get("method")
    cipher = value.get("client_cipher")
    if method != DEFAULT_METHOD or cipher != DEFAULT_CLIENT_CIPHER:
        raise RelayError("服务端中转必须使用兼容旧 Stash 的 chacha20-poly1305。")
    password = value.get("password")
    if not isinstance(password, str) or not 24 <= len(password) <= 256:
        raise RelayError("服务端中转密码长度必须为 24–256 个字符。")
    node_name = value.get("node_name")
    if not isinstance(node_name, str) or not NAME_PATTERN.fullmatch(node_name):
        raise RelayError("服务端中转节点名称无效。")
    vless_enabled = value.get("vless_enabled", False)
    if not isinstance(vless_enabled, bool):
        raise RelayError("VLESS 服务端转发开关必须是布尔值。")
    identity_secret = value.get("identity_secret", "")
    if not isinstance(identity_secret, str) or (vless_enabled and len(identity_secret) < 32):
        raise RelayError("VLESS 服务端转发身份密钥无效。")
    vless_node_name = value.get("vless_node_name", DEFAULT_VLESS_NODE_NAME)
    if not isinstance(vless_node_name, str) or not NAME_PATTERN.fullmatch(vless_node_name):
        raise RelayError("VLESS 服务端转发节点名称无效。")
    dns_ids = value.get("dns_consistent_exit_ids", [])
    if (
        not isinstance(dns_ids, list)
        or any(not isinstance(item, str) or not re.fullmatch(r"[a-f0-9]{12}", item) for item in dns_ids)
        or len(dns_ids) != len(set(dns_ids))
    ):
        raise RelayError("出口一致 DNS 必须指定不重复的出口 ID。")
    return {
        "schema_version": SCHEMA_VERSION,
        "enabled": value["enabled"],
        "shadowsocks_enabled": shadowsocks_enabled,
        "listen": listen,
        "port": _valid_port(value.get("port")),
        "method": method,
        "client_cipher": cipher,
        "password": password,
        "node_name": node_name,
        "vless_enabled": vless_enabled,
        "identity_secret": identity_secret,
        "vless_node_name": vless_node_name,
        "dns_consistent_exit_ids": dns_ids,
    }


def initialize(path: Path, port: int) -> dict:
    existing = load_config(path, required=False)
    if existing is not None:
        if existing["port"] != port:
            raise RelayError(f"服务端中转已使用端口 {existing['port']}，不会静默改成 {port}。")
        return existing
    value = {
        "schema_version": SCHEMA_VERSION,
        "enabled": True,
        "shadowsocks_enabled": True,
        "listen": "0.0.0.0",
        "port": _valid_port(port),
        "method": DEFAULT_METHOD,
        "client_cipher": DEFAULT_CLIENT_CIPHER,
        "password": secrets.token_urlsafe(32),
        "node_name": DEFAULT_NODE_NAME,
        "vless_enabled": False,
        "identity_secret": "",
        "vless_node_name": DEFAULT_VLESS_NODE_NAME,
    }
    _atomic_write(path, value)
    return value


def enable_vless(path: Path) -> dict:
    value = load_config(path)
    assert value is not None
    if not value["identity_secret"]:
        value["identity_secret"] = secrets.token_urlsafe(32)
    value["vless_enabled"] = True
    _atomic_write(path, value)
    return value


def disable_shadowsocks(path: Path) -> dict:
    value = load_config(path)
    assert value is not None
    value["shadowsocks_enabled"] = False
    _atomic_write(path, value)
    return value


def relay_client_uuid(relay: dict, name: str, exit_id: str = "") -> str:
    if not NAME_PATTERN.fullmatch(name):
        raise RelayError(f"订阅名称无效：{name}")
    secret = relay.get("identity_secret", "")
    if not isinstance(secret, str) or len(secret) < 32:
        raise RelayError("VLESS 服务端转发身份密钥无效。")
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{VLESS_EMAIL_PREFIX}{name}:{exit_id}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    identity = bytearray(digest[:16])
    identity[6] = (identity[6] & 0x0F) | 0x40
    identity[8] = (identity[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(identity)))


def _subscription_names(peer_db_path: Path, vless_policy_path: Path) -> list[str]:
    names: set[str] = set()
    try:
        peer_lines = peer_db_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        peer_lines = []
    for line in peer_lines:
        name = line.split("\t", 1)[0]
        if not NAME_PATTERN.fullmatch(name):
            raise RelayError(f"AWG 节点名称无效：{name}")
        names.add(name)
    policy = _load_json(vless_policy_path)
    clients = policy.get("clients", {})
    if not isinstance(clients, dict):
        raise RelayError("VLESS 权限文件中的 clients 必须是对象。")
    for name, client in clients.items():
        if not NAME_PATTERN.fullmatch(name):
            raise RelayError(f"VLESS 客户端名称无效：{name}")
        if isinstance(client, dict) and client.get("enabled", True):
            names.add(name)
    return sorted(names)


def _exit_proxies(path: Path) -> tuple[list[dict], str, dict[str, list[str]]]:
    config = _load_json(path)
    if config.get("version") == 4:
        default_exit_id = config.get("default_exit_id")
        exits = config.get("exits", [])
        selections = config.get("awg_exit_selections", {})
        if not isinstance(exits, list) or not isinstance(selections, dict):
            raise RelayError("多出口目录格式无效。")
    else:
        value = config.get("exit_proxy")
        exits = [{"id": "000000000001", "name": "默认出口", "proxy": value}]
        default_exit_id = "000000000001"
        selections = {}
    result: list[dict] = []
    known_ids: set[str] = set()
    for record in exits:
        if not isinstance(record, dict):
            raise RelayError("出口节点记录格式无效。")
        exit_id = record.get("id")
        name = record.get("name")
        value = record.get("proxy")
        if not isinstance(exit_id, str) or not re.fullmatch(r"[a-f0-9]{12}", exit_id):
            raise RelayError("出口节点标识无效。")
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 40:
            raise RelayError("出口节点名称无效。")
        if isinstance(value, dict) and not value.get("type") and value.get("server"):
            value = {**value, "type": "socks5"}
        if not isinstance(value, dict) or value.get("type") != "socks5":
            raise RelayError(f"VLESS 服务端中转只支持 SOCKS5 出口：{name}")
        server = value.get("server")
        port = value.get("port")
        if not isinstance(server, str) or not server or any(char.isspace() for char in server):
            raise RelayError(f"SOCKS5 出口地址无效：{name}")
        _valid_port(port)
        username = value.get("username", "")
        password = value.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str):
            raise RelayError(f"SOCKS5 出口认证信息无效：{name}")
        known_ids.add(exit_id)
        result.append({
            "id": exit_id, "name": name.strip(), "server": server, "port": port,
            "username": username, "password": password,
        })
    if not result or default_exit_id not in known_ids:
        raise RelayError("服务端中转缺少有效的默认出口。")
    clean_selections: dict[str, list[str]] = {}
    for node_name, exit_ids in selections.items():
        if isinstance(node_name, str) and NAME_PATTERN.fullmatch(node_name) and isinstance(exit_ids, list):
            clean_selections[node_name] = [
                item for item in exit_ids if isinstance(item, str) and item in known_ids
            ]
    return result, str(default_exit_id), clean_selections


def configure_dns(config_path: Path, inputs_path: Path, exit_ids: list[str]) -> dict:
    relay = load_config(config_path)
    assert relay is not None
    known = {item["id"] for item in _exit_proxies(inputs_path)[0]}
    if len(exit_ids) != len(set(exit_ids)) or any(item not in known for item in exit_ids):
        raise RelayError("出口一致 DNS 包含不存在或重复的出口 ID。")
    if exit_ids and (not relay["enabled"] or not relay["vless_enabled"]):
        raise RelayError("出口一致 DNS 需要启用 VLESS 服务端转发。")
    relay["dns_consistent_exit_ids"] = sorted(exit_ids)
    _consistent_dns_endpoints(relay, _exit_proxies(inputs_path)[0])
    _atomic_write(config_path, relay)
    return relay


def _consistent_dns_endpoints(relay: dict, exits: list[dict]) -> dict[str, dict]:
    selected = set(relay.get("dns_consistent_exit_ids", []))
    if not relay["enabled"]:
        return {}
    if selected and not relay["vless_enabled"]:
        raise RelayError("出口一致 DNS 需要启用 VLESS 服务端转发。")
    endpoints: dict[str, dict] = {}
    used_ports: set[int] = set()
    for item in exits:
        exit_id = item["id"]
        if exit_id not in selected:
            continue
        port = 20000 + int(exit_id, 16) % 30000
        if port in used_ports:
            raise RelayError("出口一致 DNS 本机端口发生冲突，请重新添加其中一个出口以生成新 ID。")
        used_ports.add(port)
        # Only native gateway connections may bootstrap via the OS resolver.
        # A local upstream would allow the worker to dial itself or another worker.
        try:
            address = ipaddress.ip_address(item["server"])
        except ValueError:
            if item["server"].rstrip(".").lower() == "localhost":
                raise RelayError("出口一致 DNS 不允许本机 SOCKS5 上游。")
        else:
            if not address.is_global:
                raise RelayError("出口一致 DNS 需要公网 SOCKS5 上游。")
        password = hmac.new(
            relay["identity_secret"].encode(), f"exit-dns:{exit_id}".encode(), hashlib.sha256,
        ).hexdigest()
        endpoints[exit_id] = {
            "address": "127.0.0.1", "port": port,
            "users": [{"user": "server-kit", "pass": password, "level": 0}],
        }
    return endpoints


def render_exit_dns_workers(config_path: Path, inputs_path: Path) -> dict[str, dict]:
    """Each exit gets its own DNS cache/context; raw DoH transport cannot recurse."""
    relay = load_config(config_path)
    assert relay is not None
    exits = _exit_proxies(inputs_path)[0]
    endpoints = _consistent_dns_endpoints(relay, exits)
    result: dict[str, dict] = {}
    for item in exits:
        local = endpoints.get(item["id"])
        if local is None:
            continue
        server = {"address": item["server"], "port": item["port"]}
        if item["username"] or item["password"]:
            server["users"] = [{"user": item["username"], "pass": item["password"], "level": 0}]
        def outbound(tag: str, strategy: str) -> dict:
            return {
                "tag": tag, "protocol": "socks", "targetStrategy": strategy,
                "settings": {"servers": [copy.deepcopy(server)]},
                "streamSettings": {"sockopt": {"domainStrategy": "AsIs"}},
            }
        result[item["id"]] = {
            "log": {"loglevel": "warning"},
            "dns": {
                "tag": "consistent-dns", "queryStrategy": "UseIPv4",
                "disableFallback": True, "enableParallelQuery": True,
                "servers": [
                    {"address": url, "domains": ["regexp:.*"]}
                    for url in ("https://1.0.0.1/dns-query", "https://8.8.8.8/dns-query")
                ],
                "hosts": {"localhost": "127.0.0.1"},
            },
            "inbounds": [{
                "tag": "local", "listen": "127.0.0.1", "port": local["port"],
                "protocol": "socks", "settings": {
                    "auth": "password", "accounts": [{
                        "user": "server-kit", "pass": local["users"][0]["pass"],
                    }], "udp": True, "ip": "127.0.0.1",
                },
                "sniffing": {"enabled": False},
            }],
            "outbounds": [
                {"tag": "block", "protocol": "blackhole"},
                outbound("resolved-exit", "ForceIPv4"),
                outbound("dns-transport", "AsIs"),
            ],
            "routing": {"domainStrategy": "IPOnDemand", "rules": [
                {"type": "field", "inboundTag": ["consistent-dns"],
                 "ip": ["1.0.0.1/32", "8.8.8.8/32"], "port": "443", "network": "tcp",
                 "outboundTag": "dns-transport"},
                {"type": "field", "inboundTag": ["consistent-dns"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                {"type": "field", "inboundTag": ["local"], "outboundTag": "resolved-exit"},
            ]},
        }
    return result


def render_xray(
    config_path: Path,
    inputs_path: Path,
    xray_path: Path,
    peer_db_path: Path = Path("/etc/amneziawg/peers.tsv"),
    vless_policy_path: Path = Path("/etc/server-kit/vless-access.json"),
    public_tag: str = "vless-public",
) -> dict:
    relay = load_config(config_path)
    assert relay is not None
    xray = copy.deepcopy(_load_json(xray_path))
    inbounds = xray.setdefault("inbounds", [])
    outbounds = xray.setdefault("outbounds", [])
    routing = xray.setdefault("routing", {})
    rules = routing.setdefault("rules", []) if isinstance(routing, dict) else None
    if not isinstance(inbounds, list) or not isinstance(outbounds, list) or not isinstance(rules, list):
        raise RelayError("Xray 的 inbounds、outbounds 或 routing.rules 格式无效。")

    inbounds[:] = [item for item in inbounds if not isinstance(item, dict) or item.get("tag") != INBOUND_TAG]
    outbounds[:] = [
        item for item in outbounds
        if not isinstance(item, dict)
        or (
            not str(item.get("tag", "")).startswith(f"{OUTBOUND_TAG}-")
            and item.get("tag") not in {OUTBOUND_TAG, BLOCK_OUTBOUND_TAG}
        )
    ]
    rules[:] = [
        item for item in rules
        if not isinstance(item, dict)
        or (
            not str(item.get("outboundTag", "")).startswith(f"{OUTBOUND_TAG}-")
            and item.get("outboundTag") not in {OUTBOUND_TAG, BLOCK_OUTBOUND_TAG}
            and INBOUND_TAG not in item.get("inboundTag", [])
            and not any(
                isinstance(user, str) and user.startswith(VLESS_EMAIL_PREFIX)
                for user in item.get("user", [])
            )
        )
    ]
    vless_inbounds = [
        item for item in inbounds
        if isinstance(item, dict)
        and item.get("protocol") == "vless"
        and (
            item.get("tag") == public_tag
            or str(item.get("tag", "")).startswith(f"{public_tag}-")
        )
    ]
    for inbound in vless_inbounds:
        clients = inbound.setdefault("settings", {}).setdefault("clients", [])
        if not isinstance(clients, list):
            raise RelayError(f"VLESS 入站 {inbound.get('tag', '')} 的客户端格式无效。")
        clients[:] = [
            client for client in clients
            if not isinstance(client, dict)
            or not str(client.get("email", "")).startswith(VLESS_EMAIL_PREFIX)
        ]
    if not relay["enabled"]:
        return xray

    exit_proxies, default_exit_id, node_exit_selections = _exit_proxies(inputs_path)
    dns_endpoints = _consistent_dns_endpoints(relay, exit_proxies)
    exit_ids = [item["id"] for item in exit_proxies]
    if relay["shadowsocks_enabled"]:
        inbounds.append({
            "tag": INBOUND_TAG,
            "listen": relay["listen"],
            "port": relay["port"],
            "protocol": "shadowsocks",
            "settings": {
                "network": "tcp,udp",
                "method": relay["method"],
                "password": relay["password"],
                "email": "server-kit-relay",
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        })
    outbound_tags: dict[str, str] = {}
    for exit_proxy in exit_proxies:
        server = {
            "address": exit_proxy["server"],
            "port": exit_proxy["port"],
        }
        if exit_proxy["username"] or exit_proxy["password"]:
            server["users"] = [{
                "user": exit_proxy["username"],
                "pass": exit_proxy["password"],
                "level": 0,
            }]
        if exit_proxy["id"] in dns_endpoints:
            server = dns_endpoints[exit_proxy["id"]]
        outbound_tag = f"{OUTBOUND_TAG}-{exit_proxy['id']}"
        outbound_tags[exit_proxy["id"]] = outbound_tag
        outbounds.append({
            "tag": outbound_tag,
            "protocol": "socks",
            "settings": {"servers": [server]},
        })
    outbounds.append({
        "tag": BLOCK_OUTBOUND_TAG,
        "protocol": "blackhole",
        "settings": {},
    })
    if relay["shadowsocks_enabled"]:
        rules.insert(0, {
            "type": "field", "inboundTag": [INBOUND_TAG],
            "outboundTag": outbound_tags[default_exit_id],
        })
        rules.insert(0, {
            "type": "field", "inboundTag": [INBOUND_TAG], "ip": ["geoip:private"],
            "outboundTag": BLOCK_OUTBOUND_TAG,
        })
    if relay["vless_enabled"]:
        if not vless_inbounds:
            raise RelayError("没有可承载服务端转发身份的公网 VLESS 入站。")
        routing["domainStrategy"] = "IPIfNonMatch"
        names = _subscription_names(peer_db_path, vless_policy_path)
        emails_by_exit: dict[str, list[str]] = {exit_id: [] for exit_id in exit_ids}
        all_emails: list[str] = []
        default_flow = next(
            (
                str(client.get("flow", ""))
                for inbound in vless_inbounds
                for client in inbound["settings"]["clients"]
                if isinstance(client, dict) and client.get("flow")
            ),
            "",
        )
        for name in names:
            selected_ids = node_exit_selections.get(name, [default_exit_id])
            for exit_id in selected_ids:
                if exit_id not in outbound_tags:
                    continue
                email = f"{VLESS_EMAIL_PREFIX}{name}:{exit_id}"
                emails_by_exit[exit_id].append(email)
                all_emails.append(email)
                for inbound in vless_inbounds:
                    clients = inbound["settings"]["clients"]
                    entry = {
                        "id": relay_client_uuid(relay, name, exit_id), "email": email,
                    }
                    if default_flow:
                        entry["flow"] = default_flow
                    clients.append(entry)
        for exit_id, emails in emails_by_exit.items():
            if emails:
                rules.insert(0, {
                    "type": "field", "user": emails,
                    "outboundTag": outbound_tags[exit_id],
                })
        if all_emails:
            rules.insert(0, {
                "type": "field", "user": all_emails, "ip": ["geoip:private"],
                "outboundTag": BLOCK_OUTBOUND_TAG,
            })
    return xray


def subscription_node(config_path: Path, server_address: str) -> dict | None:
    relay = load_config(config_path, required=False)
    if relay is None or not relay["enabled"] or not relay["shadowsocks_enabled"]:
        return None
    candidate = server_address.strip().rstrip(".")
    try:
        server_address = str(ipaddress.ip_address(candidate.strip("[]")))
    except ValueError:
        try:
            server_address = candidate.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise RelayError("服务端中转订阅地址必须是有效 IP 或域名。") from error
        labels = server_address.split(".")
        label_pattern = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
        if (
            len(server_address) > 253
            or len(labels) < 2
            or any(not label_pattern.fullmatch(label) for label in labels)
        ):
            raise RelayError("服务端中转订阅地址必须是有效 IP 或域名。")
    return {
        "name": relay["node_name"],
        "type": "ss",
        "server": server_address,
        "port": relay["port"],
        "cipher": relay["client_cipher"],
        "password": relay["password"],
        "udp": True,
    }


def vless_subscription_nodes(
    config_path: Path,
    name: str,
    template: dict,
    exit_records: list[dict],
) -> list[dict]:
    relay = load_config(config_path, required=False)
    if relay is None or not relay["enabled"] or not relay["vless_enabled"]:
        return []
    if not isinstance(template, dict) or template.get("type") != "vless":
        raise RelayError("VLESS 服务端转发缺少有效节点模板。")
    nodes: list[dict] = []
    for record in exit_records:
        if not isinstance(record, dict):
            raise RelayError("VLESS 服务端转发出口记录无效。")
        exit_id = record.get("id")
        exit_name = record.get("name")
        if not isinstance(exit_id, str) or not re.fullmatch(r"[a-f0-9]{12}", exit_id):
            raise RelayError("VLESS 服务端转发出口标识无效。")
        if not isinstance(exit_name, str) or not exit_name.strip():
            raise RelayError("VLESS 服务端转发出口名称无效。")
        node = copy.deepcopy(template)
        try:
            publish_token = exit_publish_token(exit_name)
        except ProxyResourceError as error:
            raise RelayError(str(error)) from error
        node["name"] = f"{relay['vless_node_name']}.{publish_token}"
        node["uuid"] = relay_client_uuid(relay, name, exit_id)
        nodes.append(node)
    return nodes


def vless_subscription_node(config_path: Path, name: str, template: dict) -> dict | None:
    """兼容旧调用方；新订阅应使用 vless_subscription_nodes。"""

    nodes = vless_subscription_nodes(
        config_path, name, template,
        [{"id": "000000000001", "name": "默认出口"}],
    )
    return nodes[0] if nodes else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init")
    init.add_argument("--config", type=Path, required=True)
    init.add_argument("--port", type=int, required=True)
    enable = subparsers.add_parser("enable-vless")
    enable.add_argument("--config", type=Path, required=True)
    disable_ss = subparsers.add_parser("disable-shadowsocks")
    disable_ss.add_argument("--config", type=Path, required=True)
    dns_mode = subparsers.add_parser("configure-dns")
    dns_mode.add_argument("--config", type=Path, required=True)
    dns_mode.add_argument("--clash-inputs", type=Path, required=True)
    dns_mode.add_argument("--exit-id", action="append", default=[])
    render = subparsers.add_parser("render-xray")
    render.add_argument("--config", type=Path, required=True)
    render.add_argument("--clash-inputs", type=Path, required=True)
    render.add_argument("--xray", type=Path, required=True)
    render.add_argument("--output", type=Path, required=True)
    render.add_argument("--peer-db", type=Path, default=Path("/etc/amneziawg/peers.tsv"))
    render.add_argument("--vless-policy", type=Path, default=Path("/etc/server-kit/vless-access.json"))
    render.add_argument("--public-tag", default="vless-public")
    args = parser.parse_args()
    try:
        if args.command == "init":
            relay = initialize(args.config, args.port)
            print(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "enabled": relay["enabled"],
                "port": relay["port"],
                "node_name": relay["node_name"],
            }, ensure_ascii=False, separators=(",", ":")))
        elif args.command == "enable-vless":
            relay = enable_vless(args.config)
            print(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "vless_enabled": relay["vless_enabled"],
                "vless_node_name": relay["vless_node_name"],
            }, ensure_ascii=False, separators=(",", ":")))
        elif args.command == "disable-shadowsocks":
            relay = disable_shadowsocks(args.config)
            print(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "shadowsocks_enabled": relay["shadowsocks_enabled"],
                "port": relay["port"],
            }, ensure_ascii=False, separators=(",", ":")))
        elif args.command == "configure-dns":
            relay = configure_dns(args.config, args.clash_inputs, args.exit_id)
            print(json.dumps({"dns_consistent_exit_ids": relay["dns_consistent_exit_ids"]}))
        else:
            rendered = render_xray(
                args.config, args.clash_inputs, args.xray,
                args.peer_db, args.vless_policy, args.public_tag,
            )
            _atomic_write(args.output, rendered, 0o640)
    except RelayError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

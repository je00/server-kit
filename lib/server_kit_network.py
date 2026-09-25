#!/usr/bin/env python3
"""生成统一的内网节点与订阅发布视图，不暴露任何连接凭据。"""

from __future__ import annotations

import ipaddress
import base64
import binascii
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .server_kit_port_ranges import format_ports
except ImportError:
    from server_kit_port_ranges import format_ports

try:
    from .server_kit_node_domains import (
        NodeDomainError, load_address_state, load_state as load_node_domain_state,
    )
except ImportError:  # 直接执行脚本时 lib 目录本身位于模块搜索路径
    from server_kit_node_domains import (
        NodeDomainError, load_address_state, load_state as load_node_domain_state,
    )

try:
    from .server_kit_publication_state import PublicationStateError, load as load_publication_state
except ImportError:
    from server_kit_publication_state import PublicationStateError, load as load_publication_state

try:
    from .server_kit_proxy_resources import (
        ProxyResourceError, normalized_config as load_proxy_inputs, selected_exit_ids,
    )
except ImportError:
    from server_kit_proxy_resources import (
        ProxyResourceError, normalized_config as load_proxy_inputs, selected_exit_ids,
    )


NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


@dataclass(frozen=True)
class NetworkPaths:
    awg_active: Path
    awg_disabled: Path
    awg_credentials: Path
    awg_enrollments: Path
    awg_access: Path
    awg_access_pending: Path
    vless_active: Path
    vless_pending: Path
    clash: Path
    publication_state: Path
    node_domains: Path
    clash_inputs: Path
    management: Path


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def load_awg(path: Path) -> dict[str, str]:
    peers: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return peers
    for raw in lines:
        fields = raw.split("\t")
        if len(fields) != 2 or not NAME_PATTERN.fullmatch(fields[0]):
            continue
        try:
            address = str(ipaddress.ip_address(fields[1]))
        except (ValueError, binascii.Error):
            continue
        peers[fields[0]] = address
    return peers


def load_awg_credentials(path: Path) -> dict[str, dict[str, str]]:
    """读取节点托管类型，只投影公钥指纹，不返回密钥材料。"""

    credentials: dict[str, dict[str, str]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return credentials
    for raw in lines:
        fields = raw.split("\t")
        if len(fields) != 4 or not NAME_PATTERN.fullmatch(fields[0]):
            continue
        name, public_key, _preshared_key, custody = fields
        if custody != "client":
            continue
        try:
            decoded = base64.b64decode(public_key, validate=True)
        except ValueError:
            continue
        if len(decoded) != 32:
            continue
        credentials[name] = {
            "custody": custody,
            "public_key_fingerprint": hashlib.sha256(decoded).hexdigest()[:16],
        }
    return credentials


def clean(value: object, fallback: str = "未命名") -> str:
    if not isinstance(value, str):
        return fallback
    result = "".join(character for character in value.strip() if character.isprintable())
    return result[:96] or fallback


def read_assignment(path: Path, key: str) -> str:
    """只读取简单 KEY=VALUE 状态，不执行配置文件。"""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    prefix = f"{key}="
    for line in lines:
        if not line.startswith(prefix):
            continue
        value = line[len(prefix):].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        return value
    return ""


def clean_permissions(value: object) -> list[dict[str, object]]:
    """返回网页可展示的最小授权事实，丢弃未知字段。"""
    if not isinstance(value, list):
        return []
    result: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        target = item.get("target")
        network = str(item.get("network", "tcp")).lower()
        ports = item.get("ports")
        try:
            address = (
                str(ipaddress.ip_network(item.get("ip", ""), strict=False))
                if target == "all"
                else str(ipaddress.ip_address(item.get("ip", "")))
            )
        except ValueError:
            continue
        if (
            not isinstance(target, str)
            or not NAME_PATTERN.fullmatch(target)
            or network not in {"all", "tcp", "udp"}
            or not isinstance(ports, list)
        ):
            continue
        clean_ports = sorted({port for port in ports if isinstance(port, int) and 1 <= port <= 65535})
        if not clean_ports and network != "all":
            continue
        result.append({
            "target": target,
            "target_label": "全部节点" if target == "all" else ("VPS 本机" if target == "vps" else target),
            "ip": address,
            "ports": clean_ports,
            "ports_label": "全部端口" if network == "all" else format_ports(clean_ports, separator=", "),
            "network": network,
            "network_label": "全部协议" if network == "all" else network.upper(),
        })
    return sorted(result, key=lambda item: str(item["target"]).lower())


def published_nodes(path: Path) -> tuple[dict[str, dict[str, str]], bool]:
    config = load_json(path)
    if config.get("mode") != "clash" or not isinstance(config.get("downloads"), list):
        return {}, False
    result: dict[str, dict[str, str]] = {}
    for item in config["downloads"]:
        if not isinstance(item, dict):
            continue
        name = item.get("peer_name")
        if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
            continue
        kind = str(item.get("node_kind", "")).lower()
        if kind == "amneziawg":
            kind = "awg"
        if kind not in {"awg", "vless"}:
            continue
        result[name] = {
            "name": name,
            "kind": kind,
            "kind_label": "AmneziaWG" if kind == "awg" else "VLESS",
            "state": "已发布",
            "resource_id": name,
        }
    return result, True


def build_overview(paths: NetworkPaths, writes_enabled: bool) -> dict[str, Any]:
    active_awg = load_awg(paths.awg_active)
    disabled_awg = load_awg(paths.awg_disabled)
    awg_credentials = load_awg_credentials(paths.awg_credentials)
    enrollment_state = load_json(paths.awg_enrollments)
    enrollment_items = enrollment_state.get("items", {})
    enrollment_items = enrollment_items if isinstance(enrollment_items, dict) else {}
    enrollment_history = enrollment_state.get("history", [])
    enrollment_history = enrollment_history if isinstance(enrollment_history, list) else []
    awg_access = load_json(paths.awg_access)
    awg_access_clients = awg_access.get("clients", {})
    awg_access_clients = awg_access_clients if isinstance(awg_access_clients, dict) else {}
    active_policy = load_json(paths.vless_active)
    clients = active_policy.get("clients", {})
    clients = clients if isinstance(clients, dict) else {}
    publications, configured = published_nodes(paths.clash)
    try:
        publication_state = load_publication_state(paths.publication_state)
    except PublicationStateError:
        publication_state = {"disabled": [], "clean_mode": []}
    disabled_publications = set(publication_state["disabled"])
    clean_mode_nodes = set(publication_state["clean_mode"])
    try:
        node_domains = load_node_domain_state(paths.node_domains)
        address_domains = load_address_state(paths.node_domains)
    except NodeDomainError:
        node_domains = {}
        address_domains = {}
    try:
        proxy_inputs = load_proxy_inputs(paths.clash_inputs)
    except ProxyResourceError:
        proxy_inputs = {
            "exits": [], "default_exit_id": "", "awg_exit_selections": {},
        }
    exit_options = [
        {
            "id": item["id"], "name": clean(item["name"]),
            "default": item["id"] == proxy_inputs.get("default_exit_id"),
        }
        for item in proxy_inputs.get("exits", [])
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and isinstance(item.get("name"), str)
    ]
    exit_name_by_id = {item["id"]: item["name"] for item in exit_options}
    management_peer = read_assignment(paths.management, "MANAGEMENT_ADMIN_PEER")
    management_port_text = read_assignment(paths.management, "MANAGEMENT_PORT")
    management_port = int(management_port_text) if management_port_text.isdigit() and 1 <= int(management_port_text) <= 65535 else 0
    nodes: list[dict[str, Any]] = []

    def add_node(
        name: str,
        kind: str,
        state: str,
        address: str,
        detail: str,
        permissions: list[dict[str, object]] | None = None,
        access_mode: str = "restricted",
        custody: str = "",
        public_key_fingerprint: str = "",
        domains: list[str] | None = None,
        legacy_stash: bool = False,
        exit_ids: list[str] | None = None,
    ) -> None:
        publication = publications.get(name)
        publication_enabled = name not in disabled_publications
        operational = state in {"已启用", "等待首次握手"}
        expected = operational and publication_enabled
        published = bool(publication and publication["kind"] == kind)
        if expected and published:
            publication_state = "已发布"
        elif expected:
            publication_state = "待同步"
        elif published:
            publication_state = "待同步停用" if state == "已启用" else "待同步移除"
        elif operational and not publication_enabled:
            publication_state = "发布已停用"
        else:
            publication_state = "已停用"
        nodes.append({
            "name": clean(name),
            "kind": kind,
            "kind_label": "AmneziaWG" if kind == "awg" else "VLESS",
            "address": address,
            "state": state,
            "published": published,
            "publication_state": publication_state,
            "detail": detail,
            "protected": kind == "awg" and name == management_peer,
            "permissions": permissions or [],
            "access_mode": access_mode,
            "custody": custody,
            "public_key_fingerprint": public_key_fingerprint,
            "domains": domains or [],
            "legacy_stash": legacy_stash,
            "clean_mode": name in clean_mode_nodes,
            "exit_ids": exit_ids or [],
            "exit_names": [
                exit_name_by_id[item] for item in (exit_ids or []) if item in exit_name_by_id
            ],
        })

    for name, address in active_awg.items():
        credential = awg_credentials.get(name, {})
        access = awg_access_clients.get(name, {})
        access = access if isinstance(access, dict) else {}
        mode = access.get("mode", "unrestricted")
        mode = mode if mode in {"unrestricted", "restricted"} else "unrestricted"
        permissions = clean_permissions(access.get("allow", []))
        if mode == "unrestricted":
            permissions.insert(0, {
                "target": "all", "target_label": "全部节点", "ip": "",
                "ports": [], "ports_label": "全部端口", "network": "all",
                "network_label": "全部协议",
            })
        pending = enrollment_items.get(name)
        pending = pending if isinstance(pending, dict) else {}
        pending_state = bool(pending)
        expires_epoch = pending.get("expires_epoch")
        expires_at = ""
        if isinstance(expires_epoch, int):
            expires_at = datetime.fromtimestamp(expires_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        add_node(
            name, "awg", ("等待首次握手" if pending_state else "已启用"), address,
            (f"等待首次握手 · 5 分钟内连接 · 到期 {expires_at}" if pending_state else
             f"普通双向节点 · 虚拟 IP {address}"), permissions, mode,
            credential.get("custody", ""), credential.get("public_key_fingerprint", ""),
            node_domains.get(name, []), exit_ids=selected_exit_ids(proxy_inputs, name),
        )
    for name, address in disabled_awg.items():
        credential = awg_credentials.get(name, {})
        access = awg_access_clients.get(name, {})
        access = access if isinstance(access, dict) else {}
        mode = access.get("mode", "unrestricted")
        mode = mode if mode in {"unrestricted", "restricted"} else "unrestricted"
        permissions = clean_permissions(access.get("allow", []))
        if mode == "unrestricted":
            permissions.insert(0, {
                "target": "all", "target_label": "全部节点", "ip": "",
                "ports": [], "ports_label": "全部端口", "network": "all",
                "network_label": "全部协议",
            })
        add_node(
            name, "awg", "已禁用", address,
            f"普通双向节点 · 保留虚拟 IP {address}", permissions, mode,
            credential.get("custody", ""), credential.get("public_key_fingerprint", ""),
            node_domains.get(name, []), exit_ids=selected_exit_ids(proxy_inputs, name),
        )
    for name, client in clients.items():
        if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name) or not isinstance(client, dict):
            continue
        enabled = client.get("enabled", True) is True
        permissions = clean_permissions(client.get("allow", []))
        count = len(permissions)
        add_node(
            name, "vless", "已启用" if enabled else "已禁用", "—",
            f"单向访问节点 · {count} 条内网授权",
            permissions, "restricted", legacy_stash=client.get("legacy_stash", False) is True,
            exit_ids=selected_exit_ids(proxy_inputs, name),
        )

    nodes.sort(key=lambda item: (item["kind"], item["name"].lower()))
    stale_states = {"待同步", "待同步停用", "待同步移除"}
    stale = sum(1 for item in nodes if item["publication_state"] in stale_states)
    known_node_names = {item["name"] for item in nodes}
    stale += sum(
        1 for publication in publications.values()
        if publication["name"] not in known_node_names
    )
    return {
        "schema_version": 1,
        "writes_enabled": writes_enabled,
        "subscriptions_configured": configured,
        "sync_available": configured and writes_enabled,
        "pending_vless": paths.vless_pending.is_file(),
        "pending_access": paths.awg_access_pending.is_file(),
        "management_peer": management_peer if NAME_PATTERN.fullmatch(management_peer) else "",
        "management_port": management_port,
        "exit_options": exit_options,
        "host_records": [
            {"address": address, "domains": list(domains)}
            for address, domains in sorted(address_domains.items())
        ],
        "enrollment_history": [
            {
                "name": clean(item.get("name")),
                "state": "已生效" if item.get("state") == "active" else "已超时",
                "completed_at": (
                    datetime.fromtimestamp(item["completed_epoch"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    if isinstance(item.get("completed_epoch"), int) else ""
                ),
            }
            for item in enrollment_history[:10]
            if isinstance(item, dict) and item.get("state") in {"active", "expired"}
        ],
        "summary": {
            "awg_active": len(active_awg),
            "awg_disabled": len(disabled_awg),
            "vless_active": sum(1 for item in clients.values() if isinstance(item, dict) and item.get("enabled", True) is True),
            "vless_disabled": sum(1 for item in clients.values() if isinstance(item, dict) and item.get("enabled", True) is not True),
            "disabled_total": len(disabled_awg) + sum(1 for item in clients.values() if isinstance(item, dict) and item.get("enabled", True) is not True),
            "published": len(publications),
            "stale": stale,
            "pending_enrollment": len(enrollment_items),
        },
        "nodes": nodes,
        "publications": sorted(publications.values(), key=lambda item: item["name"].lower()),
        "subscription_items": [
            {
                "name": item["name"], "kind": item["kind"], "kind_label": item["kind_label"],
                "state": item["publication_state"], "published": item["published"],
                "resource_id": item["name"],
            }
            for item in nodes if item["state"] in {"已启用", "等待首次握手"}
        ],
        "targets": [
            {"name": "all", "label": "全部节点"},
            {"name": "vps", "label": "VPS 本机"},
            *[
                {"name": name, "label": f"{name} · {address}"}
                for name, address in sorted(active_awg.items())
            ],
        ],
    }


def main() -> int:
    if len(sys.argv) != 15:
        print("节点视图参数数量不正确", file=sys.stderr)
        return 1
    paths = NetworkPaths(*(Path(value) for value in sys.argv[1:14]))
    result = build_overview(paths, sys.argv[14] == "1")
    json.dump(result, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

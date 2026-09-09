#!/usr/bin/env python3
"""从事实配置生成不含密钥和令牌的服务清单。"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from .server_kit_port_facts import PortFacts, PortFactsError
except ImportError:  # 作为独立脚本运行时，lib 目录位于 sys.path。
    from server_kit_port_facts import PortFacts, PortFactsError


@dataclass(frozen=True)
class InventoryPaths:
    vless: Path
    clash: Path
    file: Path
    mosh: Path
    awg: Path
    awg_peers: Path
    management: Path
    ports: Path
    firewall_active: Path
    firewall_candidate: Path
    firewall_transaction: Path
    ssh_auth: Path


@dataclass(frozen=True)
class RuntimeFacts:
    cert_timer_state: str = ""
    cert_next_run: str = ""
    cert_last_run: str = ""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def load_assignments(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, encoded = line.split("=", 1)
        try:
            parts = shlex.split(encoded, posix=True)
        except ValueError:
            continue
        if len(parts) == 1:
            values[key] = parts[0]
    return values


def safe_text(value: object, fallback: str = "未命名", limit: int = 96) -> str:
    if not isinstance(value, str):
        return fallback
    cleaned = "".join(character for character in value.strip() if character.isprintable())
    return cleaned[:limit] or fallback


def format_size(value: object) -> str:
    if not isinstance(value, int) or value < 0:
        return "大小未知"
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value / 1024 / 1024:.1f} MiB"


def compact_numbers(values: set[int]) -> str:
    ordered = sorted(value for value in values if 1 <= value <= 65535)
    if not ordered:
        return "无"
    parts: list[str] = []
    start = previous = ordered[0]
    for value in ordered[1:]:
        if value == previous + 1:
            previous = value
            continue
        parts.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = value
    parts.append(str(start) if start == previous else f"{start}-{previous}")
    return "/".join(parts)


def listener_rows(path: Path, service: str) -> list[dict[str, Any]]:
    listeners = load_json(path).get("listeners", [])
    if not isinstance(listeners, list):
        return []
    return [
        item
        for item in listeners
        if isinstance(item, dict) and item.get("service") == service
    ]


def exposure_label(value: object) -> str:
    return {
        "public": "公网",
        "amneziawg": "AWG 内网",
        "loopback": "仅本机",
        "private": "私有网络",
    }.get(str(value), safe_text(value, "范围未知", 24))


def vless_inventory(path: Path) -> dict[str, object]:
    data = load_json(path)
    clients = data.get("clients", {})
    items = []
    if isinstance(clients, dict):
        for client_name, client in clients.items():
            if not isinstance(client, dict):
                continue
            allow = client.get("allow", [])
            allow_count = len(allow) if isinstance(allow, list) else 0
            permission_text: list[str] = []
            if isinstance(allow, list):
                for permission in allow:
                    if not isinstance(permission, dict) or not permission.get("target"):
                        continue
                    ports = permission.get("ports", [])
                    port_values = {
                        int(port)
                        for port in ports
                        if isinstance(port, int) or (isinstance(port, str) and port.isdigit())
                    } if isinstance(ports, list) else set()
                    port_text = compact_numbers(port_values)
                    if port_text == "无":
                        port_text = ""
                    network = safe_text(permission.get("network"), "tcp", 12).upper()
                    target = safe_text(permission.get("target"), "未知目标", 64)
                    permission_text.append(f"{target} · {network} {port_text or '端口未配置'}")
            items.append(
                {
                    "name": safe_text(client_name, "未命名客户端"),
                    "state": "已启用" if client.get("enabled") is True else "已禁用",
                    "detail": "；".join(permission_text) or f"{allow_count} 条访问授权",
                }
            )
    return {"facts": {"受限客户端": str(len(items))}, "items": items}


def clash_inventory(path: Path) -> dict[str, object]:
    data = load_json(path)
    downloads = data.get("downloads", [])
    items = []
    kind_labels = {"awg": "AmneziaWG", "amneziawg": "AmneziaWG", "vless": "VLESS"}
    if isinstance(downloads, list):
        for item in downloads:
            if not isinstance(item, dict):
                continue
            peer = safe_text(item.get("peer_name"), "未绑定节点")
            raw_kind = safe_text(item.get("node_kind"), "未知", 24).lower()
            kind = kind_labels.get(raw_kind, raw_kind.upper())
            row = {
                "name": peer,
                "state": "已发布",
                "detail": (
                    f"{safe_text(item.get('download_name'), '未命名订阅')}"
                    f" · {kind} · {format_size(item.get('file_size'))}"
                ),
            }
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", peer):
                row["resource_id"] = peer
            items.append(row)
    address = safe_text(data.get("server_address"), "未配置", 96)
    port = str(data.get("port", "未配置"))
    facts = {
        "下载入口": f"https://{address}:{port}/…" if address != "未配置" else "未配置",
        "订阅数量": str(len(items)),
    }
    return {"facts": facts, "items": items}


def file_inventory(path: Path) -> dict[str, object]:
    data = load_json(path)
    if not data:
        return {"facts": {"配置状态": "未配置"}, "items": []}
    downloads = data.get("downloads", data.get("files"))
    if downloads is None and ("download_name" in data or "file_size" in data):
        downloads = [data]
    items = []
    if isinstance(downloads, list):
        for item in downloads:
            if not isinstance(item, dict):
                continue
            name = item.get("download_name", item.get("name"))
            items.append(
                {
                    "name": safe_text(name, "未命名文件"),
                    "state": "已发布",
                    "detail": format_size(item.get("file_size", item.get("size"))),
                }
            )
    return {"facts": {"配置状态": "已配置", "文件数量": str(len(items))}, "items": items}


def mosh_inventory(path: Path, sessions: int) -> dict[str, object]:
    state = load_assignments(path)
    start = state.get("MOSH_PORT_START", state.get("MOSH_PORT", "未配置"))
    end = state.get("MOSH_PORT_END", start)
    port_range = start if start == end else f"{start}-{end}"
    return {
        "facts": {
            "UDP 范围": port_range,
            "活动会话": str(max(0, sessions)),
            "访问范围": "仅 AWG 内网",
        },
        "items": [],
    }


def awg_inventory(state_path: Path, peers_path: Path) -> dict[str, object]:
    state = load_assignments(state_path)
    if not state:
        return {"facts": {"配置状态": "未配置"}, "items": []}
    primary_port = state.get("AWG_PRIMARY_PORT", "")
    backup_port1 = state.get("AWG_BACKUP_PORT1", "")
    backup_port2 = state.get("AWG_BACKUP_PORT2", "")
    ports = [
        f"{primary_port}（主）" if primary_port else "",
        f"{backup_port1}（备用 1）" if backup_port1 else "",
        f"{backup_port2}（备用 2）" if backup_port2 else "",
    ]
    items: list[dict[str, str]] = []
    try:
        lines = peers_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) < 2 or not fields[0].strip():
            continue
        items.append(
            {
                "name": safe_text(fields[0], "未命名节点"),
                "state": "普通节点",
                "detail": f"虚拟 IP {safe_text(fields[1], '未配置', 64)} · 双入口配置共用同一身份",
            }
        )
    return {
        "facts": {
            "接口": safe_text(state.get("AWG_IFACE"), "awg0", 24),
            "内网网段": safe_text(state.get("AWG_SUBNET_CIDR"), "未配置", 48),
            "服务端地址": safe_text(state.get("AWG_SERVER_IP"), "未配置", 64),
            "公网 UDP 入口": "/".join(port for port in ports if port) or "未配置",
            "MTU": safe_text(state.get("AWG_MTU"), "未配置", 8),
            "普通节点": str(len(items)),
        },
        "items": items,
    }


def management_inventory(path: Path) -> dict[str, object]:
    state = load_assignments(path)
    if not state:
        return {"facts": {"配置状态": "未配置"}, "items": []}
    address = safe_text(state.get("MANAGEMENT_AWG_IP"), "未配置", 64)
    port = safe_text(state.get("MANAGEMENT_PORT"), "未配置", 8)
    return {
        "facts": {
            "访问地址": f"http://{address}:{port}",
            "访问范围": "仅 AWG 内网",
            "管理节点": safe_text(state.get("MANAGEMENT_ADMIN_PEER"), "未配置", 64),
            "写操作": "仅超级管理员 · 二次确认",
            "控制权限": "受限 Unix Socket · 固定动作白名单",
            "会话期限": "30 分钟，关闭浏览器后失效",
        },
        "items": [],
    }


def ssh_inventory(ports_path: Path, auth_path: Path) -> dict[str, object]:
    try:
        auth_text = auth_path.read_text(encoding="utf-8")
    except OSError:
        auth_text = ""
    normalized = {line.strip().lower() for line in auth_text.splitlines() if line.strip()}
    public_key_only = {
        "pubkeyauthentication yes",
        "passwordauthentication no",
        "kbdinteractiveauthentication no",
        "authenticationmethods publickey",
    }.issubset(normalized)
    root_policy = "允许公钥，禁止密码" if "permitrootlogin prohibit-password" in normalized else "未确认"
    items: list[dict[str, str]] = []
    for listener in listener_rows(ports_path, "ssh.service"):
        addresses = listener.get("bind_addresses", [])
        address_text = ", ".join(safe_text(item, "未知", 64) for item in addresses) if isinstance(addresses, list) else "未知"
        purpose = safe_text(listener.get("purpose"), "SSH 监听", 96)
        state = "监听中" if listener.get("listening") is True else "未监听"
        items.append(
            {
                "name": purpose,
                "state": state,
                "detail": (
                    f"{str(listener.get('protocol', 'tcp')).upper()} {listener.get('port', '未配置')}"
                    f" · {exposure_label(listener.get('exposure'))} · {address_text}"
                ),
            }
        )
    return {
        "facts": {
            "登录认证": "仅 SSH 公钥" if public_key_only else "未确认",
            "密码登录": "已禁用" if "passwordauthentication no" in normalized else "未确认",
            "Root 登录": root_policy,
            "监听入口": str(len(items)),
            "保护级别": "监听与认证策略受保护；公钥可确认管理",
        },
        "items": items,
    }


def firewall_inventory(paths: InventoryPaths) -> dict[str, object]:
    try:
        port_facts = PortFacts.load(paths.ports)
    except PortFactsError:
        port_facts = None
    if paths.firewall_transaction.is_file() and paths.firewall_candidate.is_file():
        rules_path = paths.firewall_candidate
        effective = "等待确认"
    elif paths.firewall_active.is_file():
        rules_path = paths.firewall_active
        effective = "已生效"
    else:
        rules_path = None
        effective = "未配置"
    try:
        rules = rules_path.read_text(encoding="utf-8") if rules_path else ""
    except OSError:
        rules = ""

    rows = port_facts.firewall_rows(rules) if port_facts else []
    default_drop = bool(rows and rows[0][3] == "拒绝")
    unmanaged_external = sum(
        1 for item in port_facts.unmanaged if item.get("exposure") != "loopback"
    ) if port_facts else 0
    policies = [
        (name, action, f"{'AWG 内网' if scope == 'AWG' else '全部范围' if scope == '全部' else scope} · {protocol}")
        for name, scope, protocol, action in rows
    ]
    return {
        "facts": {
            "方案": "nftables 独立 inet 规则表",
            "规则表": "inet server_kit_filter",
            "当前状态": effective,
            "默认入站": "拒绝" if default_drop else "未确认",
            "未托管外部监听": str(unmanaged_external),
            "原始查看命令": "nft list table inet server_kit_filter",
        },
        "items": [
            {"name": name, "state": state, "detail": detail}
            for name, state, detail in policies
        ],
    }


def cert_inventory(runtime: RuntimeFacts) -> dict[str, object]:
    state = {"active": "已启用", "inactive": "未启用", "failed": "异常"}.get(
        runtime.cert_timer_state, "状态未知"
    )
    return {
        "facts": {
            "定时器": state,
            "下次执行": safe_text(runtime.cert_next_run, "未知", 96),
            "上次执行": safe_text(runtime.cert_last_run, "未知", 96),
            "管理方式": "systemd 定时器自动续期",
        },
        "items": [],
    }


def build_inventory(
    service_id: str,
    paths: InventoryPaths,
    mosh_sessions: int,
    runtime: RuntimeFacts | None = None,
) -> dict[str, object]:
    runtime = runtime or RuntimeFacts()
    builders = {
        "amneziawg": lambda: awg_inventory(paths.awg, paths.awg_peers),
        "management": lambda: management_inventory(paths.management),
        "vless": lambda: vless_inventory(paths.vless),
        "clash": lambda: clash_inventory(paths.clash),
        "file": lambda: file_inventory(paths.file),
        "mosh": lambda: mosh_inventory(paths.mosh, mosh_sessions),
        "cert-renew": lambda: cert_inventory(runtime),
        "firewall": lambda: firewall_inventory(paths),
        "ssh": lambda: ssh_inventory(paths.ports, paths.ssh_auth),
    }
    if service_id not in builders:
        raise ValueError(f"未登记的服务清单：{service_id}")
    result = builders[service_id]()
    return {"schema_version": 1, "service_id": service_id, **result}


def main() -> int:
    if len(sys.argv) != 15:
        print("服务清单参数数量不正确", file=sys.stderr)
        return 1
    service_id = sys.argv[1]
    paths = InventoryPaths(*(Path(value) for value in sys.argv[2:14]))
    try:
        sessions = int(sys.argv[14])
    except ValueError:
        sessions = 0
    runtime = RuntimeFacts(
        cert_timer_state=os.environ.get("SERVER_KIT_CERT_TIMER_STATE", ""),
        cert_next_run=os.environ.get("SERVER_KIT_CERT_NEXT_RUN", ""),
        cert_last_run=os.environ.get("SERVER_KIT_CERT_LAST_RUN", ""),
    )
    try:
        result = build_inventory(service_id, paths, sessions, runtime)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

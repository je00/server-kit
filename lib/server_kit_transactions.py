#!/usr/bin/env python3
"""把 SSH 与防火墙事务文件转换为稳定、脱敏的管理界面模型。"""

from __future__ import annotations

import json
import ipaddress
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROLLBACK_SECONDS = 300


@dataclass(frozen=True)
class TransactionPaths:
    ssh_auth_config: Path
    ssh_auth_transaction: Path
    firewall_active: Path
    firewall_candidate: Path
    firewall_transaction: Path
    ports: Path
    ssh_security: Path | None = None
    ssh_listener_transaction: Path | None = None


class TransactionError(RuntimeError):
    """表示事务类型或事实文件无效。"""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _transaction_state(path: Path, now: datetime) -> dict[str, object]:
    data = _load_json(path)
    created_text = data.get("created_at")
    if not isinstance(created_text, str):
        return {"state": "idle", "expires_at": "", "remaining_seconds": 0}
    try:
        created = datetime.fromisoformat(created_text.replace("Z", "+00:00"))
    except ValueError:
        raise TransactionError("事务创建时间无效")
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    expires = created.astimezone(timezone.utc) + timedelta(seconds=ROLLBACK_SECONDS)
    remaining = max(0, int((expires - now.astimezone(timezone.utc)).total_seconds()))
    return {
        "state": "pending",
        "expires_at": expires.isoformat(),
        "remaining_seconds": remaining,
    }


def _directive_map(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    result: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or " " not in line:
            continue
        key, value = line.split(None, 1)
        result[key.lower()] = value.strip().lower()
    return result


def _read_nft_set(path: Path, name: str) -> str:
    try:
        rules = path.read_text(encoding="utf-8")
    except OSError:
        return "未配置"
    block = re.search(rf"set\s+{re.escape(name)}\s*\{{(.*?)\n\s*\}}", rules, re.DOTALL)
    if not block:
        return "无"
    elements = re.search(r"elements\s*=\s*\{([^}]*)\}", block.group(1), re.DOTALL)
    if not elements:
        return "无"
    values = sorted({int(item) for item in re.findall(r"\d{1,5}", elements.group(1)) if 1 <= int(item) <= 65535})
    if not values:
        return "无"
    ranges: list[str] = []
    start = previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = value
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return "/".join(ranges)


def _ssh_auth_snapshot(paths: TransactionPaths, now: datetime) -> dict[str, object]:
    current = _directive_map(paths.ssh_auth_config)
    targets = (
        ("密码登录", "passwordauthentication", "no", "禁用"),
        ("键盘交互认证", "kbdinteractiveauthentication", "no", "禁用"),
        ("认证方式", "authenticationmethods", "publickey", "仅公钥"),
        ("Root 登录", "permitrootlogin", "prohibit-password", "仅公钥"),
    )
    changes = [
        {
            "label": label,
            "current": current.get(key, "未显式配置"),
            "target": display,
            "changed": current.get(key) != expected,
        }
        for label, key, expected, display in targets
    ]
    return {
        "schema_version": 1,
        "transaction_type": "ssh_auth",
        "title": "SSH 仅公钥认证",
        **_transaction_state(paths.ssh_auth_transaction, now),
        "writes_enabled": False,
        "ready": True,
        "blockers": [],
        "rollback_seconds": ROLLBACK_SECONDS,
        "changes": changes,
        "verifications": ["新建公网 SSH 连接", "新建 AWG 内网 SSH 连接"],
        "independent_session": True,
    }


def _ssh_listener_snapshot(
    paths: TransactionPaths, now: datetime,
    public_ip: str = "", public_port: str = "",
) -> dict[str, object]:
    security = _load_json(paths.ssh_security) if paths.ssh_security is not None else {}
    current = security.get("ssh", {})
    if not isinstance(current, dict):
        current = {}
    transaction_path = paths.ssh_listener_transaction
    pending = _load_json(transaction_path) if transaction_path is not None else {}
    target_ip = str(pending.get("public_ip") or public_ip or current.get("public_address", "未配置"))
    target_port = str(pending.get("public_port") or public_port or current.get("public_port", "未配置"))
    target_awg = str(pending.get("amneziawg_ip") or current.get("amneziawg_address", "未配置"))
    blockers: list[str] = []
    try:
        if ipaddress.ip_address(target_ip).version != 4:
            blockers.append("公网地址必须是 IPv4")
    except ValueError:
        blockers.append("公网 IPv4 无效")
    if not target_port.isdigit() or not 1024 <= int(target_port) <= 65535:
        blockers.append("公网 SSH 端口必须是 1024–65535")
    elif 32768 <= int(target_port) <= 60999:
        blockers.append("公网 SSH 端口不能位于本机临时端口范围")
    state = (
        _transaction_state(transaction_path, now)
        if transaction_path is not None
        else {"state": "idle", "expires_at": "", "remaining_seconds": 0}
    )
    changes = [
        {"label": "公网 IPv4", "current": str(current.get("public_address", "未配置")), "target": target_ip, "changed": str(current.get("public_address", "")) != target_ip},
        {"label": "公网 SSH 端口", "current": str(current.get("public_port", "未配置")), "target": target_port, "changed": str(current.get("public_port", "")) != target_port},
        {"label": "AWG SSH 端口", "current": "22", "target": f"{target_awg}:22", "changed": False},
    ]
    return {
        "schema_version": 1,
        "transaction_type": "ssh_listener",
        "title": "SSH 公网/内网监听",
        **state,
        "writes_enabled": False,
        "ready": not blockers,
        "blockers": blockers,
        "rollback_seconds": ROLLBACK_SECONDS,
        "changes": changes,
        "verifications": ["新建公网 SSH 连接", "新建 AWG 内网 SSH 连接", "确认公网 22 已按阶段保留或关闭"],
        "independent_session": True,
    }


def _firewall_snapshot(paths: TransactionPaths, now: datetime) -> dict[str, object]:
    labels = (
        ("公网 TCP", "public_tcp_ports"),
        ("公网 UDP", "public_udp_ports"),
        ("AWG TCP", "awg_tcp_ports"),
        ("AWG UDP", "awg_udp_ports"),
    )
    changes = [
        {
            "label": label,
            "current": _read_nft_set(paths.firewall_active, name),
            "target": _read_nft_set(paths.firewall_candidate, name),
            "changed": _read_nft_set(paths.firewall_active, name) != _read_nft_set(paths.firewall_candidate, name),
        }
        for label, name in labels
    ]
    ports = _load_json(paths.ports)
    unmanaged = ports.get("observed_unmanaged", [])
    blockers: list[str] = []
    if isinstance(unmanaged, list):
        for item in unmanaged:
            if not isinstance(item, dict) or item.get("exposure") == "loopback":
                continue
            protocol = str(item.get("protocol", "?"))[:8].upper()
            address = str(item.get("address", "?"))[:80]
            port = str(item.get("port", "?"))[:8]
            process = str(item.get("process", "未知进程"))[:40]
            blockers.append(f"{protocol} {address}:{port} · {process} · 未托管监听")
            if len(blockers) >= 20:
                break
    if not paths.firewall_candidate.is_file():
        blockers.append("候选规则未生成")
    return {
        "schema_version": 1,
        "transaction_type": "firewall",
        "title": "nftables 主机防火墙",
        **_transaction_state(paths.firewall_transaction, now),
        "writes_enabled": False,
        "ready": not blockers,
        "blockers": blockers,
        "rollback_seconds": ROLLBACK_SECONDS,
        "changes": changes,
        "verifications": ["公网 SSH", "AWG SSH", "VLESS", "Clash 订阅", "AWG 两个 UDP 入口"],
        "independent_session": True,
    }


def build_transaction_snapshot(
    transaction_type: str,
    paths: TransactionPaths,
    writes_enabled: bool,
    now: datetime | None = None,
    public_ip: str = "",
    public_port: str = "",
) -> dict[str, object]:
    now = now or datetime.now(timezone.utc)
    builders = {
        "ssh_auth": _ssh_auth_snapshot,
        "firewall": _firewall_snapshot,
    }
    if transaction_type not in {*builders, "ssh_listener"}:
        raise TransactionError("事务类型未登记")
    if transaction_type == "ssh_listener":
        result = _ssh_listener_snapshot(paths, now, public_ip, public_port)
    else:
        result = builders[transaction_type](paths, now)
    result["writes_enabled"] = writes_enabled
    return result


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if len(sys.argv) not in {9, 13}:
        print("事务状态参数数量不正确", file=sys.stderr)
        return 1
    path_values = [Path(item) for item in sys.argv[2:8]]
    public_ip = ""
    public_port = ""
    if len(sys.argv) == 13:
        path_values.extend(Path(item) for item in sys.argv[8:10])
        public_ip, public_port = sys.argv[10:12]
    try:
        paths = TransactionPaths(*path_values)
        writes_arg = sys.argv[12] if len(sys.argv) == 13 else sys.argv[8]
        result = build_transaction_snapshot(
            sys.argv[1], paths, writes_arg == "1",
            public_ip=public_ip, public_port=public_port,
        )
    except TransactionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

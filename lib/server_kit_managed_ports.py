#!/usr/bin/env python3
"""统一读取并校验 server-kit 可维护的服务端口。"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ManagedPortError(ValueError):
    """端口维护请求无法安全执行。"""


@dataclass(frozen=True)
class Target:
    identifier: str
    service_id: str
    label: str
    protocol: str
    fact_id: str
    minimum: int
    maximum: int
    impact: str
    restart_required: bool


TARGETS = {
    item.identifier: item
    for item in (
        Target(
            "clash", "clash", "Clash 订阅端口", "tcp", "clash-subscription", 1, 65535,
            "订阅链接端口会变化，已导入的订阅地址需要更新。", True,
        ),
        Target(
            "file", "file", "普通文件端口", "tcp", "file-service", 1, 65535,
            "所有普通文件下载链接的端口会变化。", True,
        ),
        Target(
            "awg-backup1", "amneziawg", "AWG 备用入口 1", "udp", "amneziawg-backup1", 1, 9999,
            "使用备用入口 1 的客户端需要更新端点或重新导入配置；主隧道不会重启。", False,
        ),
        Target(
            "awg-backup2", "amneziawg", "AWG 备用入口 2", "udp", "amneziawg-backup2", 1, 9999,
            "使用备用入口 2 的客户端需要更新端点或重新导入配置；主隧道不会重启。", False,
        ),
    )
}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedPortError(f"无法读取配置：{path}") from exc
    if not isinstance(value, dict):
        raise ManagedPortError(f"配置根节点不是对象：{path}")
    return value


def _load_shell_state(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return result
    except OSError as exc:
        raise ManagedPortError(f"无法读取配置：{path}") from exc
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        result[key.strip()] = value
    return result


def _port(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if 1 <= parsed <= 65535 else None


def _facts(path: Path) -> dict[str, Any]:
    value = _load_json(path)
    for key in ("listeners", "observed_unmanaged"):
        if key in value and not isinstance(value[key], list):
            raise ManagedPortError(f"端口事实字段 {key} 格式不正确。")
    return value


def build_overview(awg_state: Path, file_config: Path, clash_config: Path, ports_path: Path) -> dict[str, Any]:
    awg = _load_shell_state(awg_state)
    file_value = _load_json(file_config)
    clash_value = _load_json(clash_config)
    facts = _facts(ports_path)
    values = {
        "clash": _port(clash_value.get("port")),
        "file": _port(file_value.get("port")),
        "awg-backup1": _port(awg.get("AWG_BACKUP_PORT1")),
        "awg-backup2": _port(awg.get("AWG_BACKUP_PORT2")),
    }
    fact_by_id = {
        str(item.get("id")): item
        for item in facts.get("listeners", [])
        if isinstance(item, dict) and item.get("id")
    }
    occupied = []
    for source, managed in ((facts.get("listeners", []), True), (facts.get("observed_unmanaged", []), False)):
        for fact in source:
            if not isinstance(fact, dict):
                continue
            port = _port(fact.get("port"))
            protocol = str(fact.get("protocol", "")).lower()
            if port is None or protocol not in {"tcp", "udp"}:
                continue
            occupied.append(
                {
                    "id": str(fact.get("id", "")),
                    "protocol": protocol,
                    "port": port,
                    "label": str(fact.get("purpose") or fact.get("process") or "未托管监听"),
                    "managed": managed,
                }
            )
    items = []
    for identifier, target in TARGETS.items():
        current = values[identifier]
        fact = fact_by_id.get(target.fact_id, {})
        items.append(
            {
                "id": identifier,
                "service_id": target.service_id,
                "label": target.label,
                "protocol": target.protocol,
                "scope": "public",
                "port": current,
                "minimum": target.minimum,
                "maximum": target.maximum,
                "installed": current is not None,
                "active": bool(fact.get("service_active")),
                "listening": bool(fact.get("listening")),
                "restart_required": target.restart_required,
                "impact": target.impact,
            }
        )
    revision_source = json.dumps(
        {
            "ports": values,
            "listeners": [
                {key: item.get(key) for key in ("id", "protocol", "port", "service_active", "listening")}
                for item in facts.get("listeners", []) if isinstance(item, dict)
            ],
            "unmanaged": [
                {key: item.get(key) for key in ("protocol", "address", "port", "process")}
                for item in facts.get("observed_unmanaged", []) if isinstance(item, dict)
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "schema_version": 1,
        "revision": hashlib.sha256(revision_source.encode("utf-8")).hexdigest(),
        "items": items,
        "occupied": occupied,
    }


def build_plan(overview: dict[str, Any], target_id: str, new_port: int) -> dict[str, Any]:
    target = TARGETS.get(target_id)
    if target is None:
        raise ManagedPortError("未知的端口维护目标。")
    item = next((value for value in overview.get("items", []) if value.get("id") == target_id), None)
    if not isinstance(item, dict) or not item.get("installed"):
        raise ManagedPortError(f"{target.label}尚未安装，不能修改端口。")
    if not target.minimum <= new_port <= target.maximum:
        raise ManagedPortError(f"{target.label}必须在 {target.minimum}–{target.maximum} 之间。")
    current = int(item["port"])
    if current == new_port:
        raise ManagedPortError("新端口与当前端口相同。")
    conflicts = []
    for other in overview.get("items", []):
        if not isinstance(other, dict) or other.get("id") == target_id:
            continue
        if other.get("installed") and other.get("protocol") == target.protocol and other.get("port") == new_port:
            conflicts.append(str(other.get("label") or other.get("id")))
    for other in overview.get("occupied", []):
        if not isinstance(other, dict) or other.get("id") == target.fact_id:
            continue
        if other.get("protocol") == target.protocol and other.get("port") == new_port:
            label = str(other.get("label") or other.get("id"))
            if label not in conflicts:
                conflicts.append(label)
    if conflicts:
        raise ManagedPortError(f"{new_port}/{target.protocol.upper()} 已被{'、'.join(conflicts)}使用。")
    return {
        "schema_version": 1,
        "revision": overview.get("revision", ""),
        "target_id": target_id,
        "service_id": target.service_id,
        "label": target.label,
        "protocol": target.protocol,
        "scope": "public",
        "old_port": current,
        "new_port": new_port,
        "restart_required": target.restart_required,
        "impact": target.impact,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--awg-state", type=Path, default=Path("/etc/amneziawg/manager.conf"))
    parser.add_argument("--file-config", type=Path, default=Path("/etc/secure-file-service/config.json"))
    parser.add_argument("--clash-config", type=Path, default=Path("/etc/secure-file-service/clash-config.json"))
    parser.add_argument("--ports", type=Path, default=Path("/etc/server-kit/ports.json"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("overview")
    plan = subparsers.add_parser("plan")
    plan.add_argument("target_id", choices=tuple(TARGETS))
    plan.add_argument("new_port", type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        overview = build_overview(args.awg_state, args.file_config, args.clash_config, args.ports)
        result = overview if args.command == "overview" else build_plan(overview, args.target_id, args.new_port)
    except ManagedPortError as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, separators=(",", ":")))
        return 1
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

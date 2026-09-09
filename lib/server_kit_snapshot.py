#!/usr/bin/env python3
"""把总管脚本采集的服务行转换为稳定的 JSON 快照。"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

try:
    from .server_kit_resources import collect_resources
except ImportError:  # 脚本由总管直接执行时使用同目录导入
    from server_kit_resources import collect_resources


SCHEMA_VERSION = 1


def parse_ports(summary: str) -> list[dict[str, str]]:
    """解析总管内部端口摘要，不向调用者暴露展示用分隔符。"""
    ports: list[dict[str, str]] = []
    if not summary:
        return ports
    for item in summary.split("|"):
        parts = item.split(" · ")
        if len(parts) != 3 or " " not in parts[0]:
            continue
        protocol, port = parts[0].split(" ", 1)
        ports.append(
            {
                "protocol": protocol.lower(),
                "port": port,
                "scope": parts[1],
                "state": parts[2],
            }
        )
    return ports


def read_services() -> list[dict[str, object]]:
    services: list[dict[str, object]] = []
    for raw in sys.stdin:
        fields = raw.rstrip("\n").split("\t")
        if len(fields) != 7:
            raise ValueError("服务快照字段数量不正确")
        identifier, label, state, autostart, detail, unit, port_summary = fields
        services.append(
            {
                "id": identifier,
                "label": label,
                "state": state,
                "autostart": autostart,
                "detail": detail,
                "unit": unit or None,
                "ports": parse_ports(port_summary),
            }
        )
    return services


def main() -> int:
    services = read_services()
    counts = {"running": 0, "stopped": 0, "failed": 0, "missing": 0}
    state_keys = {
        "运行中": "running",
        "已停止": "stopped",
        "失败": "failed",
        "未安装": "missing",
    }
    for service in services:
        key = state_keys.get(str(service["state"]))
        if key:
            counts[key] += 1
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": counts,
        "resources": collect_resources(),
        "services": services,
    }
    json.dump(payload, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"无法生成服务快照：{exc}", file=sys.stderr)
        raise SystemExit(1)

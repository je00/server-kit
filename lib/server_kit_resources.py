#!/usr/bin/env python3
"""读取 Linux 主机的只读资源事实。"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any


def _percent(used: int, total: int) -> float | None:
    if total <= 0 or used < 0:
        return None
    return round(min(100.0, used * 100.0 / total), 1)


def _load(proc_root: Path) -> dict[str, Any]:
    cores = max(1, os.cpu_count() or 1)
    try:
        values = (proc_root / "loadavg").read_text(encoding="ascii").split()
        load_1, load_5, load_15 = (round(float(value), 2) for value in values[:3])
    except (OSError, ValueError):
        load_1 = load_5 = load_15 = None
    return {
        "cores": cores,
        "load_1": load_1,
        "load_5": load_5,
        "load_15": load_15,
    }


def _memory(proc_root: Path) -> dict[str, Any]:
    values: dict[str, int] = {}
    try:
        for line in (proc_root / "meminfo").read_text(encoding="ascii").splitlines():
            key, separator, raw = line.partition(":")
            if separator and raw.strip().endswith(" kB"):
                values[key] = int(raw.strip().split()[0]) * 1024
    except (OSError, ValueError):
        pass
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    used = max(0, total - available) if total else 0
    return {
        "total_bytes": total,
        "used_bytes": used,
        "usage_percent": _percent(used, total),
    }


def _disk(path: Path) -> dict[str, Any]:
    try:
        total, used, _free = shutil.disk_usage(path)
    except OSError:
        total = used = 0
    return {
        "total_bytes": total,
        "used_bytes": used,
        "usage_percent": _percent(used, total),
    }


def _uptime(proc_root: Path) -> int | None:
    try:
        return max(0, int(float((proc_root / "uptime").read_text(encoding="ascii").split()[0])))
    except (OSError, ValueError, IndexError):
        return None


def collect_resources(
    proc_root: Path = Path("/proc"), disk_path: Path = Path("/")
) -> dict[str, Any]:
    """返回不含进程、路径和用户信息的资源摘要。"""
    return {
        "cpu": _load(proc_root),
        "memory": _memory(proc_root),
        "disk": _disk(disk_path),
        "uptime_seconds": _uptime(proc_root),
    }

"""从管理代理读取主机快照。"""

from __future__ import annotations

from typing import Any

from .services import read_host


def read_snapshot() -> dict[str, Any]:
    """通过唯一管理 seam 获取只读主机状态。"""
    return read_host("overview")

#!/usr/bin/env python3
"""追加 server-kit 哈希链审计记录，供网页代理与本机 root 恢复入口复用。"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


@contextlib.contextmanager
def _lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            import fcntl
        except ImportError:
            yield
        else:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def append_audit(path: Path, actor: str, service_id: str, operation: str, outcome: str) -> None:
    """在文件锁内追加一条防篡改链记录。"""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.is_symlink():
        raise RuntimeError("审计日志路径不能是符号链接")
    with _lock(path.with_name(f".{path.name}.lock")):
        previous_hash = "0" * 64
        if path.exists():
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
            if lines:
                try:
                    previous_hash = str(json.loads(lines[-1])["hash"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise RuntimeError("审计日志链已损坏") from exc
                if len(previous_hash) != 64:
                    raise RuntimeError("审计日志链已损坏")
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "service_id": service_id,
            "operation": operation,
            "outcome": outcome,
            "previous_hash": previous_hash,
        }
        canonical = json.dumps(
            record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        record["hash"] = hashlib.sha256(canonical).hexdigest()
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            os.write(descriptor, (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))
        finally:
            os.close(descriptor)
        os.chmod(path, 0o600)

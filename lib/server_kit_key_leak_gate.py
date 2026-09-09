#!/usr/bin/env python3
"""扫描 VPS 管理链路中不应出现的 AWG 客户端私钥材料。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


MAX_SCAN_BYTES = 64 * 1024 * 1024
PRIVATE_PATTERNS = (
    b"privatekey =",
    b'"private_key"',
    b'"client_private_key"',
    b"client-private-key",
)
RUNTIME_SCOPES = (
    "var/lib/server-kit-web",
    "var/lib/server-kit-agent",
    "var/log/server-kit",
    "run/server-kit",
)
RUNTIME_EXCLUSIONS = (
    "var/lib/server-kit-web/static",
)


@dataclass(frozen=True)
class LeakFinding:
    path: str
    reason: str


def _relative(root: Path, path: Path) -> str:
    try:
        return "/" + path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _scan_file(root: Path, path: Path, findings: list[LeakFinding]) -> None:
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            findings.append(LeakFinding(_relative(root, path), "文件过大，无法完成泄密扫描"))
            return
        content = path.read_bytes().lower()
    except OSError:
        findings.append(LeakFinding(_relative(root, path), "文件不可读"))
        return
    for pattern in PRIVATE_PATTERNS:
        if pattern in content:
            findings.append(LeakFinding(_relative(root, path), "管理链路出现客户端私钥字段"))
            return


def scan_client_private_material(root: Path) -> list[LeakFinding]:
    """只扫描 server-kit 管理范围，不把 SSH 或服务端私钥误判为客户端私钥。"""

    root = root.resolve()
    findings: list[LeakFinding] = []
    awg = root / "etc/amneziawg"
    for relative in ("clients", "removed"):
        directory = awg / relative
        if directory.is_dir():
            for path in sorted(directory.rglob("*")):
                if path.is_file() and not path.is_symlink():
                    _scan_file(root, path, findings)
    if awg.is_dir():
        for path in sorted(awg.glob(".*")):
            if path.is_file() and not path.is_symlink():
                _scan_file(root, path, findings)
    credentials = awg / "peer-credentials.tsv"
    credential_names: set[str] = set()
    if credentials.is_file():
        try:
            for number, row in enumerate(credentials.read_text(encoding="utf-8").splitlines(), 1):
                fields = row.split("\t")
                if row.strip() and (len(fields) != 4 or fields[3] != "client"):
                    findings.append(LeakFinding(_relative(root, credentials), f"第 {number} 行节点凭据不符合安全要求"))
                elif row.strip():
                    credential_names.add(fields[0])
        except (OSError, UnicodeDecodeError):
            findings.append(LeakFinding(_relative(root, credentials), "密钥托管记录不可读"))
    peer_names: set[str] = set()
    for filename in ("peers.tsv", "peers.disabled.tsv"):
        path = awg / filename
        try:
            rows = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            continue
        except (OSError, UnicodeDecodeError):
            findings.append(LeakFinding(_relative(root, path), "节点清单不可读"))
            continue
        for number, row in enumerate(rows, 1):
            fields = row.split("\t")
            if len(fields) != 2 or not fields[0]:
                findings.append(LeakFinding(_relative(root, path), f"第 {number} 行节点记录无效"))
            else:
                peer_names.add(fields[0])
    missing_custody = sorted(peer_names - credential_names)
    if missing_custody:
        findings.append(LeakFinding(
            _relative(root, credentials),
            "既有节点缺少安全凭据记录：" + "、".join(missing_custody[:10]),
        ))
    for relative in RUNTIME_SCOPES:
        directory = root / relative
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            path_relative = path.relative_to(root).as_posix()
            if any(
                path_relative == excluded or path_relative.startswith(excluded + "/")
                for excluded in RUNTIME_EXCLUSIONS
            ):
                continue
            if path.is_file() and not path.is_symlink():
                _scan_file(root, path, findings)
    return findings

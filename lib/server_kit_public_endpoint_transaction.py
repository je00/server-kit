#!/usr/bin/env python3
"""稳定公网入口事务的备份完整性清单与持久化屏障。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _file_record(path: Path, label: str, *, sync: bool) -> dict[str, object]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} 不是普通文件")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        if sync:
            os.fsync(descriptor)
        return {
            "path": label,
            "type": "file",
            "mode": stat.S_IMODE(metadata.st_mode),
            "size": metadata.st_size,
            "sha256": digest.hexdigest(),
        }
    finally:
        os.close(descriptor)


def _tree_records(root: Path, label: str, *, sync: bool) -> list[dict[str, object]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"{label} 不是安全目录")
    records: list[dict[str, object]] = []
    directories: list[Path] = []
    for current, names, files in os.walk(root, topdown=True, followlinks=False):
        names.sort()
        files.sort()
        current_path = Path(current)
        directories.append(current_path)
        relative_directory = current_path.relative_to(root).as_posix()
        directory_label = label if relative_directory == "." else f"{label}/{relative_directory}"
        records.append({
            "path": directory_label,
            "type": "directory",
            "mode": stat.S_IMODE(os.stat(current_path, follow_symlinks=False).st_mode),
        })
        for name in names:
            if (current_path / name).is_symlink():
                raise ValueError(f"{label} 包含符号链接")
        for name in files:
            path = current_path / name
            if path.is_symlink():
                raise ValueError(f"{label} 包含符号链接")
            relative = path.relative_to(root).as_posix()
            records.append(_file_record(path, f"{label}/{relative}", sync=sync))
    if sync:
        for directory in reversed(directories):
            _fsync_directory(directory)
    return records


def _atomic_json(path: Path, value: dict[str, object]) -> str:
    encoded = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return hashlib.sha256(encoded).hexdigest()


def create_manifest(args: argparse.Namespace) -> str:
    entries: list[dict[str, object]] = []
    if args.fact_existed:
        entries.append(_file_record(args.fact_backup, "public-endpoint.backup", sync=True))
    if args.clash_backed_up:
        entries.append(_file_record(args.clash_config_backup, "clash-config.backup", sync=True))
        entries.extend(_tree_records(args.clash_payload_backup, "clash-subscriptions.backup", sync=True))
    for existed_name, path_name, label in (
        ("file_config_existed", "file_config_backup", "file-config.backup"),
        ("certificate_existed", "certificate_backup", "certificate.backup"),
        ("key_existed", "key_backup", "key.backup"),
        ("certificate_fact_existed", "certificate_fact_backup", "certificate-fact.backup"),
    ):
        if getattr(args, existed_name):
            entries.append(_file_record(getattr(args, path_name), label, sync=True))
    return _atomic_json(args.manifest, {"schema_version": 1, "entries": entries})


def verify_manifest(args: argparse.Namespace) -> None:
    encoded = args.manifest.read_bytes()
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    if hashlib.sha256(encoded).hexdigest() != metadata.get("backup_manifest_sha256"):
        raise ValueError("备份清单摘要不匹配")
    manifest = json.loads(encoded)
    entries = manifest.get("entries")
    if manifest.get("schema_version") != 1 or not isinstance(entries, list):
        raise ValueError("备份清单格式无效")
    actual: list[dict[str, object]] = []
    if metadata.get("fact_existed") is True:
        actual.append(_file_record(args.fact_backup, "public-endpoint.backup", sync=False))
    if metadata.get("clash_backed_up") is True:
        actual.append(_file_record(args.clash_config_backup, "clash-config.backup", sync=False))
        actual.extend(_tree_records(args.clash_payload_backup, "clash-subscriptions.backup", sync=False))
    for existed_name, path_name, label in (
        ("file_config_existed", "file_config_backup", "file-config.backup"),
        ("certificate_existed", "certificate_backup", "certificate.backup"),
        ("key_existed", "key_backup", "key.backup"),
        ("certificate_fact_existed", "certificate_fact_backup", "certificate-fact.backup"),
    ):
        if metadata.get(existed_name) is True:
            actual.append(_file_record(getattr(args, path_name), label, sync=False))
    if actual != entries:
        raise ValueError("备份内容摘要不匹配")


def verify_restored(args: argparse.Namespace) -> None:
    encoded = args.manifest.read_bytes()
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    if hashlib.sha256(encoded).hexdigest() != metadata.get("backup_manifest_sha256"):
        raise ValueError("备份清单摘要不匹配")
    entries = json.loads(encoded).get("entries")
    if not isinstance(entries, list):
        raise ValueError("备份清单格式无效")
    expected = {str(entry.get("path")): entry for entry in entries if isinstance(entry, dict)}
    actual: list[dict[str, object]] = []
    if metadata.get("fact_existed") is True:
        actual.append(_file_record(args.endpoint, "public-endpoint.backup", sync=False))
    elif os.path.lexists(args.endpoint):
        raise ValueError("原本不存在的稳定公网入口未被移除")
    if metadata.get("clash_backed_up") is True:
        actual.append(_file_record(args.clash_config, "clash-config.backup", sync=False))
        actual.extend(_tree_records(args.clash_payload, "clash-subscriptions.backup", sync=False))
    elif os.path.lexists(args.clash_config):
        raise ValueError("原本不存在的 Clash 配置意外出现")
    for existed_name, path_name, label in (
        ("file_config_existed", "file_config", "file-config.backup"),
        ("certificate_existed", "certificate", "certificate.backup"),
        ("key_existed", "key", "key.backup"),
        ("certificate_fact_existed", "certificate_fact", "certificate-fact.backup"),
    ):
        path = getattr(args, path_name)
        if metadata.get(existed_name) is True:
            actual.append(_file_record(path, label, sync=False))
        elif os.path.lexists(path):
            raise ValueError(f"原本不存在的发布文件意外出现: {label}")
    if {str(item["path"]): item for item in actual} != expected:
        raise ValueError("恢复后的在线内容与备份摘要不匹配")


def sync_restored(args: argparse.Namespace) -> None:
    for path in (
        args.endpoint, args.clash_config, args.file_config, args.certificate,
        args.key, args.certificate_fact,
    ):
        if path.is_file():
            _file_record(path, path.name, sync=True)
        if path.parent.is_dir():
            _fsync_directory(path.parent)
    if args.clash_payload.is_dir():
        _tree_records(args.clash_payload, "clash-subscriptions", sync=True)
        _fsync_directory(args.clash_payload.parent)


def sync_parent(args: argparse.Namespace) -> None:
    _fsync_directory(args.path.parent)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="operation", required=True)
    for name in ("create", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--fact-backup", type=Path, required=True)
        command.add_argument("--clash-config-backup", type=Path, required=True)
        command.add_argument("--clash-payload-backup", type=Path, required=True)
        command.add_argument("--file-config-backup", type=Path, required=True)
        command.add_argument("--certificate-backup", type=Path, required=True)
        command.add_argument("--key-backup", type=Path, required=True)
        command.add_argument("--certificate-fact-backup", type=Path, required=True)
        if name == "create":
            command.add_argument("--fact-existed", action="store_true")
            command.add_argument("--clash-backed-up", action="store_true")
            command.add_argument("--file-config-existed", action="store_true")
            command.add_argument("--certificate-existed", action="store_true")
            command.add_argument("--key-existed", action="store_true")
            command.add_argument("--certificate-fact-existed", action="store_true")
        else:
            command.add_argument("--metadata", type=Path, required=True)
    command = commands.add_parser("verify-restored")
    command.add_argument("--metadata", type=Path, required=True)
    command.add_argument("--manifest", type=Path, required=True)
    command.add_argument("--endpoint", type=Path, required=True)
    command.add_argument("--clash-config", type=Path, required=True)
    command.add_argument("--clash-payload", type=Path, required=True)
    command.add_argument("--file-config", type=Path, required=True)
    command.add_argument("--certificate", type=Path, required=True)
    command.add_argument("--key", type=Path, required=True)
    command.add_argument("--certificate-fact", type=Path, required=True)
    command = commands.add_parser("sync-restored")
    command.add_argument("--endpoint", type=Path, required=True)
    command.add_argument("--clash-config", type=Path, required=True)
    command.add_argument("--clash-payload", type=Path, required=True)
    command.add_argument("--file-config", type=Path, required=True)
    command.add_argument("--certificate", type=Path, required=True)
    command.add_argument("--key", type=Path, required=True)
    command.add_argument("--certificate-fact", type=Path, required=True)
    command = commands.add_parser("sync-parent")
    command.add_argument("--path", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.operation == "create":
        print(create_manifest(args))
    elif args.operation == "verify":
        verify_manifest(args)
    elif args.operation == "verify-restored":
        verify_restored(args)
    elif args.operation == "sync-restored":
        sync_restored(args)
    else:
        sync_parent(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from error

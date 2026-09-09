#!/usr/bin/env python3
"""server-kit 加密配置备份模块。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - Windows 仅用于本地单元测试
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:  # pragma: no cover - 由部署预检负责安装
    raise SystemExit("缺少 python3-cryptography，无法安全创建备份。") from exc


MAGIC = b"SKBACKUP1"
LEGACY_FORMAT_VERSION = 1
FORMAT_VERSION = 2
KEY_CUSTODY_VERSION = 2
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_FILE_COUNT = 2_000
BACKUP_ID_PATTERN = re.compile(r"backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z")
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
RESTORE_TRANSACTION_NAME = "restore-transaction.json"
RESTORE_ROLLBACK_UNIT = "server-kit-backup-restore-rollback"


@dataclass(frozen=True)
class Source:
    path: str
    category: str


# 只允许配置和身份资料；Git 仓库内容必须使用 Git 自身复制和校验。
SOURCES = (
    Source("/etc/server-kit", "server-kit"),
    Source("/etc/amneziawg", "amneziawg"),
    Source("/usr/local/etc/xray/config.json", "vless"),
    Source("/etc/default/vless-manager", "vless"),
    Source("/etc/secure-file-service", "file-service"),
    Source("/etc/server-kit-web", "management"),
    Source("/var/lib/server-kit-web/db.sqlite3", "management"),
    Source("/etc/ssh/sshd_config.d/20-server-kit-listen.conf", "ssh"),
    Source("/etc/ssh/sshd_config.d/30-server-kit-auth.conf", "ssh"),
    Source("/root/.ssh/authorized_keys", "ssh"),
)

EXCLUDED_PREFIXES = (
    "etc/server-kit/backups/",
    "etc/amneziawg/clients/",
    "etc/amneziawg/removed/",
)
EXCLUDED_NAMES = frozenset(
    {
        "etc/server-kit/firewall-transaction.json",
        "etc/server-kit/firewall-candidate.nft",
        "etc/server-kit/ssh-transaction.json",
        "etc/server-kit/ssh-auth-transaction.json",
        "etc/amneziawg/enrollments.json",
        "etc/amneziawg/rotations.json",
    }
)
OFFLINE_RESTORE_PATHS = frozenset(
    {
        "var/lib/server-kit-web/db.sqlite3",
        "etc/server-kit/web-secret-key",
    }
)
OFFLINE_RESTORE_PREFIXES = ("etc/server-kit-web/",)


class BackupError(Exception):
    """表示可安全展示给管理员的备份错误。"""


class SystemdRestoreScheduler:
    """使用 systemd 临时定时器执行无人值守回滚。"""

    def __init__(self, manager_path: str = "/usr/local/bin/server-kit-manager.sh") -> None:
        self.manager_path = manager_path

    def schedule(self, seconds: int) -> None:
        self.cancel()
        completed = subprocess.run(
            [
                "/usr/bin/systemd-run",
                "--quiet",
                f"--unit={RESTORE_ROLLBACK_UNIT}",
                f"--on-active={seconds}s",
                "--timer-property=AccuracySec=1s",
                self.manager_path,
                "backup",
                "restore-rollback",
                "--automatic",
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if completed.returncode != 0:
            raise BackupError("无法建立恢复自动回滚定时器。")

    def cancel(self) -> None:
        subprocess.run(
            [
                "/usr/bin/systemctl",
                "stop",
                f"{RESTORE_ROLLBACK_UNIT}.timer",
                f"{RESTORE_ROLLBACK_UNIT}.service",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        subprocess.run(
            [
                "/usr/bin/systemctl",
                "reset-failed",
                f"{RESTORE_ROLLBACK_UNIT}.service",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_relative(path: str) -> PurePosixPath:
    relative = PurePosixPath(path.lstrip("/"))
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise BackupError("备份路径不安全。")
    return relative


def _is_excluded(relative: str) -> bool:
    return relative in EXCLUDED_NAMES or any(
        relative.startswith(prefix) for prefix in EXCLUDED_PREFIXES
    ) or (
        relative.startswith("etc/server-kit/")
        and relative.endswith("-transaction.json")
    ) or (
        relative.startswith("etc/amneziawg/.")
    )


def _is_allowed_source(relative: str) -> bool:
    if _is_excluded(relative):
        return False
    for source in SOURCES:
        root = source.path.lstrip("/")
        if relative == root or relative.startswith(root + "/"):
            return True
    return False


def _is_legacy_allowed_source(relative: str) -> bool:
    """旧格式校验仅沿用历史白名单，不允许借机扩展恢复范围。"""
    for source in SOURCES:
        root = source.path.lstrip("/")
        if relative == root or relative.startswith(root + "/"):
            return not (
                relative.startswith("etc/server-kit/backups/")
                or relative in {
                    "etc/server-kit/firewall-transaction.json",
                    "etc/server-kit/firewall-candidate.nft",
                    "etc/server-kit/ssh-transaction.json",
                    "etc/server-kit/ssh-auth-transaction.json",
                }
                or relative.startswith("etc/server-kit/")
                and relative.endswith("-transaction.json")
            )
    return False


def _is_online_restore_path(relative: str) -> bool:
    return relative not in OFFLINE_RESTORE_PATHS and not any(
        relative.startswith(prefix) for prefix in OFFLINE_RESTORE_PREFIXES
    )


def _read_passphrase() -> str:
    raw = sys.stdin.buffer.readline(1025)
    if len(raw) > 1024 or not raw.endswith(b"\n"):
        raise BackupError("恢复口令长度不正确。")
    try:
        value = raw[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BackupError("恢复口令必须是 UTF-8 文本。") from exc
    if not 16 <= len(value) <= 256 or "\x00" in value:
        raise BackupError("恢复口令必须为 16–256 个字符。")
    return value


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        passphrase.encode("utf-8")
    )


class BackupStore:
    """在固定目录中创建、校验和预览 server-kit 配置备份。"""

    def __init__(
        self,
        backup_dir: Path,
        source_root: Path = Path("/"),
        web_gid: int = -1,
        scheduler: object | None = None,
        rollback_seconds: int = 300,
        writes_enabled: bool = False,
    ) -> None:
        self.backup_dir = backup_dir
        self.source_root = source_root
        self.web_gid = web_gid
        self.scheduler = scheduler or SystemdRestoreScheduler()
        self.rollback_seconds = rollback_seconds
        self.writes_enabled = writes_enabled

    def _source_path(self, absolute_path: str) -> Path:
        return self.source_root / absolute_path.lstrip("/")

    def _backup_path(self, backup_id: str) -> Path:
        if not BACKUP_ID_PATTERN.fullmatch(backup_id):
            raise BackupError("备份标识格式不正确。")
        return self.backup_dir / f"{backup_id}.skb"

    def list(self) -> dict[str, object]:
        items: list[dict[str, object]] = []
        if self.backup_dir.is_dir():
            for path in sorted(self.backup_dir.glob("backup-*.skb"), reverse=True):
                try:
                    header, _ = self._read_container(path, ciphertext_required=False)
                except BackupError:
                    continue
                items.append(self._public_header(header, path.stat().st_size, path))
        return {"schema_version": 1, "items": items}

    def create(self, passphrase: str) -> dict[str, object]:
        self.backup_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        os.chmod(self.backup_dir, 0o750)
        if self.web_gid >= 0:
            os.chown(self.backup_dir, 0, self.web_gid)
        backup_id = datetime.now(timezone.utc).strftime("backup-%Y%m%dT%H%M%SZ-") + os.urandom(4).hex()
        self._require_client_custody()
        archive, manifest = self._build_archive()
        salt = os.urandom(16)
        nonce = os.urandom(12)
        header = {
            "format_version": FORMAT_VERSION,
            "backup_id": backup_id,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "host": socket.gethostname()[:255],
            "cipher": "AES-256-GCM",
            "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "categories": sorted({item["category"] for item in manifest}),
            "file_count": len(manifest),
            "key_custody": {
                "version": KEY_CUSTODY_VERSION,
                "client_private_keys": "excluded",
            },
        }
        aad = _json_bytes(header)
        encrypted = AESGCM(_derive_key(passphrase, salt)).encrypt(nonce, archive, aad)
        target = self._backup_path(backup_id)
        fd, temporary_name = tempfile.mkstemp(prefix=".backup-", dir=self.backup_dir)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(MAGIC)
                stream.write(struct.pack(">I", len(aad)))
                stream.write(aad)
                stream.write(encrypted)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary_name, 0o640)
            if self.web_gid >= 0:
                os.chown(temporary_name, 0, self.web_gid)
            os.replace(temporary_name, target)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
        return self._public_header(header, target.stat().st_size, target)

    def verify(self, backup_id: str, passphrase: str) -> dict[str, object]:
        path = self._backup_path(backup_id)
        header, archive = self._decrypt(path, passphrase)
        legacy = int(header["format_version"]) == LEGACY_FORMAT_VERSION
        manifest = self._validate_archive(archive, legacy=legacy)
        if not legacy:
            self._record_assurance(backup_id, path, "integrity_verified_at")
        result = self._public_header(header, path.stat().st_size, path)
        result.update({"verified": True, "verified_file_count": len(manifest)})
        return result

    def delete(self, backup_id: str) -> dict[str, object]:
        """只删除固定目录中已验证标识的加密备份。"""
        self._acquire_lock()
        try:
            if self._read_transaction(required=False) is not None:
                raise BackupError("恢复事务进行中，不能删除配置备份。")
            path = self._backup_path(backup_id)
            if path.is_symlink() or not path.is_file():
                raise BackupError("备份不存在。")
            header, _ = self._read_container(path, ciphertext_required=True)
            if header.get("backup_id") != backup_id:
                raise BackupError("备份标识与容器内容不一致。")
            try:
                path.unlink()
                try:
                    self._remove_assurance(backup_id)
                except OSError:
                    # 密文已经删除时，残留的脱敏校验状态不应把成功删除误报为失败。
                    pass
                try:
                    directory = os.open(self.backup_dir, os.O_RDONLY)
                except (OSError, PermissionError):
                    directory = -1
                try:
                    if directory >= 0:
                        os.fsync(directory)
                finally:
                    if directory >= 0:
                        os.close(directory)
            except OSError as exc:
                raise BackupError("无法删除配置备份。") from exc
            return {
                "schema_version": 1,
                "backup_id": backup_id,
                "deleted": True,
            }
        finally:
            self._release_lock()

    def preview_restore(self, backup_id: str, passphrase: str) -> dict[str, object]:
        path = self._backup_path(backup_id)
        header, archive = self._decrypt(path, passphrase)
        legacy = int(header["format_version"]) == LEGACY_FORMAT_VERSION
        manifest = self._validate_archive(archive, legacy=legacy)
        changes = []
        online_changed_count = 0
        offline_changed_count = 0
        for item in manifest:
            current = self._source_path("/" + item["path"])
            if not current.is_file():
                state = "将恢复（当前缺失）"
            elif hashlib.sha256(
                self._read_consistent(current, str(item["path"]))
            ).hexdigest() != item["sha256"]:
                state = "将覆盖（内容不同）"
            else:
                state = "无需变更"
            if state != "无需变更":
                if _is_online_restore_path(str(item["path"])):
                    online_changed_count += 1
                else:
                    offline_changed_count += 1
                    state = "仅支持控制台离线恢复"
            changes.append({"path": "/" + item["path"], "category": item["category"], "state": state})
        if not legacy:
            self._record_assurance(backup_id, path, "restore_drill_at")
        return {
            "schema_version": 1,
            "backup": self._public_header(header, path.stat().st_size, path),
            "changes": changes,
            "changed_count": sum(item["state"] != "无需变更" for item in changes),
            "online_changed_count": online_changed_count,
            "offline_changed_count": offline_changed_count,
            "writes_enabled": False,
        }

    def restore_status(self, last_outcome: str = "") -> dict[str, object]:
        """返回恢复事务的脱敏状态。"""
        transaction = self._read_transaction(required=False)
        if transaction is None:
            return {
                "schema_version": 1,
                "state": "idle",
                "backup_id": "",
                "expires_at": "",
                "remaining_seconds": 0,
                "rollback_seconds": self.rollback_seconds,
                "changed_count": 0,
                "categories": [],
                "verifications": [],
                "writes_enabled": self.writes_enabled,
                "last_outcome": last_outcome,
            }
        expires_at = datetime.fromisoformat(str(transaction["expires_at"]))
        remaining = max(
            0, int((expires_at - datetime.now(timezone.utc)).total_seconds())
        )
        return {
            "schema_version": 1,
            "state": "pending",
            "backup_id": transaction["backup_id"],
            "expires_at": transaction["expires_at"],
            "remaining_seconds": remaining,
            "rollback_seconds": self.rollback_seconds,
            "changed_count": len(transaction["changed_paths"]),
            "categories": transaction["categories"],
            "verifications": [
                "确认当前 AWG 与公网 SSH 新连接仍可建立",
                "确认管理网站和 VLESS 状态符合预期",
                "确认后再按需重启使用已恢复磁盘配置的服务",
            ],
            "writes_enabled": self.writes_enabled,
            "last_outcome": last_outcome,
        }

    def apply_restore(self, backup_id: str, passphrase: str) -> dict[str, object]:
        """写入备份配置，并建立必须确认的自动回滚事务。"""
        if not self.writes_enabled:
            raise BackupError("当前服务器只允许恢复预览。")
        self._acquire_lock()
        try:
            if self._read_transaction(required=False) is not None:
                raise BackupError("已有待确认的恢复事务。")
            path = self._backup_path(backup_id)
            header, archive = self._decrypt(path, passphrase)
            if int(header["format_version"]) == LEGACY_FORMAT_VERSION:
                raise BackupError(
                    "旧格式备份可能含客户端私钥，禁止直接恢复。请创建并校验当前格式备份。"
                )
            manifest, payloads = self._archive_files(archive)
            changed = [
                item for item in manifest
                if _is_online_restore_path(str(item["path"]))
                and self._item_changed(item)
            ]
            if not changed:
                raise BackupError("没有可在线恢复的配置差异；管理数据库和网站密钥只能从控制台离线恢复。")
            rollback_name = f".restore-rollback-{os.urandom(8).hex()}.tar"
            rollback_path = self.backup_dir / rollback_name
            self._write_rollback_archive(rollback_path, changed)
            now = datetime.now(timezone.utc)
            transaction = {
                "schema_version": 1,
                "backup_id": backup_id,
                "created_at": now.isoformat(timespec="seconds"),
                "expires_at": (now + timedelta(seconds=self.rollback_seconds)).isoformat(timespec="seconds"),
                "rollback_name": rollback_name,
                "changed_paths": [str(item["path"]) for item in changed],
                "categories": sorted({str(item["category"]) for item in changed}),
            }
            self._write_transaction(transaction)
            try:
                self.scheduler.schedule(self.rollback_seconds)  # type: ignore[attr-defined]
                by_path = {str(item["path"]): item for item in manifest}
                for relative in transaction["changed_paths"]:
                    item = by_path[relative]
                    self._apply_file(
                        relative,
                        payloads[relative],
                        int(item["mode"]),
                    )
                self._validate_restored(transaction["changed_paths"])
            except Exception as exc:
                try:
                    self._rollback_locked(automatic=False)
                except Exception as rollback_error:
                    raise BackupError("恢复失败，且自动恢复原配置也失败，请立即使用控制台。") from rollback_error
                if isinstance(exc, BackupError):
                    raise
                raise BackupError("恢复配置校验失败，已恢复原配置。") from exc
            return self.restore_status()
        finally:
            self._release_lock()

    def confirm_restore(self) -> dict[str, object]:
        """确认持久化当前磁盘配置并删除短期明文回滚包。"""
        if not self.writes_enabled:
            raise BackupError("当前服务器只允许恢复预览。")
        self._acquire_lock()
        try:
            transaction = self._read_transaction(required=True)
            self.scheduler.cancel()  # type: ignore[attr-defined]
            self._rollback_path(transaction).unlink(missing_ok=True)
            self._transaction_path().unlink(missing_ok=True)
            return self.restore_status("confirmed")
        finally:
            self._release_lock()

    def rollback_restore(self, automatic: bool = False) -> dict[str, object]:
        """恢复事务开始前的文件状态。"""
        self._acquire_lock()
        try:
            self._rollback_locked(automatic)
            return self.restore_status("rolled_back")
        finally:
            self._release_lock()

    def _rollback_locked(self, automatic: bool) -> None:
        transaction = self._read_transaction(required=True)
        rollback_path = self._rollback_path(transaction)
        entries, payloads = self._read_rollback_archive(rollback_path)
        for item in entries:
            relative = str(item["path"])
            target = self._source_path("/" + relative)
            if item["existed"]:
                self._apply_file(relative, payloads[relative], int(item["mode"]))
            elif target.exists():
                if target.is_symlink() or not target.is_file():
                    raise BackupError("自动回滚遇到不安全的目标路径。")
                target.unlink()
        if not automatic:
            self.scheduler.cancel()  # type: ignore[attr-defined]
        rollback_path.unlink(missing_ok=True)
        self._transaction_path().unlink(missing_ok=True)

    def _item_changed(self, item: dict[str, object]) -> bool:
        relative = str(item["path"])
        current = self._source_path("/" + relative)
        return not current.is_file() or hashlib.sha256(
            self._read_consistent(current, relative)
        ).hexdigest() != item["sha256"]

    def _transaction_path(self) -> Path:
        return self.backup_dir / RESTORE_TRANSACTION_NAME

    def _lock_path(self) -> Path:
        return self.backup_dir / ".restore.lock"

    def _acquire_lock(self) -> None:
        self.backup_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        lock = self._lock_path()
        for _ in range(2):
            try:
                descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                try:
                    pid = int(lock.read_text(encoding="ascii").strip())
                    os.kill(pid, 0)
                except (OSError, ValueError):
                    lock.unlink(missing_ok=True)
                    continue
                raise BackupError("另一个恢复操作正在执行。")
            else:
                os.write(descriptor, str(os.getpid()).encode("ascii"))
                os.close(descriptor)
                return
        raise BackupError("无法取得恢复操作锁。")

    def _release_lock(self) -> None:
        self._lock_path().unlink(missing_ok=True)

    def _write_transaction(self, transaction: dict[str, object]) -> None:
        target = self._transaction_path()
        descriptor, temporary = tempfile.mkstemp(prefix=".restore-transaction-", dir=self.backup_dir)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(_json_bytes(transaction))
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _read_transaction(self, required: bool) -> dict[str, object] | None:
        path = self._transaction_path()
        try:
            transaction = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if required:
                raise BackupError("没有待确认的恢复事务。")
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise BackupError("恢复事务状态损坏。") from exc
        expected = {
            "schema_version", "backup_id", "created_at", "expires_at",
            "rollback_name", "changed_paths", "categories",
        }
        if (
            not isinstance(transaction, dict)
            or set(transaction) != expected
            or transaction.get("schema_version") != 1
            or not BACKUP_ID_PATTERN.fullmatch(str(transaction.get("backup_id", "")))
            or not re.fullmatch(r"\.restore-rollback-[0-9a-f]{16}\.tar", str(transaction.get("rollback_name", "")))
            or not isinstance(transaction.get("changed_paths"), list)
            or not transaction["changed_paths"]
            or not all(isinstance(item, str) and _is_allowed_source(item) for item in transaction["changed_paths"])
            or not isinstance(transaction.get("categories"), list)
        ):
            raise BackupError("恢复事务状态格式不正确。")
        try:
            datetime.fromisoformat(str(transaction["created_at"]))
            datetime.fromisoformat(str(transaction["expires_at"]))
        except ValueError as exc:
            raise BackupError("恢复事务时间格式不正确。") from exc
        return transaction

    def _rollback_path(self, transaction: dict[str, object]) -> Path:
        return self.backup_dir / str(transaction["rollback_name"])

    def _write_rollback_archive(
        self, target: Path, changed: list[dict[str, object]]
    ) -> None:
        entries: list[dict[str, object]] = []
        payloads: list[tuple[str, bytes, int]] = []
        for item in changed:
            relative = str(item["path"])
            current = self._source_path("/" + relative)
            if current.is_file() and not current.is_symlink():
                data = self._read_consistent(current, relative)
                mode = current.stat().st_mode & 0o777
                if self.source_root == Path("/") and (
                    not mode & 0o400 or mode & 0o033 or mode & 0o111
                ):
                    raise BackupError("当前配置文件权限不安全，拒绝建立恢复事务。")
                entries.append({"path": relative, "existed": True, "mode": mode, "sha256": hashlib.sha256(data).hexdigest()})
                payloads.append((relative, data, mode))
            elif not current.exists():
                entries.append({"path": relative, "existed": False, "mode": 0, "sha256": ""})
            else:
                raise BackupError("当前配置包含不安全的文件类型。")
        descriptor, temporary = tempfile.mkstemp(prefix=".restore-rollback-write-", dir=self.backup_dir)
        os.close(descriptor)
        try:
            with tarfile.open(temporary, mode="w", format=tarfile.PAX_FORMAT) as archive:
                self._add_bytes(archive, "manifest.json", _json_bytes({"schema_version": 1, "files": entries}), 0o600, 0)
                for relative, data, mode in payloads:
                    self._add_bytes(archive, f"files/{relative}", data, mode, 0)
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def _read_rollback_archive(
        path: Path,
    ) -> tuple[list[dict[str, object]], dict[str, bytes]]:
        try:
            with tarfile.open(path, mode="r:") as archive:
                members = archive.getmembers()
                if not members or members[0].name != "manifest.json" or len(members) > MAX_FILE_COUNT + 1:
                    raise BackupError("恢复回滚包格式不正确。")
                stream = archive.extractfile(members[0])
                value = json.load(stream) if stream is not None else None
                entries = value.get("files") if isinstance(value, dict) and value.get("schema_version") == 1 else None
                if not isinstance(entries, list):
                    raise BackupError("恢复回滚清单损坏。")
                by_name = {member.name: member for member in members[1:]}
                payloads: dict[str, bytes] = {}
                for item in entries:
                    if not isinstance(item, dict) or set(item) != {"path", "existed", "mode", "sha256"}:
                        raise BackupError("恢复回滚条目损坏。")
                    relative = str(item["path"])
                    if not _is_allowed_source(relative) or not isinstance(item["existed"], bool):
                        raise BackupError("恢复回滚路径不安全。")
                    if item["existed"]:
                        member = by_name.get(f"files/{relative}")
                        data_stream = archive.extractfile(member) if member is not None else None
                        data = data_stream.read() if data_stream is not None else b""
                        if hashlib.sha256(data).hexdigest() != item["sha256"]:
                            raise BackupError("恢复回滚文件校验失败。")
                        payloads[relative] = data
                return entries, payloads
        except (OSError, tarfile.TarError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise BackupError("无法读取恢复回滚包。") from exc

    def _apply_file(self, relative: str, data: bytes, mode: int) -> None:
        if (
            not _is_allowed_source(relative)
            or not 0 <= mode <= 0o777
            or (
                self.source_root == Path("/")
                and (not mode & 0o400 or mode & 0o033 or mode & 0o111)
            )
        ):
            raise BackupError("拒绝写入白名单之外或权限不安全的配置。")
        target = self._source_path("/" + relative)
        self._ensure_parent(target, relative)
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise BackupError("恢复目标不是安全的普通文件。")
        if relative == "var/lib/server-kit-web/db.sqlite3":
            self._restore_sqlite(target, data)
        else:
            descriptor, temporary = tempfile.mkstemp(prefix=".server-kit-restore-", dir=target.parent)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, mode)
                self._set_owner(Path(temporary), relative)
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        os.chmod(target, mode)
        self._set_owner(target, relative)

    def _ensure_parent(self, target: Path, relative: str) -> None:
        current = self.source_root
        for part in PurePosixPath(relative).parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise BackupError("恢复目标父目录包含符号链接。")
            current.mkdir(mode=0o755, exist_ok=True)
        if self.source_root == Path("/"):
            known = {
                "root/.ssh": (0o700, "root"),
                "etc/server-kit": (0o700, "root"),
                "etc/amneziawg": (0o700, "root"),
                "etc/server-kit-web": (0o710, "root-web"),
                "var/lib/server-kit-web": (0o750, "web"),
            }
            for prefix, (directory_mode, owner) in known.items():
                directory = self._source_path("/" + prefix)
                if relative.startswith(prefix + "/") and directory.is_dir():
                    os.chmod(directory, directory_mode)
                    self._set_owner(directory, prefix + "/", owner)

    def _set_owner(self, path: Path, relative: str, explicit: str = "") -> None:
        if self.source_root != Path("/") or pwd is None or grp is None:
            return
        web_uid = pwd.getpwnam("server-kit-web").pw_uid
        web_gid = grp.getgrnam("server-kit-web").gr_gid
        if explicit == "web" or relative.startswith("var/lib/server-kit-web/"):
            uid, gid = web_uid, web_gid
        elif explicit == "root-web" or relative.startswith("etc/server-kit-web/"):
            uid, gid = 0, web_gid
        else:
            uid, gid = 0, 0
        os.chown(path, uid, gid)

    @staticmethod
    def _restore_sqlite(target: Path, data: bytes) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix="server-kit-restore-db-")
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
            source = sqlite3.connect(f"file:{temporary}?mode=ro", uri=True)
            destination = sqlite3.connect(target)
            try:
                check = source.execute("pragma integrity_check").fetchone()
                if check != ("ok",):
                    raise BackupError("备份中的管理数据库完整性校验失败。")
                source.backup(destination)
                destination.commit()
            finally:
                destination.close()
                source.close()
        finally:
            Path(temporary).unlink(missing_ok=True)

    def _validate_restored(self, changed_paths: list[str]) -> None:
        for relative in changed_paths:
            path = self._source_path("/" + relative)
            if relative.endswith(".json"):
                try:
                    json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise BackupError("恢复后的 JSON 配置校验失败。") from exc
            if relative == "var/lib/server-kit-web/db.sqlite3":
                connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
                try:
                    if connection.execute("pragma integrity_check").fetchone() != ("ok",):
                        raise BackupError("恢复后的管理数据库校验失败。")
                finally:
                    connection.close()
        if self.source_root == Path("/") and any(path.startswith("etc/ssh/") for path in changed_paths):
            self._run_validator(["/usr/sbin/sshd", "-t"])
        if self.source_root == Path("/") and "usr/local/etc/xray/config.json" in changed_paths and Path("/usr/local/bin/xray").is_file():
            self._run_validator(["/usr/local/bin/xray", "run", "-test", "-config", "/usr/local/etc/xray/config.json"])

    def _require_client_custody(self) -> None:
        """创建备份前确认全部 AWG 节点都满足密钥安全约束。"""
        credentials = self._source_path("/etc/amneziawg/peer-credentials.tsv")
        peer_names: set[str] = set()
        for relative in ("/etc/amneziawg/peers.tsv", "/etc/amneziawg/peers.disabled.tsv"):
            path = self._source_path(relative)
            try:
                rows = path.read_text(encoding="utf-8").splitlines()
            except FileNotFoundError:
                continue
            except (OSError, UnicodeDecodeError) as exc:
                raise BackupError("无法确认 AWG 节点清单。") from exc
            for row in rows:
                fields = row.split("\t")
                if len(fields) != 2 or not fields[0]:
                    raise BackupError("AWG 节点清单格式不正确。")
                peer_names.add(fields[0])
        if not credentials.is_file():
            if peer_names:
                raise BackupError(
                    f"有 {len(peer_names)} 个节点缺少安全凭据记录；请先修复节点凭据。"
                )
            return
        try:
            rows = credentials.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise BackupError("无法确认 AWG 节点密钥托管状态。") from exc
        custody_by_name: dict[str, str] = {}
        for row in rows:
            if not row.strip():
                continue
            fields = row.split("\t")
            if len(fields) != 4 or fields[3] != "client":
                raise BackupError("AWG 节点凭据不符合安全要求。")
            custody_by_name[fields[0]] = fields[3]
        missing_nodes = sorted(peer_names - set(custody_by_name))
        if missing_nodes:
            raise BackupError(
                f"有 {len(missing_nodes)} 个节点缺少安全凭据记录；请先修复节点凭据。"
            )

    def _assurance_path(self) -> Path:
        return self.backup_dir / "assurance.json"

    def _read_assurance(self) -> dict[str, dict[str, object]]:
        try:
            value = json.loads(self._assurance_path().read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}
        items = value.get("items") if isinstance(value, dict) and value.get("schema_version") == 1 else None
        if not isinstance(items, dict):
            return {}
        result: dict[str, dict[str, object]] = {}
        for backup_id, item in items.items():
            if not BACKUP_ID_PATTERN.fullmatch(str(backup_id)) or not isinstance(item, dict):
                continue
            if not isinstance(item.get("digest"), str) or not re.fullmatch(r"[0-9a-f]{64}", item["digest"]):
                continue
            if not isinstance(item.get("size"), int) or not isinstance(item.get("mtime_ns"), int):
                continue
            clean = {
                "digest": item["digest"],
                "size": item["size"],
                "mtime_ns": item["mtime_ns"],
            }
            for field in ("integrity_verified_at", "restore_drill_at"):
                if isinstance(item.get(field), str):
                    try:
                        datetime.fromisoformat(item[field])
                    except ValueError:
                        continue
                    clean[field] = item[field]
            result[str(backup_id)] = clean
        return result

    def _write_assurance(self, items: dict[str, dict[str, object]]) -> None:
        self.backup_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".assurance-", dir=self.backup_dir)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(_json_bytes({"schema_version": 1, "items": items}))
                stream.write(b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self._assurance_path())
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _record_assurance(self, backup_id: str, path: Path, field: str) -> None:
        if field not in {"integrity_verified_at", "restore_drill_at"}:
            raise BackupError("备份安全状态字段无效。")
        items = self._read_assurance()
        digest = _sha256_file(path)
        stat = path.stat()
        item = items.get(backup_id, {})
        if item.get("digest") != digest:
            item = {"digest": digest}
        item["size"] = stat.st_size
        item["mtime_ns"] = stat.st_mtime_ns
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        item["integrity_verified_at"] = now
        item[field] = now
        items[backup_id] = item
        self._write_assurance(items)

    def _remove_assurance(self, backup_id: str) -> None:
        items = self._read_assurance()
        if backup_id in items:
            del items[backup_id]
            self._write_assurance(items)

    def _assurance_state(self, backup_id: str, path: Path) -> str:
        item = self._read_assurance().get(backup_id)
        try:
            stat = path.stat()
        except OSError:
            return "awaiting_verification"
        if (
            not item
            or item.get("size") != stat.st_size
            or item.get("mtime_ns") != stat.st_mtime_ns
        ):
            return "awaiting_verification"
        if item.get("integrity_verified_at") and item.get("restore_drill_at"):
            return "cleanup_ready"
        if item.get("integrity_verified_at"):
            return "verified"
        return "awaiting_verification"

    @staticmethod
    def _run_validator(arguments: list[str]) -> None:
        try:
            completed = subprocess.run(
                arguments, check=False, capture_output=True, text=True, timeout=20
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackupError("恢复后的服务配置校验无法完成。") from exc
        if completed.returncode != 0:
            raise BackupError("恢复后的服务配置校验失败。")

    def _build_archive(self) -> tuple[bytes, list[dict[str, object]]]:
        files: list[tuple[Path, str, str]] = []
        for source in SOURCES:
            path = self._source_path(source.path)
            if path.is_symlink():
                continue
            if path.is_file():
                files.append((path, source.path.lstrip("/"), source.category))
            elif path.is_dir():
                for child in sorted(path.rglob("*")):
                    if child.is_file() and not child.is_symlink():
                        relative = child.relative_to(self.source_root).as_posix()
                        if not _is_excluded(relative):
                            files.append((child, relative, source.category))
        # 同一路径可能同时被父目录和单文件来源命中，按路径去重。
        unique = {relative: (path, relative, category) for path, relative, category in files}
        files = [unique[key] for key in sorted(unique)]
        if not files:
            raise BackupError("没有发现可备份的 server-kit 配置。")
        if len(files) > MAX_FILE_COUNT:
            raise BackupError("配置文件数量超过安全上限。")
        manifest: list[dict[str, object]] = []
        payloads: list[tuple[str, bytes, os.stat_result]] = []
        total = 0
        for path, relative, category in files:
            _safe_relative(relative)
            if not _is_allowed_source(relative):
                continue
            data = self._read_consistent(path, relative)
            if len(data) > MAX_FILE_BYTES:
                raise BackupError(f"配置文件超过单文件上限：/{relative}")
            total += len(data)
            if total > MAX_ARCHIVE_BYTES:
                raise BackupError("配置备份超过 64 MiB 安全上限。")
            stat = path.stat()
            digest = hashlib.sha256(data).hexdigest()
            manifest.append({
                "path": relative,
                "category": category,
                "size": len(data),
                "mode": stat.st_mode & 0o777,
                "sha256": digest,
            })
            payloads.append((relative, data, stat))
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
            manifest_bytes = _json_bytes({"schema_version": 1, "files": manifest})
            self._add_bytes(archive, "manifest.json", manifest_bytes, 0o600, 0)
            for relative, data, stat in payloads:
                self._add_bytes(archive, f"files/{relative}", data, stat.st_mode & 0o777, int(stat.st_mtime))
        value = buffer.getvalue()
        if len(value) > MAX_ARCHIVE_BYTES:
            raise BackupError("配置归档超过 64 MiB 安全上限。")
        return value, manifest

    @staticmethod
    def _add_bytes(archive: tarfile.TarFile, name: str, data: bytes, mode: int, mtime: int) -> None:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = mode
        info.mtime = mtime
        info.uid = 0
        info.gid = 0
        archive.addfile(info, io.BytesIO(data))

    @staticmethod
    def _read_consistent(path: Path, relative: str) -> bytes:
        if relative == "var/lib/server-kit-web/db.sqlite3":
            fd, temporary_name = tempfile.mkstemp(prefix="server-kit-db-")
            os.close(fd)
            try:
                source = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
                destination = sqlite3.connect(temporary_name)
                try:
                    source.backup(destination)
                    destination.commit()
                finally:
                    destination.close()
                    source.close()
                return Path(temporary_name).read_bytes()
            finally:
                Path(temporary_name).unlink(missing_ok=True)
        return path.read_bytes()

    def _decrypt(self, path: Path, passphrase: str) -> tuple[dict[str, object], bytes]:
        header, encrypted = self._read_container(path, ciphertext_required=True)
        try:
            salt = base64.b64decode(str(header["salt"]), validate=True)
            nonce = base64.b64decode(str(header["nonce"]), validate=True)
            if len(salt) != 16 or len(nonce) != 12:
                raise ValueError
            archive = AESGCM(_derive_key(passphrase, salt)).decrypt(nonce, encrypted, _json_bytes(header))
        except (InvalidTag, KeyError, ValueError, TypeError) as exc:
            raise BackupError("恢复口令错误，或备份内容已被篡改。") from exc
        if len(archive) > MAX_ARCHIVE_BYTES:
            raise BackupError("解密后的配置归档超过安全上限。")
        return header, archive

    @staticmethod
    def _read_container(path: Path, ciphertext_required: bool) -> tuple[dict[str, object], bytes]:
        try:
            with path.open("rb") as stream:
                if stream.read(len(MAGIC)) != MAGIC:
                    raise BackupError("备份格式不受支持。")
                raw_size = stream.read(4)
                if len(raw_size) != 4:
                    raise BackupError("备份头不完整。")
                size = struct.unpack(">I", raw_size)[0]
                if not 1 <= size <= 16_384:
                    raise BackupError("备份头长度不正确。")
                raw_header = stream.read(size)
                header = json.loads(raw_header)
                encrypted = stream.read(MAX_ARCHIVE_BYTES + 17)
        except (OSError, json.JSONDecodeError) as exc:
            raise BackupError("无法读取备份文件。") from exc
        common = {"format_version", "backup_id", "created_at", "host", "cipher", "kdf", "salt", "nonce", "categories", "file_count"}
        if not isinstance(header, dict) or header.get("format_version") not in {LEGACY_FORMAT_VERSION, FORMAT_VERSION}:
            raise BackupError("备份头版本不受支持。")
        required = common if header["format_version"] == LEGACY_FORMAT_VERSION else common | {"key_custody"}
        if set(header) != required:
            raise BackupError("备份头字段不受支持。")
        if header["format_version"] == FORMAT_VERSION and header.get("key_custody") != {
            "version": KEY_CUSTODY_VERSION,
            "client_private_keys": "excluded",
        }:
            raise BackupError("备份密钥托管声明无效。")
        if not BACKUP_ID_PATTERN.fullmatch(str(header.get("backup_id", ""))):
            raise BackupError("备份标识不正确。")
        if ciphertext_required and not encrypted:
            raise BackupError("备份密文为空。")
        if len(encrypted) > MAX_ARCHIVE_BYTES + 16:
            raise BackupError("备份密文超过安全上限。")
        return header, encrypted

    @staticmethod
    def _validate_archive(
        archive_data: bytes, legacy: bool = False,
    ) -> list[dict[str, object]]:
        manifest, _ = BackupStore._archive_files(archive_data, legacy=legacy)
        return manifest

    @staticmethod
    def _archive_files(
        archive_data: bytes,
        legacy: bool = False,
    ) -> tuple[list[dict[str, object]], dict[str, bytes]]:
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:") as archive:
                members = archive.getmembers()
                if len(members) > MAX_FILE_COUNT + 1:
                    raise BackupError("归档文件数量超过安全上限。")
                if not members or members[0].name != "manifest.json":
                    raise BackupError("备份清单缺失。")
                for member in members:
                    _safe_relative(member.name)
                    if not member.isfile() or member.size > MAX_FILE_BYTES:
                        raise BackupError("备份包含不受支持的条目。")
                manifest_stream = archive.extractfile(members[0])
                if manifest_stream is None:
                    raise BackupError("备份清单无法读取。")
                manifest_object = json.load(manifest_stream)
                manifest = manifest_object.get("files") if isinstance(manifest_object, dict) else None
                if not isinstance(manifest, list) or len(manifest) != len(members) - 1:
                    raise BackupError("备份清单不一致。")
                by_name = {member.name: member for member in members[1:]}
                payloads: dict[str, bytes] = {}
                for item in manifest:
                    if not isinstance(item, dict) or set(item) != {"path", "category", "size", "mode", "sha256"}:
                        raise BackupError("备份清单条目不正确。")
                    relative = str(item["path"])
                    _safe_relative(relative)
                    if not (_is_legacy_allowed_source(relative) if legacy else _is_allowed_source(relative)):
                        raise BackupError("备份包含白名单之外的路径。")
                    member = by_name.get(f"files/{relative}")
                    if member is None or member.size != item["size"]:
                        raise BackupError("备份清单与文件不一致。")
                    stream = archive.extractfile(member)
                    data = stream.read() if stream is not None else b""
                    if stream is None or hashlib.sha256(data).hexdigest() != item["sha256"]:
                        raise BackupError("备份文件完整性校验失败。")
                    payloads[relative] = data
                return manifest, payloads
        except (tarfile.TarError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise BackupError("备份归档格式不正确。") from exc

    def _public_header(
        self, header: dict[str, object], size: int, path: Path,
    ) -> dict[str, object]:
        legacy = int(header["format_version"]) == LEGACY_FORMAT_VERSION
        return {
            "backup_id": header["backup_id"],
            "format_version": header["format_version"],
            "created_at": header["created_at"],
            "host": header["host"],
            "cipher": header["cipher"],
            "categories": header["categories"],
            "file_count": header["file_count"],
            "size": size,
            "download_name": f"{header['backup_id']}.skb",
            "key_custody_version": 1 if legacy else KEY_CUSTODY_VERSION,
            "client_private_keys": "may_be_included" if legacy else "excluded",
            "restore_allowed": not legacy,
            "assurance_state": "legacy" if legacy else self._assurance_state(str(header["backup_id"]), path),
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="server-kit 加密配置备份")
    parser.add_argument(
        "operation",
        choices=(
            "list", "create", "verify", "delete", "preview-restore", "restore-status",
            "restore-apply", "restore-confirm", "restore-rollback",
        ),
    )
    parser.add_argument("backup_id", nargs="?")
    parser.add_argument("--backup-dir", default="/var/lib/server-kit-backups")
    parser.add_argument("--source-root", default="/")
    parser.add_argument("--web-gid", type=int, default=-1)
    parser.add_argument("--rollback-seconds", type=int, default=300)
    parser.add_argument("--writes-enabled", action="store_true")
    parser.add_argument("--automatic", action="store_true")
    args = parser.parse_args(argv)
    if not 60 <= args.rollback_seconds <= 3600:
        parser.error("回滚窗口必须为 60–3600 秒。")
    store = BackupStore(
        Path(args.backup_dir), Path(args.source_root), args.web_gid,
        rollback_seconds=args.rollback_seconds,
        writes_enabled=args.writes_enabled,
    )
    try:
        if args.operation == "list":
            result = store.list()
        elif args.operation == "create":
            result = store.create(_read_passphrase())
        elif args.operation in {"verify", "preview-restore", "restore-apply"}:
            if not args.backup_id:
                raise BackupError("缺少备份标识。")
            passphrase = _read_passphrase()
            if args.operation == "verify":
                result = store.verify(args.backup_id, passphrase)
            elif args.operation == "preview-restore":
                result = store.preview_restore(args.backup_id, passphrase)
            else:
                result = store.apply_restore(args.backup_id, passphrase)
        elif args.operation == "delete":
            if not args.backup_id:
                raise BackupError("缺少备份标识。")
            result = store.delete(args.backup_id)
        elif args.operation == "restore-status":
            result = store.restore_status()
        elif args.operation == "restore-confirm":
            result = store.confirm_restore()
        else:
            result = store.rollback_restore(args.automatic)
    except BackupError as exc:
        print(json.dumps({"schema_version": 1, "ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"schema_version": 1, "ok": True, "result": result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

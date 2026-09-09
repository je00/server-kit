#!/usr/bin/env python3
"""安全列出、暂存并添加 root SSH 公钥。"""

from __future__ import annotations

import base64
import binascii
import json
import hashlib
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import unicodedata
from pathlib import Path


KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{20,80}\Z")
KEY_ID_PATTERN = re.compile(r"key-[0-9a-f]{64}\Z")
MAX_KEY_BYTES = 16 * 1024
PENDING_TTL = 300


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def validation_error(message: str, quiet: bool) -> None:
    if quiet:
        raise ValueError(message)
    fail(message)


def normalize_key(value: object, *, quiet: bool = False) -> tuple[str, str, str, str]:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= MAX_KEY_BYTES:
        validation_error("SSH 公钥长度无效。", quiet)
    if "\x00" in value or "\r" in value or "\n" in value:
        validation_error("SSH 公钥必须是完整的一行。", quiet)
    parts = value.strip().split(maxsplit=2)
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        validation_error("SSH 公钥类型不受支持。", quiet)
    key_type, encoded = parts[:2]
    comment = parts[2].strip()[:128] if len(parts) == 3 else ""
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        validation_error("SSH 公钥编码无效。", quiet)
    if not decoded:
        validation_error("SSH 公钥内容为空。", quiet)
    normalized = f"{key_type} {encoded}" + (f" {comment}" if comment else "")
    return key_type, encoded, comment, normalized


def fingerprint(normalized: str, pending_dir: Path, *, quiet: bool = False) -> str:
    pending_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(pending_dir, 0o700)
    descriptor, name = tempfile.mkstemp(prefix=".fingerprint.", dir=pending_dir)
    try:
        os.write(descriptor, (normalized + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        completed = subprocess.run(
            ["ssh-keygen", "-lf", name, "-E", "sha256"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    finally:
        os.unlink(name)
    if completed.returncode != 0:
        validation_error("SSH 公钥校验失败。", quiet)
    fields = completed.stdout.strip().split()
    if len(fields) < 2 or not fields[1].startswith("SHA256:"):
        validation_error("无法读取 SSH 公钥指纹。", quiet)
    return fields[1]


def key_identifier(encoded: str) -> str:
    decoded = base64.b64decode(encoded, validate=True)
    return "key-" + hashlib.sha256(decoded).hexdigest()


def validate_name(value: object) -> str:
    if not isinstance(value, str):
        fail("SSH 客户端名称无效。")
    name = value.strip()
    if not 1 <= len(name) <= 64 or any(unicodedata.category(char).startswith("C") for char in name):
        fail("SSH 客户端名称必须为 1–64 个可见字符。")
    return name


def key_from_authorized_line(raw: str, pending_dir: Path) -> dict[str, str] | None:
    words = raw.strip().split()
    index = next((i for i, word in enumerate(words) if word in KEY_TYPES), None)
    if index is None or len(words) <= index + 1:
        return None
    candidate = " ".join(words[index:])
    try:
        key_type, encoded, comment, normalized = normalize_key(candidate, quiet=True)
        key_fingerprint = fingerprint(normalized, pending_dir, quiet=True)
    except ValueError:
        return None
    return {
        "type": key_type,
        "fingerprint": key_fingerprint,
        "name": comment or "未命名客户端",
        "key_id": key_identifier(encoded),
    }


def cleanup_pending(pending_dir: Path) -> None:
    now = int(time.time())
    try:
        entries = list(pending_dir.iterdir())
    except FileNotFoundError:
        return
    for path in entries:
        if path.is_symlink() or not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            issued_at = data.get("issued_at") if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError):
            issued_at = None
        if not isinstance(issued_at, int) or not 0 <= now - issued_at <= PENDING_TTL:
            try:
                path.unlink()
            except OSError:
                pass


def existing_keys(authorized_path: Path, pending_dir: Path) -> list[dict[str, object]]:
    try:
        lines = authorized_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        lines = []
    except OSError:
        fail("无法读取 root authorized_keys。")
    items: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw in lines:
        item = key_from_authorized_line(raw, pending_dir)
        if item is None or item["key_id"] in seen:
            continue
        seen.add(item["key_id"])
        items.append(item)
    deletable = len(items) > 1
    for item in items:
        item["deletable"] = deletable
    return items


def write_authorized_keys(authorized_path: Path, content: str) -> None:
    if authorized_path.is_symlink():
        fail("root authorized_keys 不能是符号链接。")
    authorized_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(authorized_path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".authorized_keys.", dir=authorized_path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, authorized_path)
    finally:
        temporary.unlink(missing_ok=True)


def list_keys(authorized_path: Path, pending_dir: Path) -> None:
    cleanup_pending(pending_dir)
    items = existing_keys(authorized_path, pending_dir)
    print(json.dumps({"schema_version": 1, "items": items}, ensure_ascii=False, separators=(",", ":")))


def preview(authorized_path: Path, pending_dir: Path) -> None:
    try:
        request = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        fail("SSH 公钥请求格式无效。")
    if not isinstance(request, dict) or set(request) != {"public_key"}:
        fail("SSH 公钥请求字段无效。")
    key_type, encoded, comment, normalized = normalize_key(request["public_key"])
    key_fingerprint = fingerprint(normalized, pending_dir)
    duplicate = any(item["fingerprint"] == key_fingerprint for item in existing_keys(authorized_path, pending_dir))
    cleanup_pending(pending_dir)
    token = secrets.token_urlsafe(24)
    pending_path = pending_dir / f"{token}.json"
    payload = {
        "version": 1,
        "issued_at": int(time.time()),
        "public_key": normalized,
        "fingerprint": key_fingerprint,
    }
    descriptor = os.open(pending_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        json.dump(payload, output, ensure_ascii=False, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps({
        "schema_version": 1,
        "pending_token": token,
        "type": key_type,
        "fingerprint": key_fingerprint,
        "name": comment or "未命名客户端",
        "duplicate": duplicate,
        "expires_in": PENDING_TTL,
    }, ensure_ascii=False, separators=(",", ":")))


def add_key(authorized_path: Path, pending_dir: Path, token: str) -> None:
    if not TOKEN_PATTERN.fullmatch(token):
        fail("SSH 公钥暂存标识无效。")
    pending_path = pending_dir / f"{token}.json"
    if pending_path.is_symlink() or not pending_path.is_file():
        fail("SSH 公钥确认已过期或不存在。")
    try:
        data = json.loads(pending_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("SSH 公钥暂存内容无效。")
    pending_path.unlink(missing_ok=True)
    if (
        not isinstance(data, dict)
        or data.get("version") != 1
        or not isinstance(data.get("issued_at"), int)
        or not 0 <= int(time.time()) - data["issued_at"] <= PENDING_TTL
    ):
        fail("SSH 公钥确认已过期。")
    key_type, encoded, comment, normalized = normalize_key(data.get("public_key"))
    key_fingerprint = fingerprint(normalized, pending_dir)
    if key_fingerprint != data.get("fingerprint"):
        fail("SSH 公钥暂存内容校验失败。")
    current = existing_keys(authorized_path, pending_dir)
    duplicate = any(item["fingerprint"] == key_fingerprint for item in current)
    if not duplicate:
        try:
            original = authorized_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            original = ""
        except OSError:
            fail("无法读取 root authorized_keys。")
        content = original.rstrip("\n")
        content = (content + "\n" if content else "") + normalized + "\n"
        write_authorized_keys(authorized_path, content)
    print(json.dumps({
        "schema_version": 1,
        "added": not duplicate,
        "type": key_type,
        "fingerprint": key_fingerprint,
        "name": comment or "未命名客户端",
        "key_id": key_identifier(encoded),
    }, ensure_ascii=False, separators=(",", ":")))


def delete_key(authorized_path: Path, pending_dir: Path, key_id: str) -> None:
    if not KEY_ID_PATTERN.fullmatch(key_id):
        fail("SSH 公钥标识无效。")
    try:
        lines = authorized_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        fail("无法读取 root authorized_keys。")
    items = existing_keys(authorized_path, pending_dir)
    if len(items) <= 1:
        fail("至少必须保留一把有效的 root SSH 公钥。")
    target = next((item for item in items if item["key_id"] == key_id), None)
    if target is None:
        fail("SSH 公钥不存在。")
    remaining: list[str] = []
    removed = False
    for raw in lines:
        parsed = key_from_authorized_line(raw, pending_dir)
        if parsed is not None and parsed["key_id"] == key_id:
            removed = True
            continue
        remaining.append(raw)
    if not removed:
        fail("SSH 公钥不存在。")
    content = "\n".join(remaining).rstrip("\n")
    write_authorized_keys(authorized_path, content + ("\n" if content else ""))
    print(json.dumps({
        "schema_version": 1,
        "deleted": True,
        "key_id": key_id,
        "type": target["type"],
        "fingerprint": target["fingerprint"],
        "name": target["name"],
    }, ensure_ascii=False, separators=(",", ":")))


def rename_key(authorized_path: Path, pending_dir: Path, key_id: str) -> None:
    if not KEY_ID_PATTERN.fullmatch(key_id):
        fail("SSH 公钥标识无效。")
    try:
        request = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        fail("SSH 客户端改名请求无效。")
    if not isinstance(request, dict) or set(request) != {"name"}:
        fail("SSH 客户端改名字段无效。")
    name = validate_name(request["name"])
    try:
        lines = authorized_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        fail("无法读取 root authorized_keys。")
    target = next((item for item in existing_keys(authorized_path, pending_dir) if item["key_id"] == key_id), None)
    if target is None:
        fail("SSH 公钥不存在。")
    changed = False
    rewritten: list[str] = []
    for raw in lines:
        parsed = key_from_authorized_line(raw, pending_dir)
        if parsed is None or parsed["key_id"] != key_id:
            rewritten.append(raw)
            continue
        words = raw.strip().split()
        index = next(i for i, word in enumerate(words) if word in KEY_TYPES)
        marker = f"{words[index]} {words[index + 1]}"
        marker_index = raw.find(marker)
        prefix = raw[:marker_index] if marker_index >= 0 else ""
        rewritten.append(f"{prefix}{marker} {name}")
        changed = True
    if not changed:
        fail("SSH 公钥不存在。")
    write_authorized_keys(authorized_path, "\n".join(rewritten).rstrip("\n") + "\n")
    print(json.dumps({
        "schema_version": 1,
        "renamed": True,
        "key_id": key_id,
        "type": target["type"],
        "fingerprint": target["fingerprint"],
        "name": name,
    }, ensure_ascii=False, separators=(",", ":")))


def main() -> None:
    if len(sys.argv) < 4:
        fail("用法：server_kit_ssh_keys.py <list|preview|add|delete|rename> <authorized_keys> <pending_dir> [标识]")
    command, authorized_text, pending_text = sys.argv[1:4]
    authorized_path = Path(authorized_text)
    pending_dir = Path(pending_text)
    if command == "list":
        list_keys(authorized_path, pending_dir)
    elif command == "preview":
        preview(authorized_path, pending_dir)
    elif command == "add" and len(sys.argv) == 5:
        add_key(authorized_path, pending_dir, sys.argv[4])
    elif command == "delete" and len(sys.argv) == 5:
        delete_key(authorized_path, pending_dir, sys.argv[4])
    elif command == "rename" and len(sys.argv) == 5:
        rename_key(authorized_path, pending_dir, sys.argv[4])
    else:
        fail("SSH 公钥动作无效。")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""维护普通文件服务的多资源配置。"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import re
import secrets
import stat
import tempfile
from pathlib import Path
from urllib.parse import quote


RESOURCE_PATTERN = re.compile(r"file-[0-9a-f]{16}\Z")
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024
MAX_RESOURCES = 200


class FileResourceError(RuntimeError):
    """表示文件资源配置或变更无效。"""


def _stable_id(token: str) -> str:
    return "file-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _load(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FileResourceError("普通文件服务尚未安装或配置无效。") from exc
    if not isinstance(data, dict):
        raise FileResourceError("普通文件配置格式不正确。")
    downloads = data.get("downloads", data.get("files"))
    if downloads is None and all(key in data for key in ("token", "download_name", "payload_path")):
        downloads = [data]
    if not isinstance(downloads, list) or len(downloads) > MAX_RESOURCES:
        raise FileResourceError("文件资源列表格式不正确或数量过多。")
    normalized: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    seen_tokens: set[str] = set()
    for raw in downloads:
        if not isinstance(raw, dict):
            raise FileResourceError("文件资源条目格式不正确。")
        token = raw.get("token")
        name = raw.get("download_name", raw.get("name"))
        payload = raw.get("payload_path")
        resource_id = raw.get("resource_id") or (_stable_id(token) if isinstance(token, str) else "")
        if (
            not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token)
            or not isinstance(name, str) or not NAME_PATTERN.fullmatch(name)
            or not isinstance(payload, str) or not Path(payload).is_absolute()
            or not isinstance(resource_id, str) or not RESOURCE_PATTERN.fullmatch(resource_id)
            or resource_id in seen_ids or token in seen_tokens
        ):
            raise FileResourceError("文件资源条目缺少安全字段或存在重复。")
        seen_ids.add(resource_id)
        seen_tokens.add(token)
        size = raw.get("file_size", raw.get("size", 0))
        ttl = raw.get("cache_ttl", 86400)
        cache = raw.get("cdn_cache", False)
        if not isinstance(size, int) or size < 0 or not isinstance(cache, bool):
            raise FileResourceError("文件资源大小或缓存字段无效。")
        if not isinstance(ttl, int) or not 300 <= ttl <= 2_592_000:
            raise FileResourceError("CDN 缓存时间必须为 5 分钟至 30 天。")
        normalized.append({
            "resource_id": resource_id,
            "token": token,
            "download_name": name,
            "payload_path": payload,
            "sha256": str(raw.get("sha256", ""))[:64],
            "file_size": size,
            "content_type": str(raw.get("content_type", "application/octet-stream"))[:128],
            "cdn_cache": cache,
            "cache_ttl": ttl,
        })
    result = {key: value for key, value in data.items() if key not in {
        "token", "download_name", "payload_path", "sha256", "file_size", "content_type", "files"
    }}
    result["mode"] = "file"
    result["downloads"] = normalized
    return result


def _write(path: Path, data: dict[str, object]) -> None:
    original = path.stat()
    descriptor, temporary = tempfile.mkstemp(prefix=".file-resources-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, stat.S_IMODE(original.st_mode))
        if hasattr(os, "chown"):
            os.chown(temporary, original.st_uid, original.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def overview(config_path: Path, service_state: str) -> dict[str, object]:
    data = _load(config_path)
    address = data.get("server_address", "")
    port = data.get("port", 0)
    if not isinstance(address, str) or not address or not isinstance(port, int) or not 1 <= port <= 65535:
        raise FileResourceError("普通文件服务地址或端口无效。")
    if service_state not in {"运行中", "已停止", "失败", "未安装"}:
        raise FileResourceError("普通文件服务状态无效。")
    items = []
    for item in data["downloads"]:
        assert isinstance(item, dict)
        items.append({
            "resource_id": item["resource_id"],
            "name": item["download_name"],
            "size": item["file_size"],
            "cdn_cache": item["cdn_cache"],
            "cache_ttl": item["cache_ttl"],
        })
    return {
        "schema_version": 1,
        "configured": True,
        "address": address,
        "port": port,
        "service_state": service_state,
        "items": items,
    }


def add(config_path: Path, source: Path, name: str, cache: bool, ttl: int, data_dir: Path, max_bytes: int) -> dict[str, object]:
    if not NAME_PATTERN.fullmatch(name) or not 300 <= ttl <= 2_592_000:
        raise FileResourceError("文件名或 CDN 缓存时间无效。")
    data = _load(config_path)
    downloads = data["downloads"]
    assert isinstance(downloads, list)
    if len(downloads) >= MAX_RESOURCES:
        raise FileResourceError("文件资源数量已达到上限。")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, flags)
    except OSError as exc:
        raise FileResourceError("上传文件不存在或无法安全读取。") from exc
    resource_id = "file-" + secrets.token_hex(8)
    target_dir = data_dir / "files"
    target = target_dir / resource_id
    digest = hashlib.sha256()
    total = 0
    try:
        info = os.fstat(source_fd)
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= max_bytes:
            raise FileResourceError(f"上传文件必须为 1 B–{max_bytes} B。")
        target_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        with os.fdopen(os.dup(source_fd), "rb") as reader, target.open("xb") as writer:
            while chunk := reader.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise FileResourceError("上传文件超过大小上限。")
                digest.update(chunk)
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        os.chmod(target, 0o640)
        config_stat = config_path.stat()
        if hasattr(os, "chown"):
            os.chown(target, 0, config_stat.st_gid)
        downloads.append({
            "resource_id": resource_id,
            "token": secrets.token_hex(32),
            "download_name": name,
            "payload_path": str(target),
            "sha256": digest.hexdigest(),
            "file_size": total,
            "content_type": mimetypes.guess_type(name)[0] or "application/octet-stream",
            "cdn_cache": cache,
            "cache_ttl": ttl,
        })
        _write(config_path, data)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    finally:
        os.close(source_fd)
    return {"schema_version": 1, "operation": "add", "resource_id": resource_id, "payload_path": str(target)}


def detach(config_path: Path, resource_id: str) -> dict[str, object]:
    if not RESOURCE_PATTERN.fullmatch(resource_id):
        raise FileResourceError("文件资源标识格式不正确。")
    data = _load(config_path)
    downloads = data["downloads"]
    assert isinstance(downloads, list)
    matches = [item for item in downloads if item.get("resource_id") == resource_id]
    if len(matches) != 1:
        raise FileResourceError("文件资源不存在或不唯一。")
    item = matches[0]
    data["downloads"] = [entry for entry in downloads if entry is not item]
    _write(config_path, data)
    return {"schema_version": 1, "operation": "delete", "resource_id": resource_id, "payload_path": item["payload_path"]}


def purge(path: Path, data_dir: Path) -> dict[str, object]:
    data_root = data_dir.resolve()
    files_dir = (data_root / "files").resolve()
    candidate = path.resolve()
    managed_file = candidate.parent == files_dir and RESOURCE_PATTERN.fullmatch(candidate.name)
    legacy_file = candidate.parent == data_root and candidate.is_file()
    if (not managed_file and not legacy_file) or candidate.is_symlink():
        raise FileResourceError("待清理文件不在受管目录内。")
    candidate.unlink(missing_ok=True)
    return {"schema_version": 1, "purged": True}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("overview", "add", "detach", "purge"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--name", default="")
    parser.add_argument("--resource-id", default="")
    parser.add_argument("--payload-path", type=Path)
    parser.add_argument("--cdn-cache", choices=("true", "false"), default="true")
    parser.add_argument("--cache-ttl", type=int, default=86400)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--service-state", default="")
    args = parser.parse_args()
    try:
        if args.operation == "overview":
            result = overview(args.config, args.service_state)
        elif args.operation == "add":
            if args.source is None:
                raise FileResourceError("缺少上传文件。")
            result = add(args.config, args.source, args.name, args.cdn_cache == "true", args.cache_ttl, args.data_dir, args.max_bytes)
        elif args.operation == "detach":
            result = detach(args.config, args.resource_id)
        else:
            if args.payload_path is None:
                raise FileResourceError("缺少待清理文件路径。")
            result = purge(args.payload_path, args.data_dir)
    except FileResourceError as exc:
        print(str(exc), file=os.sys.stderr)
        return 1
    json.dump(result, os.sys.stdout, ensure_ascii=False, separators=(",", ":"))
    os.sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

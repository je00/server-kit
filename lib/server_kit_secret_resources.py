#!/usr/bin/env python3
"""按节点、按用途生成 Clash 敏感资源。"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable
from urllib.parse import quote


TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,256}\Z")
ITEM_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
QrRenderer = Callable[[str], bytes]


class SecretResourceError(RuntimeError):
    """表示敏感资源配置无效或无法安全生成。"""


def _validate_square_png(output: bytes) -> None:
    if (
        not output.startswith(PNG_SIGNATURE)
        or len(output) < 24
        or len(output) > 500_000
        or output[12:16] != b"IHDR"
    ):
        raise SecretResourceError("二维码 PNG 无效或过大")
    width = int.from_bytes(output[16:20], "big")
    height = int.from_bytes(output[20:24], "big")
    if width != height or not 64 <= width <= 4096:
        raise SecretResourceError("二维码 PNG 必须为合理尺寸的正方形")


def clean_label(value: object, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    cleaned = "".join(character for character in value.strip() if character.isprintable())
    return cleaned[:96] or fallback


def render_qr_png(url: str, qrencode_path: str) -> bytes:
    """用固定参数生成方形 PNG，测试环境可注入无敏感信息的样本。"""
    test_value = os.environ.get("SERVER_KIT_QR_TEST_BASE64", "")
    if os.environ.get("SERVER_KIT_TESTING") == "1" and test_value:
        try:
            output = base64.b64decode(test_value, validate=True)
        except ValueError as exc:
            raise SecretResourceError("二维码测试数据无效") from exc
    else:
        path = Path(qrencode_path)
        if not path.is_absolute():
            raise SecretResourceError("二维码程序必须使用绝对路径")
        try:
            completed = subprocess.run(
                [str(path), "-t", "PNG", "-l", "L", "-m", "2", "-s", "8", "-o", "-"],
                input=url.encode("utf-8"),
                capture_output=True,
                check=False,
                timeout=8,
                env={
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                },
                cwd="/",
            )
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise SecretResourceError("二维码生成失败") from exc
        if completed.returncode != 0:
            raise SecretResourceError("二维码生成失败")
        output = completed.stdout
    _validate_square_png(output)
    return output


def _load_subscription(config_path: Path, item_id: str) -> tuple[str, str]:
    if not ITEM_ID_PATTERN.fullmatch(item_id):
        raise SecretResourceError("节点标识格式不正确")
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SecretResourceError("无法读取 Clash 订阅配置") from exc
    if not isinstance(data, dict) or data.get("mode") != "clash":
        raise SecretResourceError("当前不是 Clash 多订阅配置")
    address = data.get("server_address")
    port = data.get("port")
    downloads = data.get("downloads")
    if (
        not isinstance(address, str)
        or not address
        or len(address) > 255
        or any(character.isspace() or not character.isprintable() for character in address)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
        or not isinstance(downloads, list)
        or len(downloads) > 50
    ):
        raise SecretResourceError("Clash 订阅配置格式不正确")

    matches = [item for item in downloads if isinstance(item, dict) and item.get("peer_name") == item_id]
    if len(matches) != 1:
        raise SecretResourceError("订阅节点不存在或不唯一")
    item = matches[0]
    token = item.get("token")
    download_name = item.get("download_name")
    if (
        not isinstance(token, str)
        or not TOKEN_PATTERN.fullmatch(token)
        or not isinstance(download_name, str)
        or not download_name
        or len(download_name) > 255
    ):
        raise SecretResourceError("Clash 订阅条目缺少安全令牌或文件名")
    url = f"https://{address}:{port}/{token}/{quote(download_name, safe='')}"
    return clean_label(item.get("peer_name"), "未命名节点"), url


def build_clash_subscription_resource(
    config_path: Path,
    resource: str,
    item_id: str,
    qr_renderer: QrRenderer,
) -> dict[str, object]:
    name, url = _load_subscription(config_path, item_id)
    common: dict[str, object] = {
        "schema_version": 1,
        "item_id": item_id,
        "name": name,
    }
    if resource == "subscription-link":
        return {**common, "resource": "clash_subscription_link", "value": url}
    if resource == "subscription-qr":
        png = qr_renderer(url)
        if not isinstance(png, bytes):
            raise SecretResourceError("二维码生成结果无效")
        _validate_square_png(png)
        return {
            **common,
            "resource": "clash_subscription_qr",
            "image_base64": base64.b64encode(png).decode("ascii"),
        }
    raise SecretResourceError("敏感资源未登记")


def build_file_download_resource(
    config_path: Path,
    resource: str,
    item_id: str,
    qr_renderer: QrRenderer,
) -> dict[str, object]:
    if not re.fullmatch(r"file-[0-9a-f]{16}", item_id):
        raise SecretResourceError("文件资源标识格式不正确")
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SecretResourceError("无法读取普通文件配置") from exc
    downloads = data.get("downloads") if isinstance(data, dict) else None
    if downloads is None and isinstance(data, dict) and all(key in data for key in ("token", "download_name")):
        token = data.get("token")
        legacy_id = "file-" + hashlib.sha256(str(token).encode("utf-8")).hexdigest()[:16]
        downloads = [{**data, "resource_id": legacy_id}]
    address = data.get("server_address") if isinstance(data, dict) else None
    port = data.get("port") if isinstance(data, dict) else None
    if not isinstance(downloads, list) or not isinstance(address, str) or not address or not isinstance(port, int) or not 1 <= port <= 65535:
        raise SecretResourceError("普通文件配置格式不正确")
    matches = [item for item in downloads if isinstance(item, dict) and item.get("resource_id") == item_id]
    if len(matches) != 1:
        raise SecretResourceError("文件资源不存在或不唯一")
    item = matches[0]
    token = item.get("token")
    name = item.get("download_name")
    if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token) or not isinstance(name, str) or not name:
        raise SecretResourceError("文件资源缺少安全令牌或文件名")
    url = f"https://{address}:{port}/{token}/{quote(name, safe='')}"
    common = {"schema_version": 1, "item_id": item_id, "name": clean_label(name, "未命名文件")}
    if resource == "file-link":
        return {**common, "resource": "file_download_link", "value": url}
    if resource == "file-qr":
        png = qr_renderer(url)
        _validate_square_png(png)
        return {**common, "resource": "file_download_qr", "image_base64": base64.b64encode(png).decode("ascii")}
    raise SecretResourceError("敏感资源未登记")


def main() -> int:
    if len(sys.argv) != 6:
        print("敏感资源参数数量不正确", file=sys.stderr)
        return 1
    try:
        renderer = lambda value: render_qr_png(value, sys.argv[2])
        if sys.argv[4] in {"subscription-link", "subscription-qr"}:
            result = build_clash_subscription_resource(Path(sys.argv[1]), sys.argv[4], sys.argv[5], renderer)
        elif sys.argv[4] in {"file-link", "file-qr"}:
            result = build_file_download_resource(Path(sys.argv[3]), sys.argv[4], sys.argv[5], renderer)
        else:
            raise SecretResourceError("敏感资源未登记")
    except SecretResourceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

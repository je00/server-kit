#!/usr/bin/env python3
"""管理每个节点的 Clash 发布开关与纯净模式。"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path


NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


class PublicationStateError(RuntimeError):
    """发布状态文件无效或无法安全写入。"""


def _names(value: object, field: str) -> list[str]:
    if not isinstance(value, list):
        raise PublicationStateError(f"发布状态中的 {field} 必须是列表。")
    names = set()
    for item in value:
        if not isinstance(item, str) or not NAME_PATTERN.fullmatch(item):
            raise PublicationStateError(f"发布状态中的 {field} 包含无效节点名称。")
        names.add(item)
    return sorted(names)


def normalize(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PublicationStateError("发布状态顶层必须是对象。")
    version = value.get("version", 1)
    if version != 1:
        raise PublicationStateError("发布状态版本不受支持。")
    return {
        "version": 1,
        "disabled": _names(value.get("disabled", []), "disabled"),
        "clean_mode": _names(value.get("clean_mode", []), "clean_mode"),
    }


def load(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {"version": 1, "disabled": [], "clean_mode": []}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PublicationStateError(f"无法读取发布状态：{error}") from error
    return normalize(value)


def write(path: Path, value: object) -> None:
    state = normalize(value)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def set_publication(path: Path, name: str, enabled: bool) -> None:
    if not NAME_PATTERN.fullmatch(name):
        raise PublicationStateError("节点名称格式不正确。")
    state = load(path)
    disabled = set(state["disabled"])
    if enabled:
        disabled.discard(name)
    else:
        disabled.add(name)
    state["disabled"] = sorted(disabled)
    write(path, state)


def set_clean_mode(path: Path, name: str, enabled: bool) -> None:
    if not NAME_PATTERN.fullmatch(name):
        raise PublicationStateError("节点名称格式不正确。")
    state = load(path)
    clean_nodes = set(state["clean_mode"])
    if enabled:
        clean_nodes.add(name)
    else:
        clean_nodes.discard(name)
    state["clean_mode"] = sorted(clean_nodes)
    write(path, state)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    publication = subparsers.add_parser("set-publication")
    publication.add_argument("name")
    publication.add_argument("state", choices=("enabled", "disabled"))
    clean_mode = subparsers.add_parser("set-clean-mode")
    clean_mode.add_argument("name")
    clean_mode.add_argument("state", choices=("enabled", "disabled"))
    args = parser.parse_args()
    try:
        if args.command == "set-publication":
            set_publication(args.config, args.name, args.state == "enabled")
        else:
            set_clean_mode(args.config, args.name, args.state == "enabled")
    except PublicationStateError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
